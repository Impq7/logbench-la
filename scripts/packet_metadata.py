"""Standalone, standard PCAP reader — the pure N-modality parser.

Input is raw pcap bytes; output is the standard traffic structure a traditional
IDS / malicious-traffic parser would emit: link/network/transport protocol,
IP version, ethertype, endpoints, ports, TCP flags, payload length, DNS query
metadata, TLS handshake metadata (SNI, record/handshake type), and the raw pcap
epoch ``timestamp``. No per-packet hashes, no clock alignment, and — critically —
no Agent concept: it does not know which agent or which interaction round a
packet belongs to, and never emits any agent-attribution field.

Raw packets remain the source of truth; this reader only decodes metadata.
"""
import ipaddress
import struct


def dns_questions(data):
    if len(data) < 12:
        raise ValueError('Short DNS header')
    count = struct.unpack('!H', data[4:6])[0]
    if count > 256:
        raise ValueError('Excessive DNS questions')
    def name(offset, visited=None):
        visited = set() if visited is None else visited
        labels, end = [], None
        for _ in range(128):
            if offset >= len(data) or offset in visited:
                raise ValueError('Invalid DNS name pointer')
            visited.add(offset)
            size = data[offset]
            if size & 0xc0 == 0xc0:
                if offset + 1 >= len(data):
                    raise ValueError('Short DNS pointer')
                tail, _ = name(((size & 63) << 8) | data[offset+1], visited)
                return '.'.join(labels + [tail]), offset + 2
            offset += 1
            if size == 0:
                return '.'.join(labels), offset
            if size > 63 or offset + size > len(data):
                raise ValueError('Invalid DNS label')
            labels.append(data[offset:offset+size].decode('utf-8', errors='replace'))
            offset += size
        raise ValueError('Excessive DNS name depth')
    questions, offset = [], 12
    for _ in range(count):
        query, offset = name(offset)
        if offset + 4 > len(data):
            raise ValueError('Short DNS question')
        qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
        questions.append({'name': query, 'type': qtype, 'class': qclass & 0x7fff})
        offset += 4
    return {'is_response': bool(data[2] & 0x80), 'questions': questions}


def _clienthello_sni(body):
    """Extract the server_name (SNI) from a TLS ClientHello body. Best-effort, never raises."""
    try:
        pos = 2 + 32                       # legacy_version + random
        slen = body[pos]                   # session id length
        pos += 1 + slen
        clen = int.from_bytes(body[pos:pos+2], 'big')
        pos += 2 + clen                    # cipher suites
        complen = body[pos]
        pos += 1 + complen                 # compression methods
        if pos + 2 > len(body):
            return None
        ext_total = int.from_bytes(body[pos:pos+2], 'big')
        pos += 2
        end = min(pos + ext_total, len(body))
        while pos + 4 <= end:
            etype = int.from_bytes(body[pos:pos+2], 'big')
            elen = int.from_bytes(body[pos+2:pos+4], 'big')
            edata = body[pos+4:pos+4+elen]
            if etype == 0 and len(edata) >= 5:  # server_name extension
                nlen = int.from_bytes(edata[0:2], 'big')
                npos = 2
                names = []
                while npos + 3 <= min(2 + nlen, len(edata)):
                    ntype = edata[npos]
                    l = int.from_bytes(edata[npos+1:npos+3], 'big')
                    if ntype == 0:
                        names.append(edata[npos+3:npos+3+l].decode('utf-8', 'replace'))
                    npos += 3 + l
                return names[0] if names else None
            pos += 4 + elen
        return None
    except (IndexError, struct.error):
        return None


def tls_handshake_meta(payload):
    """Best-effort single-segment TLS record metadata (record type, handshake type,
    version, and ClientHello SNI). Returns None when the bytes are not a TLS record.

    Only the handshake *metadata* (which is sent in the clear before the encrypted
    record) is exposed — exactly like DNS query names. Raw application payload bytes
    are never exported.
    """
    if not payload or len(payload) < 5:
        return None
    ctype = payload[0]
    if ctype not in (0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b):
        return None
    version = payload[1:3]
    if version not in (b'\x03\x00', b'\x03\x01', b'\x03\x02', b'\x03\x03'):
        return None
    rlen = int.from_bytes(payload[3:5], 'big')
    record = payload[5:5+rlen]
    meta = {'record_type': ctype, 'version': version.hex()}
    if ctype != 0x16 or len(record) < 4:
        return meta
    htype = record[0]
    meta['handshake_type'] = htype
    body = record[4:4+int.from_bytes(record[1:4], 'big')]
    if htype == 1:  # ClientHello
        sni = _clienthello_sni(body)
        if sni:
            meta['sni'] = sni
    return meta


def decode_packet(data, linktype):
    row = {'parse_status': 'ok', 'dns_query': None}
    prefix, type_offset = {1: (14, 12), 113: (16, 14), 276: (20, 0)}[linktype]
    if len(data) < prefix:
        raise ValueError('Short link header')
    ethertype = int.from_bytes(data[type_offset:type_offset+2], 'big')
    if linktype == 1:
        row['source_mac'] = data[6:12].hex(':')
        row['destination_mac'] = data[:6].hex(':')
    else:
        row['capture_packet_type'] = int.from_bytes(data[:2], 'big') if linktype == 113 else data[10]
    while ethertype in (0x8100, 0x88a8):
        if len(data) < prefix + 4:
            raise ValueError('Short VLAN header')
        ethertype = int.from_bytes(data[prefix+2:prefix+4], 'big')
        prefix += 4
    row['ethertype'] = ethertype
    ip = data[prefix:]
    if ethertype == 0x806:
        row['network_protocol'] = 'ARP'
        return row
    if ethertype == 0x800:
        if len(ip) < 20 or ip[0] >> 4 != 4:
            raise ValueError('Invalid IPv4 header')
        offset = (ip[0] & 15) * 4
        if offset < 20 or len(ip) < offset:
            raise ValueError('Invalid IPv4 IHL')
        total = int.from_bytes(ip[2:4], 'big')
        if total < offset or total > len(ip):
            raise ValueError('Invalid/truncated IPv4 total length')
        ip = ip[:total]
        row.update(ip_version=4, src=str(ipaddress.ip_address(ip[12:16])),
                   dst=str(ipaddress.ip_address(ip[16:20])), protocol=ip[9])
        fragment = int.from_bytes(ip[6:8], 'big')
        if fragment & 0x3fff:
            row.update(fragmented=True, parse_status='fragment_requires_reassembly')
            return row
    elif ethertype == 0x86dd:
        if len(ip) < 40 or ip[0] >> 4 != 6:
            raise ValueError('Invalid IPv6 header')
        total=40+int.from_bytes(ip[4:6],'big')
        if total>len(ip):
            raise ValueError('Truncated IPv6 payload')
        ip=ip[:total]
        row.update(ip_version=6, src=str(ipaddress.ip_address(ip[8:24])), dst=str(ipaddress.ip_address(ip[24:40])))
        protocol, offset = ip[6], 40
        for _ in range(16):
            if protocol in (0, 43, 60):
                if offset + 2 > len(ip):
                    raise ValueError('Short IPv6 extension')
                protocol, size = ip[offset:offset+2]
                offset += (size+1)*8
            elif protocol == 44:
                row.update(protocol=protocol, fragmented=True, parse_status='fragment_requires_reassembly')
                return row
            else:
                break
        else:
            raise ValueError('Excessive IPv6 extensions')
        row['protocol'] = protocol
    else:
        row.update(network_protocol='other', parse_status='unsupported_ethertype')
        return row
    protocol = row['protocol']
    row['network_protocol'] = {6:'TCP',17:'UDP',1:'ICMP',58:'ICMPv6'}.get(protocol, str(protocol))
    if protocol in (1, 58):
        if len(ip[offset:]) >= 2:
            row['icmp_type'], row['icmp_code'] = ip[offset], ip[offset + 1]
        return row
    if protocol not in (6,17):
        return row
    transport = ip[offset:]
    minimum = 20 if protocol == 6 else 8
    if len(transport) < minimum:
        raise ValueError('Short transport header')
    row['src_port'], row['dst_port'] = struct.unpack('!HH', transport[:4])
    if protocol == 6:
        header_size = (transport[12] >> 4)*4
        if header_size < 20 or header_size > len(transport):
            raise ValueError('Invalid TCP header length')
        row.update(tcp_seq=int.from_bytes(transport[4:8], 'big'), tcp_ack=int.from_bytes(transport[8:12], 'big'), tcp_flags=transport[13])
        payload = transport[header_size:]
    else:
        udp_length=int.from_bytes(transport[4:6],'big')
        if udp_length<8 or udp_length>len(transport):
            raise ValueError('Invalid/truncated UDP length')
        transport=transport[:udp_length]
        payload = transport[8:]
    row['payload_length'] = len(payload)
    if protocol == 17 and ({row['src_port'], row['dst_port']} & {53, 5353, 5355}):
        try:
            row['dns'] = dns_questions(payload)
            row['dns_query'] = [q['name'] for q in row['dns']['questions']]
        except ValueError as exc:
            row['dns_parse_error'] = str(exc)
    if protocol == 17 and ({row['src_port'], row['dst_port']} & {123}):
        if len(payload) >= 4:
            row['ntp'] = {'version': (payload[0] >> 3) & 0x7, 'mode': payload[0] & 0x7,
                          'stratum': payload[1]}
    # TLS handshake metadata (ClientHello SNI + record/handshake type). The SNI is
    # sent in the clear before the encrypted record, so it is extracted exactly like
    # DNS query names; raw TCP/TLS/HTTP payload bytes are still never exported.
    if protocol == 6 and payload:
        tls = tls_handshake_meta(payload)
        if tls:
            row['tls'] = tls
            row['tls_record_type'] = tls.get('record_type')
            row['tls_handshake_type'] = tls.get('handshake_type')
            row['sni_host'] = tls.get('sni')
    return row


def pcap_packets(path):
    packets = []
    with path.open('rb') as stream:
        header = stream.read(24)
        magic = {b'\xd4\xc3\xb2\xa1':('<',1e6), b'\xa1\xb2\xc3\xd4':('>',1e6),
                 b'\x4d\x3c\xb2\xa1':('<',1e9), b'\xa1\xb2\x3c\x4d':('>',1e9)}
        if len(header) != 24 or header[:4] not in magic:
            raise ValueError('Missing/unsupported PCAP header')
        endian, resolution = magic[header[:4]]
        linktype = struct.unpack(endian+'I',header[20:24])[0]
        if linktype not in (1,113,276):
            raise ValueError('Unsupported link type: '+str(linktype))
        while True:
            offset = stream.tell()
            h = stream.read(16)
            if not h:
                break
            if len(h) != 16:
                raise ValueError('Truncated packet header')
            sec, fraction, incl, orig = struct.unpack(endian+'IIII',h)
            if incl > 16*1024*1024 or incl != orig:
                raise ValueError('Truncated/invalid packet length')
            data = stream.read(incl)
            if len(data) != incl:
                raise ValueError('Truncated packet data')
            row = {'record_index':len(packets), 'offset':offset, 'timestamp':sec+fraction/resolution,
                   'length':orig, 'linktype':linktype}
            try:
                row.update(decode_packet(data,linktype))
            except (ValueError,IndexError,struct.error) as exc:
                row.update(parse_status='malformed',parse_error=str(exc))
            packets.append(row)
    return packets
