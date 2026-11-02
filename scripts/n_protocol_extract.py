"""General multi-protocol network extractor (offline, from raw pcap bytes).

Supersedes ``n_http_extract.py``. That module only handled IPv4 + TCP + port 8080
+ plaintext HTTP. This module reassembles **generic TCP/UDP flows** and, per flow,
identifies and extracts its application protocol:

  - HTTP    plaintext request/response (Content-Length framing; chunked flagged)
  - TLS     ClientHello JA3 fingerprint + SNI + cipher suites + extensions +
            supported groups / versions / ALPN; ServerHello selected suite/version;
            leaf certificate subject / issuer / SAN (best-effort DER walk)
  - DNS     queries and responses (names / types / classes)
  - NTP     UDP :123 (version / mode)
  - ARP / ICMP / ICMPv6  metadata (opcode / type / code)
  - generic TCP / UDP    flow statistics only

No agent / application attribution: the extractor does not know which agent or
which tool a flow belongs to, and emits no ``application_role`` / ``tool_call_id``
labels. Associating traffic with the agent/T/E modalities is a later fusion-stage
concern.

Timestamps are aligned to the session relative timeline via the N-event ``offset``
field (byte offset of the packet header in the pcap), which is safe under the
WSL2 clock-step ambiguity — exactly the convention used by ``n_http_extract.py``.

Standard library only (like ``session_storage.py``).
"""
import collections
import hashlib
import ipaddress
import json
import struct
from pathlib import Path

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = (0x8100, 0x88A8)

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

# link types supported by the collection tcpdump adapter (mirror packet_metadata)
LINK_ETHERNET = 1
LINK_LINUX_SLL = 113
LINK_LINUX_SLL2 = 276


# ---------------------------------------------------------------------------
# pcap framing
# ---------------------------------------------------------------------------
def parse_pcap_bytes(data):
    """Decode a whole pcap byte string into a list of packet dicts.

    Each packet carries ``offset`` (byte offset of its pcap record header) so the
    caller can map it to the collection-layer ``relative_timestamp``.
    """
    if len(data) < 24:
        return []
    magic = struct.unpack('<I', data[0:4])[0]
    if magic == 0xa1b2c3d4:
        endian = '<'
        res = 1e6
    elif magic == 0xd4c3b2a1:
        endian = '>'
        res = 1e6
    elif magic == 0x4d3cb2a1:
        endian = '<'
        res = 1e9
    elif magic == 0xa1b23c4d:
        endian = '>'
        res = 1e9
    else:
        raise ValueError('Unrecognized pcap magic: %r' % magic)
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    packets = []
    off = 24
    while off + 16 <= len(data):
        pkt_off = off
        ts_sec, ts_usec, incl, _ = struct.unpack(endian + 'IIII', data[off:off + 16])
        off += 16
        raw = data[off:off + incl]
        off += incl
        p = {'offset': pkt_off, 'ts': ts_sec + ts_usec / res, 'linktype': linktype, 'raw': raw}
        try:
            p.update(_decode_frame(raw, linktype))
        except (ValueError, IndexError, struct.error):
            p.update(network_protocol='malformed')
        packets.append(p)
    return packets


def _decode_frame(raw, linktype):
    """Decode one link-layer frame into network/transport fields + payload."""
    out = {'network_protocol': 'unknown'}
    if linktype == LINK_ETHERNET:
        if len(raw) < 14:
            raise ValueError('short ethernet')
        out['src_mac'] = raw[6:12].hex(':')
        out['dst_mac'] = raw[0:6].hex(':')
        ethertype = struct.unpack('>H', raw[12:14])[0]
        pos = 14
    elif linktype == LINK_LINUX_SLL:
        if len(raw) < 16:
            raise ValueError('short sll')
        ethertype = struct.unpack('>H', raw[14:16])[0]
        pos = 16
    elif linktype == LINK_LINUX_SLL2:
        if len(raw) < 20:
            raise ValueError('short sll2')
        ethertype = struct.unpack('>H', raw[0:2])[0]
        pos = 20
    else:
        out['network_protocol'] = 'unsupported_linktype'
        return out
    while ethertype in ETHERTYPE_VLAN:
        if len(raw) < pos + 4:
            raise ValueError('short vlan')
        ethertype = struct.unpack('>H', raw[pos + 2:pos + 4])[0]
        pos += 4
    out['ethertype'] = ethertype
    if ethertype == ETHERTYPE_ARP:
        return _decode_arp(raw[pos:], out)
    if ethertype == ETHERTYPE_IPV4:
        return _decode_ipv4(raw[pos:], out)
    if ethertype == ETHERTYPE_IPV6:
        return _decode_ipv6(raw[pos:], out)
    out['network_protocol'] = 'other'
    return out


def _decode_arp(body, out):
    if len(body) < 8:
        raise ValueError('short arp')
    out['network_protocol'] = 'ARP'
    out['arp_op'] = struct.unpack('>H', body[6:8])[0]
    return out


def _decode_ipv4(ip, out):
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise ValueError('bad ipv4')
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        raise ValueError('bad ipv4 ihl')
    total = struct.unpack('>H', ip[2:4])[0]
    if total < ihl or total > len(ip):
        raise ValueError('bad ipv4 total')
    ip = ip[:total]
    protocol = ip[9]
    frag = struct.unpack('>H', ip[6:8])[0]
    out.update(ip_version=4,
               src=str(ipaddress.IPv4Address(ip[12:16])),
               dst=str(ipaddress.IPv4Address(ip[16:20])),
               protocol=protocol)
    if frag & 0x3fff:
        out.update(fragmented=True, network_protocol='IPv4-fragment')
        return out
    return _decode_transport(protocol, ip[ihl:], out)


def _decode_ipv6(ip, out):
    if len(ip) < 40 or ip[0] >> 4 != 6:
        raise ValueError('bad ipv6')
    payload_len = struct.unpack('>H', ip[4:6])[0]
    total = 40 + payload_len
    if total > len(ip):
        raise ValueError('bad ipv6 payload')
    ip = ip[:total]
    protocol = ip[6]
    offset = 40
    for _ in range(16):
        if protocol in (0, 43, 60):  # hop-by-hop, routing, dest opts
            if offset + 2 > len(ip):
                raise ValueError('short ipv6 ext')
            protocol, size = ip[offset], ip[offset + 1]
            offset += (size + 1) * 8
        elif protocol == 44:  # fragment
            out.update(ip_version=6, protocol=44, fragmented=True,
                       network_protocol='IPv6-fragment')
            return out
        else:
            break
    else:
        raise ValueError('excessive ipv6 extensions')
    out.update(ip_version=6,
               src=str(ipaddress.IPv6Address(ip[8:24])),
               dst=str(ipaddress.IPv6Address(ip[24:40])),
               protocol=protocol)
    return _decode_transport(protocol, ip[offset:], out)


def _decode_transport(protocol, body, out):
    if protocol == PROTO_ICMP:
        out['network_protocol'] = 'ICMP'
        if len(body) >= 2:
            out['icmp_type'], out['icmp_code'] = body[0], body[1]
        return out
    if protocol == PROTO_ICMPV6:
        out['network_protocol'] = 'ICMPv6'
        if len(body) >= 2:
            out['icmp_type'], out['icmp_code'] = body[0], body[1]
        return out
    if protocol == PROTO_TCP:
        if len(body) < 20:
            raise ValueError('short tcp')
        out['network_protocol'] = 'TCP'
        sport, dport = struct.unpack('>HH', body[0:4])
        out['src_port'], out['dst_port'] = sport, dport
        out['tcp_seq'] = struct.unpack('>I', body[4:8])[0]
        out['tcp_ack'] = struct.unpack('>I', body[8:12])[0]
        doff = (body[12] >> 4) * 4
        out['tcp_flags'] = body[13]
        if doff < 20 or doff > len(body):
            raise ValueError('bad tcp doff')
        out['payload'] = body[doff:]
        return out
    if protocol == PROTO_UDP:
        if len(body) < 8:
            raise ValueError('short udp')
        sport, dport = struct.unpack('>HH', body[0:4])
        ulen = struct.unpack('>H', body[4:6])[0]
        if ulen < 8 or ulen > len(body):
            raise ValueError('bad udp length')
        out['network_protocol'] = 'UDP'
        out['src_port'], out['dst_port'] = sport, dport
        out['payload'] = body[8:ulen]
        return out
    out['network_protocol'] = 'proto-%d' % protocol
    return out


# ---------------------------------------------------------------------------
# flow reassembly
# ---------------------------------------------------------------------------
def reassemble_flows(packets):
    """Group packets into bidirectional flows and reassemble per-direction bytes.

    Returns dict keyed by canonical 5-tuple with:
      'client': (src, sport), 'server': (dst, dport),
      'c2s': reassembled bytes, 's2c': reassembled bytes,
      'c2s_offsets': pcap offsets of client->server data segments,
      'packets': count, 'first_ts', 'last_ts'.
    The ``server`` endpoint is chosen as the one matching the known tool/gateway
    ports; otherwise it is inferred from the first SYN.
    """
    flows = collections.defaultdict(list)
    for p in packets:
        if 'src_port' not in p or 'src' not in p:
            continue
        key = (p['protocol'],) + tuple(sorted(((p['src'], p['src_port']),
                                               (p['dst'], p['dst_port']))))
        flows[key].append(p)

    out = {}
    for key, ps in flows.items():
        proto = key[0]
        # identify server side: the SYN receiver for TCP, else the first packet's dst
        server_ep = None
        syn = [p for p in ps if p.get('tcp_flags', 0) & 0x02]
        if syn:
            server_ep = (syn[0]['dst'], syn[0]['dst_port'])
        else:
            server_ep = (ps[0]['dst'], ps[0]['dst_port'])
        client_ep = next(((p['src'], p['src_port']) for p in ps
                          if (p['src'], p['src_port']) != server_ep), None)

        flow = {'key': key, 'protocol': proto, 'client': client_ep, 'server': server_ep,
                'packets': len(ps), 'first_ts': min(p['ts'] for p in ps),
                'last_ts': max(p['ts'] for p in ps)}
        if proto == PROTO_TCP:
            flow['c2s'], flow['c2s_offsets'], flow['s2c'] = _reassemble_tcp(ps, client_ep, server_ep)
        else:
            flow['c2s'], flow['s2c'] = _concat_udp(ps, client_ep, server_ep)
        flow['src'], flow['sport'] = client_ep if client_ep else (None, None)
        flow['dst'], flow['dport'] = server_ep if server_ep else (None, None)
        out[key] = flow
    return out


def _reassemble_tcp(ps, client_ep, server_ep):
    def _dir(ep_match):
        segs = [p for p in ps if (p['src'], p['src_port']) == ep_match and p.get('payload')]
        segs.sort(key=lambda p: (p['tcp_seq'], p['ts']))
        buf = b''
        offsets = []
        seen = set()
        for p in segs:
            if p['tcp_seq'] in seen:
                continue
            seen.add(p['tcp_seq'])
            buf += p['payload']
            offsets.append(p['offset'])
        return buf, offsets
    c2s, c2s_off = _dir(client_ep) if client_ep else (b'', [])
    s2c, _ = _dir(server_ep) if server_ep else (b'', [])
    return c2s, c2s_off, s2c


def _concat_udp(ps, client_ep, server_ep):
    c2s = b''.join(p['payload'] for p in ps
                   if (p['src'], p['src_port']) == client_ep and p.get('payload'))
    s2c = b''.join(p['payload'] for p in ps
                   if (p['src'], p['src_port']) == server_ep and p.get('payload'))
    return c2s, s2c


# ---------------------------------------------------------------------------
# application-layer parsers
# ---------------------------------------------------------------------------
def parse_http_stream(buf):
    """Split a reassembled byte stream into HTTP messages (requests + responses)."""
    msgs = []
    pos = 0
    while pos < len(buf):
        head_end = buf.find(b'\r\n\r\n', pos)
        if head_end < 0:
            break
        head = buf[pos:head_end].decode('latin-1', errors='replace')
        line0 = head.split('\r\n')[0] if head else ''
        if line0.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ')) or \
           line0.startswith('HTTP/'):
            headers = {}
            for ln in head.split('\r\n')[1:]:
                if ':' in ln:
                    k, _, v = ln.partition(':')
                    headers[k.strip().lower()] = v.strip()
            cl = int(headers.get('content-length', '0') or '0')
            te = headers.get('transfer-encoding', '')
            body_start = head_end + 4
            if 'chunked' in te:
                msgs.append({'start_line': line0, 'headers': headers, 'body': b'',
                             'chunked': True, 'byte_offset': pos})
                pos = body_start
                continue
            body_end = body_start + cl
            body = buf[body_start:body_end]
            msgs.append({'start_line': line0, 'headers': headers, 'body': body,
                         'chunked': False, 'byte_offset': pos})
            pos = body_end
        else:
            nxt = buf.find(b'\r\n', pos)
            pos = nxt + 2 if nxt >= 0 else len(buf)
    return msgs


# --- TLS record + handshake framing ----------------------------------------
def iter_tls_records(buf):
    """Yield (content_type, version, payload) TLS records from a byte buffer."""
    pos = 0
    while pos + 5 <= len(buf):
        ctype = buf[pos]
        if ctype not in (0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d):
            break
        ver = buf[pos + 1:pos + 3]
        ln = struct.unpack('>H', buf[pos + 3:pos + 5])[0]
        if pos + 5 + ln > len(buf):
            break
        yield ctype, ver, buf[pos + 5:pos + 5 + ln]
        pos += 5 + ln


def iter_handshakes(records):
    """Yield (msg_type, body) TLS handshake messages across record boundaries."""
    carry = b''
    for ctype, ver, payload in records:
        if ctype != 0x16:
            continue
        buf = carry + payload
        pos = 0
        while pos + 4 <= len(buf):
            mtype = buf[pos]
            mlen = struct.unpack('>I', b'\x00' + buf[pos + 1:pos + 4])[0]
            if pos + 4 + mlen > len(buf):
                break
            yield mtype, buf[pos + 4:pos + 4 + mlen]
            pos += 4 + mlen
        carry = buf[pos:]


def parse_tls_clienthello(body):
    """Parse a ClientHello handshake body into a fingerprint dict."""
    r = {'type': 'client_hello'}
    try:
        r['legacy_version'] = body[0:2].hex()
        pos = 2 + 32  # random
        slen = body[pos]
        pos += 1 + slen  # session id
        clen = struct.unpack('>H', body[pos:pos + 2])[0]
        pos += 2
        suites = [struct.unpack('>H', body[pos + i:pos + i + 2])[0]
                  for i in range(0, clen, 2)]
        r['cipher_suites'] = suites
        pos += clen
        complen = body[pos]
        r['compression'] = list(body[pos + 1:pos + 1 + complen])
        pos += 1 + complen
        exts = _parse_extensions(body, pos)
        r['extensions'] = exts['types']
        r['sni'] = exts.get('sni')
        r['supported_groups'] = exts.get('supported_groups')
        r['supported_versions'] = exts.get('supported_versions')
        r['alpn'] = exts.get('alpn')
        r['signature_algorithms'] = exts.get('signature_algorithms')
        # JA3: version,ciphers,extensions,groups,ec_point_formats -> MD5
        groups = ','.join(str(g) for g in r['supported_groups']) if r['supported_groups'] else ''
        r['ja3'] = hashlib.md5(('%s,%s,%s,%s,%s' % (
            r['legacy_version'], ','.join(str(s) for s in suites),
            ','.join(str(e) for e in exts['types']), groups, '')).encode()).hexdigest()
        r['ja3_str'] = '%s,%s,%s,%s' % (r['legacy_version'],
                                        ','.join(str(s) for s in suites),
                                        ','.join(str(e) for e in exts['types']), groups)
    except (IndexError, struct.error):
        r['error'] = 'truncated_clienthello'
    return r


def parse_tls_serverhello(body):
    r = {'type': 'server_hello'}
    try:
        r['legacy_version'] = body[0:2].hex()
        pos = 2 + 32
        slen = body[pos]
        pos += 1 + slen
        r['cipher_suite'] = struct.unpack('>H', body[pos:pos + 2])[0]
        pos += 2
        r['compression'] = body[pos]
        pos += 1
        exts = _parse_extensions(body, pos)
        r['extensions'] = exts['types']
        r['selected_version'] = exts.get('supported_versions')
    except (IndexError, struct.error):
        r['error'] = 'truncated_serverhello'
    return r


def _parse_extensions(body, pos):
    if pos + 2 > len(body):
        return {'types': []}
    total = struct.unpack('>H', body[pos:pos + 2])[0]
    pos += 2
    end = min(pos + total, len(body))
    types = []
    r = {}
    while pos + 4 <= end:
        etype = struct.unpack('>H', body[pos:pos + 2])[0]
        elen = struct.unpack('>H', body[pos + 2:pos + 4])[0]
        data = body[pos + 4:pos + 4 + elen]
        types.append(etype)
        if etype == 0 and len(data) >= 5:  # server_name / SNI
            try:
                # name_list: 2-byte len, then (type, 2-byte len, name)*
                nlen = struct.unpack('>H', data[0:2])[0]
                npos = 2
                names = []
                while npos + 3 <= min(2 + nlen, len(data)):
                    ntype = data[npos]
                    l = struct.unpack('>H', data[npos + 1:npos + 3])[0]
                    if ntype == 0:
                        names.append(data[npos + 3:npos + 3 + l].decode('utf-8', 'replace'))
                    npos += 3 + l
                r['sni'] = names[0] if names else None
            except (IndexError, struct.error):
                pass
        elif etype == 10 and len(data) >= 2:  # supported_groups
            glen = struct.unpack('>H', data[0:2])[0]
            r['supported_groups'] = [struct.unpack('>H', data[2 + i:4 + i])[0]
                                     for i in range(0, min(glen, len(data) - 2), 2)]
        elif etype == 43 and len(data) >= 2:  # supported_versions
            if len(data) == 2:  # ServerHello: single 2-byte version, no length prefix
                r['supported_versions'] = data.hex()
            else:  # ClientHello: 1-byte length then version list
                vlen = data[0]
                r['supported_versions'] = [data[1 + i:3 + i].hex() for i in range(0, min(vlen, len(data) - 1), 2)]
        elif etype == 16 and len(data) >= 2:  # ALPN
            alen = struct.unpack('>H', data[0:2])[0]
            apos = 2
            protos = []
            while apos + 1 <= min(2 + alen, len(data)):
                l = data[apos]
                protos.append(data[apos + 1:apos + 1 + l].decode('utf-8', 'replace'))
                apos += 1 + l
            r['alpn'] = protos
        elif etype == 13 and len(data) >= 2:  # signature_algorithms
            slen = struct.unpack('>H', data[0:2])[0]
            r['signature_algorithms'] = [struct.unpack('>H', data[2 + i:4 + i])[0]
                                         for i in range(0, min(slen, len(data) - 2), 2)]
        pos += 4 + elen
    r['types'] = types
    return r


def parse_tls_certificates(body):
    """Extract the leaf certificate subject / issuer / SAN from a Certificate msg."""
    try:
        if len(body) < 3:
            return []
        # body: 3-byte list length, then per cert: 3-byte len + DER
        total = int.from_bytes(body[0:3], 'big')
        pos = 3
        end = min(3 + total, len(body))
        certs = []
        while pos + 3 <= end:
            clen = int.from_bytes(body[pos:pos + 3], 'big')
            der = body[pos + 3:pos + 3 + clen]
            certs.append(_cert_summary(der))
            pos += 3 + clen
        return certs
    except (IndexError, ValueError):
        return []


def _cert_summary(der):
    cn = []
    san = []
    oid_bytes = bytes([0x06, 0x03, 0x55, 0x04, 0x03])            # 2.5.4.3 commonName
    san_oid = bytes([0x06, 0x03, 0x55, 0x1d, 0x11])              # 2.5.29.17 SAN
    # commonName values in document order (issuer CN then subject CN, best effort)
    idx = 0
    while True:
        idx = der.find(oid_bytes, idx)
        if idx < 0:
            break
        val = _der_string_after(der, idx + len(oid_bytes))
        if val:
            cn.append(val)
        idx += 1
    # SAN DNS entries (context tag 0x82 within the SAN extension value)
    for m in _san_dns(der, san_oid):
        san.append(m)
    return {'subject_cn': cn[-1] if cn else None, 'issuer_cn': cn[0] if len(cn) >= 2 else None,
            'common_names': cn, 'san_dns': san}


def _der_string_after(der, pos):
    """Read the string value that follows an OID inside an RDN SET/SEQUENCE."""
    if pos + 2 > len(der):
        return None
    tag = der[pos]
    # PrintableString 0x13, UTF8String 0x0c, IA5String 0x16, BMPString 0x1e, Teletex 0x14
    if tag not in (0x0c, 0x13, 0x14, 0x16, 0x1e):
        return None
    ln = der[pos + 1]
    if ln & 0x80:
        n = ln & 0x7f
        ln = int.from_bytes(der[pos + 2:pos + 2 + n], 'big')
        pos += n
    raw = der[pos + 2:pos + 2 + ln]
    return raw.decode('utf-8', 'replace')


def _san_dns(der, san_oid):
    names = []
    idx = 0
    while True:
        idx = der.find(san_oid, idx)
        if idx < 0:
            break
        # the extension value follows: OCTET STRING wrapping a SEQUENCE of GeneralNames
        pos = idx + len(san_oid)
        try:
            # skip optional critical flag (BOOLEAN 0x01 0x01 0xff)
            if pos + 3 <= len(der) and der[pos] == 0x01 and der[pos + 1] == 0x01:
                pos += 3
            if der[pos] != 0x04:  # OCTET STRING
                idx += 1
                continue
            ln = der[pos + 1]
            if ln & 0x80:
                n = ln & 0x7f
                ln = int.from_bytes(der[pos + 2:pos + 2 + n], 'big')
                pos += n
            content = der[pos + 2:pos + 2 + ln]
            # walk GeneralNames for DNS (context tag 0x82)
            cpos = 0
            while cpos + 2 <= len(content):
                tag = content[cpos]
                if tag == 0x82:  # dNSName
                    l = content[cpos + 1]
                    if l & 0x80:
                        nn = l & 0x7f
                        l = int.from_bytes(content[cpos + 2:cpos + 2 + nn], 'big')
                        cpos += nn
                    names.append(content[cpos + 2:cpos + 2 + l].decode('utf-8', 'replace'))
                    cpos += 2 + l
                else:
                    cpos += 1
        except (IndexError, ValueError):
            pass
        idx += 1
    return names


def parse_dns_message(payload):
    """Parse a DNS message (query or response) into names/types."""
    if len(payload) < 12:
        return None
    try:
        flags = struct.unpack('>H', payload[2:4])[0]
        qd = struct.unpack('>H', payload[4:6])[0]
        an = struct.unpack('>H', payload[6:8])[0]
        is_resp = bool(flags & 0x8000)
        names = []
        offset = 12
        for _ in range(min(qd, 32)):
            name, offset = _dns_name(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype, qclass = struct.unpack('>HH', payload[offset:offset + 4])
            names.append({'name': name, 'type': qtype, 'class': qclass & 0x7fff})
            offset += 4
        return {'is_response': is_resp, 'questions': names, 'answer_count': an}
    except (IndexError, ValueError):
        return None


def _dns_name(data, offset):
    labels = []
    seen = set()
    while True:
        if offset >= len(data) or offset in seen:
            raise ValueError('bad dns name')
        seen.add(offset)
        size = data[offset]
        if size & 0xc0 == 0xc0:
            if offset + 1 >= len(data):
                raise ValueError('short dns pointer')
            tail, _ = _dns_name(data, ((size & 63) << 8) | data[offset + 1])
            labels.append(tail)
            return '.'.join(x for x in labels if x), offset + 2
        offset += 1
        if size == 0:
            return '.'.join(labels), offset
        if size > 63 or offset + size > len(data):
            raise ValueError('bad dns label')
        labels.append(data[offset:offset + size].decode('utf-8', 'replace'))
        offset += size


def parse_ntp(payload):
    if len(payload) < 4:
        return None
    li_vn_mode = payload[0]
    return {'version': (li_vn_mode >> 3) & 0x7, 'mode': li_vn_mode & 0x7,
            'stratum': payload[1]}


# ---------------------------------------------------------------------------
# flow classification
# ---------------------------------------------------------------------------
def classify_flow(flow):
    """Identify the application protocol carried by a flow (pure traffic signal)."""
    sport, dport = flow.get('sport'), flow.get('dport')
    if dport in (53, 5353, 5355) or sport in (53, 5353, 5355):
        return 'dns'
    if dport == 123 or sport == 123:
        return 'ntp'
    c2s = flow.get('c2s') or b''
    if c2s[:3] == b'\x16\x03\x00' or c2s[:3] == b'\x16\x03\x01' or c2s[:2] == b'\x16\x03':
        return 'tls'
    if c2s.startswith((b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HTTP/')):
        return 'http'
    return 'tcp' if flow['protocol'] == PROTO_TCP else 'udp'


# ---------------------------------------------------------------------------
# session-level extraction
# ---------------------------------------------------------------------------
def _load_pcap_bytes(folder, kind):
    """Read a pcap for a session via logical name with physical fallback."""
    folder = Path(folder)
    candidates = {
        'api': ['network_api.pcap', 'network.pcap'],
        'tools': ['network_tools.pcap'],
    }[kind]
    # direct physical files first
    for name in candidates:
        for rel in ('02_modal_evidence', ''):
            p = folder / rel / name if rel else folder / name
            if p.exists():
                return p.read_bytes()
    # storage manifest logical access
    try:
        from session_storage import SessionStore
        store = SessionStore(folder)
        for name in candidates:
            if name in store.manifest.get('legacy_files', {}):
                return store.read_bytes(name)
    except Exception:
        pass
    return None


def _offset_to_rel(n_events, capture_name):
    mapping = {}
    aliases = {'network_api': ('network_api', 'network'), 'network_tools': ('network_tools',)}
    wanted = aliases.get(capture_name, (capture_name,))
    for n in n_events:
        if n.get('offset') is not None and n.get('relative_timestamp') is not None and n.get('capture') in wanted:
            mapping[n['offset']] = n['relative_timestamp']
    return mapping


def _flow_summary(f):
    """Strip raw bytes from a reassembled flow, keeping only pure metadata."""
    return {'protocol': 'TCP' if f['protocol'] == PROTO_TCP else 'UDP',
            'proto_num': f['protocol'], 'src': f.get('src'), 'sport': f.get('sport'),
            'dst': f.get('dst'), 'dport': f.get('dport'),
            'application': f.get('application'),
            'packets': f['packets'], 'c2s_bytes': len(f.get('c2s') or b''),
            's2c_bytes': len(f.get('s2c') or b''), 'first_ts': f['first_ts'],
            'last_ts': f['last_ts']}


def extract_session_full(session_folder, n_events):
    """Extract a full multi-protocol summary for one session.

    Returns a dict with keys: flows, tls, http, dns, ntp, arp, icmp. Every
    time-bearing record carries ``relative_timestamp`` aligned via the N-event
    ``offset`` field. No agent/application attribution (no ``application_role``,
    no ``tool_call_id``, no capture labels) is produced.
    """
    folder = Path(session_folder)
    summary = {'flows': [], 'tls': [], 'http': [], 'dns': [], 'ntp': [], 'arp': [],
               'icmp': []}
    for kind, cap in (('api', 'network_api'), ('tools', 'network_tools')):
        data = _load_pcap_bytes(folder, kind)
        if not data:
            continue
        packets = parse_pcap_bytes(data)
        rel_map = _offset_to_rel(n_events, cap)
        for p in packets:
            p['relative_timestamp'] = rel_map.get(p['offset'])
        # non-flow protocols
        for p in packets:
            proto = p.get('network_protocol')
            if proto == 'ARP':
                summary['arp'].append({'op': p.get('arp_op'), 'ts': p['relative_timestamp']})
            elif proto in ('ICMP', 'ICMPv6'):
                summary['icmp'].append({'type': p.get('icmp_type'), 'code': p.get('icmp_code'),
                                        'ts': p['relative_timestamp']})
        for key, f in reassemble_flows(packets).items():
            f['application'] = classify_flow(f)
            f['relative_timestamp'] = rel_map.get(f['c2s_offsets'][0]) if f.get('c2s_offsets') else None
            app = f['application']
            if app == 'tls':
                _extract_tls(summary, f)
            elif app == 'http':
                _extract_http(summary, f)
            elif app == 'dns':
                _extract_dns(summary, f)
            elif app == 'ntp':
                _extract_ntp(summary, f)
            summary['flows'].append(_flow_summary(f))
    summary['flow_count'] = len(summary['flows'])
    summary['tls_count'] = len(summary['tls'])
    summary['dns_count'] = len(summary['dns'])
    return summary


def _stream_for(flow):
    return flow.get('c2s') or b'', flow.get('s2c') or b''


def _extract_tls(summary, flow):
    c2s, s2c = _stream_for(flow)
    entry = {'src': flow.get('src'), 'sport': flow.get('sport'),
             'dst': flow.get('dst'), 'dport': flow.get('dport'),
             'relative_timestamp': flow.get('relative_timestamp'), 'handshake_types': []}
    for direction, buf in (('client', c2s), ('server', s2c)):
        records = list(iter_tls_records(buf))
        for mtype, body in iter_handshakes(records):
            entry['handshake_types'].append(mtype)
            if mtype == 1:
                entry['client_hello'] = parse_tls_clienthello(body)
            elif mtype == 2:
                entry['server_hello'] = parse_tls_serverhello(body)
            elif mtype == 11:
                entry['certificates'] = parse_tls_certificates(body)
    summary['tls'].append(entry)


def _extract_http(summary, flow):
    c2s, _ = _stream_for(flow)
    for msg in parse_http_stream(c2s):
        if msg['start_line'].startswith('HTTP/'):
            continue
        req = {'method': msg['start_line'].split(' ')[0],
               'path': msg['start_line'].split(' ')[1] if ' ' in msg['start_line'] else '',
               'content_length': int(msg['headers'].get('content-length', '0') or '0'),
               'relative_timestamp': flow.get('relative_timestamp')}
        summary['http'].append(req)


def _extract_dns(summary, flow):
    c2s, s2c = _stream_for(flow)
    for buf, direction in ((c2s, 'query'), (s2c, 'response')):
        for i in range(0, len(buf), 512):  # crude frame scan; UDP DNS is single-message
            chunk = buf[i:i + 512]
            m = parse_dns_message(chunk)
            if m:
                summary['dns'].append({'direction': direction,
                                       'questions': m['questions'],
                                       'is_response': m['is_response'],
                                       'answer_count': m['answer_count'],
                                       'relative_timestamp': flow.get('relative_timestamp')})
                break


def _extract_ntp(summary, flow):
    c2s, _ = _stream_for(flow)
    m = parse_ntp(c2s) if c2s else None
    if m:
        m.update(relative_timestamp=flow.get('relative_timestamp'))
        summary['ntp'].append(m)


if __name__ == '__main__':
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from session_storage import load_model_inputs
    folder = Path(sys.argv[1])
    n_events = load_model_inputs(folder)['N']
    summary = extract_session_full(folder, n_events)
    print(json.dumps(summary, ensure_ascii=False, indent=2, default=str)[:8000])
