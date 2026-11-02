"""Extract plaintext HTTP tool-call semantics from network_tools.pcap (real N bytes).

The tool traffic is plaintext HTTP POST /call to the mock backend (172.20.0.2:8080),
body = {"name": ..., "arguments": ...}. This module reassembles TCP streams and parses
HTTP requests, then aligns each request to the session's relative timeline via the
`offset` field already present in N events (network.events.jsonl) — safe under the
WSL2 clock-step ambiguity that makes a global time base unreliable.

Output per session: a list of tool HTTP requests, each with:
  method, path, headers, body(json), name, arguments, content_length, tool_call_id,
  relative_timestamp (aligned), src/sport/dst/dport, n_segments.
"""
import json
import struct
from collections import defaultdict
from pathlib import Path

TOOL_PORT = 8080
TCP_FLAG_ACK = 0x10


def parse_pcap(path):
    """Return list of TCP packets: {offset, ts, src, sport, dst, dport, seq, flags, payload}."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xa1b2c3d4 else ('>' if magic == 0xd4c3b2a1 else None)
    if endian is None:
        raise ValueError('Unrecognized pcap magic: %r' % magic)
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    pkts = []
    off = 24
    while off + 16 <= len(data):
        pkt_off = off
        ts_sec, ts_usec, incl, _ = struct.unpack(endian + 'IIII', data[off:off + 16])
        off += 16
        raw = data[off:off + incl]
        off += incl
        if linktype != 1 or len(raw) < 14:
            continue
        ethtype = struct.unpack('>H', raw[12:14])[0]
        if ethtype != 0x0800:  # IPv4 only
            continue
        ip = raw[14:]
        if len(ip) < 20:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:  # TCP only
            continue
        src = '.'.join(map(str, ip[12:16]))
        dst = '.'.join(map(str, ip[16:20]))
        tcp = ip[ihl:]
        sport, dport = struct.unpack('>HH', tcp[0:4])
        seq = struct.unpack('>I', tcp[4:8])[0]
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        payload = tcp[doff:]
        pkts.append({'offset': pkt_off, 'ts': ts_sec + ts_usec / 1e6, 'src': src, 'sport': sport,
                     'dst': dst, 'dport': dport, 'seq': seq, 'flags': flags, 'payload': payload})
    return pkts


def _reassemble(packets):
    """Group packets into flows and reassemble client->server bytes in seq order (dedup)."""
    flows = defaultdict(list)
    for p in packets:
        key = tuple(sorted([(p['src'], p['sport']), (p['dst'], p['dport'])]))
        flows[key].append(p)
    streams = []
    for key, ps in flows.items():
        server = None
        for p in ps:
            if p['dport'] == TOOL_PORT:
                server = (p['dst'], p['dport'])
            if p['sport'] == TOOL_PORT:
                server = (p['src'], p['sport'])
        if server is None:
            continue
        up = [p for p in ps if p['dport'] == TOOL_PORT]  # client -> backend
        up.sort(key=lambda p: p['seq'])
        seen_seq = set()
        buf = b''
        offsets = []
        first_ts = None
        for p in up:
            if not p['payload']:
                continue
            if p['seq'] in seen_seq:
                continue
            seen_seq.add(p['seq'])
            if first_ts is None:
                first_ts = p['ts']
            buf += p['payload']
            offsets.append(p['offset'])
        if buf:
            streams.append({'buf': buf, 'offsets': offsets, 'first_ts': first_ts})
    return streams


def _split_http(stream):
    """Split a reassembled byte stream into HTTP requests using Content-Length."""
    reqs = []
    buf = stream['buf']
    pos = 0
    while pos < len(buf):
        start = pos
        head_end = buf.find(b'\r\n\r\n', pos)
        if head_end < 0:
            break
        head = buf[pos:head_end].decode('latin-1', errors='replace')
        lines = head.split('\r\n')
        request_line = lines[0] if lines else ''
        if not (request_line.startswith(('POST ', 'GET ', 'PUT ', 'DELETE '))):
            # Not an HTTP request start; skip to next request line.
            nxt = buf.find(b'\r\n', pos)
            pos = nxt + 2 if nxt >= 0 else len(buf)
            continue
        headers = {}
        for ln in lines[1:]:
            if ':' in ln:
                k, _, v = ln.partition(':')
                headers[k.strip().lower()] = v.strip()
        cl = int(headers.get('content-length', '0') or '0')
        body_start = head_end + 4
        body_end = body_start + cl
        body = buf[body_start:body_end]
        reqs.append({'request_line': request_line, 'headers': headers, 'body': body,
                     'byte_offset': start, 'header_end': head_end})
        pos = body_end
    return reqs


def extract_session(session_folder, n_events):
    """Return tool HTTP requests for one session, aligned to relative timeline.

    n_events: list of N modality events (from load_model_inputs) used only to map
    pcap packet offset -> relative_timestamp.
    """
    folder = Path(session_folder)
    pcap = folder / '02_modal_evidence' / 'network_tools.pcap'
    if not pcap.exists():
        return []
    offset_to_rel = {}
    for n in n_events:
        if n.get('capture') == 'network_tools' and n.get('offset') is not None:
            offset_to_rel[n['offset']] = n.get('relative_timestamp')
    packets = parse_pcap(pcap)
    streams = _reassemble(packets)
    requests = []
    for stream in streams:
        http_reqs = _split_http(stream)
        # map each request to relative time via the first data segment's pcap offset
        for req in http_reqs:
            rel = None
            # find the offset of the segment that begins this request (closest <= byte boundary)
            # approximate: use the offset whose segment contains the request start
            for off in stream['offsets']:
                # offsets are packet starts; we only have request byte_offset in the stream.
                # Simplest robust approach: use the first offset of the stream.
                pass
            # fallback: use the first data segment offset of the whole stream
            first_off = stream['offsets'][0] if stream['offsets'] else None
            rel = offset_to_rel.get(first_off)
            # parse body json
            name = arguments = None
            try:
                obj = json.loads(req['body'].decode('utf-8'))
                name = obj.get('name')
                arguments = obj.get('arguments')
            except Exception:
                pass
            requests.append({
                'method': req['request_line'].split(' ')[0] if req['request_line'] else '',
                'path': req['request_line'].split(' ')[1] if ' ' in req['request_line'] else '',
                'content_length': int(req['headers'].get('content-length', '0') or '0'),
                'tool_call_id': req['headers'].get('x-tool-call-id'),
                'name': name, 'arguments': arguments,
                'body_raw': req['body'].decode('utf-8', errors='replace'),
                'relative_timestamp': rel,
            })
    return requests
