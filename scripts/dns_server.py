"""Minimal DNS responder for the split-container benchmark.

Runs in a dedicated ``dns_server`` container on the isolated business network,
listening on UDP 53. The backend's external-send tools resolve the exfiltration
target domain through the container's system resolver (``socket.getaddrinfo``),
which emits a real DNS query here; this responder answers the A query with the
co-located TLS receiver's IP, so the network modality records a complete
``DNS query -> DNS response -> TCP -> TLS`` chain. AAAA and other types receive
a NOERROR empty answer (matching a resolver that has no IPv6 record).

The responder is a passive network fixture: it does not participate in the
oracle and its output never enters any observable projection — only the
backend's libc resolver sees it. stdout carries a single readiness line; each
query is logged (name, type, answered IP) to stderr for debugging.

``receiver_ip`` arrives as one JSON line on stdin: ``{"receiver_ip": "172.30.0.3"}``.
"""
import json
import socket
import struct
import sys

HOST = '0.0.0.0'
PORT = 53
TTL = 300


def parse_question(data):
    """Return (qname_text, qtype, qclass, question_end_offset). Raises ValueError."""
    if len(data) < 12:
        raise ValueError('short DNS header')
    qdcount = struct.unpack('!H', data[4:6])[0]
    if qdcount == 0:
        raise ValueError('no question')
    offset = 12
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError('truncated qname')
        size = data[offset]
        if size & 0xC0 == 0xC0:
            raise ValueError('compressed qname unsupported')
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(data):
            raise ValueError('bad label')
        labels.append(data[offset:offset + size].decode('utf-8', 'replace'))
        offset += size
    if offset + 4 > len(data):
        raise ValueError('truncated question tail')
    qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
    return '.'.join(labels), qtype, qclass, offset + 4


def build_response(query, receiver_ip):
    """Build a DNS response for a single-question A/AAAA query. Returns bytes.

    A (type 1) -> one answer with the receiver IP. Anything else (AAAA=28, etc.)
    -> NOERROR with zero answers. The RD flag is echoed from the query; QR and RA
    are set; rcode stays 0.
    """
    qname, qtype, qclass, qend = parse_question(query)
    ident = query[0:2]
    rd = struct.unpack('!H', query[2:4])[0] & 0x0100
    flags = 0x8000 | rd | 0x0080            # QR=1, RD echoed, RA=1, rcode=0
    ancount = 1 if qtype == 1 else 0
    response = struct.pack('!HHHHHH', struct.unpack('!H', ident)[0], flags,
                           1, ancount, 0, 0)
    response += query[12:qend]              # question section, verbatim
    if ancount:
        response += (b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, TTL, 4)
                     + socket.inet_aton(receiver_ip))
    return response


def main():
    config = {}
    if not sys.stdin.isatty():
        try:
            config = json.loads(sys.stdin.readline() or '{}')
        except ValueError:
            config = {}
    receiver_ip = config.get('receiver_ip') or '172.30.0.3'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    print(json.dumps({'kind': 'dns_ready', 'host': HOST, 'port': PORT,
                      'receiver_ip': receiver_ip}), flush=True)
    while True:
        data, addr = sock.recvfrom(65535)
        try:
            qname, qtype, qclass, _ = parse_question(data)
            sock.sendto(build_response(data, receiver_ip), addr)
            sys.stderr.write(json.dumps({'event': 'dns_query', 'peer': list(addr),
                'name': qname, 'qtype': qtype,
                'answered': receiver_ip if qtype == 1 else None}) + '\n')
        except ValueError as exc:
            sys.stderr.write(json.dumps({'event': 'dns_bad_query', 'peer': list(addr),
                'error': str(exc)}) + '\n')
        sys.stderr.flush()


if __name__ == '__main__':
    main()
