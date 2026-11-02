"""Metadata-only examination of non-IPv4 frames in the current audit scope."""
import collections
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
out=Path(sys.argv[1]).resolve()
if out.parent != (ROOT/'experiment').resolve() or not out.name.startswith('paper-collection-audit-'):
    raise ValueError('Unexpected output directory')
counts=collections.Counter()
per_session=[]
for folder in sorted((ROOT/'DataSet/deepseek-development/sessions').glob('native-session-*')):
    row=collections.Counter()
    with (folder/'network.pcap').open('rb') as f:
        h=f.read(24)
        endian='<' if h[:4]==b'\xd4\xc3\xb2\xa1' else '>'
        while ph:=f.read(16):
            size=struct.unpack(endian+'IIII',ph)[2]
            data=f.read(size)
            if data[12:14]!=b'\x86\xdd':
                continue
            ip=data[14:]
            nxt=ip[6]
            position=40
            while nxt in (0,43,60):
                nxt, length=ip[position:position+2]
                position+=(length+1)*8
            multicast=ip[24]==255
            if nxt in (6,17):
                sp,dp=struct.unpack('!HH',ip[position:position+4])
                key=f'protocol={nxt},src_port={sp},dst_port={dp},multicast_dst={multicast}'
            else:
                key=f'protocol={nxt},icmpv6_type={ip[position] if nxt==58 else None},multicast_dst={multicast}'
            counts[key]+=1
            row[key]+=1
    per_session.append({'session_id':folder.name,'ipv6_metadata_counts':dict(row)})
result={'counts':dict(counts),'sessions':per_session,
    'interpretation':'Packet metadata only. Namespace ingress alone does not prove session-process causation. No payload or DNS names extracted.'}
with (out/'ipv6_metadata.json').open('x',encoding='utf-8') as f:
    json.dump(result,f,indent=2)
(out/'ipv6_audit_source.py').write_bytes(Path(__file__).read_bytes())
print(json.dumps(counts))
