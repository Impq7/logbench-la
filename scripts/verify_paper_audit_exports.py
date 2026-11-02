"""Verify audit CSV exports and add targeted forensic evidence; no source mutation."""
import collections
import csv
import json
from pathlib import Path
import struct
import sys

from audit_paper_collection import args, sha

ROOT = Path(__file__).resolve().parents[1]
out = Path(sys.argv[1]).resolve()
if out.parent != (ROOT / 'experiment').resolve() or not out.name.startswith('paper-collection-audit-'):
    raise ValueError('Expected named audit output inside this project')
sessions = json.loads((out / 'sessions.json').read_text(encoding='utf-8'))
def table(name):
    with (out/name).open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))
manifest, labels, flows = [table(n) for n in ['session_manifest.csv','labels.csv','derived_network_flows.csv']]
checks = {
    'manifest_22_unique_sessions':len(manifest)==22 and len({r['session_id'] for r in manifest})==22,
    'labels_22_unique_sessions':len(labels)==22 and len({r['session_id'] for r in labels})==22,
    'manifest_labels_same_session_groups':{(r['session_id'],r['source_task_group_id']) for r in manifest} == {(r['session_id'],r['source_task_group_id']) for r in labels},
    'unknown_harm_preserved':sum(r['y_harm']=='NaN' for r in labels)==2,
    'no_fabricated_harm_time':all(r['t_harm']=='NaN' for r in labels),
    'coverage_values_allowed':all(r[k] in ('OK','partial_loss','collector_failure') for r in manifest for k in ('coverage_T','coverage_E','coverage_N')),
    'no_truth_fields_in_manifest_or_flows':not any(k in ('y_attempt','y_harm','t_inj','t_harm') for t in (manifest,flows) for k in t[0]),
}
for s in sessions:
    m=next(r for r in manifest if r['session_id']==s['session_id'])
    l=next(r for r in labels if r['session_id']==s['session_id'])
    checks['label_values_match_sources:'+s['session_id']] = l['y_attempt']==str(s['attempt']) and l['y_harm']==('NaN' if s['harm'] is None else str(s['harm']))
    checks['exposure_time_presence:'+s['session_id']] = (l['t_inj']!='NaN')==(s['attempt']==1)
groups=collections.defaultdict(set)
for s in sessions:
    groups[s['group']].add(s['split'])
checks['no_source_group_crosses_splits']=all(len(v)==1 for v in groups.values())
et, ipv6_next, ancestor_unresolved=collections.Counter(),collections.Counter(),0
open_count, open_without_inode=0,0
for s in sessions:
    folder=ROOT/'DataSet/deepseek-development/sessions'/s['session_id']
    events=[json.loads(r) for r in (folder/'endpoint.jsonl').read_text(encoding='utf-8').splitlines()]
    entities={e['processEntityId'] for e in events}
    ancestor_unresolved += sum(e['parentEntityId'] not in entities for e in events)
    for e in events:
        if e['eventName']=='openat':
            open_count+=1
            open_without_inode+=not any(k in args(e) for k in ('inode','dev','file_id'))
    with (folder/'network.pcap').open('rb') as f:
        h=f.read(24)
        endian='<' if h[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
        while ph:=f.read(16):
            size=struct.unpack(endian+'IIII',ph)[2]
            data=f.read(size)
            ty=int.from_bytes(data[12:14],'big')
            et[hex(ty)]+=1
            if ty==0x86dd:
                ipv6_next[data[20]]+=1
inventory=json.loads((out/'raw_inventory.json').read_text())
checks['raw_inventory_still_unchanged']=all(sha(ROOT/r['path'])==r['sha256'] for r in inventory)
stats=json.loads((out/'statistics.json').read_text())
non_tcp=et['0x86dd']+et['0x806']
checks['derived_flow_packet_totals_reconcile']=sum(int(r['packet_count']) for r in flows)==stats['all_attempts']['events']['N']['total']-non_tcp
result={'passed':all(checks.values()),'checks':checks,'flow_rows':len(flows),
    'flow_packets':sum(int(r['packet_count']) for r in flows),'eth0_ethertypes':dict(et),
    'ipv6_next_header':dict(ipv6_next),'openat_events':open_count,'openat_without_stable_file_identity':open_without_inode,
    'parent_references_outside_observed_process_entity_set':ancestor_unresolved,
    'parent_count_caveat':'Unresolved in direct event-ID set; not an exhaustive fork/ancestry reconstruction or proof of cross-session mixing.',
    'scope':'No model calls, no training, all writes confined to audit directory.'}
with (out/'export_verification.json').open('x',encoding='utf-8') as f:
    json.dump(result,f,indent=2,ensure_ascii=False)
(out/'export_verification_source.py').write_bytes(Path(__file__).read_bytes())
print(json.dumps(result,ensure_ascii=False))
raise SystemExit(0 if result['passed'] else 1)
