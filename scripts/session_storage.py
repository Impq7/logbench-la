"""Four-directory session storage. Standard library only, including remote Python 3.6.

Packing is byte-preserving. Duplicate aliases are removed only after round-trip SHA
verification. Model loading never consults the QA/evidence/label directories.
"""
import base64
import collections
import csv
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import time
import uuid

REVISION = 'four-directory-gzip-r1'          # legacy split-container layout (deprecated)
OFFICIAL_REVISION = 'three-directory-atif-r1'  # official-engine layout (current)
MODEL_FILES = {'T':'T.trajectory.jsonl', 'E':'E.endpoint.events.jsonl.gz', 'N':'N.network.events.jsonl'}
LEGACY_MODEL_FILES = {m:n if n.endswith('.gz') else n+'.gz' for m,n in MODEL_FILES.items()}
# Payload-free Agent-behavior view of the T trajectory (optional sibling of T.trajectory.jsonl.gz).
BEHAVIOR_T_FILE = 'T.behavior.jsonl'
ATIF_FILE = 'T.atif.json'
DIRECTORIES = ('01_model_inputs','02_modal_evidence','03_runtime','04_repro_qa')   # legacy
OFFICIAL_DIRECTORIES = ('raw','model_inputs','labels')                              # official engine


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2,sort_keys=True)


def safe_path(root, relative):
    root=Path(root).resolve()
    path=(root/relative).resolve()
    if root not in path.parents:
        raise ValueError('Storage path escapes session')
    return path


def model_files(folder):
    """Current filenames, with read compatibility for already published gzip T/N."""
    model = Path(folder)/'model_inputs'
    return {m:n if (model/n).is_file() else LEGACY_MODEL_FILES[m] for m,n in MODEL_FILES.items()}


def load_model_inputs(folder, view='raw'):
    """The detector entry reads only the three fixed observable files.

    ``view='behavior'`` swaps the T trajectory for the payload-free Agent-behavior
    view (``T.behavior.jsonl.gz``); E and N are identical in both views. The
    behavior file is an optional sibling of the original trajectory, which is
    never modified by the view selection.
    """
    folder=Path(folder).resolve()
    model=folder/'model_inputs'
    if not model.is_dir():
        raise ValueError('Structured model inputs required; audit/raw fallback is disabled')
    names={p.name for p in model.iterdir()}
    files = model_files(folder)
    required=set(files.values())
    optional={BEHAVIOR_T_FILE,ATIF_FILE,BEHAVIOR_T_FILE+'.gz',ATIF_FILE+'.gz'}
    if not required.issubset(names) or (names-required-optional):
        raise ValueError('Unexpected or missing files in model-input boundary')
    behavior = BEHAVIOR_T_FILE if BEHAVIOR_T_FILE in names else BEHAVIOR_T_FILE+'.gz'
    if view=='behavior' and behavior not in names:
        raise ValueError('Behavior T view requested but missing: '+BEHAVIOR_T_FILE)
    t_name=behavior if view=='behavior' else files['T']
    result={}
    for modality,name in [('T',t_name),('E',files['E']),('N',files['N'])]:
        path=safe_path(model,name)
        with (gzip.open if name.endswith('.gz') else open)(str(path),'rt',encoding='utf-8') as stream:
            result[modality]=[json.loads(line) for line in stream if line.strip()]
    return result


class SessionStore:
    """Audit-only logical access to the labels/ directory of an official-engine session.

    The labels/ dir holds ``report.json`` / ``labels.json`` / catalog CSVs; the
    ``labels/storage_manifest.json`` records their SHA-256 for verification. This
    store never exposes model inputs (``model_inputs/``) or raw evidence (``raw/``)
    through the logical-name interface — those are integrity-checked separately.
    """
    def __init__(self, folder):
        self.folder=Path(folder)
        path=self.folder/'labels'/'storage_manifest.json'
        self.manifest=read_json(path) if path.exists() else None

    def names(self):
        if self.manifest:
            return [n[len('labels/'):] for n in self.manifest.get('labels',{})]
        return [p.name for p in (self.folder/'labels').iterdir() if p.is_file()]

    def read_bytes(self,name):
        if Path(name).name!=name:
            raise ValueError('Logical names must be flat basenames')
        if not self.manifest:
            return (self.folder/'labels'/name).read_bytes()
        expected=self.manifest['labels'].get('labels/'+name)
        if expected is None:
            raise ValueError('Unknown label file: '+name)
        data=(self.folder/'labels'/name).read_bytes()
        if digest(data)!=expected:
            raise ValueError('Label byte hash mismatch: '+name)
        return data

    def json(self,name):
        return json.loads(self.read_bytes(name).decode('utf-8-sig'))

    def rows(self,name):
        return [json.loads(line) for line in self.read_bytes(name).decode('utf-8').splitlines() if line]


def verify_packed(folder):
    """Legacy four-directory integrity check (independent of the new SessionStore)."""
    folder=Path(folder)
    manifest=read_json(folder/'04_repro_qa'/'storage_manifest.json')
    if manifest.get('revision')!=REVISION:
        raise ValueError('Missing structured storage manifest')
    for name,expected in manifest['physical_files'].items():
        if digest(safe_path(folder,name).read_bytes())!=expected:
            raise ValueError('Stored file hash mismatch: '+name)
    # Group aliases so each gzip is inflated once, not once per duplicate original.
    grouped=collections.defaultdict(list)
    for name,entry in manifest['legacy_files'].items():
        grouped[entry.get('path')].append((name,entry))
    for relative,entries in grouped.items():
        if relative is not None:
            path=safe_path(folder,relative)
            data=gzip.open(str(path),'rb').read() if entries[0][1]['codec']=='gzip' else path.read_bytes()
        for name,entry in entries:
            value=base64.b64decode(entry['inline_base64']) if relative is None else (
                data[entry['offset']:entry['offset']+entry['length']] if 'offset' in entry else data)
            if digest(value)!=entry['sha256']:
                raise ValueError('Round-trip hash mismatch: '+name)
    return {'passed':True,'logical_files':len(manifest['legacy_files']),
        'physical_files':len(manifest['physical_files'])+1,'source_bytes':manifest['source_bytes'],
        'stored_bytes':sum(p.stat().st_size for p in folder.rglob('*') if p.is_file()),
        'deduplicated_aliases':manifest['deduplicated_aliases']}


def verify_official_packed(folder):
    """Integrity-check an official-engine three-directory session (raw/model_inputs/labels)."""
    folder=Path(folder)
    manifest=read_json(folder/'labels'/'storage_manifest.json')
    if manifest.get('revision')!=OFFICIAL_REVISION:
        raise ValueError('Missing/unknown official storage manifest')
    counts={}
    for section in ('model_inputs','labels','raw'):
        for relative,expected in manifest.get(section,{}).items():
            path=folder/relative
            if not path.is_file() or digest(path.read_bytes())!=expected:
                raise ValueError('Stored file hash mismatch: '+relative)
            counts[section]=counts.get(section,0)+1
    return {'passed':True,'model_inputs':counts.get('model_inputs',0),
        'labels':counts.get('labels',0),'raw':counts.get('raw',0),
        'source_bytes':manifest.get('source_bytes'),
        'stored_bytes':sum(p.stat().st_size for p in folder.rglob('*') if p.is_file())}


def pack_official_session(session_dir, meta):
    """Assemble a derived flat session into the official three-directory layout.

    The flat session dir (produced by enrich) contains:
      * ``trajectory.jsonl`` / ``endpoint.events.jsonl`` / ``network.events.jsonl``
        -> gzip into ``model_inputs/`` (T/E/N);
      * ``report.json`` / ``labels.json`` / ``session_manifest.csv`` / ``labels.csv``
        -> ``labels/``;
      * a ``raw/`` subdir holding the byte-identical native run_dir.

    A ``labels/storage_manifest.json`` records the SHA-256 of every file (including
    the whole ``raw/`` subtree) so ``verify_official_packed`` can later confirm the
    session is untampered.
    """
    session_dir=Path(session_dir).resolve()
    flat=session_dir
    if not (flat/'raw').is_dir():
        raise ValueError('Official pack requires a raw/ subdir (native run_dir)')
    if (flat/'labels'/'storage_manifest.json').exists():
        return verify_official_packed(flat)
    required=['trajectory.jsonl','trajectory.atif.json','timing.json','endpoint.events.jsonl','network.events.jsonl',
              'report.json','labels.json']
    missing=[n for n in required if not (flat/n).is_file()]
    if missing:
        raise ValueError('Missing flat session files: '+repr(missing))
    report=read_json(flat/'report.json')
    session_id=report.get('run_id') or meta.get('run_id')
    if not session_id:
        raise ValueError('Official pack requires a run_id')
    stage=flat/('.storage-stage-'+uuid.uuid4().hex[:12])
    stage.mkdir()
    try:
        (stage/'model_inputs').mkdir()
        (stage/'labels').mkdir()
        # 1) T/N stay readable; only E is compressed.
        manifest={'model_inputs':{},'labels':{},'raw':{}}
        for name,modality in [('trajectory.jsonl','T'),('endpoint.events.jsonl','E'),('network.events.jsonl','N')]:
            data=(flat/name).read_bytes()
            dest=stage/'model_inputs'/MODEL_FILES[modality]
            if modality == 'E':
                with dest.open('xb') as raw:
                    with gzip.GzipFile(filename='',mode='wb',fileobj=raw,compresslevel=6,mtime=0) as stream:
                        stream.write(data)
            else:
                dest.write_bytes(data)
            manifest['model_inputs']['model_inputs/'+MODEL_FILES[modality]]=digest(dest.read_bytes())
        from agentdojo_to_atif import validate_atif
        full_trace = read_json(flat/'trajectory.atif.json')
        validate_atif(full_trace)
        if full_trace['steps'] != [json.loads(line) for line in (flat/'trajectory.jsonl').read_text(encoding='utf-8').splitlines() if line]:
            raise ValueError('ATIF/step projection mismatch')
        dest = stage/'model_inputs'/ATIF_FILE
        shutil.copyfile(flat/'trajectory.atif.json', dest)
        manifest['model_inputs']['model_inputs/'+ATIF_FILE] = digest(dest.read_bytes())
        # 2) labels: move report/labels/csv verbatim (identity, not gzip).
        for name in ('report.json','labels.json','timing.json','session_manifest.csv','labels.csv'):
            src=flat/name
            if not src.is_file():
                continue
            dest=stage/'labels'/name
            shutil.copy2(str(src),str(dest))
            manifest['labels']['labels/'+name]=digest(dest.read_bytes())
        # 3) raw: move the whole native run_dir subtree, hash every file.
        raw_src=flat/'raw'
        raw_dst=stage/'raw'
        shutil.move(str(raw_src),str(raw_dst))
        for p in sorted(raw_dst.rglob('*')):
            if p.is_file():
                manifest['raw']['raw/'+p.relative_to(raw_dst).as_posix()]=digest(p.read_bytes())
        # catalog from per-session CSVs.
        catalog={}
        for name,key in [('session_manifest.csv','session'),('labels.csv','labels')]:
            if (stage/'labels'/name).is_file():
                records=list(csv.DictReader(io.StringIO((stage/'labels'/name).read_text(encoding='utf-8-sig'))))
                if len(records)==1:
                    catalog[key]=records[0]
        if 'session' not in catalog:
            catalog['session']={'session_id':session_id,
                'source_task_group_id':meta.get('lineage','NaN'),'scenario':meta.get('scenario','unknown'),
                'backbone':meta.get('backbone','NaN'),'collection_ready':'True',
                'coverage_T':'OK','coverage_E':'OK','coverage_N':'OK'}
        if 'labels' not in catalog:
            lab=read_json(stage/'labels'/'labels.json') if (stage/'labels'/'labels.json').is_file() else {}
            catalog['labels']={'session_id':lab.get('session_id') or session_id,
                'source_task_group_id':meta.get('lineage','NaN'),
                **{k:('NaN' if lab.get(k) is None else str(lab[k])) for k in
                   ('user_task_id','injection_task_id','attack_type','y_attempt','y_harm','first_harm_time','task_success')}}
        manifest.update({'revision':OFFICIAL_REVISION,'session_id':session_id,
            'catalog':catalog,'source_bytes':sum(p.stat().st_size for p in flat.rglob('*') if p.is_file())})
        write_json(stage/'labels'/'storage_manifest.json',manifest)
        verify_official_packed(stage)
        # Install the three complete directories, then drop the flat sources.
        for name in OFFICIAL_DIRECTORIES:
            os.replace(str(stage/name),str(flat/name))
        stage.rmdir()
        for name in required:
            p=flat/name
            if p.exists():
                p.unlink()
        for name in ('session_manifest.csv','labels.csv'):
            p=flat/name
            if p.exists():
                p.unlink()
        return verify_official_packed(flat)
    except Exception:
        raise


def flow_rows(records):
    """Aggregate packet records into bidirectional flows by pure network 5-tuple.


    No agent attribution (session/capture/connection/application) and no flow-id
    hash — the flow key is the canonical bidirectional 5-tuple only.
    """
    flows = {}
    for p in records:
        if p.get('src_port') is None:
            continue
        endpoints = sorted(((p['src'], p['src_port']), (p['dst'], p['dst_port'])))
        key = (p['protocol'], tuple(endpoints))
        flow = flows.setdefault(key, {'protocol': p['protocol'], 'endpoints': endpoints,
            'packets': 0, 'bytes': 0, 'start_ts': p['timestamp'], 'end_ts': p['timestamp']})
        flow['packets'] += 1
        flow['bytes'] += p['length']
        flow['start_ts'] = min(flow['start_ts'], p['timestamp'])
        flow['end_ts'] = max(flow['end_ts'], p['timestamp'])
    return list(flows.values())


def pack_session(folder):
    """In-place compaction of an explicit session, after successful byte verification."""
    folder=Path(folder).resolve()
    if (folder/'04_repro_qa/storage_manifest.json').exists():
        return verify_packed(folder)
    if not folder.is_dir() or any(p.is_dir() for p in folder.iterdir()):
        raise ValueError('Packing requires a flat session or an already sealed session')
    original={p.name:p for p in folder.iterdir() if p.is_file()}
    report=read_json(folder/'report.json')
    for name,expected in report.get('sha256',{}).items():
        if name not in original or digest(original[name].read_bytes())!=expected:
            raise ValueError('Original registered raw hash mismatch: '+name)
    stage=folder/('.storage-stage-'+uuid.uuid4().hex[:12])
    stage.mkdir()
    for name in DIRECTORIES:
        (stage/name).mkdir()
    aliases,physical,assigned={}, {},set()
    duplicate_count=0
    def put(relative,data,compressed):
        path=safe_path(stage,relative)
        path.parent.mkdir(parents=True,exist_ok=True)
        if compressed:
            with path.open('xb') as raw:
                with gzip.GzipFile(filename='',mode='wb',fileobj=raw,compresslevel=6,mtime=0) as stream:
                    stream.write(data)
        else:
            with path.open('xb') as stream:
                stream.write(data)
        physical[relative]=digest(path.read_bytes())
        return {'path':relative,'codec':'gzip' if compressed else 'identity'}
    def register(name,entry,data=None):
        data=original[name].read_bytes() if data is None else data
        aliases[name]=dict(entry,sha256=digest(data),length=len(data))
        assigned.add(name)
    def move(name,relative,compressed=False):
        if name in original:
            data=original[name].read_bytes()
            register(name,put(relative,data,compressed),data)
    def merge_segments(names,relative):
        values=[(name,original[name].read_bytes()) for name in names if name in original]
        if not values:
            return
        entry=put(relative,b''.join(data for _,data in values),True)
        offset=0
        for name,data in values:
            register(name,dict(entry,offset=offset),data)
            offset+=len(data)
    try:
        for name,modality in [('trajectory.jsonl','T'),('endpoint.events.jsonl','E'),('network.events.jsonl','N')]:
            move(name,'01_model_inputs/'+LEGACY_MODEL_FILES[modality],True)
        raw_names=['endpoint_agent.jsonl','endpoint_backend.jsonl'] if 'endpoint_agent.jsonl' in original else ['endpoint.jsonl']
        merge_segments(raw_names,'03_runtime/endpoint.raw.jsonl.gz')
        # Hash equality is mandatory. Distinct events/roles are never deduplicated.
        raw_digests={aliases[name]['sha256']:aliases[name] for name in raw_names if name in aliases}
        for name,path in original.items():
            if name in assigned or not (name.endswith('.stdout.log') or name in ('endpoint_live.jsonl','endpoint_agent_live.jsonl','endpoint_backend_live.jsonl')):
                continue
            value=path.read_bytes()
            if digest(value) in raw_digests:
                register(name,raw_digests[digest(value)],value)
                duplicate_count+=1
        merge_segments(['arrival_endpoint_agent.jsonl','arrival_endpoint_backend.jsonl'] if 'arrival_endpoint_agent.jsonl' in original else ['arrival_endpoint.jsonl'],
            '02_modal_evidence/arrival_endpoint.jsonl.gz')
        mapping={
            'network.pcap':('02_modal_evidence/network.pcap',False),
            'network_api.pcap':('02_modal_evidence/network.pcap',False),
            'network_tools.pcap':('02_modal_evidence/network_tools.pcap',False),
            'connections.jsonl':('02_modal_evidence/connections.jsonl.gz',True),
            'network.flows.jsonl':('02_modal_evidence/network.flows.jsonl.gz',True),
            'arrival_network.jsonl':('02_modal_evidence/arrival_network.jsonl.gz',True),
            'arrival_network_api.jsonl':('02_modal_evidence/arrival_network.jsonl.gz',True),
            'arrival_network_tools.jsonl':('02_modal_evidence/arrival_network_tools.jsonl.gz',True),
            'clock_sync.jsonl':('03_runtime/clock_sync.jsonl.gz',True),
            'tracee_metrics_before.txt':('03_runtime/tracee_metrics_before.txt',False),
            'tracee_metrics_after.txt':('03_runtime/tracee_metrics_after.txt',False),
            'tracee_agent_before.txt':('03_runtime/agent/tracee_metrics_before.txt',False),
            'tracee_agent_after.txt':('03_runtime/agent/tracee_metrics_after.txt',False),
            'tracee_backend_before.txt':('03_runtime/backend/tracee_metrics_before.txt',False),
            'tracee_backend_after.txt':('03_runtime/backend/tracee_metrics_after.txt',False),
            'tcpdump.log':('03_runtime/tcpdump.log',False),'network_api.log':('03_runtime/tcpdump.log',False),
            'tcpdump_tools.log':('03_runtime/tcpdump_tools.log',False),'network_tools.log':('03_runtime/tcpdump_tools.log',False),
            'requests.jsonl':('04_repro_qa/requests.jsonl.gz',True),'lifecycle.jsonl':('04_repro_qa/lifecycle.jsonl.gz',True),
            'worker.py':('04_repro_qa/worker.py',False),'split_agent_worker.py':('04_repro_qa/worker.py',False)}
        for name,(target,compressed) in mapping.items():
            if name not in assigned:
                move(name,target,compressed)
        catalog={}
        for name,key in [('session_manifest.csv','session'),('labels.csv','labels')]:
            if name in original:
                value=original[name].read_bytes()
                records=list(csv.DictReader(io.StringIO(value.decode('utf-8-sig'))))
                if len(records)!=1:
                    raise ValueError('Per-session CSV must have one row')
                catalog[key]=records[0]
                register(name,{'inline_base64':base64.b64encode(value).decode('ascii')},value)
        # Failed collectors are still indexed. Missing oracle evidence stays NaN,
        # and the model loader will reject absent modalities instead of filling zeros.
        if 'session' not in catalog:
            catalog['session']={'session_id':report['run_id'],
                'source_task_group_id':report.get('source_task_lineage','NaN'),
                'scenario':report.get('scenario','Banking' if report.get('native_task_id') else 'unknown'),
                'backbone':report.get('model_requested','NaN'),'collection_ready':str(report.get('ready',False)),
                'coverage_T':'unknown_not_recorded','coverage_E':'unknown_not_recorded','coverage_N':'unknown_not_recorded'}
        if 'labels' not in catalog:
            label=read_json(original['labels.json']) if 'labels.json' in original else {}
            catalog['labels']={'session_id':report['run_id'],'source_task_group_id':report.get('source_task_lineage','NaN'),
                **{key:('NaN' if label.get(key) is None else str(label[key])) for key in ('y_attempt','y_harm','first_harm_time','task_success')}}
        if 'network.flows.jsonl' not in original and 'network.events.jsonl' in original:
            records=[json.loads(line) for line in original['network.events.jsonl'].read_text(encoding='utf-8').splitlines() if line]
            data=''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in flow_rows(records)).encode('utf-8')
            put('02_modal_evidence/network.flows.jsonl.gz',data,True)
        for name,path in original.items():
            if name in assigned:
                continue
            value=path.read_bytes()
            if not value and name.endswith('.log'):
                register(name,{'inline_base64':''},value)
                continue
            if name.startswith(('network_backend','network_loopback','arrival_network_backend','arrival_network_loopback')) or name=='network.verification.events.jsonl':
                target='02_modal_evidence/verification/'+name
            elif name.startswith(('endpoint','arrival_endpoint')) or name.endswith('.log') or name.startswith('tracee_'):
                target='03_runtime/extra/'+name
            else:
                target='04_repro_qa/'+name
            compressed=name.endswith(('.jsonl','.log'))
            move(name,target+('.gz' if compressed else ''),compressed)
        manifest={'revision':REVISION,'session_id':report['run_id'],'legacy_files':aliases,
            'physical_files':physical,'catalog':catalog,'source_bytes':sum(p.stat().st_size for p in original.values()),
            'deduplicated_aliases':duplicate_count,'raw_roles':raw_names,
            'model_boundary':'Only 01_model_inputs/T,E,N gzip files; no evidence, labels, oracle or QA fallback'}
        write_json(stage/'04_repro_qa/storage_manifest.json',manifest)
        verify_packed(stage)
        # Install all four complete directories before unlinking any original.
        for name in DIRECTORIES:
            os.replace(str(stage/name),str(folder/name))
        stage.rmdir()
        verify_packed(folder)
        for name,path in original.items():
            expected=aliases[name]['sha256']
            if path.resolve().parent!=folder or digest(path.read_bytes())!=expected:
                raise ValueError('Original changed during compaction; refuse delete')
        for path in original.values():
            path.unlink()
        return verify_packed(folder)
    except Exception:
        # Leave sources intact on pre-install failure; retain a small explicit failure record.
        raise


def rebuild_catalog(dataset):
    dataset=Path(dataset)
    manifest=dataset/'manifest'
    manifest.mkdir(parents=True,exist_ok=True)
    lock=manifest/'.catalog.lock'
    deadline=time.monotonic()+15
    while True:
        try:
            fd=os.open(str(lock),os.O_CREAT|os.O_EXCL|os.O_WRONLY)
            break
        except FileExistsError:
            if time.monotonic()>=deadline:
                raise
            time.sleep(.05)
    try:
        records={'sessions':[],'labels':[]}
        seen=set()
        for folder in sorted((dataset/'sessions').iterdir()):
            if not folder.is_dir() or folder.name.startswith('.'):
                continue
            store=SessionStore(folder)
            if not store.manifest:
                raise ValueError('Catalog cannot silently skip unpacked sessions: '+folder.name)
            catalog=store.manifest['catalog']
            for source,target in [('session','sessions'),('labels','labels')]:
                if source not in catalog:
                    raise ValueError('Missing session catalog metadata')
                row=dict(catalog[source])
                row['session_path']='sessions/'+folder.name
                records[target].append(row)
            sid=catalog['session']['session_id']
            if sid in seen or sid!=folder.name or catalog['labels']['session_id']!=sid:
                raise ValueError('Duplicate/mismatched session identity')
            seen.add(sid)
        for name,values in records.items():
            fields=list(dict.fromkeys(k for row in values for k in row)) if values else ['session_id','session_path']
            temporary=manifest/('.'+name+'-'+uuid.uuid4().hex[:12]+'.tmp')
            with temporary.open('x',encoding='utf-8-sig',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=fields)
                writer.writeheader()
                writer.writerows(values)
            os.replace(str(temporary),str(manifest/(name+'.csv')))
        return {'sessions':len(records['sessions']),'labels':len(records['labels'])}
    finally:
        os.close(fd)
        lock.unlink()
