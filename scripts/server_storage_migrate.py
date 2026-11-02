"""Remote, project-scoped storage compaction. Called with payload in memory."""
import base64
import hashlib
import json
from pathlib import Path


def execute_storage(payload):
    namespace={'__name__':'session_storage_remote'}
    exec(compile(payload['module'],'session_storage.py','exec'),namespace)
    root=Path('/root/wxq/agent_benchmark/logbench-la-clean').resolve()
    results=[]
    for spec in payload['sessions']:
        old,new=Path(spec['old']).resolve(),Path(spec['new']).resolve()
        for path in (old,new):
            if root not in path.parents or path.name!=spec['session_id'] or not path.name.startswith(('native-session-','split-session-')):
                raise ValueError('Remote migration escaped the explicit project/session')
        if new.exists():
            if old!=new and old.exists():
                raise ValueError('Both old and new paths exist; do not guess or merge')
            source=new
        elif old.exists():
            source=old
        else:
            raise ValueError('Missing explicitly requested remote session')
        value=namespace['pack_session'](source)
        actual=namespace['SessionStore'](source).manifest
        if {name:entry['sha256'] for name,entry in actual['legacy_files'].items()}!=spec['logical_hashes']:
            raise ValueError('Local and remote original logical files differ')
        if source!=new:
            new.parent.mkdir(parents=True,exist_ok=True)
            source.rename(new)
        results.append(dict(value,session_id=spec['session_id'],path=str(new)))
    catalogs={}
    for item in payload['datasets']:
        dataset=Path(item['path']).resolve()
        if root not in dataset.parents:
            raise ValueError('Catalog path escaped project')
        manifest=dataset/'manifest'
        manifest.mkdir(parents=True,exist_ok=True)
        frozen=manifest/'frozen.json'
        data=base64.b64decode(item['frozen_base64'])
        if frozen.exists():
            if frozen.read_bytes()!=data:
                raise ValueError('Refuse to overwrite different frozen configuration')
        else:
            with frozen.open('xb') as stream:
                stream.write(data)
        catalogs[str(dataset)]=namespace['rebuild_catalog'](dataset)
    return {'passed':True,'sessions':results,'catalogs':catalogs,'model_requests':0,
        'source_bytes':sum(r['source_bytes'] for r in results),'stored_bytes':sum(r['stored_bytes'] for r in results)}
