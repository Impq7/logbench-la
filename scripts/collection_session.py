"""Versioned, lossless metadata views and a small fail-closed collection gate.

Raw T/E/PCAP are never rewritten. Unknown ancestry/objects/flows stay explicit.
This is collection infrastructure, not a native graph/traffic detector adapter.
"""
import collections
import csv
import hashlib
import json
from pathlib import Path

from packet_metadata import pcap_packets
from validate_native_session import audit_labels
from validate_sensor_contract import loss_values


def read(path):
    if not path.exists() and (path.parent/'04_repro_qa/storage_manifest.json').exists():
        from session_storage import SessionStore
        return SessionStore(path.parent).json(path.name)
    return json.loads(path.read_text(encoding='utf-8'))


def rows(path):
    if not path.exists() and (path.parent/'04_repro_qa/storage_manifest.json').exists():
        from session_storage import SessionStore
        return SessionStore(path.parent).rows(path.name)
    return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines() if x] if path.exists() else []


def sha(path):
    if not path.exists() and (path.parent/'04_repro_qa/storage_manifest.json').exists():
        from session_storage import SessionStore
        return hashlib.sha256(SessionStore(path.parent).read_bytes(path.name)).hexdigest()
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024*1024), b''):
            h.update(data)
    return h.hexdigest()


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)


def save_rows(path, records):
    with path.open('x', encoding='utf-8') as stream:
        for row in records:
            stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False)+'\n')


def save_csv(path, fields, records):
    with path.open('x', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for row in records:
            writer.writerow({k:'NaN' if row.get(k) is None else row[k] for k in fields})


def freeze_collection(root):
    settings=read(root/'configs/collection-integrity.json')
    source=root/'DataSet/deepseek-development/manifest/frozen.json'
    old=read(source)
    snapshot={'collection_settings':settings,'source_manifest_sha256':sha(source),
              'native_manifest':old['native_manifest'],'gateway_snapshot':read(root/'configs/pilot.json')}
    snapshot['gateway_snapshot']['max_output_tokens']=settings['max_output_tokens']
    destination=root/'DataSet'/settings['dataset_directory']/'manifest/frozen.json'
    destination.parent.mkdir(parents=True,exist_ok=True)
    if destination.exists():
        if read(destination)!=snapshot:
            raise ValueError('Collection config changed after freezing; use a new named dataset revision')
    else:
        save(destination,snapshot)
    return snapshot


def event_args(event):
    return {a['name']:a.get('value') for a in event.get('args', [])}


def connection_tuple(c):
    return (c['protocol'],) + tuple(sorted(((c['local_ip'], c['local_port']), (c['remote_ip'], c['remote_port']))))


def file_open_links(endpoint):
    """Tracee syscall timestamps are entry times; LSM runs inside that syscall."""
    by_thread=collections.defaultdict(list)
    for index,event in enumerate(endpoint):
        if event['eventName'] in ('openat','security_file_open'):
            by_thread[event['hostThreadId']].append((index,event))
    links={}
    for events in by_thread.values():
        pending=None
        for index,event in sorted(events,key=lambda item:(item[1]['timestamp'],item[0])):
            args=event_args(event)
            if event['eventName']=='openat':
                pending=(index,args.get('pathname')) if event['returnValue']>=0 else None
            elif pending and args.get('syscall_pathname',args.get('pathname'))==pending[1]:
                links[pending[0]]={'file_path':args.get('pathname'),
                    'file_object_id':':'.join(str(args.get(k)) for k in ('dev','inode','ctime')) if args.get('inode') is not None else None,
                    'file_identity_source_index':index}
                pending=None
    return links


def check_trajectory(trace):
    errors = []
    events = {r['event_id']:r for r in trace}
    calls = {r['call_id']:r for r in trace if r['role']=='tool_call'}
    forbidden = {'y_attempt','y_harm','t_harm','t_inj','first_harm_time','reasoning_content','evaluation','oracle'}
    for row in trace:
        if forbidden.intersection(row):
            errors.append('truth_or_hidden_reasoning_in_T')
        if row['role']=='tool_call':
            parent = events.get(row.get('parent_event_id'), {})
            if row['parent_call_id'] is not None or parent.get('role')!='assistant' or not any(
                    c['id']==row['call_id'] for c in parent.get('tool_calls',[])):
                errors.append('invalid_tool_parent')
            if not isinstance(row['tool_arguments'],dict):
                errors.append('unstructured_tool_arguments')
        if row['role']=='tool' and row['call_id'] not in calls:
            errors.append('orphan_tool_result')
    if len(events)!=len(trace) or len(calls)!=sum(r['role']=='tool_call' for r in trace):
        errors.append('duplicate_T_identity')
    if collections.Counter(r['call_id'] for r in trace if r['role']=='tool_call') != collections.Counter(r['call_id'] for r in trace if r['role']=='tool'):
        errors.append('missing_tool_result')
    for a,b in zip(trace,trace[1:]):
        if b['relative_timestamp'] <= a['relative_timestamp'] or b['arrival_monotonic'] < a['arrival_monotonic']:
            errors.append('T_time_order')
    return errors


def write_catalog(folder, report, coverage, settings, trace=(), labels=None):
    session={'session_id':report['run_id'],'source_task_group_id':report['source_task_lineage'],
             'scenario':'Banking','backbone':report['model_requested'],
             **{'coverage_'+m:coverage[m]['coverage_flag'] for m in 'TEN'}}
    if not (folder/'session_manifest.csv').exists():
        save_csv(folder/'session_manifest.csv',list(session),[session])
    labels=labels or {}
    exposure=next((r['relative_timestamp'] for r in trace if r['timestamp']==labels.get('exposure_time')),None)
    injected=report['condition']=='injected'
    label_row=dict(session_id=report['run_id'],source_task_group_id=report['source_task_lineage'],
        y_attempt=labels.get('y_attempt'),y_harm=labels.get('y_harm'),t_inj=exposure,t_harm=labels.get('first_harm_time'),
        **{k:settings[k] if injected else 'not_applicable' for k in ('attack_strategy','attack_surface','attack_goal')})
    if not (folder/'labels.csv').exists():
        save_csv(folder/'labels.csv',list(label_row),[label_row])


def failed_run(folder, settings, report, errors):
    coverage={}
    for modality,names in {'T':['trajectory.jsonl'], 'E':['endpoint.jsonl','endpoint_live.jsonl'],
                           'N':['network.pcap','network_tools.pcap']}.items():
        retained=any((folder/name).exists() and (folder/name).stat().st_size>24 for name in names)
        coverage[modality]={'coverage_flag':'partial_loss' if retained else 'collector_failure',
                            'reasons':['incomplete_collection_or_validation; see errors'], 'loss_counters':None}
    if not (folder/'coverage.json').exists():
        save(folder/'coverage.json',coverage)
    write_catalog(folder,report,coverage,settings)
    result={'passed':False,'session_id':report['run_id'],'errors':errors,'coverage':coverage,
            'eligible_for_formal_results':False}
    save(folder/'collection_validation.json',result)
    return result


def normalize(folder, settings):
    if (folder/'04_repro_qa/storage_manifest.json').exists():
        from session_storage import SessionStore,verify_packed
        storage=verify_packed(folder)
        retained=SessionStore(folder).json('collection_validation.json')
        return dict(retained,storage_verification=storage,
            verification_note='Original semantic QA retained; lossless storage bytes independently verified')
    if (folder/'collection_validation.json').exists():
        raise ValueError('Validation already exists; preserve immutable run evidence')
    report=read(folder/'report.json')
    try:
        return normalize_complete(folder,settings)
    except Exception as exc:
        return failed_run(folder,settings,report,[type(exc).__name__+': '+str(exc)])


def normalize_complete(folder, settings):
    report = read(folder/'report.json')
    sid = report['run_id']
    errors, warnings = [], []
    raw_hashes = report.get('sha256', {})
    for name, expected in raw_hashes.items():
        if Path(name).name != name or not (folder/name).exists() or sha(folder/name)!=expected:
            errors.append('raw_hash:'+name)
    trace, endpoint = rows(folder/'trajectory.jsonl'), rows(folder/'endpoint.jsonl')
    arrivals = rows(folder/'arrival_endpoint.jsonl')
    lifecycle = rows(folder/'lifecycle.jsonl')
    artifact = read(folder/'gateway_artifact.json') if (folder/'gateway_artifact.json').exists() else None
    labels = read(folder/'labels.json') if (folder/'labels.json').exists() else {}
    coverage = {m:{'coverage_flag':'collector_failure', 'reasons':[]} for m in 'TEN'}
    if not artifact or not lifecycle or not report.get('clock_origin'):
        errors.append('incomplete_worker_or_clock_metadata')
        return failed_run(folder,settings,report,errors)
    start = next((r for r in lifecycle if r['event']=='task_start'), None)
    end = next((r for r in lifecycle if r['event']=='task_end'), None)
    if not start or not end or sum(r['event']=='task_start' for r in lifecycle)!=1 or sum(r['event']=='task_end' for r in lifecycle)!=1:
        raise ValueError('Missing/duplicate lifecycle boundary')
    origin = report['clock_origin']
    clocks = rows(folder/'clock_sync.jsonl')
    offsets = [r['timestamp']-r['monotonic'] for r in clocks]
    spread = max(offsets)-min(offsets) if offsets else None
    if spread is None or spread > settings['max_clock_offset_spread_seconds']:
        errors.append('clock_alignment_unstable_or_missing')
    # This is a measured offset spread, not a proof about unobserved clock jumps.
    uncertainty = (spread or 0) + max((r['sampling_uncertainty_seconds'] for r in clocks), default=0)
    def relative(epoch):
        # One fixed anchor preserves event ordering; sampled drift is checked separately.
        return epoch-origin['timestamp']
    requests = [r for r in rows(folder/'requests.jsonl') if r['record_type']=='request_end']
    started_requests = [r for r in rows(folder/'requests.jsonl') if r['record_type']=='request_start']
    if {r['request_id'] for r in requests}!={r['request_id'] for r in started_requests}:
        errors.append('request_end_missing')
    if any('finish_reason' not in r for r in requests if r.get('status')==200):
        errors.append('api_finish_reason_missing')
    if len(trace)!=artifact['trajectory_count'] or any(r['session_id']!=sid for r in trace):
        errors.append('T_stream_count_or_session_mismatch')
    errors.extend(check_trajectory(trace))
    if artifact['termination']!='completed':
        errors.append('task_not_completed')
    coverage['T'] = {'coverage_flag':'OK' if len(trace)==artifact['trajectory_count'] else 'partial_loss',
                     'reasons':[], 'events':len(trace), 'termination':artifact['termination']}
    label_check = audit_labels(trace,artifact,labels,report['condition'],attempt_basis='confirmed_payload')
    errors.extend(label_check['errors'])
    if labels.get('y_harm')==1 and labels.get('first_harm_time') is None:
        warnings.append('exact_first_harm_time_unavailable; retain observed interval only')
    source_root=Path(__file__).resolve().parents[1]/'third_party/agentdojo/src/agentdojo'
    for name,expected in artifact['provenance']['source_hashes'].items():
        path=(source_root/name).resolve()
        if source_root.resolve() not in path.parents or sha(path)!=expected:
            errors.append('native_source_hash_mismatch:'+name)
    connections = []
    calls = {r['call_id']:r for r in trace if r['role']=='tool_call'}
    for record in requests + artifact['receipts']:
        c = record.get('connection')
        if not c:
            warnings.append('connection_metadata_unavailable')
            continue
        is_tool = 'tool_call_id' in record
        cid = record['tool_call_id'] if is_tool else record['request_id']
        connections.append(dict(c, session_id=sid, connection_id=cid,
            tool_call_id=record.get('tool_call_id'), application_role='tool_http' if is_tool else 'llm_api',
            pid=start['worker_pid'], started_at=calls[cid]['timestamp'] if is_tool else record['started_at'],
            ended_at=record['timestamp'] if is_tool else record['arrived_at']))
    save_rows(folder/'connections.jsonl',connections)
    connection_lookup=collections.defaultdict(list)
    for c in connections:
        connection_lookup[connection_tuple(c)].append(c)
    raw_lines=(folder/'endpoint.jsonl').read_bytes().splitlines(keepends=True)
    if len(arrivals)!=len(endpoint) or not report.get('endpoint_live_matches_final'):
        errors.append('E_arrival_count_or_live_mismatch')
    e_out=[None]*len(endpoint)
    fd_objects = {}
    opened_files=file_open_links(endpoint)
    parents={e['processEntityId']:e['parentEntityId'] for e in endpoint}
    def ancestry(pid):
        chain,seen=[],{pid}
        while pid in parents and parents[pid] and parents[pid] not in seen:
            pid=parents[pid]
            seen.add(pid)
            chain.append(sid+':'+str(pid))
        return chain
    for index,event in sorted(enumerate(endpoint), key=lambda x:(x[1]['timestamp'],x[0])):
        a=event_args(event)
        pid=event['processEntityId']
        name=event['eventName']
        fd=a.get('fd',a.get('sockfd'))
        resource=fd_objects.get((pid,fd),{})
        path=a.get('pathname')
        if name=='security_file_open':
            resource={'file_path':path,'file_object_id':':'.join(str(a.get(k)) for k in ('dev','inode','ctime')) if a.get('inode') is not None else None}
        elif name=='openat' and event['returnValue']>=0:
            resource=opened_files.get(index,{'file_path':path,'file_object_id':None})
            fd_objects[(pid,event['returnValue'])]=resource
        elif name in ('dup','dup2','dup3') and event['returnValue']>=0:
            resource=fd_objects.get((pid,a.get('oldfd')), {})
            fd_objects[(pid,event['returnValue'])]=resource
        elif name=='socket' and event['returnValue']>=0:
            fd_objects[(pid,event['returnValue'])]={}
            resource={}
        elif name in ('connect','accept','accept4'):
            address=a.get('addr') or {}
            remote=address.get('sin_addr',address.get('sin6_addr'))
            port=address.get('sin_port',address.get('sin6_port'))
            peer='remote' if name=='connect' else 'local'
            candidates=[c for c in connections if c['pid']==event['processId'] and c[peer+'_ip']==remote
                        and str(c[peer+'_port'])==str(port) and c['started_at']<=event['timestamp']/1e9<=c['ended_at']
                        and (name=='connect' or c['application_role']=='tool_http')]
            if len(candidates)==1:
                c=candidates[0]
                resource={'socket_five_tuple':[c['local_ip'],c['local_port'],c['remote_ip'],c['remote_port'],c['protocol']],
                          'connection_id':c['connection_id']}
                target_fd=fd if name=='connect' else event['returnValue']
                if target_fd>=0:
                    fd_objects[(pid,target_fd)]=resource
        if name=='close':
            fd_objects.pop((pid,fd),None)
        arrival=arrivals[index] if index<len(arrivals) else {}
        if arrival.get('sha256')!=hashlib.sha256(raw_lines[index]).hexdigest() or arrival.get('record_index')!=index:
            errors.append('E_arrival_hash_mismatch')
        if event['mountNamespace']!=report['target_mount_namespace'] or event.get('containerId') not in ('',report['target_container_id']):
            errors.append('E_wrong_session_namespace')
        telemetry_io=(event['processId']==start['worker_pid'] and name=='write' and a.get('fd')==1)
        within=start['timestamp']<=event['timestamp']/1e9<=end['timestamp']
        row=dict(event,session_id=sid,raw_index=index,raw_sha256=hashlib.sha256(raw_lines[index]).hexdigest(),
            container_namespace=event['mountNamespace'],stable_process_id=sid+':'+str(pid),
            process_ancestry=ancestry(pid),ancestry_complete=False,
            syscall_name=event.get('syscall') or name,return_code=event['returnValue'],
            file_path=resource.get('file_path') or path,file_object_id=resource.get('file_object_id'),
            file_identity_source_index=resource.get('file_identity_source_index'),
            socket_five_tuple=resource.get('socket_five_tuple'),connection_id=resource.get('connection_id'),
            relative_timestamp=relative(event['timestamp']/1e9),arrival_timestamp=arrival.get('arrival_time'),
            arrival_relative_timestamp=arrival.get('arrival_monotonic',origin['monotonic'])-origin['monotonic'],
            event_time_basis='epoch_mapped_to_monotonic',clock_offset_spread_seconds=spread,
            observation_role='collector_io' if telemetry_io else ('task' if within else 'outside_task'),
            remote_tool_action=False)
        e_out[index]=row
    save_rows(folder/'endpoint.events.jsonl',sorted(e_out,key=lambda r:(r['relative_timestamp'],r['raw_index'])))
    before=loss_values((folder/'tracee_metrics_before.txt').read_text())
    after=loss_values((folder/'tracee_metrics_after.txt').read_text())
    loss={k:after[k]-before[k] for k in before.keys() & after.keys()}
    e_ok=bool(endpoint) and before.keys()==after.keys() and bool(loss) and all(v==0 for v in loss.values())
    coverage['E']={'coverage_flag':'OK' if e_ok else 'partial_loss','events':len(endpoint),'loss_counters':loss,
        'missing_container_enrichment':sum(not e.get('containerId') for e in endpoint),
        'collector_io_events':sum(e['observation_role']=='collector_io' for e in e_out),
        'object_or_socket_identity_unknown_events':sum(not e.get('file_object_id') and not e.get('socket_five_tuple') for e in e_out)}
    coverage['E']['successful_openat_without_file_identity']=sum(e['eventName']=='openat' and e['returnValue']>=0 and not e.get('file_object_id') for e in e_out)
    if coverage['E']['successful_openat_without_file_identity']:
        warnings.append('some_successful_file_opens_have_unknown_object_identity')
    e_connected={e.get('connection_id') for e in e_out if e['eventName']=='connect'}
    accepted={e.get('connection_id') for e in e_out if e['eventName'] in ('accept','accept4')}
    if any(c['connection_id'] not in e_connected for c in connections):
        errors.append('observed_connection_missing_from_endpoint')
    if any(c['connection_id'] not in accepted for c in connections if c['application_role']=='tool_http'):
        errors.append('tool_connection_missing_server_accept')
    if not e_ok:
        errors.append('E_loss_or_empty')
    if any('/tmp/native-state-' in json.dumps(event) for event in endpoint):
        errors.append('evaluation_snapshot_file_IO_in_E')
    n_out,flows=[],{}
    network_losses={}
    import re
    for name,interface,logname in [('network','eth0','tcpdump.log'),('network_tools','lo','tcpdump_tools.log')]:
        packets=pcap_packets(folder/(name+'.pcap'))
        indices=rows(folder/('arrival_'+name+'.jsonl'))
        text=(folder/logname).read_text()
        dropped=re.search(r'(\d+) packets dropped by kernel',text)
        captured=re.search(r'(\d+) packets captured',text)
        network_losses[name]=int(dropped[1]) if dropped else None
        if not captured or int(captured[1])!=len(packets) or len(indices)!=len(packets) or network_losses[name]!=0:
            errors.append(name+'_count_or_loss')
        if not report.get(name+'_alive_before_stop') or report.get(name+'_exit_code')!=0:
            errors.append(name+'_collector_exited_early')
        if interface=='lo' and any(a['timestamp']==b['timestamp'] and a['length']==b['length'] for a,b in zip(packets,packets[1:])):
            errors.append('loopback_duplicate_capture')
        for i,packet in enumerate(packets):
            index=indices[i] if i<len(indices) else {}
            if packet['record_index']!=index.get('record_index'):
                errors.append(name+'_arrival_index_mismatch')
            c=None
            if 'src_port' in packet:
                key=(packet['protocol'],)+tuple(sorted(((packet['src'],packet['src_port']),(packet['dst'],packet['dst_port']))))
                matches=[c for c in connection_lookup[key] if c['started_at']-.1<=packet['timestamp']<=c['ended_at']+1]
                c=matches[0] if len(matches)==1 else None
                flow_id=hashlib.sha256(json.dumps([sid,key,c['connection_id'] if c else None]).encode()).hexdigest()[:24]
            else:
                flow_id=None
            direction=('client_to_service' if packet.get('src')==c['local_ip'] and packet.get('src_port')==c['local_port'] else 'service_to_client') if c else 'unattributed'
            packet.update(session_id=sid,interface=interface,flow_id=flow_id,direction=direction,
                application_role=c['application_role'] if c else 'unattributed',connection_id=c['connection_id'] if c else None,
                relative_timestamp=relative(packet['timestamp']),arrival_timestamp=index.get('arrival_time'),
                arrival_relative_timestamp=index['arrival_monotonic']-origin['monotonic'] if 'arrival_monotonic' in index else None,
                event_time_basis='epoch_mapped_to_monotonic',clock_offset_spread_seconds=spread,
                packet_count=1,byte_count=packet['length'],start_ts=packet['timestamp'],end_ts=packet['timestamp'],
                five_tuple=[packet.get(k) for k in ('src','src_port','dst','dst_port','protocol')] if flow_id else None)
            n_out.append(packet)
            if flow_id:
                flow=flows.setdefault(flow_id,{'session_id':sid,'flow_id':flow_id,'protocol':packet['protocol'],
                    'endpoints':list(key[1:]),'application_role':packet['application_role'],'connection_id':packet['connection_id'],
                    'start_ts':packet['timestamp'],'end_ts':packet['timestamp'],'packet_count':0,'byte_count':0,'dns_query':[]})
                flow['packet_count']+=1
                flow['byte_count']+=packet['length']
                flow['end_ts']=packet['timestamp']
                flow['dns_query']=sorted(set(flow['dns_query']+(packet.get('dns_query') or [])))
    n_out.sort(key=lambda r:(r['relative_timestamp'],r['interface'],r['record_index']))
    for flow in flows.values():
        flow['relative_timestamp']=relative(flow['start_ts'])
        flow['direction']='bidirectional'
        flow['five_tuple']=[*flow['endpoints'][0],*flow['endpoints'][1],flow['protocol']]
    save_rows(folder/'network.events.jsonl',n_out)
    save_rows(folder/'network.flows.jsonl',list(flows.values()))
    coverage['N']={'coverage_flag':'OK' if n_out and all(v==0 for v in network_losses.values()) else 'partial_loss',
        'packets':len(n_out),'loss_counters':network_losses,
        'parse_status_counts':dict(collections.Counter(p['parse_status'] for p in n_out)),
        'unattributed_packets':sum(p['direction']=='unattributed' for p in n_out)}
    if any(p['parse_status']=='malformed' or p.get('dns_parse_error') for p in n_out):
        errors.append('packet_metadata_parse_error')
    connected={p.get('connection_id') for p in n_out}
    if any(c['connection_id'] not in connected for c in connections):
        errors.append('observed_connection_missing_from_pcap')
    if any(not r.get('connection') for r in requests if r.get('status')==200):
        errors.append('successful_API_connection_identity_missing')
    if not report['capture_ready_at']<=report['task_started_at']<report['task_ended_at']<=report['capture_ended_at']:
        errors.append('capture_does_not_cover_task')
    for modality,prefixes in [('T',('T_','request_','api_','truth_','invalid_tool_','unstructured_','orphan_','duplicate_T','missing_tool_')),
                              ('E',('E_','observed_connection_missing_from_endpoint','tool_connection_missing_server')),
                              ('N',('network','loopback_','packet_','observed_connection_missing_from_pcap'))]:
        reasons=[error for error in errors if error.startswith(prefixes)]
        coverage[modality]['reasons']=reasons
        if reasons and coverage[modality]['coverage_flag']=='OK':
            coverage[modality]['coverage_flag']='partial_loss'
    save(folder/'coverage.json',coverage)
    write_catalog(folder,report,coverage,settings,trace,labels)
    arrival_delays={}
    for modality,records in [('T',trace),('E',e_out),('N',n_out)]:
        delays=sorted(r['arrival_timestamp']-(r['timestamp']/1e9 if modality=='E' else r['timestamp'])
                      for r in records if r.get('arrival_timestamp') is not None)
        arrival_delays[modality]={'count':len(delays),'min':min(delays) if delays else None,
            'median':delays[len(delays)//2] if delays else None,
            'p95':delays[min(len(delays)-1,int(.95*len(delays)))] if delays else None,'max':max(delays) if delays else None}
    result={'passed':not errors,'session_id':sid,'collection_revision':settings['collection_revision'],
        'errors':sorted(set(errors)),'warnings':sorted(set(warnings)), 'coverage':coverage,
        'clock':{'offset_spread_seconds':spread,'sample_bracket_plus_spread_seconds':uncertainty,
                 'note':'Empirical sampling uncertainty; not a guarantee of exact event synchronization or harm timing.'},
        'collector_arrival_delay_seconds':arrival_delays,
        'counts':{'T':len(trace),'E':len(endpoint),'N':len(n_out),'flows':len(flows)},
        'label_audit':label_check,'eligible_for_formal_results':False,
        'source_hashes':{p.name:sha(p) for p in [Path(__file__),Path(__file__).with_name('packet_metadata.py'),
            Path(__file__).with_name('validate_native_session.py'),Path(__file__).with_name('validate_sensor_contract.py')]}}
    save(folder/'collection_validation.json',result)
    return result


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('folder',type=Path)
    args=parser.parse_args()
    settings=read(Path(__file__).resolve().parents[1]/'configs/collection-integrity.json')
    print(json.dumps(normalize(args.folder,settings),ensure_ascii=False,indent=2))
