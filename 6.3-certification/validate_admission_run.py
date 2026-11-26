#!/usr/bin/env python3
"""Check a complete admission run and independently recompute its CSV statistics."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct
import tarfile

TIMES = ('sample_ns', 'challenge_encode_ns', 'respond_ns', 'response_encode_ns',
         'response_decode_ns', 'verify_ns')
PREP = ('normalize_ns', 'salt_prepare_ns', 'snapshot_ns')
MEMORY = ('baseline_live_heap_bytes', 'retained_live_heap_bytes',
          'retained_heap_increment_bytes', 'baseline_peak_rss_bytes', 'preparation_peak_rss_bytes')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare_csv(path, grouped, key_fields):
    rows = list(csv.DictReader(path.open()))
    require(len(rows) == len(grouped), f'{path.name}: row count')
    seen = set()
    for row in rows:
        key = tuple(row[f] for f in key_fields)
        require(key in grouped and key not in seen, f'{path.name}: unexpected/duplicate key {key}')
        seen.add(key)
        samples = grouped[key]
        require(int(row['repetitions']) == len(samples), 'summary repetition count')
        require(set(row) == set(key_fields) | {'repetitions'} |
                {f+s for f in samples[0] for s in ('_mean', '_stdev')}, 'summary columns')
        for name in samples[0]:
            values = [s[name] for s in samples]
            if all(v is None for v in values):
                expected = {'mean': None, 'stdev': None}
            else:
                require(all(v is not None for v in values), 'mixed missing measurements')
                expected = {'mean': statistics.mean(values),
                            'stdev': statistics.stdev(values) if len(values) > 1 else None}
            for suffix, value in expected.items():
                actual = row[name+'_'+suffix]
                require(actual == '' if value is None else
                        math.isclose(float(actual), value, rel_tol=1e-12, abs_tol=1e-8),
                        f'{path.name}: {key} {name}_{suffix}')
    return len(rows)


def validate(folder):
    cfg = json.loads((folder/'config.json').read_text())
    manifest = json.loads((folder/'manifest.json').read_text())
    require(manifest['status'] == 'complete', 'incomplete run')
    require(manifest['config_sha256'] == sha(folder/'config.json'), 'config hash')
    require(manifest['data_manifest_sha256'] == sha(folder/'data-manifest.json'), 'data manifest hash')
    require(manifest['source_archive_sha256'] == sha(folder/'source.tar.gz'), 'source archive hash')
    with tarfile.open(folder/'source.tar.gz') as archive:
        hashes = {m.name: hashlib.sha256(archive.extractfile(m).read()).hexdigest()
                  for m in archive.getmembers() if m.isfile()}
        require(hashes == manifest['source_sha256'], 'archived source files')
    data_manifest = json.loads((folder/'data-manifest.json').read_text())
    files = {x['file']:x for x in data_manifest['outputs']}
    v2 = manifest.get('measurement_schema') == 'commitment-v2'
    prep_fields = PREP[1:] if v2 else PREP
    if v2:
        require(manifest['record_format'] == cfg.get('record_format', 'work2.score-record.v1'), 'record format configuration')
    formal = cfg['stage'] == 'linux-client-formal'
    stage = 'formal' if formal else 'preexperiment'
    repeats = cfg['repetitions']
    expected = Counter()
    groups = cfg.get('groups', ['B1','B2','B3'])
    require(groups and len(set(groups)) == len(groups) and set(groups) <= {'B1','B2','B3'}, 'selected groups')
    b2_sizes = cfg['b2_records'] if isinstance(cfg['b2_records'],list) else [cfg['b2_records']]
    for rep in range(1, repeats+1):
        for data in cfg['datasets'] if 'B1' in groups else []:
            sizes = cfg['b1_records']
            for n in sizes[data] if isinstance(sizes, dict) else sizes:
                expected[(rep, 'B1', data, n, cfg['rho'], cfg['epsilon'])] += 1
        for data in cfg.get('b3_datasets', cfg['datasets']) if 'B3' in groups else []:
            expected[(rep, 'B3', data, cfg['b3_records'], cfg['rho'], cfg['epsilon'])] += 1
        for n in b2_sizes if 'B2' in groups else []:
            for p in cfg['b2_parameters']:
                expected[(rep, 'B2', cfg['b2_dataset'], n, p['rho'], p['epsilon'])] += 1
    raw = [json.loads(line) for line in (folder/'raw.jsonl').read_text().splitlines()]
    actual = Counter()
    processes, grouped = defaultdict(list), defaultdict(list)
    audits_total = 0
    for row in raw:
        c, r, rep = row['case'], row['measurement'], row['repetition']
        require(row['returncode'] == 0 and not row.get('validation_failed'), 'failed measurement')
        actual[(rep,c['group'],c['dataset'],c['n'],c['rho'],c['epsilon'])] += 1
        processes[row['process_id']].append(row)
        require(r['stage'] == 'offchain-'+stage and r['go_version'] == 'go1.26.1', 'stage/toolchain')
        if formal:
            require((r['os'],r['arch']) == ('linux','amd64'), 'formal host')
        require(r['gomaxprocs'] == cfg['gomaxprocs'] and r['challenge_budget'] == cfg['challenge_budget'], 'runtime/budget')
        require((r['n'],r['rho'],r['epsilon']) == (c['n'],c['rho'],c['epsilon']), 'requested parameters')
        require(set(r['preparation']) == set(prep_fields) and all(r['preparation'][f] > 0 for f in prep_fields), 'preparation timers')
        checks = ['reconstructed_commitment', 'all_decoded_samples_verified', 'tampered_record_rejected']
        if v2:
            checks.append('dataset_roundtrip_verified')
            require(r.get('measurement_schema') == 'commitment-v2' and r.get('record_format') == manifest['record_format'], 'measurement scope')
        require(r['checks'] == dict.fromkeys(checks, True), 'correctness checks')
        require(r['m'] == min(r['n'],math.ceil(math.log(r['epsilon'])/math.log1p(-r['rho']))), 'sample size')
        require(r['input_ciphertext_bytes'] == r['encoded_dataset_bytes']+28, 'AES-GCM byte accounting')
        require(r['dimensions'] == files[c['dataset']]['dimensions'] and r['record_bytes'] > 0, 'input description')
        require(len(r['audits']) == c['audits'] <= cfg['challenge_budget'], 'audit count')
        union = set()
        for j, audit in enumerate(r['audits'], 1):
            indices = audit['indices']
            require(audit['audit'] == j and len(indices) == r['m'] and indices == sorted(set(indices))
                    and 1 <= indices[0] <= indices[-1] <= r['n'], 'sample indices')
            digest = hashlib.sha256(b'WORK2_CHALLENGE_V1'+struct.pack('>Q',len(indices))+
                                    b''.join(struct.pack('>Q',i) for i in indices)).hexdigest()
            require(audit['challenge_hash'] == '0x'+digest, 'challenge digest')
            union.update(indices)
            require(audit['cumulative_distinct_records'] == len(union), 'sample union')
            require(audit['salt_bytes'] == 32*r['m'] and audit['proof_hash_bytes'] % 32 == 0, 'proof/salt sizes')
            require(all(audit[t] > 0 for t in TIMES) and audit['response_wire_bytes'] > audit['sample_record_bytes'] > 0
                    and audit['challenge_wire_bytes'] > 0, 'component measurements')
        audits_total += len(r['audits'])
        modes = [('once',1)] if c['group'] != 'B3' else [(mode,k) for k in cfg['b3_checkpoints'] for mode in ('reuse','reaudit')]
        for mode,k in modes:
            active = r['audits'][:1 if mode == 'reuse' else k]
            metrics = {name: sum(a[name] for a in active) for name in TIMES}
            metrics.update(r['preparation'])
            prep, cost = sum(r['preparation'].values()), sum(metrics[t] for t in TIMES)
            metrics.update(preparation_ns=prep,audit_component_ns=cost,total_component_ns=prep+cost,
                           amortized_component_ns=(prep+cost)/k,audit_count=len(active),submitted_records=len(active)*r['m'],
                           distinct_records=len(set(i for a in active for i in a['indices'])),
                           response_wire_bytes=sum(a['response_wire_bytes'] for a in active),
                           challenge_wire_bytes=sum(a['challenge_wire_bytes'] for a in active),
                           record_bytes=r['record_bytes'],input_ciphertext_bytes=r['input_ciphertext_bytes'])
            key = (c['group'],c['dataset'],r['n'],r['dimensions'],r['m'],r['rho'],r['epsilon'],mode,k)
            grouped[tuple(map(str,key))].append(metrics)
    require(actual == expected, 'missing, extra or duplicate configurations')
    require(sorted(processes) == list(range(1,len(processes)+1)), 'process IDs')
    commitments = []
    for rows in processes.values():
        first = rows[0]
        require(all(x['repetition'] == first['repetition'] and x['measurement']['commitment'] == first['measurement']['commitment']
                    and x['measurement']['preparation'] == first['measurement']['preparation']
                    and (x['case']['group'],x['case']['dataset'],x['case']['n']) ==
                        (first['case']['group'],first['case']['dataset'],first['case']['n']) for x in rows), 'shared process metadata')
        commitments.append(first['measurement']['commitment'])
        if first['case']['group'] == 'B2':
            ordered = [cfg['b2_parameters'][i] for i in manifest['b2_policy_orders'][first['repetition']-1]]
            require([(x['case']['rho'],x['case']['epsilon']) for x in rows] == [(p['rho'],p['epsilon']) for p in ordered], 'policy schedule')
            require([x['case']['policy_position'] for x in rows] == list(range(1,len(ordered)+1)), 'policy positions')
        else:
            require(len(rows) == 1, 'unexpected process sharing')
    require(len(set(commitments)) == len(commitments), 'independent processes reused a commitment')
    if cfg.get('balance_case_order'):
        grid, schedule = manifest['case_grid'], manifest['case_orders']
        keys = [(c['group'],c['dataset'],c['n']) for c in grid]
        expected_keys = {(key[1],key[2],key[3]) for key in expected}
        require(set(keys) == expected_keys and len(keys) == len(expected_keys), 'case grid')
        require(len(schedule) == repeats and all(sorted(o) == list(range(len(grid))) for o in schedule), 'case schedule')
        for rep, order in enumerate(schedule,1):
            observed = [(r[0]['case']['group'],r[0]['case']['dataset'],r[0]['case']['n'])
                        for _,r in sorted(processes.items()) if r[0]['repetition'] == rep]
            require(observed == [keys[i] for i in order], 'executed case order')
        for case in range(len(grid)):
            counts = [sum(o[pos] == case for o in schedule) for pos in range(len(grid))]
            require(max(counts)-min(counts) <= 1, 'unbalanced case positions')
    orders = manifest['b2_policy_orders']
    count = len(cfg['b2_parameters'])
    require(len(orders) == repeats and all(sorted(o) == list(range(count)) for o in orders), 'order permutations')
    for policy in range(count):
        counts = [sum(o[pos] == policy for o in orders) for pos in range(count)]
        require(max(counts)-min(counts) <= 1, 'unbalanced policy positions')
    require(manifest['successful_processes'] == len(processes) and manifest['measurement_points'] == len(raw), 'manifest counts')
    summary_count = compare_csv(folder/'summary.csv',grouped,('group','dataset','n','dimensions','m','rho','epsilon','mode','k'))
    require(summary_count == manifest['summary_rows'], 'summary manifest count')
    mem_path = folder/'memory-raw.jsonl'
    mem = [json.loads(line) for line in mem_path.read_text().splitlines()] if mem_path.exists() else []
    mem_expected = {(rep,data,n) for rep in range(1,repeats+1) for data,sizes in cfg.get('memory_records', {}).items() for n in sizes}
    mem_seen, mem_grouped = set(), defaultdict(list)
    for row in mem:
        c,r = row['case'],row['measurement']
        key = (row['repetition'],c['dataset'],c['n'])
        require(key not in mem_seen and row['returncode'] == 0 and r['retained_snapshot_verified'], 'memory process')
        mem_seen.add(key)
        require(r['stage'] == 'snapshot-memory-'+stage and r['n'] == c['n'] and r['gomaxprocs'] == cfg['gomaxprocs']
                and r['go_version'] == 'go1.26.1', 'memory metadata')
        require(r['retained_heap_increment_bytes'] == r['retained_live_heap_bytes']-r['baseline_live_heap_bytes'], 'heap delta')
        if formal:
            require((r['os'],r['arch']) == ('linux','amd64') and r['preparation_peak_rss_bytes'] >= r['baseline_peak_rss_bytes'] > 0, 'memory host/RSS')
        mem_grouped[(c['dataset'],str(c['n']))].append({f:r[f] for f in MEMORY})
    require(mem_seen == mem_expected and len(mem) == manifest['successful_memory_processes'], 'memory coverage')
    memory_count = compare_csv(folder/'memory-summary.csv',mem_grouped,('dataset','n')) if mem_grouped else 0
    return dict(valid=True,stage=cfg['stage'],timing_processes=len(processes),measurement_points=len(raw),
                verified_audits=audits_total,summary_rows=summary_count,memory_processes=len(mem),
                memory_summary_rows=memory_count,all_observations_retained=True,
                checks=['configuration coverage','source/config hashes','metadata and correctness flags',
                        'sample counts/positions/digests/unions','B2 shared snapshots and balanced positions',
                        'independent-process commitments','all CSV means and sample standard deviations'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder',type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(args.folder),indent=2))
