#!/usr/bin/env python3
"""Prepare, run and independently verify the common-exp SVM size supplement.

The measured binaries and fixtures come from the verified 2026-11-15 snapshot.
Only the out-of-timer schedule changes. Run on Linux SGX; analyze locally.
"""
import argparse
import base64
import collections
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tarfile
import time

SYSTEMS = ('work2', 'vddpi', 'privacyguard')
SIZES = (5000, 10000)
BATCH = 'svm-common-exp-scaling-20261121'
BASIS = 'svm-threeway-exp-20261115'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_bundle(bundle):
    for name, digest in read(bundle / 'manifest.json')['files'].items():
        assert sha(bundle / name) == digest, name


def make_schedule():
    treatments = [(n, system) for n in SIZES for system in SYSTEMS]
    rng = random.Random(20261121)
    rows = []
    # Balanced six-treatment Williams design, repeated in two shuffled blocks.
    base = (0, 1, 5, 2, 4, 3)
    for block in (1, 2):
        mapping = list(treatments)
        rng.shuffle(mapping)
        shifts = list(range(6))
        rng.shuffle(shifts)
        for offset, shift in enumerate(shifts):
            repetition = (block - 1) * 6 + offset + 1
            for position, index in enumerate(base, 1):
                n, system = mapping[(index + shift) % 6]
                rows.append(dict(n=n, system=system, math_mode=1,
                                 block=block, repetition=repetition, position=position))
    assert len(rows) == 72
    for n, system in treatments:
        group = [x for x in rows if (x['n'], x['system']) == (n, system)]
        assert len(group) == 12
        assert collections.Counter(x['position'] for x in group) == {p: 2 for p in range(1, 7)}
    return rows


def prepare(impl):
    basis = impl / 'results/6.6-comparison' / BASIS
    source = basis / 'remote/bundle'
    check_bundle(source)
    assert sha(source / 'manifest.json') == read(basis / 'freeze.json')['manifest_sha256']
    result = impl / 'results/6.6-comparison' / BATCH
    build = impl / 'build' / BATCH
    assert not result.exists() and not build.exists(), 'Refuse to overwrite a batch'
    result.mkdir()
    (result / 'reproduction').mkdir()
    bundle = build / 'bundle'
    bundle.mkdir(parents=True)
    # Copy only the prior freeze's allowlisted files, excluding generated caches.
    original = read(source / 'manifest.json')['files']
    for name, digest in original.items():
        target = bundle / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, target)
        assert sha(target) == digest
    driver = Path(__file__).resolve()
    shutil.copy2(driver, bundle / 'run.py')
    shutil.copy2(driver, result / 'reproduction/common_exp_scaling.py')
    shutil.copy2(source / 'vddpi_hardware.py', result / 'reproduction/vddpi_hardware.py')
    config = dict(
        purpose='Supplement common-exp protected-processing totals at 5000 and 10000 records',
        systems=SYSTEMS, sizes=SIZES, repetitions=12, observations=72, math_mode=1,
        common_exp=read(source / 'configuration.json')['common_exp'],
        source_solver_sha256=read(source / 'configuration.json')['source_solver_sha256'],
        timing='Primary: original continuous protected-processing total; diagnostic: C++ train plus predict',
        scheduling='Two balanced six-treatment Williams blocks; seed 20261121',
        preflight='One separate functional execution per size and system; excluded by design from the 72 measurements',
        exclusion_policy='No timing-based exclusions, retries or early stopping; validation failure aborts the batch',
        reuse='32561-record mode-1 observations remain in the verified 20261115 batch; reuse requires environment and binary compatibility',
        interpretation='Controlled common-exp workload comparison, not a claim about production library replacement or end-to-end protocol latency',
    )
    save(result / 'configuration.json', config)
    save(bundle / 'configuration.json', config)
    save(bundle / 'schedule.json', make_schedule())
    inputs = {}
    for n in (*SIZES, 32561):
        fixture = read(bundle / f'baseline/work2-svm/input/adult-{n}/fixture.json')
        raw = bundle / f'vddpi/input/adult-{n}.csv'
        assert fixture['n'] == n and fixture['records_sha256'] == sha(raw)
        assert fixture['expected'] == read(bundle / f'baseline/reference/expected-{n}.json')
        inputs[str(n)] = dict(records_sha256=sha(raw), fixture_sha256=sha(bundle / f'baseline/work2-svm/input/adult-{n}/fixture.json'))
    files = {name: sha(bundle / name) for name in original}
    save(bundle / 'manifest.json', dict(files=files))
    changed = [name for name in files if files[name] != original[name]]
    assert set(changed) == {'run.py', 'configuration.json', 'schedule.json'}, changed
    save(result / 'source-basis.json', dict(
        basis=BASIS, basis_manifest_sha256=sha(source / 'manifest.json'),
        basis_source_sha256=sha(basis / 'source.tar.gz'),
        changed_files=changed, identical_frozen_files=len(files)-len(changed), inputs=inputs,
    ))
    with tarfile.open(result / 'deployment.tar.gz', 'w:gz') as archive:
        for name in (*files, 'manifest.json'):
            archive.add(bundle / name, arcname='bundle/' + name)
    save(result / 'freeze.json', dict(
        manifest_sha256=sha(bundle / 'manifest.json'),
        deployment_sha256=sha(result / 'deployment.tar.gz'),
        driver_sha256=sha(driver), observations=72,
    ))
    check_bundle(bundle)
    print(json.dumps(dict(status='prepared', result=str(result), build=str(build), unchanged_files=len(files)-3)))


def phases(detail, total_ns):
    stamps = detail['stamps_ns']
    assert len(stamps) == 6 and all(type(x) is int and x > 0 for x in stamps)
    values = [b-a for a, b in zip(stamps, stamps[1:])]
    assert min(values) >= 0 and values[1] > 0 and values[2] > 0
    assert sum(values) <= total_ns + 1_000_000
    return dict(zip(('parse_and_transform', 'svm_train', 'training_set_predict', 'summary_encoding', 'cleanup'), values))


def fingerprint(system, probe):
    assert probe['mode'] == 1
    raw = (base64.b64decode(probe['native_and_common_entry_bytes']) if system == 'work2'
           else bytes.fromhex(probe['native_and_common_entry_hex']))
    assert len(raw) == 128
    return dict(native_hex=raw[:64].hex(), common_hex=raw[64:].hex())


def label_for(index, item):
    return f'{index:02}-{item["system"]}-n{item["n"]}-r{item["repetition"]}'


def run_bundle(root, out, phase):
    if sys.flags.optimize:
        raise RuntimeError('Validation requires assertions to be enabled (run without -O)')
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
    check_bundle(root)
    out.mkdir(exist_ok=False)
    helper = load_module(root / 'vddpi_hardware.py', 'vddpi_hardware')
    hardware = helper.Hardware(root, out / 'vddpi-1', app_folder='vddpi', math_mode=1)
    base = root / 'baseline'
    env = dict(os.environ, GOMAXPROCS='4')
    for key in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_DEBUG', 'OE_SIMULATION', 'SGX_MODE', 'GODEBUG', 'GOGC', 'PG_FAIL_CRYPTO_AT'):
        env.pop(key, None)
    pg_env = dict(env, LD_LIBRARY_PATH=str(base / 'runtime'))
    rows, fingerprints, sessions = [], {}, set()

    def execute(label, argv, cwd=None, environ=None):
        d = out / label
        d.mkdir()
        save(d / 'command.json', dict(argv=argv, cwd=str(cwd or base), timeout=900))
        start = time.monotonic()
        with (d / 'stdout.txt').open('wb') as so, (d / 'stderr.txt').open('wb') as se:
            p = subprocess.run(argv, cwd=cwd or base, env=environ or env, stdout=so, stderr=se, timeout=900)
        save(d / 'exit.json', dict(returncode=p.returncode, wall_seconds=time.monotonic()-start))
        assert p.returncode == 0, (label, p.returncode)
        return d

    try:
        hardware.probe()
        pg = base / 'pg-svm'
        execute('pg-load', [str(base/'bin/load-probe'), str(pg/'isv_enclave.signed.so')], environ=pg_env)
        bad = execute('pg-bad-tag', [str(pg/'app'), str(pg/'isv_enclave.signed.so'), str(base/'pg-fixtures/bad-tag'), str(out/'bad-protected'), 'reject-input'], environ=pg_env)
        assert helper.parse(bad/'stdout.txt', 'status')['status'] == 'rejected_as_expected'
        assert not (out/'bad-protected').exists()
        schedule = read(root/'schedule.json')
        if phase == 'preflight':
            schedule = [dict(n=n, system=s, math_mode=1, repetition=0) for n in SIZES for s in SYSTEMS]
        save(out/'schedule.json', schedule)
        for index, item in enumerate(schedule, 1):
            n, system = item['n'], item['system']
            label = label_for(index, item)
            print(label, flush=True)
            expected = read(base/f'reference/expected-{n}.json')
            if system == 'vddpi':
                row = hardware.execute(label, n)
                q, actual, ms = row['phases_ns'], row['result'], row['processing_ms']
                detail, probe = q['svm_diagnostic'], q['math_probe']
            elif system == 'privacyguard':
                target = out/(label+'-protected')
                d = execute(label, [str(pg/'app'), str(pg/'isv_enclave.signed.so'), str(base/f'pg-fixtures/adult-{n}'), str(target), 'normal', '1'], environ=pg_env)
                q = helper.parse(d/'stdout.txt', 'status')
                assert q['status'] == 'ok'
                v = execute(label+'-verify', [str(base/'bin/svmpilotverify'), str(base/f'reference/expected-{n}.json'), str(target)])
                actual, ms = read(v/'stdout.txt'), q['processing_ms_diagnostic_only']
                detail = helper.parse(d/'stdout.txt', 'svm_diagnostic')['svm_diagnostic']
                probe = helper.parse(d/'stdout.txt', 'math_probe')['math_probe']
                keys = (target/'public-session-keys.bin').read_bytes()
                assert len(keys) == 32
                for key in (keys[:16], keys[16:]):
                    digest = hashlib.sha256(key).hexdigest()
                    assert digest not in sessions
                    sessions.add(digest)
                row = dict(phases_ns=None)
            else:
                assert system == 'work2'
                w = base/'work2-svm'
                (w/f'input/adult-{n}/input.bin').read_bytes()
                d = execute(label, ['ego', 'run', str(w/'executionbench'), '-fixture', f'/input/adult-{n}', '-math-probe', '1'], cwd=w)
                q = helper.parse(d/'stdout.txt', 'schema')
                assert q['validated'] and q['backend'] == 'sgx-build' and q['go'] == 'go1.26.1' and q['gomaxprocs'] == 4
                assert q['clock'] == 'clock_monotonic_raw' and sum(q['phases_ns'].values()) == q['total_ns']
                assert q['fixture_sha256'] == sha(w/f'input/adult-{n}/fixture.json')
                actual, ms = q['result'], q['total_ns']/1e6
                detail, probe = q['svm_diagnostic'], q['math_probe']
                row = dict(phases_ns=q['phases_ns'])
            helper.compare(actual, expected)
            fp = fingerprint(system, probe)
            assert system not in fingerprints or fingerprints[system] == fp
            fingerprints[system] = fp
            row.update(item, name=label, result=actual, processing_ms=ms, svm_diagnostic=detail,
                       core_phases_ns=phases(detail, ms*1e6), math_probe=probe, validated=True)
            rows.append(row)
            save(out/'observations.json', rows)
            print(json.dumps(dict(name=label, processing_ms=ms, validated=True)), flush=True)
        assert len(rows) == (6 if phase == 'preflight' else 72)
        assert len({fp['common_hex'] for fp in fingerprints.values()}) == 1
        check_bundle(root)
        save(out/'summary.json', dict(status='passed', phase=phase, manifest_sha256=sha(root/'manifest.json'), observations=rows, fingerprints=fingerprints))
    except BaseException as error:
        save(out/'summary.json', dict(status='failed', phase=phase, error=repr(error), observations=rows))
        raise


def analyze(batch, impl, prior_batch=None):
    remote = batch/'remote'
    bundle, out = remote/'bundle', remote/'results/formal'
    check_bundle(bundle)
    for name, digest in read(remote/'evidence-files.json').items():
        assert sha(remote/name) == digest, name
    assert sha(bundle/'manifest.json') == read(batch/'freeze.json')['manifest_sha256']
    helper = load_module(bundle/'vddpi_hardware.py', 'vddpi_hardware')
    verifier_api = load_module(impl/'6.6-comparison/svm_verifier.py', 'svm_verifier')
    summary = read(out/'summary.json')
    assert summary['status'] == 'passed' and summary['phase'] == 'formal'
    assert summary['manifest_sha256'] == sha(bundle/'manifest.json')
    assert read(remote/'results/preflight/summary.json')['status'] == 'passed'
    rows, schedule = summary['observations'], read(bundle/'schedule.json')
    assert rows == read(out/'observations.json') and len(rows) == len(schedule) == 72
    assert schedule == make_schedule() == read(out/'schedule.json')
    report = bytes.fromhex(read(out/'vddpi-1/hardware-acceptance.json')['report']['local_report_hex'])
    assert len(report) == 432 and not int.from_bytes(report[48:56], 'little') & 2
    assert report[64:96].hex() == read(bundle/'signatures.json')['benchmark']['mrenclave']
    assert helper.parse(out/'pg-bad-tag/stdout.txt', 'status')['status'] == 'rejected_as_expected'
    groups, fingerprints, sessions = collections.defaultdict(list), {}, set()
    with verifier_api.prepare_verifier() as verifier:
        for index, (row, item) in enumerate(zip(rows, schedule), 1):
            n, system = item['n'], item['system']
            name = label_for(index, item)
            assert row['name'] == name and all(row[k] == v for k, v in item.items()) and row['validated']
            expected_path = bundle/f'baseline/reference/expected-{n}.json'
            expected = read(expected_path)
            if system == 'vddpi':
                d = out/'vddpi-1'/name
                q = helper.parse(d/'stdout.txt', 'processing_ns')
                actual, ms = read(d/'received.json'), q['processing_ns']/1e6
                assert q['protected_done_ns']-q['begin_ns'] == q['processing_ns']
                assert q['cached'] and q['network_send_after_endpoint']
                assert q['protected_bytes'] > q['plaintext_bytes'] == len((d/'received.json').read_bytes())
                assert read(d/'config.json')['math_probe_mode'] == 1 and read(d/'peer.json')['error'] is None
                inspection = helper.parse(out/'vddpi-1'/(name+'-inspect')/'stdout.txt', 'condition')
                assert inspection['condition']['counter'] == '1' and inspection['client_cn'] == 'test-consumer'
                assert inspection['input_sha256'] == row['records_sha256'] == sha(bundle/f'vddpi/input/adult-{n}.csv')
                detail, probe = q['svm_diagnostic'], q['math_probe']
            elif system == 'privacyguard':
                d = out/name
                q = helper.parse(d/'stdout.txt', 'status')
                assert q['status'] == 'ok'
                recovered = subprocess.run([str(verifier), str(expected_path), str(out/(name+'-protected'))], capture_output=True, text=True, check=True)
                actual, ms = json.loads(recovered.stdout), q['processing_ms_diagnostic_only']
                keys = (out/(name+'-protected')/'public-session-keys.bin').read_bytes()
                assert len(keys) == 32
                for key in (keys[:16], keys[16:]):
                    digest = hashlib.sha256(key).hexdigest()
                    assert digest not in sessions
                    sessions.add(digest)
                detail = helper.parse(d/'stdout.txt', 'svm_diagnostic')['svm_diagnostic']
                probe = helper.parse(d/'stdout.txt', 'math_probe')['math_probe']
            else:
                d = out/name
                q = helper.parse(d/'stdout.txt', 'schema')
                actual, ms = q['result'], q['total_ns']/1e6
                assert q['validated'] and sum(q['phases_ns'].values()) == q['total_ns']
                assert q['backend'] == 'sgx-build' and q['clock'] == 'clock_monotonic_raw' and q['gomaxprocs'] == 4 and q['go'] == 'go1.26.1'
                assert q['fixture_sha256'] == sha(bundle/f'baseline/work2-svm/input/adult-{n}/fixture.json')
                detail, probe = q['svm_diagnostic'], q['math_probe']
            assert read(d/'exit.json')['returncode'] == 0
            helper.compare(actual, expected)
            helper.compare(row['result'], expected)
            assert ms == row['processing_ms'] and ms > 0
            assert detail == row['svm_diagnostic'] and probe == row['math_probe']
            assert phases(detail, ms*1e6) == row['core_phases_ns']
            fp = fingerprint(system, probe)
            assert system not in fingerprints or fingerprints[system] == fp
            fingerprints[system] = fp
            groups[(n, system)].append(row)
    assert fingerprints == summary['fingerprints'] and len({fp['common_hex'] for fp in fingerprints.values()}) == 1
    prior_dir = prior_batch if prior_batch is not None else (batch.parent/BASIS if (batch.parent/BASIS).exists() else impl/'results/6.6-comparison'/BASIS)
    prior = read(prior_dir/'analysis.json')
    assert fingerprints == prior['fingerprints']
    statistics_rows = []
    for (n, system), samples in sorted(groups.items()):
        assert len(samples) == 12
        values = [x['processing_ms'] for x in samples]
        statistics_rows.append(dict(n=n, system=system, count=len(values), total_ms=dict(
            mean=statistics.mean(values), sd=statistics.stdev(values), min=min(values), max=max(values), values=values),
            train_predict_ms=statistics.mean((x['core_phases_ns']['svm_train']+x['core_phases_ns']['training_set_predict'])/1e6 for x in samples)))
    save(batch/'analysis.json', dict(status='independently_verified', observations=72, groups=statistics_rows, fingerprints=fingerprints))
    for row in statistics_rows:
        print(row['n'], row['system'], 'mean_s', row['total_ms']['mean']/1000, 'sd_ms', row['total_ms']['sd'])


def main():
    if sys.flags.optimize:
        raise RuntimeError('Validation requires assertions to be enabled (run without -O)')
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    p = subs.add_parser('prepare')
    p.add_argument('--impl', type=Path, required=True)
    p = subs.add_parser('run')
    p.add_argument('bundle', type=Path)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--phase', choices=('preflight', 'formal'), required=True)
    p = subs.add_parser('analyze')
    p.add_argument('batch', type=Path)
    p.add_argument('--impl', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--prior', type=Path, help='path to the prior 32,561-record common-exp batch')
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.impl.resolve())
    elif args.command == 'run':
        run_bundle(args.bundle.resolve(), args.out.resolve(), args.phase)
    else:
        analyze(args.batch.resolve(), args.impl.resolve(), args.prior.resolve() if args.prior else None)


if __name__ == '__main__':
    main()
