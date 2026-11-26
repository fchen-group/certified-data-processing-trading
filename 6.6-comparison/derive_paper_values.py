#!/usr/bin/env python3
"""Derive the three-size common-exp table from independently verified groups."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys

read = lambda path: json.loads(path.read_text())
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if sys.flags.optimize:
        raise RuntimeError('Validation requires assertions to be enabled (run without -O)')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--supplement', type=Path, required=True,
                        help='verified 5,000/10,000 common-exp batch directory (svm-common-exp-scaling-20261121)')
    parser.add_argument('--prior', type=Path,
                        help='verified 32,561 common-exp batch directory (default: sibling svm-threeway-exp-20261115)')
    parser.add_argument('--out', type=Path,
                        help='output JSON path (default: <supplement>/paper-values.json)')
    args = parser.parse_args()
    here = args.supplement.resolve()
    prior_dir = args.prior.resolve() if args.prior else (here.parent / 'svm-threeway-exp-20261115')
    out_path = args.out.resolve() if args.out else (here / 'paper-values.json')

    supplement, prior = read(here / 'analysis.json'), read(prior_dir / 'analysis.json')
    assert supplement['status'] == prior['status'] == 'independently_verified'
    assert supplement['fingerprints'] == prior['fingerprints']
    new_bundle, old_bundle = here / 'remote/bundle', prior_dir / 'remote/bundle'
    old_files = read(old_bundle / 'manifest.json')['files']
    new_files = read(new_bundle / 'manifest.json')['files']
    assert old_files.keys() == new_files.keys()
    for name in old_files:
        assert sha(old_bundle / name) == old_files[name] and sha(new_bundle / name) == new_files[name]
        if name not in ('run.py', 'configuration.json', 'schedule.json'):
            assert old_files[name] == new_files[name], name
    old_env, new_env = read(prior_dir / 'remote/results/environment.json'), read(here / 'remote/results/environment.json')
    assert old_env['ego_runtime_sha256'] == new_env['ego_runtime_sha256']
    for key in ('cpu', 'uname', 'packages', 'ego_go', 'image', 'docker'):
        assert old_env[key]['returncode'] == new_env[key]['returncode'] == 0
        assert old_env[key]['stdout'] == new_env[key]['stdout']
    assert read(here / 'local-verification.json')['basis_analysis_identical']
    rows = []
    for n in (5000, 10000, 32561):
        means = {}
        for system in ('privacyguard', 'vddpi', 'work2'):
            if n == 32561:
                group = next(g for g in prior['groups'] if g['system'] == system and g['math_mode'] == 1)
                source = prior_dir.name
            else:
                group = next(g for g in supplement['groups'] if g['system'] == system and g['n'] == n)
                source = here.name
            values = group['total_ms']['values']
            assert len(values) == group['count'] == 12
            assert statistics.mean(values) == group['total_ms']['mean']
            means[system] = statistics.mean(values) / 1000
            rows.append(dict(n=n, system=system, source_batch=source, count=12,
                             mean_s=means[system], sd_s=statistics.stdev(values) / 1000))
        print(n, *(f'{means[s]:.3f}' for s in ('privacyguard', 'vddpi', 'work2')))
    gaps = []
    for n in (5000, 10000, 32561):
        means = {r['system']: r['mean_s'] for r in rows if r['n'] == n}
        for system in ('privacyguard', 'vddpi'):
            gaps.append(dict(n=n, against=system, difference_s=means['work2'] - means[system],
                             overhead_percent=100 * (means['work2'] / means[system] - 1)))
    full_observations = read(prior_dir / 'remote/results/diagnostic/observations.json')
    work2_full = [x for x in full_observations if x['system'] == 'work2' and x['math_mode'] == 1]
    assert len(work2_full) == 12
    direct_ms = statistics.mean((x['phases_ns']['commitment'] + x['phases_ns']['encrypt_sign']) / 1e6 for x in work2_full)
    record = dict(metric='Continuous protected-processing total with common exp', observations=108,
                  fresh_observations=72, reused_observations=36, groups=rows, gaps=gaps,
                  work2_full_commitment_encrypt_sign_ms=direct_ms,
                  supplement_analysis_sha256=sha(here / 'analysis.json'),
                  prior_analysis_sha256=sha(prior_dir / 'analysis.json'))
    out_path.write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
