# Section 6.3: Data Certification and Reuse

This module benchmarks off-chain dataset commitment construction (B1), sampling audit processing across `(rho, epsilon)` and dataset size `N` (B2), certification reuse vs. per-trade re-auditing over 10 trades (B3), and on-chain certification gas.

## Contents

- `prepare_adult.py` / `test_prepare_adult.py`: downloads, SHA-256 verifies, and prepares UCI Adult and synthetic Adult-format datasets (`data/adult/full-records/`).
- `commitmentbench/` & `commitment_length.py`: fixed-record-length (128 B, 1 KiB, 4 KiB) commitment construction sweep (Figure 3(a)).
- `admissionbench/` & `run_admission_pilot.py`: off-chain certification, sampling scaling (Figure 3(b)), and 10-trade reuse/re-audit driver (`configs/admission-client-formal.json`, `configs/admission-sampling-scaling-formal.json`).
- `admissiongasbench/` & `admissionchainbench/`: on-chain certification gas and trajectory drivers.
- `validate_admission_run.py` & `plot_certification.py`: independent offline validators and Figure 3 generator.
- `test_admission_pilot.py`: unit tests for dataset/scheduling/aggregation logic.

## Running Unit Tests

```sh
python3 -m unittest discover -s 6.3-certification -p "test_*.py"
```

## Preparing Datasets

```sh
python3 6.3-certification/prepare_adult.py --download --raw data/adult/raw --out data/adult/full-records
```

## Running Benchmarks

```sh
# B1 fixed-record-length commitment construction sweep
python3 6.3-certification/commitment_length.py prepare --config configs/commitment-length-formal.json --out tmp/b1-inputs
python3 6.3-certification/commitment_length.py run --config configs/commitment-length-formal.json --inputs tmp/b1-inputs --out tmp/b1-run

# B1 Adult reference + B3 reuse/re-audit (30 repetitions; input directory is read from prepared_dir in config)
python3 6.3-certification/run_admission_pilot.py --config configs/admission-client-formal.json --out tmp/b1-b3-run

# B2 sampling scaling across N=1k, 10k, 100k (30 repetitions)
python3 6.3-certification/run_admission_pilot.py --config configs/admission-sampling-scaling-formal.json --out tmp/b2-run
```

## Offline Re-Verification and Plotting (Figure 3)

Given extracted raw evidence directories from the Release/Zenodo archive:

```sh
python3 6.3-certification/commitment_length.py validate --out <path/to/commitment-length-20261113>
python3 6.3-certification/validate_admission_run.py <path/to/admission-certification-20261030>
python3 6.3-certification/validate_admission_run.py <path/to/admission-sampling-scaling-20261113>

python3 6.3-certification/plot_certification.py \
  --offchain <path/to/admission-certification-20261030> \
  --sampling <path/to/admission-sampling-scaling-20261113> \
  --construction <path/to/commitment-length-20261113> \
  --out tmp/fig3-output
```

Use `--preview` with `plot_certification.py` when rendering non-formal local smoke runs.
