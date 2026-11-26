# Section 6.4: Protected Execution Performance

This module evaluates enclave initialization and remote attestation (C1, Table III) and same-host Native vs. Intel SGX protected processing performance across tasks T1 (basic statistics) and T2 (income classification) (C2, Figure 4).

## Contents

- `executionbench/`: isolated compute benchmark binary sharing `pkg/worker` and `pkg/analyzer` with the production enclave.
- `train_adult.py` & `requirements-training.txt`: offline logistic regression training script that reproduces `data/adult/classification/` from `adult.data` and `adult.test`.
- `run_execution.py` & `test_run_execution.py`: balanced fresh-process C2 benchmark runner (`configs/execution-formal.json`) and unit tests.
- `plot_execution.py`: offline C2 verifier, C1 summary checker, and Figure 4 / `paper-summary.json` generator (requires `matplotlib`).

## Running Unit Tests

```sh
python3 -m unittest discover -s 6.4-execution -p "test_*.py"
```

## Building & Running Measurements

Prerequisites: prepare `data/adult/full-records/` via `6.3-certification/prepare_adult.py` (see `6.3-certification/README.md`). The pre-trained T2 model and reference outputs in `data/adult/classification/` are included in the repository and can be regenerated with `train_adult.py` using the pinned packages in `requirements-training.txt`.

```sh
# Build Native benchmark executable
python3 prototype/build.py native --execution-bench --out build/native-exec

# On a Linux Intel SGX host (EGo 1.9.0): also build the signed SGX executable
python3 prototype/build.py sgx --execution-bench --runtime <path/to/runtime.json> --out build/sgx-exec

# Run formal Native vs. SGX comparison (requires Linux SGX host + acceptance record)
python3 6.4-execution/run_execution.py \
  --config configs/execution-formal.json \
  --native-build build/native-exec \
  --sgx-build build/sgx-exec \
  --sgx-fixture-root build/sgx-exec/input \
  --acceptance <path/to/acceptance.json> \
  --out tmp/execution-run
```

For formal runs (`stage: "formal"`), `run_execution.py` requires an operator-recorded `acceptance.json` binding the exact build (`validated: true`, `source_hash`, `mrenclave`, `benchmark_sha256`, `protocol_evidence`, and `diagnostic_evidence`) after end-to-end SGX protocol validation. C1 initialization and remote-attestation timings are collected via `prototype/client -timings` against fresh `enclave` instances.

## Formal Bundle Verification and Plotting (Table III & Figure 4)

`plot_execution.py` is a strict formal-evidence verifier and figure generator: it does not consume a bare `run_execution.py` directory directly, but instead expects a packaged formal C1+C2 evidence directory containing `SHA256SUMS`, `sgx-evidence.tar.gz`, `formal-summary.json`, `formal-independent-verification.json`, and `c1-verification.json`:

```sh
python3 6.4-execution/plot_execution.py \
  --results <path/to/formal-evidence-dir> \
  --figure tmp/fig4/execution_performance.pdf \
  --summary tmp/fig4/paper-summary.json
```

This checks all `SHA256SUMS`, recomputes all 600 C2 observations directly from the packaged observation log, checks the 30 C1 run records and means in `c1-verification.json`, and writes Figure 4 and `paper-summary.json`. Published summary values are recorded in `results/paper-snapshots/6.4-execution/paper-summary.json`.
