# Section 6.6: Comparison with Related Schemes

This module provides the common C++ SVM workload, third-party adaptation patches/manifests, and offline verification scripts for the controlled Intel SGX performance comparison (Table V) between our prototype, PrivacyGuard, and VDDPI on RBF C-SVC SVM training and prediction (LIBSVM 3.23) across `N = 5,000`, `10,000`, and `32,561` Adult training records.

## Contents

**Offline verification entry points:**
- `verify/`: standalone Go offline verifier (`main.go`) that decrypts PrivacyGuard protected delivery artifacts and checks exact result parity against independent LIBSVM CLI references.
- `svm_verifier.py`: helper that builds `6.6-comparison/verify` for the current host.
- `common_exp_scaling.py`: balanced Williams-block hardware runner and independent offline analyzer (`analyze` verifies all 72 raw observations at `N = 5,000` and `10,000` against the frozen deployment bundle; to preserve manifest integrity, bundle runs load the frozen copy of `vddpi_hardware.py` inside the bundle).
- `derive_paper_values.py`: verifies cross-batch binary and environment parity between the `5,000/10,000` batch (`svm-common-exp-scaling-20261121`, 72 runs) and the `32,561` batch (`svm-threeway-exp-20261115`, 36 runs) and derives Table V (`paper-values.json`).

**Frozen workload sources & third-party build references:**
- `common_svm/`: formal 32,561-record common C++ task (`svm_task.cpp`, `svm_task.h`, `svm.cpp`, `svm.h`, `transform.hpp`, `math_probe.cpp`, `diag_platform.cpp`, `measurement.cpp`), our prototype's SVM adapter templates (`prototype_adapter/`), Intel SGX SDK `e_exp.o` extraction helper (`extract_exp.py`), solver dispatch patch (`solver-dispatch.patch`), and PrivacyGuard common-`exp` patch and container build reference (`privacyguard-exp.patch`, `build_pg.sh`).
- `prepare_privacyguard_source.py` & `prepare_privacyguard_t1.py`: fetch, SHA-256/Git-blob verify, and apply the base compatibility/harness patches to the pinned PrivacyGuard upstream archive (`third_party/privacyguard/`).
- `prepare_vddpi.py`: verifies and patches the pinned VDDPI upstream archive (`third_party/vddpi/`).
- `vddpi_hardware.py`: standalone Gramine-SGX runner helper for VDDPI (`VDDPI_RUNTIME_IMAGE` overrides the default container digest when invoking this module directly outside a frozen bundle).

## Fetching Excluded Third-Party Dependencies & Toolchain Notes

Large upstream archives, SDK installers, and CPython 3.6.9 wheels are excluded from Git:

```sh
# 1. PrivacyGuard upstream archive (pinned commit 1ef665f)
python3 6.6-comparison/prepare_privacyguard_source.py --fetch

# 2. VDDPI upstream archive (pinned commit 7f2994b) + CPython 3.6.9 + pinned wheels
python3 third_party/vddpi/dependencies/fetch_dependencies.py
```

For rebuilding third-party SGX toolchains on Linux x86_64:
- **PrivacyGuard:** prepare the exact 6.6 common-`exp` SVM source tree from the fetched upstream archive:
  ```sh
  python3 6.6-comparison/prepare_privacyguard_t1.py --out tmp/pg-svm --flavor benchmark
  cp 6.6-comparison/common_svm/{diag_platform.cpp,math_probe.cpp,svm.h,svm_task.cpp,svm_task.h,transform.hpp} tmp/pg-svm/CEE/isv_enclave/
  cp 6.6-comparison/common_svm/svm.cpp tmp/pg-svm/CEE/isv_enclave/enclave_svm.cpp
  patch --batch --fuzz=0 -p1 -d tmp/pg-svm/CEE -i "$(pwd)/6.6-comparison/common_svm/privacyguard-exp.patch"
  ```
  Then download and verify the three Intel SGX SDK `2.27.100.1` / protobuf packages listed in `third_party/privacyguard/toolchain.json`, build `third_party/privacyguard/Dockerfile.build`, extract `probe_exp.o` with `common_svm/extract_exp.py`, and compile `tmp/pg-svm/CEE` using `common_svm/build_pg.sh`.
- **VDDPI:** after running `fetch_dependencies.py`, build `third_party/vddpi/adapter/Dockerfile.toolchain` and `Dockerfile.runtime`, and prepare the patched application source with `python3 6.6-comparison/prepare_vddpi.py --out tmp/vddpi-app`.

> Note: This repository preserves the complete common-`exp` sources, patches, and container build steps for auditability, together with standalone offline verifiers; it does not provide a single-command orchestrator across all three SGX container toolchains.

## Verification of Table V Results

Given completed common-`exp` hardware measurement batches (the `N = 5,000` / `10,000` batch and the `N = 32,561` batch):

```sh
# 1. Independently verify all 72 raw observations at N=5,000 and 10,000 (builds 6.6-comparison/verify automatically)
python3 6.6-comparison/common_exp_scaling.py analyze \
  <path/to/scaling-batch-dir> \
  --impl . \
  --prior <path/to/full-batch-dir>

# 2. Check cross-batch binary/environment parity and combine with the verified 32,561 analysis.json to derive Table V
python3 6.6-comparison/derive_paper_values.py \
  --supplement <path/to/scaling-batch-dir> \
  --prior <path/to/full-batch-dir> \
  --out tmp/table5-paper-values.json
```

> Run without Python `-O` optimization; both scripts enforce assertions to guarantee complete validation. Published Table V values are recorded in `results/paper-snapshots/6.6-comparison/paper-values.json`.
