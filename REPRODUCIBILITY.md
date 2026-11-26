# Reproducibility Guide

This guide documents the experimental environment, datasets, tasks, timing boundaries, on-chain rules, and mapping between evaluation artifacts and the paper's tables and figures.

## 1. Environment & Pinned Toolchains

| Component | Configuration Used in Paper Evaluation |
|---|---|
| SGX Compute Host | Intel Xeon 6982P-C (8 vCPU, ~15 GiB RAM, 15.5 GiB EPC), Ubuntu 22.04 (`linux/amd64`), non-debug SGX hardware mode |
| Client Host | 2 vCPU, 8 GiB RAM, Ubuntu 22.04 (same availability zone as compute host for Section 6.3 and C1 attestation measurements) |
| Core Prototype | EGo `1.9.0`, Go `1.26.1`, Intel SGX DCAP `1.27`, Solidity `0.8.24` (optimizer enabled, `paris` EVM compiler target) |
| Cryptographic Primitives | Input encryption: AES-256-GCM; Result encryption: RFC 9180 HPKE (X25519 + HKDF-SHA256 + AES-256-GCM); Receipts: secp256k1 ECDSA |
| On-Chain Gas Evaluation | Anvil `1.5.1` pinned to `Osaka` execution rules; all receipts, logs, and state transitions independently replayed with pinned Geth |
| Testnet Validation | Ethereum Sepolia used for contract deployment and end-to-end protocol functional validation (local Osaka gas numbers are never reported as Sepolia measurements) |
| Comparison Baselines (6.6) | PrivacyGuard (`1ef665f`, Intel SGX SDK `2.27.100.1`, GCC/G++ `11.4.0`); VDDPI (`7f2994b`, Gramine `1.9`, CPython `3.6.9`) |

Protocol domain-separation identifiers (e.g., `WORK2_RECEIPT_V1`, `WORK2_RESULT_HPKE_V1`, `WORK2_ACCOUNT_AUTH_V1`, `WORK2_CHALLENGE_V1`) and frozen experiment payload tags (`WORK2_D2_PAYLOAD_V1`) are preserved verbatim for test-vector and archived-evidence compatibility.

## 2. Datasets & Analysis Tasks

- **UCI Adult Dataset:** All 48,842 raw records (`adult.data`: 32,561 training records; `adult.test`: 16,281 test records), retaining all 14 attributes, income label, and `?` missing-value markers. Downloaded and SHA-256 verified via `6.3-certification/prepare_adult.py --download`.
  - Nested prefixes for Section 6.3 and T1 use a fixed permutation of all 48,842 records (`seed = 20261029`).
  - Synthetic Adult-format records for scale extension up to 100,000 records are sampled from the empirical column distributions (`seed = 20261030`, pairing education and education-num).
  - Fixed-byte-length synthetic records (128 B, 1 KiB, 4 KiB) for Section 6.3 commitment construction are deterministically generated with SHAKE256 (`6.3-certification/commitment_length.py`).
- **T1 (Basic Statistics):** Computes record count, mean, and population variance of `age` and `hours_per_week` over Adult records (`N = 1,000; 5,000; 10,000; 48,842`) and synthetic records (`50,000; 100,000`).
- **T2 (Income Classification):** Runs logistic regression inference (108 standardized/one-hot features trained offline on `adult.data` via `6.4-execution/train_adult.py`) over held-out `adult.test` prefixes (`N = 1,000; 5,000; 10,000; 16,281`, `seed = 20261030`), outputting record count and count predicted `>50K`.
- **T3 (Common SVM Training & Prediction, Section 6.6):** Calls a shared C++ LIBSVM 3.23 task (`6.6-comparison/common_svm/svm_task.cpp`, compiled with `-O2 -ffp-contract=off`) performing RBF C-SVC training (`C = 1`, `gamma = 1/108`, `eps = 0.001`, 100 MiB cache, `shrinking = 1`, `probability = 0`) followed by training-set prediction over `N = 5,000; 10,000; 32,561` nested prefixes of `adult.data`, returning summary counts and `rho`.

## 3. Measurement Methodology & Timing Boundaries

- **Repetitions & Ordering:** Off-chain benchmarks run 30 independent fresh-process repetitions per configuration in Sections 6.3 and 6.4, and 12 independent repetitions per configuration in Section 6.6. Run orders are balanced across configurations using fixed-seed Latin / Williams block designs. No observations are dropped for timing variance.
- **Section 6.3 (Data Certification & Reuse):**
  - *Commitment construction:* Timed from in-memory record slices through per-record `crypto/rand` salt generation, leaf hashing, Merkle tree construction, and final `(N, root)` commitment. Excludes file I/O and schema parsing.
  - *Sampling processing:* Timed across RA challenge generation, DO sample/proof response construction, wire JSON encoding/decoding, and RA proof verification (`audit_component_ns`). Excludes human business review, disk I/O, network latency, and chain confirmation.
  - *Reuse comparison (B3):* Both reuse and per-trade re-audit pay commitment construction once (`N = 10,000`, `rho = 5%`, `epsilon = 10^-4`, `m = 180`, budget `Q = 100`, 10 trades).
- **Section 6.4 (Protected Execution):**
  - *C1 (Initialization & Remote Attestation):* 1 warmup + 30 fresh enclaves measured on real SGX hardware with cached DCAP collateral; reports startup-to-ready (including report generation) and DO/DB remote report fetch and strict verification.
  - *C2 (Native vs. SGX Compute):* Same-host comparison (`GOMAXPROCS=4`, `768 MiB` Go memory limit, pre-warmed host page cache for input ciphertext). Timed continuously from reading input ciphertext through decryption/parsing, commitment reconstruction, analysis, HPKE result encryption, and receipt signing.
- **Section 6.5 (On-Chain Cost & Result Delivery):**
  - Measured via actual `gasUsed` from successful receipts under Anvil `1.5.1` (`Osaka` rules), independently replayed with Geth.
  - Normal trade total sums five calls: `registerTrade` (DO), `deposit` (DB), `confirmKey` (DO), `confirmKey` (DB), and `settle` (DO). Contract deployment, `withdraw`, `timeoutRefund`, and counter initialization are reported separately.
  - Fixed-rate USD estimates use the Etherscan daily mean over 2025-11-01 to 2026-10-31 (`0.9364 Gwei` and `$2,378.61/ETH`): `gas * 0.9364e-9 * 2378.61`.
- **Section 6.6 (Controlled Three-Way Comparison):**
  - All three systems execute the same C++ LIBSVM 3.23 task on the same SGX host in non-debug hardware mode, retaining each system's own input and output protection workflow:
    - *Ours:* ciphertext read, decryption/parsing, commitment reconstruction, common SVM task, HPKE result encryption, receipt signing.
    - *PrivacyGuard:* ciphertext/tag read, SDK decryption, common SVM task, fresh result key generation, result encryption, ciphertext/key hashing, delivery packet protection.
    - *VDDPI:* Gramine encrypted cache read, usage-condition check and counter decrement, common SVM task, output encoding, TLS record protection via `MemoryBIO` (cache persistence/deletion executes after the timing endpoint and is verified separately).
  - To isolate framework and protection differences from divergent math-library `exp()` implementations, all three systems link the same Intel SGX SDK `2.27.100.1` `e_exp.o` object (symbol renamed to `work2_probe_exp`) and record runtime machine-code fingerprints.

## 4. Mapping to Paper Figures and Tables

| Paper Artifact | Experimental Module | Archived Raw Batch (Companion Release / Zenodo) | Summary Snapshot in Repo |
|---|---|---|---|
| Figure 3(a) & 3(b), Section 6.3 reuse metrics | [6.3-certification/](6.3-certification/README.md) | `commitment-length-20261113`, `admission-sampling-scaling-20261113`, `admission-certification-20261030` | `results/paper-snapshots/6.3-certification/` |
| Table III (C1) & Figure 4 (C2) | [6.4-execution/](6.4-execution/README.md) | `execution-final-20261031` | `results/paper-snapshots/6.4-execution/paper-summary.json` |
| Table IV (D1) & Figure 5 (D2) | [6.5-chain/](6.5-chain/README.md) | `osaka-gas-20261103`, `gas-price-20261103` | `results/paper-snapshots/6.5-chain/` |
| Table V (E1 common-`exp` comparison) | [6.6-comparison/](6.6-comparison/README.md) | `svm-common-exp-scaling-20261121` (5k, 10k) + `svm-threeway-exp-20261115` (32,561) | `results/paper-snapshots/6.6-comparison/paper-values.json` |

## 5. Verification Scope (Local Native vs. SGX Hardware)

- **Locally verifiable without SGX:** Solidity contract tests (`forge test`), Go unit & Anvil integration tests (`bash prototype/test.sh`), native end-to-end two-trade demo (`python3 prototype/demo.py`), Python unit tests (`6.3-certification/` and `6.4-execution/`), Section 6.3 off-chain benchmarks, Section 6.5 local Osaka gas runs, and offline verification/plotting scripts (plotting requires `matplotlib`) once the companion raw evidence archive is downloaded.
- **Requires Linux Intel SGX hardware:** EGo `1.9.0` enclave signing and DCAP attestation (`prototype/build.py sgx`, `prototype/sgx_smoke.sh`), Section 6.4 SGX runs, and Section 6.6 three-way SGX runs. Native tests confirm functional and offline verification correctness, not SGX hardware performance.
