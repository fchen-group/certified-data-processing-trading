# Paper Summary Snapshots

This directory contains lightweight, read-only summary snapshots of the published experimental values reported in Sections 6.3--6.6:

- `6.3-certification/`: summary tables for commitment construction (`commitment-length-summary.csv`), sampling scaling (`admission-sampling-scaling-summary.csv`), Adult reference & 10-trade reuse (`admission-certification-summary.csv`, `certification-summary.json`).
- `6.4-execution/paper-summary.json`: C1 attestation means (Table III) and C2 Native vs. SGX means and phase breakdowns (Figure 4).
- `6.5-chain/`: Osaka gas summary (`osaka-summary.json`, Table IV & Figure 5) and Etherscan 1-year gas/ETH price summary (`gas-price-summary.json`).
- `6.6-comparison/paper-values.json`: three-size common-`exp` SVM means and relative overheads across PrivacyGuard, VDDPI, and our prototype (Table V).

These snapshots record the published summary values reported in the paper. Large raw execution logs, transaction receipt dumps, and SGX hardware evidence bundles are not stored in Git; the scripts in `6.3-certification/` through `6.6-comparison/` reproduce the measurements and validate or plot generated outputs.
