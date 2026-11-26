# Paper Summary Snapshots

This directory contains lightweight, read-only summary snapshots of the published experimental values reported in Sections 6.3--6.6:

- `6.3-certification/`: summary tables for commitment construction (`commitment-length-summary.csv`), sampling scaling (`admission-sampling-scaling-summary.csv`), Adult reference & 10-trade reuse (`admission-certification-summary.csv`, `certification-summary.json`).
- `6.4-execution/paper-summary.json`: C1 attestation means (Table III) and C2 Native vs. SGX means and phase breakdowns (Figure 4).
- `6.5-chain/`: Osaka gas summary (`osaka-summary.json`, Table IV & Figure 5) and Etherscan 1-year gas/ETH price summary (`gas-price-summary.json`).
- `6.6-comparison/paper-values.json`: three-size common-`exp` SVM means and relative overheads across PrivacyGuard, VDDPI, and our prototype (Table V).

These snapshots are provided for quick inspection of reported numbers. Full raw observation logs, transaction receipts, and SGX hardware evidence required to re-verify raw observations and regenerate publication figures will be published in the companion Release / Zenodo archive.
