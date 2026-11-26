# Section 6.5: On-Chain Cost and Result Delivery

This module measures per-operation gas costs for normal trades, withdrawals, timeout refunds, and contract deployment (D1, Table IV), as well as the scaling of total trade gas with result ciphertext size from 128 B to 64 KiB plaintext (D2, Figure 5).

## Contents

- `tradegasbench/`: Go driver executing the 256-transaction D1/D2/refund matrix against `TSC.sol`, verifying state transitions, event logs, and HPKE result decryption (`configs/trade-gas.json`, `data/trade-gas/`).
- `summarize_trade_gas.py`: offline receipt auditor that recomputes all per-operation and five-call gas statistics and verifies Osaka formal evidence manifests.
- `plot_trade_gas.py`: Figure 5 stacked bar chart generator (`result_delivery_cost.pdf` + `provenance.json`; requires `matplotlib`).

## Running Local Verification Tests

The full 256-transaction trade-gas CLI and tamper-rejection checks are exercised by the Go integration suite:

```sh
go test -v -race -tags integration -run TestTradeGas ./integration/...
```

## Offline Re-Verification and Plotting (Table IV & Figure 5)

Given the extracted `osaka-gas-20261103` raw archive:

```sh
# Audit all 256 receipts and verify Geth independent replay manifest
python3 6.5-chain/summarize_trade_gas.py <path/to/osaka-gas-20261103>/trade

# Render Figure 5 (Result delivery cost)
python3 6.5-chain/plot_trade_gas.py \
  --run <path/to/osaka-gas-20261103>/trade \
  --out tmp/fig5-output
```

Published summary values and the Etherscan gas/ETH price window (2025-11-01 to 2026-10-31) are also available in `results/paper-snapshots/6.5-chain/`.
