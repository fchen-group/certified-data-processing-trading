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

## Receipt Auditing and Plotting (Table IV & Figure 5)

Given a completed `tradegasbench` run directory:

```sh
# Audit all 256 receipts (and Osaka independent-replay manifest when present)
python3 6.5-chain/summarize_trade_gas.py <path/to/trade-run-dir>

# Render Figure 5 (Trade gas cost versus result size)
python3 6.5-chain/plot_trade_gas.py \
  --run <path/to/trade-run-dir> \
  --out tmp/fig5-output
```

Published summary values and the Etherscan gas/ETH price window (2025-11-01 to 2026-10-31) are recorded in `results/paper-snapshots/6.5-chain/`.
