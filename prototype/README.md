# Prototype Entry Points

Start with [client/main.go](client/main.go) at the `prepare` action: DO reads records, generates per-record random salts, constructs the dataset commitment, and writes the private dataset and audit application. Follow the certification flow through `audit-open`, `audit-challenge`, `audit-respond`, and `audit-decide`. For the exact actor-by-actor sequence and file handoffs, see [demo.py](demo.py).

For trade execution, read [enclave/main.go](enclave/main.go), which loads a funded trade and starts the execution service. Trace the execution handler in [server.go](../pkg/worker/server.go) into [compute.go](../pkg/worker/compute.go), and then back to the client `settle` and `decrypt` actions. Atomic on-chain ciphertext delivery and owner payment credit are implemented in `settle` inside [TSC.sol](../contracts/src/TSC.sol).

## Commands

```sh
python3 prototype/build.py native   # Build build/native/client and build/native/enclave
bash prototype/test.sh              # Run Foundry contract tests and Go (-race) unit + integration tests
python3 prototype/demo.py           # Run the local two-trade certificate-reuse demonstration
```
