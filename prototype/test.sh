#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=go1.26.1 GOWORK=off
go version
forge test --offline --root contracts
go test -race -tags integration ./pkg/... ./prototype/... ./6.3-certification/... ./6.4-execution/... ./6.5-chain/... ./6.6-comparison/... ./integration/...
