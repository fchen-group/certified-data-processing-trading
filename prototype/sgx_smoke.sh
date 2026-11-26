#!/usr/bin/env bash
# Hardware environment acceptance only; this does not run the trading protocol.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
export PATH="/opt/ego/bin:/usr/local/go/bin:$PATH"
export GOTOOLCHAIN=local GOWORK=off GOFLAGS=
unset OE_SIMULATION OE_DEBUG
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]]
[[ $(dpkg-query -W -f='${Version}' ego) == 1.9.0 ]]
[[ $(ego-go version) == *'go1.26.1 '* ]]
[[ $(GOTOOLCHAIN=go1.26.1 go version) == *'go1.26.1 '* ]]
[[ -r /dev/sgx_enclave && -w /dev/sgx_enclave ]]
mkdir -p build
OUT=$(mktemp -d "$ROOT/build/sgx-smoke.XXXXXX")
printf 'Build and evidence directory: %s\n' "$OUT"
exec > >(tee "$OUT/run.log") 2>&1
sha256sum go.mod go.sum diagnostics/sgx/attester/main.go diagnostics/sgx/verifier/main.go \
  diagnostics/sgx/enclave.json prototype/sgx_smoke.sh > "$OUT/source-SHA256SUMS"
ego-go build -mod=readonly -trimpath -buildvcs=false -tags=ego -o "$OUT/attester" ./diagnostics/sgx/attester
GOTOOLCHAIN=go1.26.1 CGO_CFLAGS=-I/opt/ego/include CGO_LDFLAGS='-L/opt/ego/lib -Wl,-rpath,/opt/ego/lib' \
  go build -mod=readonly -trimpath -buildvcs=false -tags=dcap -o "$OUT/verifier" ./diagnostics/sgx/verifier
cp diagnostics/sgx/enclave.json "$OUT/enclave.json"
cd "$OUT"
ego sign enclave.json
chmod 600 signing-key.pem
ego uniqueid attester > mrenclave.txt
python3 -c 'import secrets; print(secrets.token_hex(32))' > nonce.txt
ego run attester -nonce "$(cat nonce.txt)" > attester.log
python3 - <<'PY'
import json
from pathlib import Path
reports = []
for line in Path('attester.log').read_text().splitlines():
    if line.startswith('{"report":'):
        reports.append(json.loads(line))
if len(reports) != 1:
    raise SystemExit('expected exactly one enclave report')
Path('report.json').write_text(json.dumps(reports[0]) + '\n')
print('Hardware enclave returned result:', reports[0]['result'])
PY
if ./verifier -report report.json -measurement "$(cat mrenclave.txt)" -nonce "$(cat nonce.txt)" | tee verification.json; then
  VERIFY_STATUS=0
else
  VERIFY_STATUS=$?
fi
printf '%s\n' "$VERIFY_STATUS" > verification-exit.txt
sha256sum attester verifier enclave.json mrenclave.txt nonce.txt report.json verification.json > SHA256SUMS
if (( VERIFY_STATUS != 0 )); then
  printf 'SGX_SMOKE_FAIL: strict attestation verification failed; evidence retained.\n'
  exit "$VERIFY_STATUS"
fi
printf 'SGX_SMOKE_PASS\n'
