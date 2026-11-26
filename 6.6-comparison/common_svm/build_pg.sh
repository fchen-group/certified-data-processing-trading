#!/bin/bash
# Reference Linux SGX container build script for the PrivacyGuard common-exp SVM binary.
# Set PG_SRC_DIR (e.g., tmp/pg-svm/CEE) and RESULT_DIR (containing static/probe_exp.o)
# before running inside the Intel SGX SDK 2.27 build container.
set -euo pipefail
abs_dir() { (cd -- "$1" && pwd); }
SRC="$(abs_dir "${PG_SRC_DIR:?set PG_SRC_DIR to the prepared PrivacyGuard CEE directory (e.g., tmp/pg-svm/CEE)}")"
mkdir -p "${RESULT_DIR:?set RESULT_DIR to the output directory containing static/probe_exp.o}"
E="$(abs_dir "$RESULT_DIR")"
if [[ -n "${SGX_SIGN_KEY:-}" ]]; then
  SIGN_KEY="$(abs_dir "$(dirname -- "$SGX_SIGN_KEY")")/$(basename -- "$SGX_SIGN_KEY")"
else
  SIGN_KEY="local-test-signing.pem"
fi
PARENT="$(dirname "$SRC")"
mkdir -p "$PARENT/common" "$E/local" "$E/static" "$E/pg-svm"
cd "$SRC"
make clean
make SGX_MODE=HW SGX_DEBUG=0 PG_BENCHMARK=1 .config_HW_RELEASE_x64
make SGX_MODE=HW SGX_DEBUG=0 PG_BENCHMARK=1 isv_app/isv_enclave_u.c isv_enclave/isv_enclave_t.c
cp "$E/static/probe_exp.o" "$PARENT/common/probe_exp.o"
make SGX_MODE=HW SGX_DEBUG=0 PG_BENCHMARK=1 -j2
/opt/intel/sgxsdk/bin/x64/sgx_sign sign -key "$SIGN_KEY" -enclave isv_enclave.so -out isv_enclave.signed.so -config isv_enclave/isv_enclave.config.xml
/opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave isv_enclave.signed.so -dumpfile "$E/local/pg-dump.txt"
cp app isv_enclave.signed.so "$E/pg-svm/"
cp isv_enclave.so "$E/static/privacyguard-enclave.so"
nm -u isv_enclave.so > "$E/local/pg-undefined.txt"
nm -S isv_enclave.so > "$E/local/pg-symbols.txt"
objdump -d --disassemble=exp isv_enclave.so > "$E/static/pg-native-exp.txt"
objdump -d --disassemble=work2_probe_exp isv_enclave.so > "$E/static/pg-common-exp.txt"
g++ --version > "$E/local/compiler.txt"
