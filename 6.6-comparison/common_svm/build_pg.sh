#!/bin/bash
# Reference Linux SGX container build script for the PrivacyGuard common-exp SVM binary.
# Set BUILD_DIR and RESULT_DIR before running inside the Intel SGX SDK 2.27 build container.
set -euo pipefail
B="${BUILD_DIR:?set BUILD_DIR to the prepared PrivacyGuard SVM build directory}"
E="${RESULT_DIR:?set RESULT_DIR to the output directory containing static/probe_exp.o}"
cd "$B/pg-source"
make clean
make SGX_MODE=HW SGX_DEBUG=0 PG_BENCHMARK=1 .config_HW_RELEASE_x64
make SGX_MODE=HW SGX_DEBUG=0 PG_BENCHMARK=1 isv_app/isv_enclave_u.c isv_enclave/isv_enclave_t.c
cp "$E/static/probe_exp.o" "$B/common/probe_exp.o"
make SGX_MODE=HW SGX_DEBUG=0 PG_BENCHMARK=1 -j2
/opt/intel/sgxsdk/bin/x64/sgx_sign sign -key local-test-signing.pem -enclave isv_enclave.so -out isv_enclave.signed.so -config isv_enclave/isv_enclave.config.xml
/opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave isv_enclave.signed.so -dumpfile "$E/local/pg-dump.txt"
cp app isv_enclave.signed.so "$B/bundle/baseline/pg-svm/"
cp isv_enclave.so "$E/static/privacyguard-enclave.so"
nm -u isv_enclave.so > "$E/local/pg-undefined.txt"
nm -S isv_enclave.so > "$E/local/pg-symbols.txt"
objdump -d --disassemble=exp isv_enclave.so > "$E/static/pg-native-exp.txt"
objdump -d --disassemble=work2_probe_exp isv_enclave.so > "$E/static/pg-common-exp.txt"
g++ --version > "$E/local/compiler.txt"
