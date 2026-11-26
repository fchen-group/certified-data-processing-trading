#!/usr/bin/env bash
# /work is a fresh source prepared with prepare_privacyguard_t1.py.
# /evidence is a fresh evidence directory. Compile/sign only, no enclave loading.
set -euo pipefail
cd /work/CEE
flavor=$(python3 -c 'import json; print(json.load(open("/work/t1-source-manifest.json"))["flavor"])')
benchmark=0
if [[ "$flavor" == benchmark ]]; then benchmark=1; fi
make clean
make SGX_MODE=HW SGX_DEBUG=0 PG_BENCHMARK="$benchmark" -j1
umask 077
openssl genrsa -3 -out local-test-signing.pem 3072
sgx_sign sign -key local-test-signing.pem -enclave isv_enclave.so \
 -out isv_enclave.signed.so -config isv_enclave/isv_enclave.config.xml
sgx_sign dump -enclave isv_enclave.signed.so -dumpfile /evidence/enclave-dump.txt -cssfile /evidence/enclave-css.bin
openssl rsa -in local-test-signing.pem -pubout -out /evidence/signing-public.pem
nm isv_enclave.so > /evidence/symbols.txt
if [[ "$benchmark" == 1 ]]; then
 grep -q ' [tT] ECALL_prepare_test_sessions$' /evidence/symbols.txt
else
 if grep -q 'ECALL_prepare_test_sessions' /evidence/symbols.txt; then exit 1; fi
fi
sha256sum app isv_enclave.so isv_enclave.signed.so > /evidence/artifact-sha256.txt
cp /work/t1-source-manifest.json /evidence/source-manifest.json
{
 g++ --version
 uname -m
 dpkg-query -W 'libsgx-*' libprotobuf23
} > /evidence/environment.txt
sgx_sign gendata -enclave isv_enclave.so -config isv_enclave/isv_enclave.config.xml \
 -out /evidence/signing-data.bin
python3 /t1/verify-hw.py
