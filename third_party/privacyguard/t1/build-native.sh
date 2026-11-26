#!/usr/bin/env bash
# CWD: prepared benchmark CEE with edger8r-generated headers.
set -euo pipefail
SDK=${SGX_SDK:-/opt/intel/sgxsdk}
g++ -std=c++11 -O1 -g -ffp-contract=off -fno-omit-frame-pointer \
    -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra \
    -Werror=return-type -Werror=builtin-declaration-mismatch -DPG_NATIVE -DPG_BENCHMARK \
    -I"$SDK/include" -Iisv_app -Iisv_enclave -Iisv_enclave/include -Iservice_provider -I/t1 \
    /t1/native_trusted.cpp /t1/native_bridge.cpp /t1/native_crypto.cpp \
    isv_enclave/enclave_keccak.cpp isv_app/t1_io.cpp isv_app/bench.cpp \
    -lcrypto -o pgbench-native
