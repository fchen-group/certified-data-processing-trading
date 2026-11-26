#!/usr/bin/env bash
# Compile and inspect only. Do not run the upstream app or load the enclave.
set -euo pipefail
cd /work/CEE
{
    cat /etc/os-release
    uname -m
    gcc --version
    g++ --version
    ld --version
    make --version
    openssl version
    dpkg-query -W 'libsgx-*' libprotobuf23 libc6 libstdc++6 libssl-dev
    dpkg --audit
    apt-get check
} > /evidence/environment.txt 2>&1

# The upstream archive includes generated files. Never reuse them.
make clean
make -Bn SGX_MODE=HW SGX_DEBUG=0 SGX_ARCH=x64 > /evidence/build-commands.txt
make SGX_MODE=HW SGX_DEBUG=0 SGX_ARCH=x64 -j1

# A fresh local test key is used, not the author's committed sample key.
umask 077
openssl genrsa -3 -out buildcheck-key.pem 3072
openssl rsa -in buildcheck-key.pem -pubout -out /evidence/signing-public.pem
sgx_sign sign -key buildcheck-key.pem -enclave isv_enclave.so \
    -out isv_enclave.signed.so -config isv_enclave/isv_enclave.config.xml
sgx_sign dump -enclave isv_enclave.signed.so \
    -dumpfile /evidence/enclave-dump.txt -cssfile /evidence/enclave-css.bin
sgx_sign gendata -enclave isv_enclave.so -config isv_enclave/isv_enclave.config.xml \
    -out /evidence/signing-data.bin
python3 /runner/verify-build.py
