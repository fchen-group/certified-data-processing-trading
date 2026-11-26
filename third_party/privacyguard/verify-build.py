#!/usr/bin/env python3
"""Static build/signature checks only; deliberately never run the CEE app."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

work = Path('/work/CEE')
out = Path('/evidence')


def command(*args):
    return subprocess.check_output(args, text=True, cwd=work)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


dump = (out / 'enclave-dump.txt').read_text()


def scalar(name):
    found = re.search(re.escape('metadata->' + name) + r': (0x[0-9a-fA-F]+)', dump)
    require(found is not None, 'missing metadata field: ' + name)
    return int(found.group(1), 16)


def byte_array(name, length):
    found = re.search(re.escape('metadata->' + name) + r':\n((?:0x[0-9a-fA-F]{2}\s+)+)', dump)
    require(found is not None, 'missing metadata bytes: ' + name)
    data = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', found.group(1)))
    require(len(data) == length, 'unexpected length: ' + name)
    return data


flags = scalar('enclave_css.body.attributes.flags')
mask = scalar('enclave_css.body.attribute_mask.flags')
require(flags & 2 == 0 and mask & 2 != 0, 'signature must disallow DEBUG')
require(scalar('attributes.flags') & 2 == 0, 'metadata unexpectedly enables DEBUG')
measurement = byte_array('enclave_css.body.enclave_hash.m', 32).hex()
modulus = byte_array('enclave_css.key.modulus', 384)
exponent = byte_array('enclave_css.key.exponent', 4)
require(int.from_bytes(exponent, 'little') == 3, 'expected RSA exponent 3')
public_modulus = command('openssl', 'rsa', '-pubin', '-in', str(out / 'signing-public.pem'),
                         '-noout', '-modulus').strip().split('=', 1)[1]
require(int(public_modulus, 16) == int.from_bytes(modulus, 'little'), 'signing key mismatch')
signature = byte_array('enclave_css.key.signature', 384)[::-1]
(out / 'signature.bin').write_bytes(signature)
require((out / 'signing-data.bin').stat().st_size == 256, 'unexpected signed data size')
verification = command('openssl', 'dgst', '-sha256', '-verify', str(out / 'signing-public.pem'),
                       '-signature', str(out / 'signature.bin'), str(out / 'signing-data.bin'))
(out / 'signature-verification.txt').write_text(verification)
require(verification.strip() == 'Verified OK', 'RSA signature verification failed')

symbols = command('nm', '--defined-only', 'isv_enclave.so')
(out / 'enclave-symbols.txt').write_text(symbols)
for name in ['ECALL_compute_task1', 'ECALL_get_K_result_hashes',
             'sgx_ECALL_compute_task1', 'sgx_ECALL_get_K_result_hashes', 'g_ecall_table', 'enclave_entry']:
    require(re.search(r'\b' + re.escape(name) + r'$', symbols, re.M) is not None, 'missing enclave symbol: ' + name)
undefined = command('nm', '-u', 'isv_enclave.so')
(out / 'enclave-undefined.txt').write_text(undefined)
# The SDK runtime has an optional weak PCL entry when PCL is not linked.
# Reject every other unresolved symbol, including any strong dependency.
weak_optional = {'w _Z9pcl_entryPvS_'}
require(all(' '.join(line.split()) in weak_optional for line in undefined.splitlines()),
        'unexpected undefined enclave symbols')
host_symbols = command('nm', '-C', '--defined-only', 'app')
(out / 'host-symbols.txt').write_text(host_symbols)
for name in ['enclave_compute_task', 'send_K_result_msgs', 'ECALL_compute_task1', 'ECALL_get_K_result_hashes']:
    require(re.search(r'\b' + re.escape(name) + r'$', host_symbols, re.M) is not None,
            'missing host processing symbol: ' + name)

artifacts = {}
for name in ['app', 'libservice_provider.so', 'isv_enclave.so', 'isv_enclave.signed.so',
             'sample_libcrypto/libsample_libcrypto.so']:
    data = (work / name).read_bytes()
    require(data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 little endian: ' + name)
    require(int.from_bytes(data[18:20], 'little') == 62, 'expected x86_64: ' + name)
    dynamic = command('readelf', '-d', name)
    require('sgx_urts_sim' not in dynamic and 'sgx_uae_service_sim' not in dynamic, 'simulation runtime linked')
    (out / (name.replace('/', '_') + '.readelf.txt')).write_text(command('readelf', '-h', name) + dynamic)
    artifacts[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
require('libsgx_urts.so' in (out / 'app.readelf.txt').read_text(), 'host does not link hardware URTS')
require('Shared library:' not in (out / 'isv_enclave.so.readelf.txt').read_text(), 'enclave has dynamic dependencies')
commands = (out / 'build-commands.txt').read_text()
require('-O2' in commands and '-O0' not in commands and '-lsgx_trts_sim' not in commands,
        'incorrect build flags')
summary = {
    'build_check_passed': True, 'hardware_execution_tested': False,
    'remote_attestation_tested': False, 'functional_correctness_tested': False,
    'performance_measured': False, 'sdk': '2.27.100.1', 'mode': 'HW', 'optimization': '-O2',
    'signed_debug_allowed': False, 'mrenclave': measurement,
    'optional_weak_symbols': [line.strip() for line in undefined.splitlines()],
    'mrsigner': hashlib.sha256(modulus).hexdigest(), 'rsa_signature_verified': True,
    'upstream_sample_crypto': 'Prebuilt upstream host-side RA sample library; hashed, linked, not executed or rebuilt',
    'artifacts': artifacts,
}
(out / 'verification.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps({'build_check_passed': True, 'mrenclave': measurement, 'hardware_execution_tested': False}))
