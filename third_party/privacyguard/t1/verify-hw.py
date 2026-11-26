#!/usr/bin/env python3
"""Static signature/interface checks for the T1 build. Never load the enclave."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

work=Path('/work/CEE');out=Path('/evidence')
manifest=json.loads((out/'source-manifest.json').read_text());benchmark=manifest['flavor']=='benchmark'
def run(*args):return subprocess.check_output(args,cwd=work,text=True)
def require(ok,why):
 if not ok:raise RuntimeError(why)
dump=(out/'enclave-dump.txt').read_text()
def scalar(name):
 m=re.search(re.escape('metadata->'+name)+r': (0x[0-9a-fA-F]+)',dump);require(m is not None,name);return int(m[1],16)
def array(name,n):
 m=re.search(re.escape('metadata->'+name)+r':\n((?:0x[0-9a-fA-F]{2}\s+)+)',dump);require(m is not None,name)
 b=bytes(int(x,16) for x in re.findall(r'0x([0-9a-fA-F]{2})',m[1]));require(len(b)==n,name);return b
require(not scalar('attributes.flags')&2,'DEBUG metadata')
require(not scalar('enclave_css.body.attributes.flags')&2 and scalar('enclave_css.body.attribute_mask.flags')&2,'DEBUG allowed')
modulus=array('enclave_css.key.modulus',384);sig=array('enclave_css.key.signature',384)[::-1]
require(int.from_bytes(array('enclave_css.key.exponent',4),'little')==3,'RSA exponent')
public=run('openssl','rsa','-pubin','-in',str(out/'signing-public.pem'),'-noout','-modulus').strip().split('=')[1]
require(int(public,16)==int.from_bytes(modulus,'little'),'signing key')
(out/'signature.bin').write_bytes(sig)
require((out/'signing-data.bin').stat().st_size==256,'signed data size')
verification=run('openssl','dgst','-sha256','-verify',str(out/'signing-public.pem'),'-signature',str(out/'signature.bin'),str(out/'signing-data.bin'))
require(verification.strip()=='Verified OK','RSA signature');(out/'signature-verification.txt').write_text(verification)
symbols=run('nm','--defined-only','isv_enclave.so')
for name in ['ECALL_compute_task1','ECALL_get_K_result_hashes','g_ecall_table','enclave_entry']:
 require(re.search(r'\b'+name+r'$',symbols,re.M),name)
require(bool(re.search(r' [tT] ECALL_prepare_test_sessions$',symbols,re.M))==benchmark,'test setter isolation')
require(not re.search(r'\bprintf$',symbols,re.M),'conflicting printf wrapper remains')
undefined=run('nm','-u','isv_enclave.so');require(all(' '.join(x.split())=='w _Z9pcl_entryPvS_' for x in undefined.splitlines()),'unresolved enclave symbol')
elf=run('readelf','-d','isv_enclave.so');require('Shared library:' not in elf,'enclave dynamic dependency')
host=run('readelf','-d','app');require('libsgx_urts.so' in host and '_sim' not in host,'hardware host runtime')
(out/'host-dynamic.txt').write_text(host);(out/'undefined.txt').write_text(undefined)
summary=dict(flavor=manifest['flavor'],static_verification_passed=True,hardware_execution_tested=False,remote_attestation_tested=False,
 signed_debug_allowed=False,rsa_signature_verified=True,test_session_injection_present=benchmark,
 mrenclave=array('enclave_css.body.enclave_hash.m',32).hex(),mrsigner=hashlib.sha256(modulus).hexdigest())
(out/'verification.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
