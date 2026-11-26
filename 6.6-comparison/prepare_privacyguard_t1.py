#!/usr/bin/env python3
"""Replay the immutable author source + compatibility/T1 patches in a NEW directory."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parent.parent
PG=ROOT/'third_party/privacyguard'

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--out',type=Path,required=True)
 p.add_argument('--flavor',choices=['production','benchmark'],required=True)
 a=p.parse_args();out=a.out.resolve()
 if out.exists():raise SystemExit('refusing to overwrite existing source')
 subprocess.run([sys.executable,str(ROOT/'6.6-comparison/prepare_privacyguard_source.py'),'--extract-to',str(out)],check=True)
 for patch in ['compat-sdk227.patch','t1-adapter.patch']:
  subprocess.run(['patch','--batch','--fuzz=0','-p1','-d',str(out),'-i',str(PG/patch)],check=True)
 files={'adult_t1.hpp':'isv_enclave','t1_core.inc':'isv_enclave','t1_io.h':'isv_app','t1_io.cpp':'isv_app','bench.cpp':'isv_app'}
 for name,folder in files.items():shutil.copyfile(PG/'t1'/name,out/'CEE'/folder/name)
 if a.flavor=='benchmark':
  path=out/'CEE/isv_enclave/isv_enclave.edl';s=path.read_text()
  if s.count('    trusted {')!=1 or s.count('    untrusted {')!=1:raise RuntimeError('unexpected EDL')
  s=s.replace('    trusted {','    trusted {\n        public sgx_status_t ECALL_prepare_test_sessions([in,size=16] uint8_t *ida, [in,size=16] uint8_t *dc);',1)
  s=s.replace('    untrusted {','    untrusted {\n        void OCALL_processing_end();',1)
  path.write_text(s)
 manifest={'flavor':a.flavor,'upstream_commit':'1ef665fca9dadf00bc0bb363842ab471a747ab0a','inputs':{}}
 for f in [PG/'compat-sdk227.patch',PG/'t1-adapter.patch',*sorted((PG/'t1').glob('*')),Path(__file__)]:
  if f.is_file():manifest['inputs'][str(f.relative_to(ROOT))]=hashlib.sha256(f.read_bytes()).hexdigest()
 manifest['edl_sha256']=hashlib.sha256((out/'CEE/isv_enclave/isv_enclave.edl').read_bytes()).hexdigest()
 (out/'t1-source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(f'Prepared {a.flavor} source at {out}')
