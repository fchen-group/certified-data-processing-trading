"""Extract and symbol-rename e_exp.o from Intel SGX SDK 2.27 libsgx_tstdc.a."""
import os
from pathlib import Path
import subprocess, hashlib, json, shutil, tempfile

E = Path(os.environ.get('RESULT_DIR', 'results/common-exp'))
B = Path(os.environ.get('BUILD_DIR', 'build/common-exp'))
archive = Path(os.environ.get('SGX_TSTDC_ARCHIVE', '/opt/intel/sgxsdk/lib64/libsgx_tstdc.a'))
(E / 'static').mkdir(parents=True, exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory() as d:
    subprocess.run(['ar','x',str(archive),'e_exp.o'],cwd=d,check=True)
    obj=Path(d)/'e_exp.o'
    undefined=subprocess.check_output(['nm','-u',str(obj)],text=True)
    if undefined.strip():
        raise RuntimeError(f'unexpected undefined symbols in e_exp.o: {undefined}')
    shutil.copy2(obj,E/'static/sdk-e_exp.o')
    subprocess.run(['objcopy','--redefine-sym','exp=work2_probe_exp',str(obj),str(E/'static/probe_exp.o')],check=True)
    for folder in (B/'common',B/'work2-source/pkg/svmpilot'):
        if folder.exists():
            shutil.copy2(E/'static/probe_exp.o',folder/'probe_exp.o')
    (E/'static/sdk-exp-disassembly.txt').write_text(subprocess.check_output(['objdump','-dr',str(obj)],text=True))
    (E/'static/exp-object-origin.json').write_text(json.dumps(dict(archive=str(archive),archive_sha256=sha(archive),member='e_exp.o',original_sha256=sha(obj),renamed_sha256=sha(E/'static/probe_exp.o'),undefined_symbols=undefined),indent=2)+'\n')
print('isolated exp object extracted; no undefined dependencies')
