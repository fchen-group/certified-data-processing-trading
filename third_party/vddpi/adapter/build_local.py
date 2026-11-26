#!/usr/bin/env python3
"""Run inside the fixed Linux toolchain; no SGX execution is claimed here."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(args, cwd, log):
    with log.open("wb") as f:
        subprocess.run(args, cwd=str(cwd), stdout=f, stderr=subprocess.STDOUT, check=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("prepared", type=Path)
    p.add_argument("evidence", type=Path)
    args = p.parse_args()
    root, evidence = args.prepared.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    app = root / "app"
    core = root / "common"
    flags = ["-std=c++11", "-O2", "-fPIC", "-shared", "-ffp-contract=off",
             "-Wl,-z,relro,-z,now", "-Wl,--build-id=none"]
    cmd = ["g++"] + flags + ["svm.cpp", "svm_task.cpp", "measurement.cpp", "-o", str(app / "code/libcommon_svm.so")]
    run(cmd, core, evidence / "common-build.log")
    cpython = Path("/opt/Python-3.6.9")
    template = (root / "python.c.template").read_text()
    for flavor, name in (("service", "main.py"), ("benchmark", "bench.py")):
        c = template.replace('#define DP_PROGRAM "./code/main.py"', '#define DP_PROGRAM "./code/{}"'.format(name))
        import re
        c = re.sub(r'#define DP_HASH_VALUE ".*"', '#define DP_HASH_VALUE "{}"'.format(sha(app / "code" / name)), c)
        c = re.sub(r'#define GCP_HASH_VALUE ".*"', '#define GCP_HASH_VALUE "{}"'.format(sha(app / "gen_cert.py")), c)
        (cpython / "Programs/python.c").write_text(c)
        (evidence / ("python-" + flavor + ".c")).write_text(c)
        run(["make", "python", "-j4"], cpython, evidence / (flavor + "-interpreter-build.log"))
        shutil.copy2(cpython / "python", app / ("mypython-" + flavor))
    for name in ("data", "certs"):
        (app / name).mkdir(exist_ok=True)
    meta = {
        "common_compile_command": cmd,
        "compiler": subprocess.check_output(["g++", "--version"], text=True).splitlines()[0],
        "python": subprocess.check_output(["/opt/vddpi-python/bin/python3.6", "--version"], text=True).strip(),
        "gramine": subprocess.check_output(["gramine-sgx", "--version"], text=True).strip(),
        "runtime_freeze": Path("/opt/vddpi-runtime-freeze.txt").read_text().splitlines(),
        "artifacts": {str(f.relative_to(app)): sha(f) for f in [app / "mypython-service", app / "mypython-benchmark", app / "code/libcommon_svm.so"]},
        "hardware_execution": False,
    }
    (evidence / "build.json").write_text(json.dumps(meta, indent=2) + "\n")
    (evidence / "dpkg.txt").write_bytes(subprocess.check_output(["dpkg-query", "-W"]))
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
