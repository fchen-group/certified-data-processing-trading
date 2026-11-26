#!/usr/bin/env python3
"""Build in a fresh directory and record exact sources/tool versions.

SGX builds require an installed EGo 1.9.0 Linux environment. The script does not
install system packages or substitute native execution for missing hardware.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=ROOT, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def source_files():
    files = [ROOT / "go.mod", ROOT / "go.sum", ROOT / "contracts/foundry.toml"]
    for folder in ("prototype", "pkg", "contracts/src", "configs", "6.3-certification", "6.4-execution", "6.5-chain"):
        files += [p for p in (ROOT / folder).rglob("*")
                  if p.is_file() and p.suffix in (".go", ".json", ".sol", ".py", ".sh", ".txt")]
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("native", "sgx", "dcap"))
    parser.add_argument("--runtime", type=Path, help="production chain configuration, embedded before SGX build")
    parser.add_argument("--out", type=Path, help="new output directory (must not exist)")
    parser.add_argument("--execution-bench", action="store_true", help="also build the isolated public-fixture compute benchmark")
    args = parser.parse_args()
    if args.execution_bench and args.mode == "dcap":
        parser.error("--execution-bench is supported only for native and sgx builds")
    out = (args.out or ROOT / "build" / args.mode).resolve()
    if out.exists():
        parser.error(f"output already exists: {out}; select a new --out directory")
    env = os.environ.copy()
    # Do not let ambient GOFLAGS silently inject build tags or alter source paths.
    env.update(GOFLAGS="", GOWORK="off", GOTOOLCHAIN="go1.26.1")
    # EGo must use its bundled compiler rather than switch to stock Go.
    ego_env = dict(env, GOTOOLCHAIN="local")
    versions = {"host": platform.platform(), "go": run("go", "version", env=env)}
    runtime = None
    if args.mode in ("sgx", "dcap"):
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            parser.error("SGX/DCAP builds require Linux x86_64 with EGo 1.9.0 installed")
        versions["ego_package"] = run("dpkg-query", "-W", "-f=${Version}", "ego")
        if not re.match(r"^1\.9\.0(?:[-+~]|$)", versions["ego_package"]):
            parser.error("expected the pinned EGo 1.9.0 package")
    if args.mode == "sgx":
        enclave_config = json.loads((ROOT / "configs/enclave.json").read_text())
        if enclave_config["heapSize"] < 1024:
            parser.error("current compiled resource policy requires at least a 1024 MB enclave heap")
        if not args.runtime:
            parser.error("--runtime is required; the repository default deliberately has no trust anchor")
        runtime = json.loads(args.runtime.read_text())
        required = {"rpc", "chain_id", "contract", "code_hash", "rpc_spki_sha256", "development"}
        if set(runtime) != required or runtime["development"] is not False:
            parser.error("provide exactly the production chain configuration fields")
        if not runtime["rpc"].startswith("https://") or runtime["chain_id"] <= 0:
            parser.error("production requires HTTPS and a positive chain ID")
        for name, size in (("contract", 40), ("code_hash", 64)):
            if not re.fullmatch("0x[0-9a-fA-F]{" + str(size) + "}", runtime[name]) or int(runtime[name], 16) == 0:
                parser.error(f"invalid {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", runtime["rpc_spki_sha256"]):
            parser.error("RPC SPKI pin must be 64 lowercase hexadecimal characters")
        versions["ego_go"] = run("ego-go", "version", env=ego_env)
        if "go1.26.1 " not in versions["ego_go"]:
            parser.error("expected EGo 1.9.0's Go 1.26.1 toolchain")
    print(run("forge", "build", "--root", str(ROOT / "contracts")))
    versions["forge"] = run("forge", "--version")
    artifact = json.loads((ROOT / "contracts/out/TSC.sol/TSC.json").read_text())
    # An outdated embedded ABI must never silently accompany a new contract.
    if artifact["abi"] != json.loads((ROOT / "pkg/chain/tsc.abi.json").read_text()):
        parser.error("TSC artifact and embedded ABI differ; update pkg/chain/tsc.abi.json before building")
    out.mkdir(parents=True)
    stage = out / "source"
    for src in source_files():
        target = stage / src.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target)
    if runtime is not None:
        (stage / "pkg/deployment/runtime.json").write_text(json.dumps(runtime, indent=2) + "\n")
    hashes = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(stage.rglob("*")) if p.is_file()}
    source_hash = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    flags = ["build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-buildid="]
    packages = {
        "client": "./prototype/client",
        "enclave": "./prototype/enclave",
        "executionbench": "./6.4-execution/executionbench",
    }
    if args.mode == "native":
        for command in ("client", "enclave") + (("executionbench",) if args.execution_bench else ()):
            run("go", *flags, "-o", str(out / command), packages[command], cwd=stage, env=env)
    elif args.mode == "dcap":
        env["CGO_CFLAGS"] = "-I/opt/ego/include"
        env["CGO_LDFLAGS"] = "-L/opt/ego/lib -Wl,-rpath,/opt/ego/lib"
        run("go", *flags, "-tags=dcap", "-o", str(out / "client"), packages["client"], cwd=stage, env=env)
    else:
        run("ego-go", *flags, "-tags=ego", "-o", str(out / "enclave"), packages["enclave"], cwd=stage, env=ego_env)
        shutil.copyfile(stage / "configs/enclave.json", out / "enclave.json")
        print(run("ego", "sign", "enclave.json", cwd=out))
        measurement = run("ego", "uniqueid", "enclave", cwd=out)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", measurement):
            raise RuntimeError("unexpected ego uniqueid output; do not register this build")
        versions["mrenclave"] = "0x" + measurement.lower()
        os.chmod(out / "signing-key.pem", 0o600)
        if args.execution_bench:
            run("ego-go", *flags, "-tags=ego", "-o", str(out / "executionbench"), packages["executionbench"], cwd=stage, env=ego_env)
            benchmark_config = dict(enclave_config, exe="executionbench")
            (out / "executionbench.json").write_text(json.dumps(benchmark_config, indent=2) + "\n")
            print(run("ego", "sign", "executionbench.json", cwd=out))
            measurement = run("ego", "uniqueid", "executionbench", cwd=out)
            if not re.fullmatch(r"[0-9a-fA-F]{64}", measurement):
                raise RuntimeError("unexpected benchmark ego uniqueid output")
            versions["benchmark_mrenclave"] = "0x" + measurement.lower()
    manifest = {"mode": args.mode, "source_hash": "0x" + source_hash,
                "tools": versions, "files": hashes, "execution_benchmark": args.execution_bench}
    if args.execution_bench:
        manifest["benchmark_sha256"] = hashlib.sha256((out / "executionbench").read_bytes()).hexdigest()
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Build: {out}\nSource hash: 0x{source_hash}")
    if "mrenclave" in versions:
        print("MRENCLAVE: " + versions["mrenclave"])


if __name__ == "__main__":
    main()
