#!/usr/bin/env python3
"""Native CLI smoke test: one manual audit decision, two trades, one certificate.

This uses separate actor directories and a TLS worker, but is not SGX isolation.
All accounts and data are generated solely for this local demonstration.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def put(path, data):
    with path.open("x") as file:
        json.dump(data, file, indent=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build/native")
    parser.add_argument("--keep", action="store_true", help="retain generated demo files under tmp/")
    args = parser.parse_args()
    build = args.build.resolve()
    binary, enclave = build / "client", build / "enclave"
    if not binary.is_file() or not enclave.is_file():
        parser.error("build the native executables first: python3 prototype/build.py native")
    os.umask(0o077)
    (ROOT / "tmp").mkdir(exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="demo-", dir=ROOT / "tmp"))
    for name in ("ra", "do", "db", "host", "public"):
        (root / name).mkdir()
    processes, logs = [], []
    success = False
    rpc_url = f"http://127.0.0.1:{free_port()}"

    def rpc(method, params=None):
        request = urllib.request.Request(rpc_url, json.dumps({"jsonrpc": "2.0", "id": 1,
            "method": method, "params": params or []}).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    def start(command, logfile):
        log = logfile.open("x")
        logs.append(log)
        process = subprocess.Popen([str(x) for x in command], stdout=log, stderr=log)
        processes.append(process)
        return process

    def command(action, role=None, **flags):
        cmd = [str(binary), action]
        if role:
            cmd += ["-config", str(root / role / "config.json")]
        for key, value in flags.items():
            cmd += ["-" + key.replace("_", "-"), str(value)]
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
        if result.returncode:
            raise RuntimeError(f"{action} failed: {result.stderr.strip()}")
        return result.stdout.strip()

    try:
        node = start(["anvil", "--silent", "--host", "127.0.0.1", "--port", rpc_url.rsplit(":", 1)[1],
                      "--chain-id", "31337"], root / "host/anvil.log")
        for _ in range(100):
            if node.poll() is not None:
                raise RuntimeError("anvil failed to start")
            try:
                rpc("eth_chainId")
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("anvil not ready")
        addresses = {}
        chain = {"rpc": rpc_url, "chain_id": 31337, "contract": "0x" + "00" * 20,
                 "code_hash": "0x" + "00" * 32, "rpc_spki_sha256": "", "development": True}
        for role in ("ra", "do", "db"):
            addresses[role] = command("keygen", output=root / role / "account.key")
            rpc("anvil_setBalance", [addresses[role], hex(10**20)])
            put(root / role / "config.json", {"chain": chain, "account_key": str(root / role / "account.key")})
        chain_path = root / "public/chain.json"
        command("deploy", "ra", input=ROOT / "contracts/out/TSC.sol/TSC.json", output=chain_path)
        chain = json.loads(chain_path.read_text())
        for role in ("ra", "do", "db"):
            cfg = {"chain": chain, "account_key": str(root / role / "account.key")}
            (root / role / "config.json").write_text(json.dumps(cfg))
        now = int(rpc("eth_getBlockByNumber", ["latest", False])["timestamp"], 16)
        put(root / "do/records.json", [{"id": str(i), "features": [i, 1]} for i in range(101)])
        put(root / "public/description.json", {"version": "demo-v1", "source": "synthetic fixture",
            "batch": "demo-batch-1", "format": "work2.score-record.v1", "records": 101,
            "summary": "Functional test only, no business authenticity claim", "selection": "all generated records"})
        put(root / "public/policy.json", {"rho": 0.1, "epsilon": 0.01, "max_challenges": 2,
            "material_deadline": now + 3600, "audit_deadline": now + 7200,
            "business_rules": "Manual operator decision; this demo uses a controlled fixture."})
        application, dataset = root / "public/application.json", root / "do/dataset.json"
        challenge, response = root / "public/challenge.json", root / "ra/response.json"
        command("prepare", "do", input=root / "do/records.json", description=root / "public/description.json",
                policy=root / "public/policy.json", application=application, dataset=dataset)
        aid = command("audit-open", "ra", application=application, batch="demo-batch-1")
        command("audit-challenge", "ra", application=application, id=aid, output=challenge)
        command("audit-respond", "do", application=application, challenge=challenge, dataset=dataset, output=response)
        put(root / "ra/decision.json", {"accepted": True, "received_at": now,
                                       "evidence_reference": "demo operator accepts known synthetic fixture"})
        did = command("audit-decide", "ra", application=application, challenge=challenge,
                      response=response, input=root / "ra/decision.json")
        print(f"Native demo: audit {aid}, certificate {did}; manual decision fixture accepted.")
        manifest = json.loads((build / "manifest.json").read_text())
        for iteration, threshold in enumerate((10, 150), start=1):
            agreement = root / "public" / f"agreement-{iteration}.json"
            put(agreement, {"did": int(did), "owner": addresses["do"], "buyer": addresses["db"],
                "source_hash": manifest["source_hash"],
                "measurement": "0x" + hashlib.sha256(enclave.read_bytes()).hexdigest(),
                "price_wei": "1000000", "duration_seconds": 600})
            tid = command("trade-register", "do", input=agreement)
            command("trade-check", "db", input=agreement, id=tid)
            command("deposit", "db", input=agreement, id=tid)
            cipher, aeskey = root / "host" / f"input-{tid}.bin", root / "do" / f"aes-{tid}.key"
            command("encrypt-input", "do", dataset=dataset, id=tid, secret_file=aeskey, output=cipher)
            port = free_port()
            certificate = root / "public" / f"worker-{tid}.pem"
            worker = start([enclave, "-tid", tid, "-input", cipher, "-listen", f"127.0.0.1:{port}",
                            "-dev-config", chain_path, "-dev-cert-out", certificate], root / "host" / f"worker-{tid}.log")
            for _ in range(100):
                if worker.poll() is not None:
                    raise RuntimeError("native worker failed to start")
                if certificate.exists():
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        pass
                time.sleep(0.05)
            else:
                raise RuntimeError("worker not ready")
            for role in ("do", "db"):
                cfg = {"chain": chain, "account_key": str(root / role / "account.key"),
                       "worker_url": f"https://127.0.0.1:{port}", "development_certificate": str(certificate)}
                (root / role / "config.json").write_text(json.dumps(cfg))
                command("confirm-key", role, id=tid)
            parameters, result_key = root / "db" / f"parameters-{tid}.json", root / "db" / f"result-{tid}.key"
            put(parameters, {"weights": [1, 2], "bias": 0, "threshold": threshold})
            command("db-input", "db", id=tid, parameters=parameters, secret_file=result_key)
            command("do-input", "do", id=tid, secret_file=aeskey)
            execution = root / "do" / f"execution-{tid}.json"
            command("execute", "do", id=tid, output=execution)
            command("settle", "do", id=tid, input=execution, margin=30)
            output = root / "db" / f"result-{tid}.json"
            command("decrypt", "db", id=tid, secret_file=result_key, output=output)
            actual = json.loads(output.read_text())
            expected = {"count": 101, "above_threshold": sum(i + 2 > threshold for i in range(101))}
            if actual != expected:
                raise RuntimeError(f"incorrect decrypted result: {actual}")
            print(f"Trade {tid}: reused certificate {did}, settled, decrypted result {actual}.")
            worker.terminate()
            worker.wait(timeout=5)
        command("withdraw", "do")
        print("DO withdrawal succeeded. Both CLI executions matched independent expected results.")
        success = True
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log in logs:
            log.close()
        if success and not args.keep:
            shutil.rmtree(root)
        else:
            print(f"Demo files retained: {root}")


if __name__ == "__main__":
    main()
