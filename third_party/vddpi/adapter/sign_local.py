#!/usr/bin/env python3
"""Render, validate and sign candidate manifests; hardware acceptance is separate."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from graminelibos import Manifest, Sigstruct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("app", type=Path)
    p.add_argument("evidence", type=Path)
    args = p.parse_args()
    app, evidence = args.app.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    os.chdir(app)
    # Local interpreter caches are reproducible artifacts, not trusted source.
    for cache in (app / "code").rglob("__pycache__"):
        shutil.rmtree(cache)
    for name in ("sgx-data", "sgx-certs", "input", "logs"):
        (app / name).mkdir(exist_ok=True)
    key = evidence / "PUBLIC_TEST_signing_key.pem"
    if not key.exists():
        subprocess.run(["gramine-sgx-gen-private-key", str(key)], check=True)
    template = Path(__file__).with_name("sgx.manifest.template").read_text()
    records = {}
    for flavor, script in (("service", "main.py"), ("benchmark", "bench.py")):
        manifest = Manifest.from_template(template, {"flavor": flavor, "script": script})
        manifest.check()
        path = app / (flavor + ".manifest")
        path.write_text(manifest.dumps())
        output = path.with_suffix(".manifest.sgx")
        sigfile = path.with_suffix(".sig")
        command = ["gramine-sgx-sign", "--manifest", str(path), "--output", str(output),
                   "--sigfile", str(sigfile), "--key", str(key), "--date", "2026-11-04"]
        with (evidence / (flavor + "-sign.log")).open("wb") as f:
            subprocess.run(command, stdout=f, stderr=subprocess.STDOUT, check=True)
        signed = Manifest(output.read_text())
        signed.check()
        sig = Sigstruct.from_bytes(sigfile.read_bytes())
        public = rsa.RSAPublicNumbers(sig["exponent"], int.from_bytes(sig["modulus"], "little")).public_key()
        public.verify(sig["signature"][::-1], sig.get_signing_data(), padding.PKCS1v15(), hashes.SHA256())
        assert sig["attribute_flags"] & 2 == 0, "debug enclave is forbidden"
        assert sig["attribute_flags_mask"] & 2, "signature must enforce non-debug"
        assert not signed["sgx"]["debug"]
        trusted = signed["sgx"]["trusted_files"]
        by_uri = {item["uri"].replace("file:./", "file:"): item for item in trusted}
        for name in ("code/libcommon_svm.so", "code/main.py", "code/bench.py", "code/plib.py"):
            assert by_uri["file:" + name]["sha256"] == sha(app / name), name
        records[flavor] = {
            "mrenclave": sig["enclave_hash"].hex(), "flags": sig["attribute_flags"],
            "flags_mask": sig["attribute_flags_mask"], "trusted_file_count": len(trusted),
            "manifest_sha256": sha(path), "signed_manifest_sha256": sha(output),
            "sigstruct_sha256": sha(sigfile), "non_debug": True,
            "rsa_signature_verified": True, "hardware_loaded": False, "encrypted_mounts_tested": False,
        }
    (evidence / "signatures.json").write_text(json.dumps(records, indent=2) + "\n")
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
