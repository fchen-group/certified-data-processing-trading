#!/usr/bin/env python3
"""Additional local checks; no SGX/RA or performance claim."""
import argparse
import hashlib
import json
import ssl
import subprocess
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("app", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    app = args.app.resolve()
    checks = {}

    def reject(flavor, argv, code):
        result = subprocess.run([str(app / ("mypython-" + flavor))] + argv, cwd=str(app),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        assert result.returncode == code and not result.stdout, result.stderr
        return {"returncode": result.returncode, "stderr": result.stderr.decode()}

    for flavor, name in (("service", "main.py"), ("benchmark", "bench.py")):
        for option in ("-c", "-m", "arbitrary.py"):
            checks[flavor + "_reject_" + option] = reject(flavor, [option, "print(1)"], 2)
        path = app / "code" / name
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\n# altered application\n")
            checks[flavor + "_tampered_application"] = reject(flavor, [], 3)
            path.unlink()
            checks[flavor + "_missing_application"] = reject(flavor, [], 3)
        finally:
            path.write_bytes(original)
        assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(original).digest()

    # A paired MemoryBIO test deliberately corrupts an authentic TLS record.
    # Independent-process recovery is covered separately by check_local.py.
    sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sc.load_cert_chain(str(app / "certs/server.pem"), str(app / "certs/server.key"))
    sc.load_verify_locations(cafile=str(app / "code/RootCA.pem"))
    sc.verify_mode = ssl.CERT_REQUIRED
    cc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cc.load_verify_locations(cafile=str(app / "code/RootCA.pem"))
    cc.load_cert_chain(str(app / "certs/client.pem"), str(app / "certs/client.key"))
    si, so, ci, co = (ssl.MemoryBIO() for _ in range(4))
    server = sc.wrap_bio(si, so, server_side=True)
    client = cc.wrap_bio(ci, co, server_hostname="vddpi-test")
    done = [False, False]
    for _ in range(100):
        for i, endpoint in enumerate((server, client)):
            if not done[i]:
                try:
                    endpoint.do_handshake()
                    done[i] = True
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
        while so.pending:
            ci.write(so.read())
        while co.pending:
            si.write(co.read())
        if all(done):
            break
    assert all(done), "TLS handshake did not converge"
    # Consume any post-handshake session tickets before injecting the result.
    try:
        assert not client.read(4096)
    except ssl.SSLWantReadError:
        pass
    assert server.write(b'{"count":20}') == 12
    record = bytearray(so.read())
    assert len(record) > 12
    record[-1] ^= 1
    ci.write(bytes(record))
    try:
        client.read(4096)
    except ssl.SSLError as exc:
        assert "BAD_RECORD_MAC" in str(exc) or "DECRYPTION_FAILED" in str(exc), str(exc)
        checks["tampered_tls_record_rejected"] = str(exc)
    else:
        raise AssertionError("corrupted TLS record was accepted")
    args.output.write_text(json.dumps(checks, indent=2) + "\n")
    print(json.dumps({"checks": len(checks), "passed": True}))


if __name__ == "__main__":
    main()
