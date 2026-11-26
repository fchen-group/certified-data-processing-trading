#!/usr/bin/env python3
"""Native Linux acceptance of the adapted real request/TLS path, not SGX timing.

Uses real X.509/JWT signatures and a separate verifying TLS client. Synthetic
application-identity evidence is an explicit PUBLIC_TEST_ONLY fixture; it is
not an attestation quote or a verification of Intel hardware.
"""
import argparse
import base64
import hashlib
import json
import math
import os
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
import jwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier, ExtendedKeyUsageOID

PYTHON = "/opt/vddpi-python/bin/python3.6"
IDENTITY = "11" * 32


def sha(data):
    return hashlib.sha256(data).hexdigest()


def certificate(cn, issuer, issuer_key, key, ca=False, identity=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.utcnow()
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(issuer.subject if issuer else subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    if identity:
        carrier = bytes(112) + bytes.fromhex(IDENTITY) + bytes(288)
        value = repr({"isvEnclaveQuoteBody": base64.b64encode(carrier).decode()}).encode()
        builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.5"), value), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256(), default_backend())


def key_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def setup_identities(app):
    certs = app / "certs"
    certs.mkdir(exist_ok=True)
    ca_key = rsa.generate_private_key(65537, 2048, default_backend())
    ca = certificate("PUBLIC TEST CA", None, None, ca_key, ca=True)
    (app / "code/RootCA.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (certs / "RootCA.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    pairs = {}
    for name, cn in (("server", "vddpi-test"), ("client", "test-consumer"), ("provider", "test-provider")):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        cert = certificate(cn, ca, ca_key, key, identity=(name == "client"))
        (certs / (name + ".key")).write_bytes(key_bytes(key))
        (certs / (name + ".key")).chmod(0o600)
        (certs / (name + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        pairs[name] = (key, cert)
    (certs / "PUBLIC_TEST_ONLY").write_text("Synthetic identity carrier; NOT a remotely verified SGX certificate.\n")
    fixtures = app / "fixtures"
    fixtures.mkdir(exist_ok=True)
    for name in ("RootCA.pem", "server.pem", "server.key", "client.pem", "client.key"):
        (fixtures / name).write_bytes((certs / name).read_bytes())
        (certs / name).unlink()
    return pairs


def compare(actual, expected):
    assert set(actual) == set(expected), actual
    for key in ("count", "support_vectors", "training_correct"):
        assert actual[key] == expected[key], (key, actual, expected)
    assert math.isfinite(actual["rho"])
    assert abs(actual["rho"] - expected["rho"]) <= 1e-7 * (1 + abs(expected["rho"]))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("prepared", type=Path)
    p.add_argument("reference", type=Path)
    p.add_argument("evidence", type=Path)
    p.add_argument("--sizes", default="5000,10000,32561")
    p.add_argument("--input-manifest", type=Path, default=Path(__file__).resolve().parent / "common/input-manifest.json")
    args = p.parse_args()
    input_manifest = args.input_manifest.resolve()
    root, ref, evidence = args.prepared.resolve(), args.reference.resolve(), args.evidence.resolve()
    app = root / "app"
    evidence.mkdir(parents=True, exist_ok=False)
    pairs = setup_identities(app)
    os.chdir(str(app))
    sys.path.insert(0, str(app / "code"))
    import main as service
    import plib
    raw = (ref / "official-train-shuffled.csv").read_bytes()
    rows = raw.splitlines()
    assert len(rows) == 32561
    data_id = "https://public-fixture/data/svm/shared"
    cache = app / "data" / data_id.replace("/", "-")
    cache.parent.mkdir(exist_ok=True)
    fixture_payload = {"consumer": "test-consumer", "app_ID": IDENTITY, "data_ID": data_id,
                       "arg_num": "1", "status": "completed"}

    def tokens(payload=None, signer=None):
        signed = jwt.encode(payload or fixture_payload, key_bytes(signer or pairs["provider"][0]), algorithm="RS512")
        pem = pairs["provider"][1].public_bytes(serialization.Encoding.PEM).decode().replace("\n", "\\n")
        return signed + "," + pem + "\n"

    # Same input hashes as the preceding two-system pilot; input selection is
    # checked outside the timer. Native cache is plaintext ONLY for this test.
    expected_inputs = json.loads(input_manifest.read_text())["nested_subsets"]
    for n in map(int, args.sizes.split(",")):
        assert sha(b"\n".join(rows[:n]) + b"\n") == expected_inputs[str(n)], n
    observations = []
    timeout = 900

    def prepare(n, condition=None, client="test-consumer", raw_override=None):
        chosen = raw_override if raw_override is not None else b"\n".join(rows[:n]) + b"\n"
        config = {"public_test_only": True, "mode": "prepare", "data_id": data_id,
                  "input": str(evidence / "current-input.csv"), "input_sha256": sha(chosen),
                  "client_cn": client, "condition": condition or {"counter": "2", "expirationDate": "", "location": ""}}
        Path(config["input"]).write_bytes(chosen)
        if cache.exists():
            cache.unlink()
        (app / "config.json").write_text(json.dumps(config))
        prepared = subprocess.run([str(app / "mypython-benchmark")], cwd=str(app), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        assert prepared.returncode == 0, prepared.stderr.decode()
        return config, chosen

    def execute(label, config, authorization, expected=None, rejection=None):
        # Independent OS process: the measured application never runs the peer
        # decryption or the reference checks before its timer endpoint.
        output = evidence / label
        output.mkdir()
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(30)
        config = dict(config, mode="run", peer_host="127.0.0.1", peer_port=listener.getsockname()[1], tokens="tokens.txt")
        (app / "config.json").write_text(json.dumps(config))
        (app / "tokens.txt").write_text(authorization)
        (output / "config.json").write_text(json.dumps(config, indent=2))
        started = time.monotonic()
        child = subprocess.Popen([str(app / "mypython-benchmark")], cwd=str(app), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        received = b""
        peer_error = None
        try:
            conn, _ = listener.accept()
            conn.settimeout(timeout)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cafile=str(app / "code/RootCA.pem"))
            context.load_cert_chain(str(app / "certs/client.pem"), str(app / "certs/client.key"))
            with context.wrap_socket(conn, server_hostname="vddpi-test") as peer:
                while True:
                    block = peer.recv(65536)
                    if not block:
                        break
                    received += block
        except Exception as exc:
            peer_error = type(exc).__name__ + ": " + str(exc)
        finally:
            listener.close()
        try:
            stdout, stderr = child.communicate(timeout=max(1, timeout - (time.monotonic()-started)))
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate()
            raise RuntimeError("acceptance subprocess timed out: " + label)
        (output / "stdout").write_bytes(stdout)
        (output / "stderr").write_bytes(stderr)
        (output / "received.json").write_bytes(received)
        record = {"case": label, "returncode": child.returncode, "received_bytes": len(received), "peer_error": peer_error}
        if expected is not None:
            assert child.returncode == 0, (label, stderr.decode())
            assert not peer_error, (label, peer_error)
            compare(json.loads(received), expected)
            stats = json.loads(stdout.decode().splitlines()[-1])
            assert stats["processing_ns"] > 0 and stats["network_send_after_endpoint"]
            assert stats["protected_bytes"] > len(received) and stats["plaintext_bytes"] == len(received)
            remaining = int(config["condition"]["counter"]) - 1
            if remaining:
                assert json.loads(cache.read_text())["condition"]["counter"] == str(remaining)
            else:
                assert not cache.exists(), "last permitted use must remove cached input"
            record["actual"] = json.loads(received)
            record["input_sha256"] = config["input_sha256"]
            record["processing_ns_diagnostic_only"] = stats["processing_ns"]
        else:
            assert child.returncode != 0 and not received, (label, child.returncode, received)
            assert rejection in stderr.decode(), (label, stderr.decode())
        observations.append(record)
        print(json.dumps(record), flush=True)

    for n in map(int, args.sizes.split(",")):
        config, chosen = prepare(n)
        expected = json.loads((ref / ("expected-{}.json".format(n))).read_text())
        execute("valid-{}".format(n), config, tokens(), expected=expected)

    # Rejection checks use the real signed-token/cache path. No all-true policy
    # stubs and no simulated encryption are used in these process tests.
    small = b"\n".join(rows[:20]) + b"\n"
    config, _ = prepare(20)
    bad = dict(fixture_payload, app_ID="22" * 32)
    execute("wrong-app", config, tokens(bad), rejection="Invalid App")
    config, _ = prepare(20)
    bad = dict(fixture_payload, consumer="another-consumer")
    execute("wrong-token-consumer", config, tokens(bad), rejection="Invalid consumer")
    config, _ = prepare(20)
    other_key = rsa.generate_private_key(65537, 2048, default_backend())
    execute("bad-token-signature", config, tokens(signer=other_key), rejection="Signature verification failed")
    config, _ = prepare(20, client="another-consumer")
    execute("wrong-cache-client", config, tokens(), rejection="cached data belongs to another client")
    config, _ = prepare(20, condition={"counter": "0", "expirationDate": "", "location": ""})
    execute("counter-exhausted", config, tokens(), rejection="usage condition is not met")
    config, _ = prepare(20)
    bad = dict(fixture_payload, arg_num="2")
    execute("wrong-argument", config, tokens(bad), rejection="invalid argument number")
    config, _ = prepare(20, raw_override=b"malformed record\n")
    execute("invalid-record", config, tokens(), rejection="common SVM task rejected input")
    config, _ = prepare(20)
    execute("empty-token", config, "", rejection="no authorized inputs")

    unit = {}
    # Exercise the actual date/location comparisons using deterministic oracle
    # replies. Only the network response is substituted in these unit checks.
    condition = {"counter": "1", "expirationDate": "2000-01-01", "location": ""}
    class Reply:
        text = json.dumps({"datetime": "2026-11-04T12:00:00"})
    with patch.object(service.requests, "get", return_value=Reply()):
        assert service.check_condition_phase(condition) == (False, 0)
    unit["expired_condition_rejected"] = True
    condition = {"counter": "1", "expirationDate": "", "location": "JP"}
    Reply.text = json.dumps({"countryCode": "SG"})
    with patch.object(service.requests, "post", return_value=Reply()):
        assert service.check_condition_phase(condition) == (False, 1)
    unit["location_mismatch_rejected"] = True
    for counter in ("-1", "NaN", "0"):
        assert not service.check_condition_phase(dict(condition, counter=counter))[0]
    unit["invalid_counter_rejected"] = True
    a = json.loads(plib.run_svm({"data": small.decode()}))
    b = json.loads(plib.run_svm({"data": small.rstrip(b"\n").decode()}))
    compare(a, b)
    assert a["count"] == 20
    unit["last_record_with_and_without_newline"] = True
    config, _ = prepare(20, condition={"counter": "1", "expirationDate": "", "location": ""})
    execute("last-permitted-use", config, tokens(), expected=a)
    unit["last_permitted_use_deletes_cache"] = True
    summary = {"scope": "native Linux functional validation, not SGX or performance", "process_cases": observations,
               "unit_checks": unit, "synthetic_identity_fixture": True, "encrypted_file_hardware_validation": False}
    (evidence / "verification.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("LOCAL_ACCEPTANCE_COMPLETE", flush=True)


if __name__ == "__main__":
    main()
