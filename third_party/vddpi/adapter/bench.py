"""PUBLIC_TEST_ONLY measurement entry; shares request() with the service.

Native execution is a functional check, not encrypted-file or SGX evidence.
Under the SGX manifest, ./data and ./certs are encrypted Gramine mounts.
"""
import hashlib
import json
import os
import sys
import traceback
import main as service
from bio_transport import DeferredTLS


def main():
    with open("config.json") as f:
        config = json.load(f)
    if config.get("public_test_only") is not True:
        raise RuntimeError("only public research fixtures are accepted")
    if config["mode"] == "probe":
        # A hardware-generated local REPORT, not a remotely verified quote.
        with open("/dev/attestation/report", "rb") as f:
            report = f.read()
        if len(report) != 432:
            raise RuntimeError("invalid SGX REPORT length")
        flags = int.from_bytes(report[48:56], "little")
        if flags & 2:
            raise RuntimeError("debug enclave is forbidden")
        print(json.dumps({"local_report_hex": report.hex(), "flags": flags,
                          "mrenclave": report[64:96].hex(), "remote_verified": False}))
        return
    data_id = config["data_id"]
    path = "./data/" + data_id.replace("/", "-")
    if config["mode"] == "inspect":
        with open(path) as f:
            cached = json.load(f)
        print(json.dumps({"condition": cached["condition"], "client_cn": cached["clientCN"],
                          "input_sha256": hashlib.sha256(cached["data"]["data"].encode("ascii")).hexdigest()}))
        return
    if config["mode"] == "prepare":
        # Only public test credentials are provisioned this way. With Gramine,
        # the fixed, trusted fixtures are copied into encrypted mounts by the
        # very same measured program that will later read the cached input.
        for name in ("RootCA.pem", "server.pem", "server.key", "client.pem", "client.key"):
            with open("./fixtures/" + name, "rb") as f:
                content = f.read()
            destination = "./certs/" + name
            if os.path.exists(destination):
                with open(destination, "rb") as f:
                    if f.read() != content:
                        raise RuntimeError("existing fixture identity differs")
            else:
                with open(destination, "wb") as f:
                    f.write(content)
                os.chmod(destination, 0o600)
        with open(config["input"], "rb") as f:
            raw = f.read((32 << 20) + 1)
        if len(raw) > 32 << 20 or hashlib.sha256(raw).hexdigest() != config["input_sha256"]:
            raise ValueError("fixture input mismatch")
        data = {"path": path, "clientCN": config["client_cn"],
                "data": {"data": raw.decode("ascii")}, "condition": config["condition"]}
        if os.path.exists(path):
            raise RuntimeError("refuse to overwrite prepared input")
        service.cache_data(data, path)
        print(json.dumps({"prepared": True, "input_sha256": config["input_sha256"]}))
        return
    if config["mode"] != "run":
        raise ValueError("invalid benchmark mode")
    transport = DeferredTLS(config["peer_host"], config["peer_port"],
                            "./certs/server.pem", "./certs/server.key", "./code/RootCA.pem")
    service.tls_socket = transport
    try:
        with open(config["tokens"]) as f:
            tokens = f.read()
        result = service.request(transport.client_cn, tokens)
        stats = service.LAST_MEASUREMENT
        if not result[-2] or not stats or not stats["cached"]:
            raise RuntimeError("benchmark requires valid cached input path")
        if not (stats["begin_ns"] <= stats["input_done_ns"] <= stats["protected_done_ns"] <= stats["cleanup_done_ns"]):
            raise RuntimeError("nonmonotonic timestamps")
        stats.update({"tls_version": transport.tls.version(), "cipher": transport.tls.cipher(),
                      "protected_bytes": len(transport.records), "plaintext_bytes": transport.plaintext_bytes,
                      "network_send_after_endpoint": True, "scope": "public-test processing entry"})
        # Persistence/deletion completed in request(); actual transmission is
        # deferred until now. No elapsed interval is estimated or subtracted.
        transport.flush()
        print(json.dumps(stats, sort_keys=True))
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
