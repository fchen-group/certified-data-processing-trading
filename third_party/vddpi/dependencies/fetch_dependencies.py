#!/usr/bin/env python3
"""Fetch and SHA-256 verify pinned VDDPI upstream and CPython 3.6.9 build dependencies.

Downloads large upstream archives and Python wheels excluded from Git so
third_party/vddpi/adapter/Dockerfile.toolchain and Dockerfile.runtime can be
built from scratch. Every downloaded file is verified against manifest.json
or source.json before being kept.
"""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

DEPS_DIR = Path(__file__).resolve().parent
VDDPI_DIR = DEPS_DIR.parent
PYTHON_URL = "https://www.python.org/ftp/python/3.6.9/Python-3.6.9.tar.xz"
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"

WHEEL_PACKAGES = {
    "wheels/PyJWT-2.4.0-py3-none-any.whl": ("PyJWT", "2.4.0"),
    "wheels/certifi-2024.6.2-py3-none-any.whl": ("certifi", "2024.6.2"),
    "wheels/cffi-1.15.1-cp36-cp36m-manylinux_2_5_x86_64.manylinux1_x86_64.whl": ("cffi", "1.15.1"),
    "wheels/charset_normalizer-2.0.12-py3-none-any.whl": ("charset-normalizer", "2.0.12"),
    "wheels/cryptography-3.4.8-cp36-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl": ("cryptography", "3.4.8"),
    "wheels/idna-3.4-py3-none-any.whl": ("idna", "3.4"),
    "wheels/pip-21.3.1-py3-none-any.whl": ("pip", "21.3.1"),
    "wheels/pycparser-2.21-py2.py3-none-any.whl": ("pycparser", "2.21"),
    "wheels/requests-2.27.1-py2.py3-none-any.whl": ("requests", "2.27.1"),
    "wheels/urllib3-1.26.20-py2.py3-none-any.whl": ("urllib3", "1.26.20"),
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download_and_verify(url: str, target: Path, expected_sha256: str, expected_size=None) -> None:
    if target.exists():
        actual = sha256_file(target)
        if actual == expected_sha256:
            print(f"OK (cached): {target.relative_to(VDDPI_DIR)}")
            return
        raise ValueError(f"Checksum mismatch on existing file {target}: expected {expected_sha256}, got {actual}")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    print(f"Downloading {url} -> {target.relative_to(VDDPI_DIR)}")
    req = urllib.request.Request(url, headers={"User-Agent": "certified-data-processing-trading-fetch"})
    with urllib.request.urlopen(req, timeout=180) as resp, tmp.open("wb") as out:
        while True:
            buf = resp.read(1 << 20)
            if not buf:
                break
            out.write(buf)
    actual = sha256_file(tmp)
    if actual != expected_sha256 or (expected_size is not None and tmp.stat().st_size != expected_size):
        tmp.unlink(missing_ok=True)
        raise ValueError(f"Downloaded file failed verification for {target.name}: got {actual}")
    tmp.replace(target)
    print(f"OK (verified): {target.relative_to(VDDPI_DIR)}")


def resolve_wheel_url(package: str, version: str, filename: str) -> str:
    req = urllib.request.Request(
        PYPI_JSON_URL.format(package=package, version=version),
        headers={"User-Agent": "certified-data-processing-trading-fetch"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        meta = json.loads(resp.read().decode("utf-8"))
    for item in meta.get("urls", []):
        if item.get("filename") == filename:
            return item["url"]
    raise RuntimeError(f"Pinned wheel {filename} not found on PyPI for {package}=={version}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true", help="only check already-downloaded files")
    args = parser.parse_args()

    manifest = json.loads((DEPS_DIR / "manifest.json").read_text())
    source = json.loads((VDDPI_DIR / "source.json").read_text())

    if args.verify_only:
        upstream = VDDPI_DIR / "upstream.tar.gz"
        if not upstream.is_file() or sha256_file(upstream) != source["archive_sha256"]:
            raise RuntimeError("upstream.tar.gz missing or checksum mismatch")
        py_entry = manifest["Python-3.6.9.tar.xz"]
        py_path = DEPS_DIR / "Python-3.6.9.tar.xz"
        if not py_path.is_file() or sha256_file(py_path) != py_entry["sha256"]:
            raise RuntimeError("Python-3.6.9.tar.xz missing or checksum mismatch")
        for rel in WHEEL_PACKAGES:
            p = DEPS_DIR / rel
            if not p.is_file() or sha256_file(p) != manifest[rel]["sha256"]:
                raise RuntimeError(f"{rel} missing or checksum mismatch")
        print("All VDDPI upstream and Python 3.6.9 dependencies verified.")
        return

    download_and_verify(source["archive_url"], VDDPI_DIR / "upstream.tar.gz", source["archive_sha256"])
    py_entry = manifest["Python-3.6.9.tar.xz"]
    download_and_verify(PYTHON_URL, DEPS_DIR / "Python-3.6.9.tar.xz", py_entry["sha256"], py_entry["size"])
    for rel, (package, version) in WHEEL_PACKAGES.items():
        entry = manifest[rel]
        target = DEPS_DIR / rel
        if target.exists() and sha256_file(target) == entry["sha256"]:
            print(f"OK (cached): {target.relative_to(VDDPI_DIR)}")
            continue
        url = resolve_wheel_url(package, version, target.name)
        download_and_verify(url, target, entry["sha256"], entry["size"])


if __name__ == "__main__":
    main()
