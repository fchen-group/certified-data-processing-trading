#!/usr/bin/env python3
"""Fetch or verify the pinned, unmodified PrivacyGuard archive; safely extract it.

No upstream executable or build script is run. Git blob hashes are checked for
every archived file, including files outside the selected CEE build target.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request

COMMIT = "1ef665fca9dadf00bc0bb363842ab471a747ab0a"
TREE = "caacd7978bf7329e16e0bf67092e7058eb5359d3"
ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "third_party" / "privacyguard"
ARCHIVE = STORE / f"PrivacyGuard-{COMMIT}.tar.gz"
TREE_FILE = STORE / "upstream-tree.json"
MANIFEST = STORE / "source.json"
ARCHIVE_URL = f"https://codeload.github.com/yang-sec/PrivacyGuard/tar.gz/{COMMIT}"
TREE_URL = f"https://api.github.com/repos/yang-sec/PrivacyGuard/git/trees/{TREE}?recursive=1"


def fetch(url, target):
    if target.exists():
        return
    request = urllib.request.Request(url, headers={"User-Agent": "cdpt-source-verification"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    # Exclusive creation prevents silently replacing an existing source record.
    with target.open("xb") as output:
        output.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="download missing pinned source files")
    parser.add_argument("--extract-to", type=Path, help="extract verified source into a new directory")
    args = parser.parse_args()
    if args.fetch:
        STORE.mkdir(parents=True, exist_ok=True)
        fetch(TREE_URL, TREE_FILE)
        fetch(ARCHIVE_URL, ARCHIVE)
    tree = json.loads(TREE_FILE.read_text())
    if tree.get("truncated") or tree.get("sha") != TREE:
        raise ValueError("unexpected or truncated Git tree")
    entries = {item["path"]: item for item in tree["tree"] if item["type"] == "blob"}
    if any(item["type"] not in ("blob", "tree") for item in tree["tree"]):
        raise ValueError("unsupported submodule entry")
    prefix = f"PrivacyGuard-{COMMIT}"
    verified = {}
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts
            if not parts or parts[0] != prefix or ".." in parts:
                raise ValueError("unexpected archive path")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("unsupported archive entry")
            name = "/".join(parts[1:])
            if name not in entries or name in verified:
                raise ValueError(f"unexpected or duplicate source file: {name}")
            data = archive.extractfile(member).read()
            digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            entry = entries[name]
            if digest != entry["sha"] or len(data) != entry["size"]:
                raise ValueError(f"source hash mismatch: {name}")
            if entry["mode"] not in ("100644", "100755"):
                raise ValueError(f"unsupported Git mode: {name}")
            if bool(member.mode & 0o111) != (entry["mode"] == "100755"):
                raise ValueError(f"executable mode mismatch: {name}")
            verified[name] = {"git_blob": digest, "sha256": hashlib.sha256(data).hexdigest(),
                              "size": len(data), "mode": entry["mode"]}
        if set(verified) != set(entries):
            raise ValueError("archive does not cover the complete Git tree")
        record = {"repository": "https://github.com/yang-sec/PrivacyGuard", "commit": COMMIT,
                  "tree": TREE, "archive_url": ARCHIVE_URL, "tree_url": TREE_URL,
                  "archive_sha256": hashlib.sha256(ARCHIVE.read_bytes()).hexdigest(),
                  "tree_file_sha256": hashlib.sha256(TREE_FILE.read_bytes()).hexdigest(),
                  "files": dict(sorted(verified.items()))}
        if MANIFEST.exists():
            if json.loads(MANIFEST.read_text()) != record:
                raise ValueError("source manifest differs from the verified archive")
        else:
            with MANIFEST.open("x") as output:
                json.dump(record, output, indent=2, ensure_ascii=False)
                output.write("\n")
        if args.extract_to:
            destination = args.extract_to.resolve()
            if destination.exists():
                raise ValueError("extraction destination already exists")
            destination.mkdir(parents=True)
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                name = "/".join(PurePosixPath(member.name).parts[1:])
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    output.write(archive.extractfile(member).read())
                target.chmod(int(verified[name]["mode"], 8) & 0o777)
    print(json.dumps({"verified_files": len(verified), "commit": COMMIT,
                      "archive_sha256": record["archive_sha256"],
                      "extracted_to": str(args.extract_to) if args.extract_to else None}))


if __name__ == "__main__":
    main()
