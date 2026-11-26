#!/usr/bin/env python3
"""Prepare B/T1 record inputs from UCI Adult; no model training or business audit.

Preserves full raw record bytes, including unknown values and income labels.
The official train/test files remain separate in raw/; the shuffled union is
for B/T1 only, never a classification train/test split.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import random
import urllib.request
import zipfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
URL = "https://archive.ics.uci.edu/static/public/2/adult.zip"
# Observed from the official HTTPS download; these pins detect later changes,
# not an independently signed publisher checksum.
PINS = {
    "adult.zip": "7537312dd56c2b98035880805ce99e68183a30ee468aa5329d6df0fbb3cc21bb",
    "adult.data": "5b00264637dbfec36bdeaab5676b0b309ff9eb788d63554ca0a249491c86603d",
    "adult.test": "a2a9044bc167a35b2361efbabec64e89d69ce82d9790d2980119aac5fd7e9c05",
    "adult.names": "c248284c0b5de30c9e1958d6cdd168a34a654758b620e68f46aefa83fc0a576a",
}
NUMERIC = (0, 2, 4, 10, 11, 12)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fields(raw):
    row = [v.strip() for v in raw.decode("ascii").split(",")]
    if len(row) != 15 or any(not v for v in row):
        raise ValueError("Adult row must contain 14 attributes and one label")
    if row[-1].removesuffix(".") not in ("<=50K", ">50K"):
        raise ValueError("invalid Adult income label")
    for i in NUMERIC:
        if row[i] != "?" and (not row[i].isascii() or not row[i].isdecimal()):
            raise ValueError("invalid Adult numeric field")
    for i, low, high in ((0, 17, 90), (12, 1, 99)):
        if row[i] != "?" and not low <= int(row[i]) <= high:
            raise ValueError("unexpected Adult numeric range")
    return row


def parse_adult(text, split=None):
    data = text.encode("ascii") if isinstance(text, str) else text
    records, counts = [], {"raw": 0, "missing": 0, "retained": 0}
    for raw in data.split(b"\n"):
        raw = raw.removesuffix(b"\r")  # CRLF is a separator, not record content.
        if not raw.strip() or raw.lstrip().startswith(b"|"):
            continue
        row = fields(raw)  # Validate without rewriting the committed bytes.
        counts["raw"] += 1
        counts["missing"] += int("?" in row[:-1])
        records.append(raw)
    counts["retained"] = len(records)
    return records, counts


def synthetic_records(count, seed, source):
    # Independently resample empirical fields. This is a size/format workload,
    # not a model of Adult's joint distribution or additional real subjects.
    if count <= 0 or not source:
        raise ValueError("positive count and source records required")
    parsed = [fields(r) for r in source]
    columns = list(zip(*parsed))
    education = [(r[3], r[4]) for r in parsed]
    rng = random.Random(seed)
    result = []
    for _ in range(count):
        row = [rng.choice(column) for column in columns]
        row[3], row[4] = rng.choice(education)
        result.append(", ".join(row).encode("ascii"))
    return result


def write_records(path, records):
    content = b"".join(r + b"\n" for r in records)
    with path.open("xb") as out:
        out.write(content)
    n = len(records)
    columns = [[int(fields(r)[i]) for r in records] for i in (0, 12)]
    stats = [{"field": name, "sum": sum(c), "sum_squares": sum(x*x for x in c),
              "mean": sum(c)/n, "population_variance": (n*sum(x*x for x in c)-sum(c)**2)/(n*n)}
             for name, c in zip(("age", "hours-per-week"), columns)]
    lengths = [len(r) for r in records]
    return {"file": path.name, "sha256": sha(content), "records": n, "dimensions": 14,
            "record_format": "adult.raw.v1", "file_bytes": len(content),
            "record_bytes_without_newlines": sum(lengths),
            "record_length": {"min": min(lengths), "mean": sum(lengths)/n, "max": max(lengths)},
            "reference_statistics": stats}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw-dir", type=Path, default=ROOT / "data/adult/raw")
    p.add_argument("--out", type=Path, default=ROOT / "data/adult/full-records")
    p.add_argument("--download", action="store_true", help="download pinned archive if absent")
    p.add_argument("--seed", type=int, default=20261029)
    p.add_argument("--synthetic-count", type=int, default=100000)
    args = p.parse_args()
    if args.out.exists():
        p.error("output already exists; choose a new directory")
    if args.synthetic_count <= 0:
        p.error("synthetic count must be positive")
    args.raw_dir.mkdir(parents=True, exist_ok=True)
    archive = args.raw_dir / "adult.zip"
    downloaded = None
    if not archive.exists():
        if not args.download:
            p.error("archive missing; use --download or place the official archive in raw/")
        with urllib.request.urlopen(URL, timeout=60) as response:
            content = response.read(10*1024*1024 + 1)
        if sha(content) != PINS["adult.zip"]:
            raise ValueError("official archive changed; review it before updating the pin")
        archive.write_bytes(content)
        downloaded = datetime.now(timezone.utc).isoformat()
    if sha(archive.read_bytes()) != PINS["adult.zip"]:
        raise ValueError("archive checksum mismatch")
    with zipfile.ZipFile(archive) as z:
        for name in ("adult.data", "adult.test", "adult.names"):
            content = z.read(name)
            if sha(content) != PINS[name]:
                raise ValueError(f"checksum mismatch: {name}")
            target = args.raw_dir / name
            if target.exists():
                if target.read_bytes() != content:
                    raise ValueError(f"existing raw file differs: {name}")
            else:
                with target.open("xb") as out:
                    out.write(content)
    train, train_counts = parse_adult((args.raw_dir / "adult.data").read_bytes(), "train")
    test, test_counts = parse_adult((args.raw_dir / "adult.test").read_bytes(), "test")
    if (train_counts["raw"], test_counts["raw"], len(train), len(test)) != (32561, 16281, 32561, 16281):
        raise ValueError("unexpected official split counts")
    combined = train + test
    random.Random(args.seed).shuffle(combined)
    args.out.mkdir(parents=True)
    real = write_records(args.out / "adult-full.csv", combined)
    synthetic = write_records(args.out / "synthetic-full.csv", synthetic_records(args.synthetic_count, args.seed + 1, train + test))
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
        "script_sha256": sha(Path(__file__).read_bytes()), "source_url": URL,
        "dataset_url": "https://archive.ics.uci.edu/dataset/2/adult", "doi": "10.24432/C5XW20",
        "attribution": "Becker, B. & Kohavi, R. (1996). Adult. UCI Machine Learning Repository.",
        "license": "CC BY 4.0", "raw_sha256": PINS, "downloaded_utc": downloaded,
        "archive_mtime_utc": datetime.fromtimestamp(archive.stat().st_mtime, timezone.utc).isoformat(),
        "record_format": "adult.raw.v1",
        "record_boundary": "strip LF/CRLF only; skip blank and | comment lines; preserve all record bytes and order after seeded shuffle",
        "cleaning": "no record deletion, imputation, deduplication or field projection; retain ? and test-label punctuation",
        "splits": {"train": train_counts, "test": test_counts},
        "attributes": 14, "labels_in_records": True,
        "statistics_fields": ["age", "hours-per-week"],
        "usage": "B/T1 only; combined split is NOT a T2 training or test set",
        "subset_order": "fixed seeded shuffle; take prefixes for nested real-data subsets",
        "seed": args.seed, "synthetic_seed": args.seed + 1,
        "synthetic_distribution": "empirical column resampling with education/education-num paired; fixed seed; same 15-column text format; scaling workload only, not a joint-distribution or classification dataset",
        "outputs": [real, synthetic],
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(args.out), "train": train_counts, "test": test_counts,
                      "real_records": len(combined), "synthetic_records": args.synthetic_count}))


if __name__ == "__main__":
    main()
