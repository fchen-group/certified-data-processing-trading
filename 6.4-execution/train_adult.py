#!/usr/bin/env python3
"""Train the fixed T2 workload on the official Adult training split only.

Writes new artifacts, never edits the reviewed Go transform automatically.
The shuffled test records retain all original attributes, labels and '?' values.
"""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import random
import sys
import warnings

import numpy as np
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from threadpoolctl import threadpool_limits

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "6.3-certification"))
from prepare_adult import ROOT, PINS, parse_adult, fields, NUMERIC

CATEGORICAL = (1, 3, 5, 6, 7, 8, 9, 13)
SEED = 20261030


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2, allow_nan=False)
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=ROOT / "data/adult/raw")
    parser.add_argument("--out", type=Path, default=ROOT / "data/adult/classification")
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output must be a new directory")
    versions = {}
    for line in (ROOT / "6.4-execution/requirements-training.txt").read_text().splitlines():
        name, expected = line.split("==")
        versions[name] = importlib.metadata.version(name)
        if versions[name] != expected:
            parser.error(f"{name}: expected {expected}, found {versions[name]}")
    records = {}
    for name, count in (("adult.data", 32561), ("adult.test", 16281)):
        content = (args.raw / name).read_bytes()
        if digest(content) != PINS[name]:
            raise ValueError(f"source checksum mismatch: {name}")
        records[name], _ = parse_adult(content)
        if len(records[name]) != count:
            raise ValueError("unexpected official split size")
    test_rows = list(records["adult.test"])
    random.Random(SEED).shuffle(test_rows)
    train = np.array([fields(r) for r in records["adult.data"]], dtype=object)
    test = np.array([fields(r) for r in test_rows], dtype=object)

    def numeric(rows):
        return np.array([[np.nan if r[i] == "?" else float(r[i]) for i in NUMERIC]
                         for r in rows], dtype=np.float64)

    train_numeric = numeric(train)
    medians = np.nanmedian(train_numeric, axis=0)
    train_numeric = np.where(np.isnan(train_numeric), medians, train_numeric)
    scaler = StandardScaler().fit(train_numeric)
    encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False,
                            dtype=np.float64).fit(train[:, CATEGORICAL])

    def features(rows):
        nums = numeric(rows)
        nums = np.where(np.isnan(nums), medians, nums)
        return np.hstack((scaler.transform(nums), encoder.transform(rows[:, CATEGORICAL])))

    x_train = features(train)
    y_train = np.array([r[14].removesuffix(".") == ">50K" for r in train])
    model = LogisticRegression(C=1.0, solver="lbfgs", tol=1e-8, max_iter=2000)
    with warnings.catch_warnings(), threadpool_limits(limits=1):
        warnings.simplefilter("error", ConvergenceWarning)
        model.fit(x_train, y_train)
        scores = model.decision_function(features(test))
        predictions = model.predict(features(test))
    if not np.array_equal(scores > 0, predictions):
        raise ValueError("unexpected decision threshold convention")
    transform = {
        "format": "adult.raw.v1",
        "numeric_columns": list(NUMERIC), "medians": medians.tolist(),
        "means": scaler.mean_.tolist(), "scales": scaler.scale_.tolist(),
        "categorical_columns": list(CATEGORICAL),
        "categories": [c.tolist() for c in encoder.categories_],
        "dimension": int(x_train.shape[1]),
    }
    args.out.mkdir(parents=True)
    write_json(args.out / "transform.json", transform)
    write_json(args.out / "parameters.json", {
        "task": "adult-income-v1", "weights": model.coef_[0].tolist(),
        "bias": float(model.intercept_[0]), "threshold": 0.0,
    })
    with (args.out / "test.csv").open("xb") as f:
        f.write(b"".join(r + b"\n" for r in test_rows))
    write_json(args.out / "reference.json", {
        "test_sha256": digest((args.out / "test.csv").read_bytes()),
        "scores": scores.tolist(), "predictions": predictions.astype(int).tolist(),
        "count": len(test_rows), "above_threshold": int(predictions.sum()),
    })
    labels = np.array([r[14].removesuffix(".") == ">50K" for r in test])
    write_json(args.out / "manifest.json", {
        "purpose": "fixed execution workload; test accuracy is a correctness diagnostic",
        "python": platform.python_version(), "packages": versions,
        "source_files": {n: PINS[n] for n in records},
        "training_records": len(train), "test_records": len(test),
        "test_shuffle_seed": SEED, "feature_dimension": int(x_train.shape[1]),
        "missing_numeric": "training median", "missing_categorical": "explicit ? category",
        "unknown_categorical": "all-zero one-hot group", "label_is_feature": False,
        "estimator": "LogisticRegression", "C": 1.0, "penalty": "l2",
        "solver": "lbfgs", "tol": 1e-8, "max_iter": 2000,
        "iterations": int(model.n_iter_[0]), "test_accuracy": float(np.mean(predictions == labels)),
        "files": {p.name: digest(p.read_bytes()) for p in sorted(args.out.iterdir())},
    })
    print(json.dumps({"output": str(args.out), "features": int(x_train.shape[1]),
                      "iterations": int(model.n_iter_[0]), "predicted_above": int(predictions.sum())}))


if __name__ == "__main__":
    main()
