#!/usr/bin/env python3
"""Render Section 6.4 from verified, frozen C1/C2/C3 evidence, without rerunning it.

Writes one manuscript figure and a numerical/provenance summary. Raw archives
and measurement summaries are read-only. Requires matplotlib.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
from statistics import mean
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "6.3-certification"))
from plot_certification import BLUE, ORANGE, axes_style, style
import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, NullFormatter, NullLocator, StrMethodFormatter

PHASES = {"load_ciphertext", "decrypt_parse", "commitment", "analyze", "encrypt_sign"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_outputs(root, *outputs):
    root = root.resolve()
    protected = [root / "SHA256SUMS"]
    protected.extend(root / line.split("  ", 1)[1]
                     for line in protected[0].read_text().splitlines())
    for output in outputs:
        resolved = output.resolve()
        require(resolved != root and root not in resolved.parents,
                "outputs must be outside the frozen results directory")
        # resolve() catches symlink aliases; samefile() also catches hard links.
        if resolved.exists():
            require(not any(resolved.samefile(source) for source in protected),
                    "output aliases frozen evidence")


def load_evidence(root):
    for line in (root / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        require(digest(root / name) == expected, "checksum mismatch: " + name)
    proof = json.loads((root / "formal-independent-verification.json").read_text())
    require(proof["passed"] and proof["observations"] == 600, "formal verification missing")
    require(digest(root / "sgx-evidence.tar.gz") == proof["archive_sha256"], "archive mismatch")
    with tarfile.open(root / "sgx-evidence.tar.gz") as archive:
        def read(name):
            original = archive.extractfile("results/formal/" + name).read()
            # The small raw/ view is for direct reading; the archive is authoritative.
            if name in ("config.json", "observations.jsonl", "schedule.json") and (root / "raw").exists():
                visible = root / "raw" / name
                require(visible.is_file() and visible.read_bytes() == original,
                        "raw view differs from original archive: " + name)
            return original
        config = json.loads(read("config.json"))
        rows = [json.loads(line) for line in read("observations.jsonl").splitlines()]
        schedule = json.loads(read("schedule.json"))
        summary = json.loads(read("summary.json"))
    require(config["stage"] == "formal" and config["repetitions"] == 30, "not formal data")
    require(len(rows) == len(schedule) == 600, "incomplete observations")
    require(summary == json.loads((root / "formal-summary.json").read_text()), "summary mismatch")
    cases = {case["id"]: case for case in config["cases"]}
    groups = defaultdict(list)
    for i, (row, job) in enumerate(zip(rows, schedule)):
        backend = "native" if row["backend"] == "native" else "sgx"
        require(row["backend"] in ("native", "sgx-build"), "unknown backend")
        require((row["case"], row["repeat"], backend) ==
                (job["case"], job["repeat"], job["backend"]), "schedule mismatch")
        require(row["order"] == i and row["validated"] and not row.get("diagnostic"), "invalid row")
        require(row["go"] == "go1.26.1" and row["gomaxprocs"] == 4 and
                row["memory_limit"] == 768 * 1024**2, "execution condition mismatch")
        require(row["clock"] == "clock_monotonic_raw" and
                set(row["phases_ns"]) == PHASES and min(row["phases_ns"].values()) > 0 and
                sum(row["phases_ns"].values()) == row["total_ns"], "timing mismatch")
        require(row["n"] == cases[row["case"]]["n"], "record count mismatch")
        groups[row["case"], backend].append(row)
    require(set(groups) == {(case, mode) for case in cases for mode in ("native", "sgx")},
            "incomplete case coverage")
    computed = {}
    for key, observations in groups.items():
        require(len(observations) == 30 and {r["repeat"] for r in observations} == set(range(1, 31)),
                "incomplete or duplicate repetitions")
        entry = {"case": key[0], "backend": key[1], "n": cases[key[0]]["n"],
                 "repetitions": 30, "mean_ns": mean(r["total_ns"] for r in observations),
                 "mean_phases_ns": {p: mean(r["phases_ns"][p] for r in observations)
                                    for p in sorted(PHASES)}}
        require(entry == next(s for s in summary if (s["case"], s["backend"]) == key),
                "raw observations disagree with published mean")
        computed[key] = entry
    c1 = json.loads((root / "c1-verification.json").read_text())
    require(c1["passed"] and c1["runs"] == 30 and c1["warmups"] == 1 and c1["distinct_keys"] == 31,
            "C1 verification missing")
    formal = [r for r in c1["rows"] if not r["warmup"]]
    require(len(formal) == 30 and {r["index"] for r in formal} == set(range(1, 31)), "C1 coverage")
    c1_ms = {key: mean(r[key] for r in formal) / 1e6 for key in c1["summary"]}
    for key, value in c1_ms.items():
        require(math.isclose(value, c1["summary"][key]["mean_ms"], rel_tol=1e-12), "C1 mean mismatch")
    provenance = {name: digest(root / name) for name in (
        "sgx-evidence.tar.gz", "client-evidence.tar.gz", "formal-independent-verification.json",
        "formal-summary.json", "c1-verification.json", "diagnostic-decision.json")}
    return computed, c1_ms, provenance


def performance_figure(data):
    fig, axes = plt.subplots(1, 2, figsize=(7.35, 2.9))
    fig.subplots_adjust(left=.085, right=.98, bottom=.22, top=.81, wspace=.32)
    for index, (ax, task, title) in enumerate(zip(axes, ("t1", "t2"),
            ("(a) Basic statistics", "(b) Income classification"))):
        axes_style(ax)
        for dataset, line, size in (("synthetic", "--", 5.0), ("adult", "-", 3.8)):
            for backend, color, marker, label in (("native", BLUE, "o", "Native"),
                                                  ("sgx", ORANGE, "^", "SGX")):
                rows = sorted((r for r in data.values() if r["case"].startswith(task + "-" + dataset)
                               and r["backend"] == backend), key=lambda r: r["n"])
                if not rows:
                    continue
                require(all(r["n"] > 0 and r["mean_ns"] > 0 for r in rows),
                        "logarithmic axes require positive observations")
                ax.plot([r["n"] for r in rows], [r["mean_ns"] / 1e6 for r in rows],
                        color=color, marker=marker, linestyle=line, markersize=size,
                        markerfacecolor="white", markeredgewidth=1.1,
                        label=label + (" (synthetic)" if dataset == "synthetic" else " (Adult)"))
        ax.set(title=title, xlabel=r"Records, $N$", ylabel="Processing time (ms)")
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlim(800, 125000 if index == 0 else 20000)
        ax.set_ylim(1, 1000 if index == 0 else 150)
        ticks = [1000, 5000, 10000, 50000, 100000] if index == 0 else [1000, 5000, 10000, 16281]
        labels = ["1k", "5k", "10k", "50k", "100k"] if index == 0 else ["1k", "5k", "10k", "16.3k"]
        ax.set_xticks(ticks, labels=labels)
        ax.xaxis.set_minor_locator(NullLocator())
        ax.set_yticks([1, 10, 100, 1000] if index == 0 else [1, 10, 100])
        ax.yaxis.set_major_formatter(StrMethodFormatter("{x:g}"))
        ax.yaxis.set_minor_locator(LogLocator(base=10, subs=range(2, 10)))
        ax.yaxis.set_minor_formatter(NullFormatter())
        ax.tick_params(axis="y", which="minor", width=.45, length=1.8)
    handles, labels = axes[0].get_legend_handles_labels()
    order = [2, 3, 0, 1]
    fig.legend([handles[i] for i in order], [labels[i] for i in order], loc="upper center",
               bbox_to_anchor=(.53, 1.015), ncol=4, frameon=False, handlelength=2.0,
               columnspacing=1.5)
    return fig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--figure", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    require(args.figure.suffix == ".pdf" and args.summary.suffix == ".json", "output formats")
    require(args.summary.name == "paper-summary.json", "use a separate derived paper-summary.json")
    validate_outputs(args.results, args.figure, args.summary)
    data, c1, provenance = load_evidence(args.results)
    comparisons = {}
    for case in sorted({key[0] for key in data}):
        native, sgx = data[case, "native"], data[case, "sgx"]
        increment = sgx["mean_ns"] - native["mean_ns"]
        comparisons[case] = {
            "n": sgx["n"], "native_ms": native["mean_ns"] / 1e6, "sgx_ms": sgx["mean_ns"] / 1e6,
            "overhead_percent": 100 * increment / native["mean_ns"],
            "sgx_phases_ms": {p: v / 1e6 for p, v in sgx["mean_phases_ns"].items()},
            "sgx_phase_percent": {p: 100 * v / sgx["mean_ns"] for p, v in sgx["mean_phases_ns"].items()}}
    style()
    fig = performance_figure(data)
    args.figure.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.figure, metadata={"Title": "Protected execution performance",
        "Subject": json.dumps(provenance, sort_keys=True), "Creator": "6.4-execution/plot_execution.py",
        "CreationDate": None, "ModDate": None})
    plt.close(fig)
    report = {"source_sha256": provenance, "observations": 600, "repetitions_per_case_backend": 30,
              "c1_mean_ms": c1, "comparisons": comparisons, "figure_sha256": digest(args.figure),
              "plot_script_sha256": digest(Path(__file__)),
              "plot": {"xscale": "log", "yscale": "log", "log_base": 10,
                       "x": "actual record count", "y": "mean processing time in milliseconds",
                       "data_positions": "unmodified; tick labels may be rounded"},
              "scope": "C1 startup/report verification and C2/C3 compute-only measurements; all observations retained"}
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Verified 600 observations and 30 C1 repetitions; wrote {args.figure}")


if __name__ == "__main__":
    main()
