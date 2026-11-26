#!/usr/bin/env python3
"""Validate a run, render certification costs and summarize reuse at k=10.

Requires an explicit input and a NEW output directory. No cloud/chain access;
never replaces manuscript figures or mixes old gas with new off-chain results.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import tempfile

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "cdpt-matplotlib"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from validate_admission_run import validate
from commitment_length import validate as validate_construction

BLUE, ORANGE, GREEN = "#0072B2", "#D55E00", "#009E73"

def style():
    times = Path("/System/Library/Fonts/Supplemental/Times New Roman.ttf")
    if times.exists():
        font_manager.fontManager.addfont(str(times))
        family = "Times New Roman"
    else:
        family = "STIXGeneral"
    plt.rcParams.update({
        "font.family": family, "mathtext.fontset": "stix",
        "font.size": 9, "axes.labelsize": 9.5, "axes.titlesize": 10,
        "xtick.labelsize": 8.5, "ytick.labelsize": 8.5, "legend.fontsize": 8.5,
        "axes.linewidth": 0.7, "lines.linewidth": 1.35, "lines.markersize": 4,
        "pdf.fonttype": 42, "ps.fonttype": 42, "axes.unicode_minus": False,
        "savefig.facecolor": "white", "axes.spines.top": False,
        "axes.spines.right": False,
    })


def axes_style(ax):
    ax.grid(axis="y", color="#E3E5E8", linewidth=0.55)
    ax.set_axisbelow(True)
    ax.tick_params(width=0.65, length=3, pad=3)


def series(ax, rows, xkey, ykey, scale, color, marker, label, linestyle="-", xscale=1,
           markersize=4):
    x = [float(r[xkey]) / xscale for r in rows]
    y = [float(r[ykey + "_mean"]) / scale for r in rows]
    return ax.plot(x, y, color=color, marker=marker, label=label,
                   linestyle=linestyle, markerfacecolor="white", markeredgewidth=1.1,
                   markersize=markersize)[0]


def reuse_summary(rows):
    chosen = [r for r in rows if r["group"] == "B3" and int(r["k"]) == 10
              and r["dataset"].startswith("adult-")]
    if len(chosen) != 2 or {r["mode"] for r in chosen} != {"reuse", "reaudit"}:
        raise ValueError("exactly one Adult reuse/reaudit pair at k=10 required")
    by_mode = {r["mode"]: r for r in chosen}
    n, m = int(chosen[0]["n"]), int(chosen[0]["m"])
    result = {"n": n, "m": m, "trades": 10,
              "scope": "certification operations only; both groups construct the commitment once",
              "modes": {}, "chain_gas": "not included; requires separately verified chain provenance",
              "expected_distinct_reaudit": n*(1-(1-m/n)**10)}
    for mode, row in by_mode.items():
        result["modes"][mode] = {
            "certifications": int(float(row["audit_count_mean"])),
            "commitment_ms": float(row["preparation_ns_mean"])/1e6,
            "cumulative_local_ms": float(row["total_component_ns_mean"])/1e6,
            "amortized_local_ms": float(row["amortized_component_ns_mean"])/1e6,
            "distinct_sampled_positions_mean": float(row["distinct_records_mean"]),
            "cumulative_response_bytes_mean": float(row["response_wire_bytes_mean"])}
    return result


def cost_figure(rows, cfg, v2, sampling=None, construction=None):
    fig, axes = plt.subplots(1, 2, figsize=(5.9, 2.65))
    fig.subplots_adjust(left=0.095, right=0.975, bottom=0.23, top=0.85, wspace=0.38)
    for ax in axes:
        axes_style(ax)
    ax = axes[0]
    if construction:
        construction_rows, construction_cfg = construction
        if construction_cfg["record_lengths"] != [128, 1024, 4096]:
            raise ValueError("unexpected construction lengths")
        for length, label, color, marker, line in zip(
                construction_cfg["record_lengths"], ["128 B", "1 KiB", "4 KiB"],
                [BLUE, ORANGE, GREEN], ["o", "s", "^"], ["-", "--", "-."]):
            selected = sorted((r for r in construction_rows if int(r["record_length"]) == length),
                              key=lambda r: int(r["n"]))
            if [int(r["n"]) for r in selected] != construction_cfg["records"]:
                raise ValueError("construction grid mismatch")
            series(ax, selected, "n", "preparation_ns", 1e6, color, marker, label, line, 1000)
    else:
        names = {"Adult": cfg["b2_dataset"],
                 "Synthetic": next(n for n in cfg["datasets"] if n.startswith("synthetic-"))}
        for label, color, marker, line, size in [
            ("Synthetic", ORANGE, "s", "--", 5.5), ("Adult", BLUE, "o", "-", 3.5)]:
            selected = sorted((r for r in rows if r["group"] == "B1" and r["dataset"] == names[label]),
                              key=lambda r: int(r["n"]))
            if not selected:
                raise ValueError("missing B1 series")
            series(ax, selected, "n", "preparation_ns", 1e6, color, marker, label, line, 1000,
                   markersize=size)
    ax.set(title="(a) Commitment construction" if v2 else "(a) Data preparation",
           xlabel=r"Records, $N$",
           ylabel="Construction time (ms)" if v2 else "Preparation time (ms)")
    ax.set_xticks([0, 50, 100], labels=["0", "50k", "100k"])
    ax.set_ylim(bottom=0)
    handles, labels = ax.get_legend_handles_labels()
    if not construction:
        handles, labels = handles[::-1], labels[::-1]
    ax.legend(handles, labels, loc="upper left", frameon=False,
              handlelength=1.7, borderaxespad=0.2)
    sampling_rows, sampling_cfg = sampling if sampling else (rows, cfg)
    sizes = sampling_cfg["b2_records"]
    sizes = sizes if isinstance(sizes, list) else [sizes]
    if len(sizes) > 3:
        raise ValueError("figure layout supports at most three sampling sizes")
    for n, color, marker, line in zip(sizes, [BLUE, ORANGE, GREEN], ["o", "s", "^"],
                                     ["-", "--", "-."]):
        selected = sorted((r for r in sampling_rows if r["group"] == "B2" and int(r["n"]) == n),
                          key=lambda r: int(r["m"]))
        if len(selected) != len(sampling_cfg["b2_parameters"]) or any(
                r["dataset"] != sampling_cfg["b2_dataset"] for r in selected):
            raise ValueError("B2 configuration mismatch")
        label = rf"$N={n // 1000}\mathrm{{k}}$" if len(sizes) > 1 else None
        series(axes[1], selected, "m", "audit_component_ns", 1e6, color, marker, label, line)
    if len(sizes) > 1:
        axes[1].legend(loc="upper left", frameon=False, handlelength=1.8, borderaxespad=.2)
    axes[1].set(title="(b) Sample processing", xlabel=r"Sample size, $m$",
                ylabel="Total processing time (ms)")
    for ax in axes[1:]:
        ax.set_xlim(left=0)
        ax.set_ylim(bottom=0)
    return fig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offchain", type=Path, required=True)
    parser.add_argument("--sampling", type=Path, help="independently validated B2 scale sweep for panel (b)")
    parser.add_argument("--construction", type=Path, help="validated record-length sweep for panel (a)")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--preview", action="store_true", help="allow explicitly labelled preexperiment preview")
    args = parser.parse_args()
    checked = validate(args.offchain)
    cfg = json.loads((args.offchain/"config.json").read_text())
    if not args.preview and (cfg["stage"] != "linux-client-formal" or cfg["repetitions"] != 30):
        parser.error("paper figures require 30 formal Linux repetitions; use --preview for smoke data")
    with (args.offchain/"summary.csv").open() as f:
        rows = list(csv.DictReader(f))
    run = json.loads((args.offchain/"manifest.json").read_text())
    provenance = {name: hashlib.sha256((args.offchain/name).read_bytes()).hexdigest()
                  for name in ("raw.jsonl", "summary.csv", "config.json", "manifest.json")}
    report = {"source": str(args.offchain.resolve()), "source_sha256": provenance,
              "preview": args.preview, "measurement_schema": run.get("measurement_schema", "legacy"),
              "validation": checked, "reuse": reuse_summary(rows)}
    sampling = None
    if args.sampling:
        sampling_checked = validate(args.sampling)
        sampling_cfg = json.loads((args.sampling/"config.json").read_text())
        sampling_run = json.loads((args.sampling/"manifest.json").read_text())
        if not args.preview and (sampling_cfg["stage"] != "linux-client-formal" or
                                 sampling_cfg["repetitions"] != 30):
            parser.error("sampling panel requires 30 formal Linux repetitions")
        for name, sha in run["source_sha256"].items():
            if name.startswith(("cmd/admissionbench/", "6.3-certification/admissionbench/", "pkg/protocol/", "pkg/admission/")):
                if sampling_run["source_sha256"].get(name) != sha:
                    raise ValueError("sampling measurement core changed: " + name)
        if sampling_run.get("measurement_schema") != run.get("measurement_schema"):
            raise ValueError("measurement schemas differ")
        with (args.sampling/"summary.csv").open() as f:
            sampling = (list(csv.DictReader(f)), sampling_cfg)
        report["sampling"] = {
            "source": str(args.sampling.resolve()), "validation": sampling_checked,
            "source_sha256": {name: hashlib.sha256((args.sampling/name).read_bytes()).hexdigest()
                              for name in ("raw.jsonl", "summary.csv", "config.json", "manifest.json")}}
    construction = None
    if args.construction:
        construction_checked = validate_construction(args.construction)
        construction_cfg = json.loads((args.construction/"config.json").read_text())
        construction_run = json.loads((args.construction/"manifest.json").read_text())
        if not args.preview and (construction_cfg["stage"] != "linux-client-formal" or
                                 construction_cfg["repetitions"] != 30):
            parser.error("construction panel requires 30 formal Linux repetitions")
        protocol_sources = {name: digest for name, digest in run["source_sha256"].items()
                            if name.startswith("pkg/protocol/")}
        if not protocol_sources or protocol_sources != {
                name: digest for name, digest in construction_run["source_sha256"].items()
                if name.startswith("pkg/protocol/")}:
            raise ValueError("commitment protocol sources changed")
        with (args.construction/"summary.csv").open() as f:
            construction = (list(csv.DictReader(f)), construction_cfg)
        report["construction"] = {
            "source": str(args.construction.resolve()), "validation": construction_checked,
            "source_sha256": {name: hashlib.sha256((args.construction/name).read_bytes()).hexdigest()
                              for name in ("raw.jsonl", "summary.csv", "config.json", "manifest.json")}}
    report["plot_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.out.mkdir(parents=True, exist_ok=False)
    style()
    fig = cost_figure(rows, cfg, run.get("measurement_schema") == "commitment-v2", sampling, construction)
    prefix = "preview_" if args.preview else ""
    if args.preview:
        fig.text(.5, .99, "PREEXPERIMENT: validation preview only", ha="center", va="top", fontsize=8)
    fig.savefig(args.out/(prefix+"certification_cost.pdf"), metadata={
        "Title": prefix+"certification cost", "Subject": json.dumps({"offchain": provenance,
            "sampling": report.get("sampling", {}).get("source_sha256"),
            "construction": report.get("construction", {}).get("source_sha256")}),
        "Creator": "6.3-certification/plot_certification.py", "CreationDate": None, "ModDate": None})
    fig.savefig(args.out/(prefix+"certification_cost.png"), dpi=240)
    plt.close(fig)
    (args.out/"certification_summary.json").write_text(json.dumps(report, indent=2)+"\n")
    print(args.out)


if __name__ == "__main__":
    main()
