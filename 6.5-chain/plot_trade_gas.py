#!/usr/bin/env python3
"""Render stacked trade gas by result size from verified transaction receipts."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "cdpt-matplotlib"))
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from summarize_trade_gas import summarize_measurement, require


def verified_summary(run):
    checked, evidence = summarize_measurement(run, require_formal=True)
    saved = json.loads((run / "summary.json").read_text())
    require(saved == checked, "saved summary differs from independent recomputation")
    return checked, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    args = parser.parse_args()
    checked, evidence = verified_summary(args.run)
    groups = sorted((v for k, v in checked["groups"].items() if k.startswith("D2/")),
                    key=lambda v: v["plaintext_bytes"])
    require([g["plaintext_bytes"] for g in groups] == [128, 512, 1024, 4096, 16384, 65536],
            "unexpected D2 matrix")
    require(all(g["samples"] == 5 for g in groups), "five samples per size required")
    # Use each D2 group's own receipts, not a fixed offset copied from D1.
    preceding_operations = ["registerTrade", "deposit", "confirmKey/DO", "confirmKey/DB"]
    preceding = [sum(g["operations_gas"][op]["mean"] for op in preceding_operations)
                 for g in groups]
    settlement = [g["operations_gas"]["settle"]["mean"] for g in groups]
    totals = [g["normal_five_call_gas"]["mean"] for g in groups]
    require(all(math.isclose(base + delivery, total, rel_tol=0, abs_tol=1e-6)
                for base, delivery, total in zip(preceding, settlement, totals)),
            "stacked costs differ from five-call receipt totals")
    args.out.mkdir(parents=True, exist_ok=False)
    times = Path("/System/Library/Fonts/Supplemental/Times New Roman.ttf")
    if times.exists():
        font_manager.fontManager.addfont(str(times))
    plt.rcParams.update({
        "font.family": "Times New Roman" if times.exists() else "STIXGeneral",
        "mathtext.fontset": "stix", "font.size": 9, "axes.labelsize": 9.5,
        "xtick.labelsize": 8.5, "ytick.labelsize": 8.5,
        "axes.linewidth": 0.7, "lines.linewidth": 1.35, "lines.markersize": 4,
        "pdf.fonttype": 42, "ps.fonttype": 42, "axes.unicode_minus": False,
        "savefig.facecolor": "white", "axes.spines.top": False, "axes.spines.right": False,
        "hatch.linewidth": .5,
    })
    fig, ax = plt.subplots(figsize=(4.8, 2.95))
    fig.subplots_adjust(left=.135, right=.985, bottom=.20, top=.96)
    x = list(range(len(groups)))
    base = [value / 1e6 for value in preceding]
    delivery = [value / 1e6 for value in settlement]
    y = [value / 1e6 for value in totals]
    ax.bar(x, base, width=.60, color="#0072B2", edgecolor="#222222",
           linewidth=.6, hatch="//", label="Registration, deposit & key confirmation")
    ax.bar(x, delivery, bottom=base, width=.60, color="#D55E00", edgecolor="#222222",
           linewidth=.6, label="Settlement & delivery")
    ax.set_xticks(x, labels=[f'{g["ciphertext_bytes"] / 1024:.2f}' for g in groups])
    upper = math.ceil(max(y) * 1.12 * 2) / 2
    step = .5 if upper <= 4 else 1
    ax.set(xlabel="Result ciphertext size (KiB)", ylabel=r"Total trade gas ($10^6$)",
           ylim=(0, upper), xlim=(-.6, len(groups) - .4))
    ax.set_yticks([i * step for i in range(math.floor(upper / step) + 1)])
    for position, total in zip(x, y):
        ax.annotate(f"{total:.3f}", (position, total), xytext=(0, 4),
                    textcoords="offset points", ha="center", va="bottom", fontsize=8.5)
    ax.legend(loc="upper left", frameon=False, fontsize=8.0,
              handlelength=1.7, handletextpad=.6, borderaxespad=.4, labelspacing=.45)
    ax.grid(axis="y", color="#E3E5E8", linewidth=.55)
    ax.set_axisbelow(True)
    ax.tick_params(width=.65, length=3, pad=3)
    provenance = {name: hashlib.sha256((args.run / name).read_bytes()).hexdigest()
                  for name in ("run.json", "verification.json", "summary.json")}
    fig.savefig(args.out / "result_delivery_cost.pdf", metadata={
        "Title": "Result delivery cost", "Subject": json.dumps(provenance),
        "Creator": "6.5-chain/plot_trade_gas.py", "CreationDate": None, "ModDate": None})
    plt.close(fig)
    (args.out / "provenance.json").write_text(json.dumps({
        "source": str(args.run.resolve()), "source_sha256": provenance,
        "formal_evidence": evidence,
        "plot_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "ciphertext_bytes": [g["ciphertext_bytes"] for g in groups],
        "mean_pre_settlement_gas": preceding,
        "mean_settlement_gas": settlement,
        "mean_total_trade_gas": totals,
        "pre_settlement_operations": preceding_operations,
        "excluded_costs": ["data certification", "deployment", "withdrawal", "refund"],
        "plot_type": "stacked bars; pre-settlement costs hatched, settlement solid",
        "x_axis": "equally spaced size categories; actual ciphertext KiB rounded to two decimals",
        "y_axis": "mean sum of five-call receipt gas divided by 1000000",
        "y_limits": [0, upper],
    }, indent=2) + "\n")
    print(args.out)


if __name__ == "__main__":
    main()
