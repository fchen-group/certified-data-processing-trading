#!/usr/bin/env python3
"""Run fresh-process, off-chain admission measurements. No SGX or chain calls."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STAGES = ("sample_ns", "challenge_encode_ns", "respond_ns", "response_encode_ns",
          "response_decode_ns", "verify_ns")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files():
    paths = [ROOT / "go.mod", ROOT / "go.sum"]
    for folder in ("6.3-certification", "pkg"):
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.is_file() and p.suffix in (".go", ".json", ".py"))
    paths.append(ROOT / "configs/admission-client-formal.json")
    paths.append(ROOT / "configs/admission-sampling-scaling-formal.json")
    return sorted(set(paths))


def cases(cfg):
    groups = cfg.get("groups", ["B1", "B2", "B3"])
    if not groups or len(set(groups)) != len(groups) or set(groups) - {"B1", "B2", "B3"}:
        raise ValueError("groups must be a nonempty selection of B1/B2/B3")
    if "B1" in groups:
        for dataset in cfg["datasets"]:
            sizes = cfg["b1_records"]
            for n in sizes[dataset] if isinstance(sizes, dict) else sizes:
                yield {"group": "B1", "dataset": dataset, "n": n,
                       "rho": cfg["rho"], "epsilon": cfg["epsilon"], "audits": 1}
    if "B2" in groups:
        sizes = cfg["b2_records"]
        for n in sizes if isinstance(sizes, list) else [sizes]:
            yield {"group": "B2", "dataset": cfg["b2_dataset"], "n": n,
                   "policies": cfg["b2_parameters"], "audits": 1}
    if "B3" in groups:
        for dataset in cfg.get("b3_datasets", cfg["datasets"]):
            yield {"group": "B3", "dataset": dataset, "n": cfg["b3_records"],
                   "rho": cfg["rho"], "epsilon": cfg["epsilon"], "audits": max(cfg["b3_checkpoints"])}


def memory_cases(cfg):
    for dataset, sizes in cfg.get("memory_records", {}).items():
        for n in sizes:
            yield {"group": "memory", "dataset": dataset, "n": n}


def policy_orders(count, repetitions, seed=None):
    """Randomized blocks of cyclic Latin rows; each position differs by <=1."""
    if count < 1 or repetitions < 1:
        raise ValueError("positive policy count and repetitions required")
    if seed is None:  # Preserve the pilot's recorded deterministic rotation.
        return [[(j+i) % count for j in range(count)] for i in range(repetitions)]
    rng = random.Random(seed)
    orders = []
    while len(orders) < repetitions:
        base = list(range(count))
        rng.shuffle(base)
        offsets = list(range(count))
        rng.shuffle(offsets)
        orders.extend(base[i:] + base[:i] for i in offsets[:repetitions-len(orders)])
    return orders


def host_info():
    info = {"system": platform.system(), "machine": platform.machine(), "kernel": platform.release(),
            "logical_cpus": os.cpu_count()}
    if platform.system() == "Linux":
        cpu = Path("/proc/cpuinfo").read_text()
        info["cpu_models"] = sorted({line.split(":", 1)[1].strip() for line in cpu.splitlines()
                                     if line.startswith("model name")})
        mem = Path("/proc/meminfo").read_text().splitlines()
        info["mem_total_bytes"] = int(next(line for line in mem if line.startswith("MemTotal:")).split()[1])*1024
        info["os_release"] = Path("/etc/os-release").read_text()
        info["load_average"] = os.getloadavg()
    return info


def validate_memory(spec, result, require_linux):
    if result["stage"] not in ("snapshot-memory-preexperiment", "snapshot-memory-formal") or result["n"] != spec["n"] or not result["retained_snapshot_verified"]:
        raise ValueError("invalid snapshot-memory measurement")
    if result["retained_heap_increment_bytes"] != result["retained_live_heap_bytes"]-result["baseline_live_heap_bytes"]:
        raise ValueError("inconsistent live heap accounting")
    if require_linux and (result["os"] != "linux" or not result["preparation_peak_rss_bytes"] or
                          not result["baseline_peak_rss_bytes"] or
                          result["preparation_peak_rss_bytes"] < result["baseline_peak_rss_bytes"]):
        raise ValueError("missing or inconsistent Linux peak RSS")


def summarize_memory(raw):
    grouped = {}
    for run in raw:
        grouped.setdefault((run["case"]["dataset"], run["case"]["n"]), []).append(run["measurement"])
    result = []
    for (dataset, n), values in grouped.items():
        row = {"dataset": dataset, "n": n, "repetitions": len(values)}
        for field in ("baseline_live_heap_bytes", "retained_live_heap_bytes", "retained_heap_increment_bytes",
                      "baseline_peak_rss_bytes", "preparation_peak_rss_bytes"):
            data = [v[field] for v in values]
            if all(v is None for v in data):
                row[field+"_mean"], row[field+"_stdev"] = "", ""
            elif any(v is None for v in data):
                raise ValueError("cannot combine supported and missing RSS measurements")
            else:
                row[field+"_mean"] = statistics.mean(data)
                row[field+"_stdev"] = statistics.stdev(data) if len(data)>1 else ""
        result.append(row)
    return result


def summarize(raw, checkpoints):
    """Aggregate independent trajectories, never treat their prefixes as repeats."""
    grouped = {}
    for run in raw:
        spec, r = run["case"], run["measurement"]
        settings = [("once", 1)] if spec["group"] != "B3" else [
            (mode, k) for k in checkpoints for mode in ("reuse", "reaudit")]
        prep = sum(r["preparation"].values())
        for mode, k in settings:
            active = r["audits"][:1 if mode == "reuse" else k]
            audit_ns = sum(a[name] for a in active for name in STAGES)
            metrics = {"preparation_ns": prep, "audit_component_ns": audit_ns,
                       "total_component_ns": prep + audit_ns,
                       "amortized_component_ns": (prep + audit_ns) / k,
                       "audit_count": len(active), "submitted_records": len(active)*r["m"],
                       "distinct_records": active[-1]["cumulative_distinct_records"],
                       "response_wire_bytes": sum(a["response_wire_bytes"] for a in active),
                       "challenge_wire_bytes": sum(a["challenge_wire_bytes"] for a in active),
                       "record_bytes": r["record_bytes"], "input_ciphertext_bytes": r["input_ciphertext_bytes"]}
            metrics.update(r["preparation"])
            metrics.update({name: sum(a[name] for a in active) for name in STAGES})
            key = (spec["group"], spec["dataset"], r["n"], r["dimensions"], r["m"],
                   r["rho"], r["epsilon"], mode, k)
            grouped.setdefault(key, []).append(metrics)
    result = []
    for key, samples in grouped.items():
        row = dict(zip(("group", "dataset", "n", "dimensions", "m", "rho", "epsilon", "mode", "k"), key))
        row["repetitions"] = len(samples)
        for metric in samples[0]:
            values = [s[metric] for s in samples]
            row[metric + "_mean"] = statistics.mean(values)
            row[metric + "_stdev"] = statistics.stdev(values) if len(values) > 1 else ""
        result.append(row)
    return result


def unpack_measurements(spec, measurements):
    """Validate a paired B2 sweep before accepting any point for aggregation."""
    if spec["group"] != "B2":
        return [(spec, measurements)]
    policies = spec["policies"]
    if not policies or len(measurements) != len(policies):
        raise ValueError("incomplete B2 sweep")
    if len({(p["rho"], p["epsilon"]) for p in policies}) != len(policies):
        raise ValueError("duplicate B2 policies")
    if len({r["commitment"] for r in measurements}) != 1:
        raise ValueError("B2 policies did not share a salted snapshot")
    points = []
    for p, r in zip(policies, measurements):
        if (r["rho"], r["epsilon"], r["n"]) != (p["rho"], p["epsilon"], spec["n"]):
            raise ValueError("B2 measurement differs from requested policy or input size")
        if r["preparation"] != measurements[0]["preparation"]:
            raise ValueError("B2 preparation was not shared")
        points.append(({k: v for k, v in spec.items() if k != "policies"} | p | {"policy_position": len(points)+1}, r))
    return points


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/admission-client-formal.json")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    if cfg["stage"] not in ("local-preexperiment", "linux-client-preexperiment", "linux-client-formal") or cfg["repetitions"] <= 0 or cfg["gomaxprocs"] <= 0:
        parser.error("invalid measurement configuration")
    formal = cfg["stage"] == "linux-client-formal"
    if formal and type(cfg.get("order_seed")) is not int:
        parser.error("formal measurement requires a fixed integer order_seed")
    hardware = host_info()
    require_linux = cfg["stage"].startswith("linux-client-")
    if require_linux and (hardware["system"] != "Linux" or hardware["machine"] != "x86_64"):
        parser.error("Linux client configuration requires Linux x86_64")
    if cfg["gomaxprocs"] > hardware["logical_cpus"]:
        parser.error("configured parallelism exceeds host logical CPUs")
    checkpoints = cfg["b3_checkpoints"]
    if not checkpoints or sorted(set(checkpoints)) != checkpoints or checkpoints[0] < 1:
        parser.error("checkpoints must be positive, sorted and unique")
    if max(checkpoints) > cfg["challenge_budget"]:
        parser.error("challenge budget is insufficient")
    policies = cfg["b2_parameters"]
    if not policies or len(policies) > cfg["challenge_budget"] or len({(p["rho"], p["epsilon"]) for p in policies}) != len(policies):
        parser.error("B2 requires unique policies within the challenge budget")
    orders = policy_orders(len(policies), cfg["repetitions"], cfg.get("order_seed"))
    inputs = ROOT / cfg["prepared_dir"]
    data_manifest = json.loads((inputs / "manifest.json").read_text())
    record_format = cfg.get("record_format", "work2.score-record.v1")
    if record_format == "adult.raw.v1" and data_manifest.get("record_format") != record_format:
        parser.error("input format does not match the dataset manifest")
    if cfg.get("measurement_schema", "commitment-v2") != "commitment-v2":
        parser.error("this executable measures commitment-v2; use archived code for old timing scopes")
    files = {entry["file"]: entry for entry in data_manifest["outputs"]}
    requested = list(cases(cfg))
    if not requested:
        parser.error("empty timing configuration")
    case_orders = (policy_orders(len(requested), cfg["repetitions"], cfg["order_seed"]+1)
                   if cfg.get("balance_case_order") else [list(range(len(requested)))]*cfg["repetitions"])
    if len({(r["group"], r["dataset"], r["n"]) for r in requested}) != len(requested):
        parser.error("duplicate timing measurement configuration")
    memory_requested = list(memory_cases(cfg))
    if len({(r["dataset"],r["n"]) for r in memory_requested}) != len(memory_requested):
        parser.error("duplicate memory measurement configuration")
    if memory_requested and record_format != "work2.score-record.v1":
        parser.error("legacy memory profiling is not part of the full-record remeasurement")
    all_requested = requested + memory_requested
    for spec in all_requested:
        name = spec["dataset"]
        if name not in files or Path(name).name != name:
            parser.error("dataset not in preparation manifest")
        if not 0 < spec["n"] <= files[name]["records"]:
            parser.error("record count outside prepared dataset")
    for name in {case["dataset"] for case in all_requested}:
        if digest(inputs / name) != files[name]["sha256"]:
            parser.error("prepared input changed: " + name)
    result_group = "6.3-certification" if formal else "history"
    out = args.out or ROOT / "results" / result_group / (("admission-formal-" if formal else "admission-pilot-") + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(args.config, out / "config.json")
    shutil.copyfile(inputs / "manifest.json", out / "data-manifest.json")
    env = dict(os.environ, GOTOOLCHAIN="go1.26.1", GOWORK="off", GOFLAGS="", GOGC="100", GOMEMLIMIT="off", GODEBUG="")
    manifest = {"status": "running", "started_utc": datetime.now(timezone.utc).isoformat(),
                "measurement_schema": "commitment-v2", "record_format": record_format,
                "stage": cfg["stage"], "host": platform.platform(), "machine": platform.machine(),
                "logical_cpus": os.cpu_count(), "python": platform.python_version(),
                "hardware": hardware, "runtime_environment": {k:env[k] for k in ("GOTOOLCHAIN","GOWORK","GOGC","GOMEMLIMIT","GODEBUG")},
                "scope": "off-chain component times, not full certification or transaction latency",
                "excludes": ["record boundary selection and schema validation", "file I/O", "process startup", "chain checks and transactions",
                             "TLS/network transfer", "business review", "SGX"],
                "memory_profile": "separate fresh processes, after all time measurements; never included in timing aggregates",
                "memory_enabled": bool(memory_requested),
                "memory_peak_rss": "Linux VmHWM through input loading, normalization, salting and tree construction; includes startup/runtime, not tree-only memory or EPC; null on non-Linux",
                "memory_retention": "live Go HeapAlloc after GC with only the retained snapshot; baseline delta is an estimate including runtime caches, not exact object size or RSS",
                "snapshot_ns": "immutable record/salt copy, proof-tree construction AND final N/root commitment; once per trajectory",
                "salt_prepare_ns": "independent crypto/rand salts and necessary record copies",
                "preparation_scope": "loaded record bytes to salts, retained proof tree and final commitment; no per-record JSON conversion for Adult",
                "wire_bytes": "compact JSON Challenge/Response envelopes; no TLS/TCP headers or business evidence",
                "reuse_comparison": "shared measured first preparation/audit; reaudit extends the same retained snapshot; reuse has no later audit work",
                "b2_sweep": "one process and salted snapshot per dataset/size/repetition; saved policy order; preparation shared, not additive across policy points",
                "b2_policy_orders": orders, "order_seed": cfg.get("order_seed"),
                "case_grid": requested, "case_orders": case_orders,
                "order_design": "randomized cyclic Latin blocks" if cfg.get("order_seed") is not None else "cyclic rotation",
                "trajectory_state": "local budget only; each process is an independent measurement, not a production budget reset",
                "aggregation": "sums of timed components; prefix/amortized values derived from raw measurements, not end-to-end wall time",
                "randomness": "crypto/rand for salts and challenges; recorded challenge positions; no deterministic protocol secrets",
                "correctness": "every response serialized, decoded and verified; execution reconstruction and tampered-record checks after timing",
                "config_sha256": digest(out / "config.json"), "data_manifest_sha256": digest(out / "data-manifest.json")}
    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    raw = []
    memory_raw = []
    processes = 0
    memory_processes = 0
    try:
        (ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="admission-build-", dir=ROOT / "tmp") as temp:
            stage = Path(temp)
            hashes = {}
            # Compile from a frozen copy and preserve that exact source snapshot.
            with tarfile.open(out / "source.tar.gz", "w:gz") as archive:
                for src in source_files():
                    relative = src.relative_to(ROOT)
                    target = stage / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(src, target)
                    hashes[str(relative)] = digest(target)
                    archive.add(target, arcname=str(relative))
            manifest["source_sha256"] = hashes
            manifest["source_archive_sha256"] = digest(out / "source.tar.gz")
            manifest["go"] = subprocess.check_output(["go", "version"], env=env, text=True).strip()
            binary = stage / "admissionbench"
            build = ["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=",
                     "-o", str(binary), "./6.3-certification/admissionbench"]
            with (out / "build.log").open("w") as log:
                subprocess.run(build, cwd=stage, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            manifest["binary_sha256"] = digest(binary)
            manifest["build_command"] = build[:7] + ["<temporary-binary>", "./6.3-certification/admissionbench"]
            with (out / "raw.jsonl").open("w") as raw_file:
                for repetition in range(1, cfg["repetitions"] + 1):
                    for case_index in case_orders[repetition-1]:
                        spec = dict(requested[case_index])
                        if spec["group"] == "B2":
                            policies = spec["policies"]
                            spec["policies"] = [policies[i] for i in orders[repetition-1]]
                        command = [str(binary), "-input", str(inputs / spec["dataset"]), "-records", str(spec["n"]),
                                   "-format", record_format, "-audits", str(spec["audits"]),
                                   "-budget", str(cfg["challenge_budget"]), "-gomaxprocs", str(cfg["gomaxprocs"])]
                        if formal:
                            command += ["-stage", "formal"]
                        if spec["group"] == "B2":
                            command += ["-policies", json.dumps(spec["policies"])]
                        else:
                            command += ["-rho", str(spec["rho"]), "-epsilon", str(spec["epsilon"])]
                        proc = subprocess.run(command, capture_output=True, text=True, env=env)
                        process_id = processes + 1
                        entry = {"repetition": repetition, "process_id": process_id, "case": spec, "returncode": proc.returncode}
                        if proc.returncode:
                            entry.update(stderr=proc.stderr, stdout=proc.stdout)
                            raw_file.write(json.dumps(entry, separators=(",", ":")) + "\n")
                            raw_file.flush()
                            raise RuntimeError("case failed; raw output retained: " + str(spec))
                        try:
                            points = unpack_measurements(spec, json.loads(proc.stdout))
                        except (ValueError, KeyError, TypeError):
                            entry.update(stdout=proc.stdout, stderr=proc.stderr, validation_failed=True)
                            raw_file.write(json.dumps(entry, separators=(",", ":")) + "\n")
                            raw_file.flush()
                            raise
                        for point, measurement in points:
                            if (measurement.get("measurement_schema") != "commitment-v2" or
                                measurement.get("record_format") != record_format or
                                measurement["dimensions"] != files[spec["dataset"]]["dimensions"] or
                                not all(measurement["checks"].values())):
                                raise ValueError("measurement format or correctness check mismatch")
                            row = {**entry, "case": point, "measurement": measurement}
                            raw_file.write(json.dumps(row, separators=(",", ":")) + "\n")
                            raw.append(row)
                        raw_file.flush()
                        processes += 1
                    print(f"completed repetition {repetition}/{cfg['repetitions']}", flush=True)
            if memory_requested:
                with (out / "memory-raw.jsonl").open("w") as memory_file:
                    for repetition in range(1, cfg["repetitions"] + 1):
                        for spec in memory_requested:
                            proc = subprocess.run([str(binary), "-profile", "memory", "-input", str(inputs/spec["dataset"]),
                                                   "-records", str(spec["n"]), "-gomaxprocs", str(cfg["gomaxprocs"])] +
                                                  (["-stage", "formal"] if formal else []),
                                                  capture_output=True, text=True, env=env)
                            entry = {"repetition": repetition, "case": spec, "returncode": proc.returncode}
                            try:
                                if proc.returncode:
                                    raise RuntimeError("memory process failed")
                                result = json.loads(proc.stdout)
                                validate_memory(spec, result, require_linux)
                                entry["measurement"] = result
                            except (ValueError, KeyError, TypeError, RuntimeError):
                                entry.update(stdout=proc.stdout, stderr=proc.stderr, validation_failed=True)
                                memory_file.write(json.dumps(entry, separators=(",", ":"))+"\n")
                                memory_file.flush()
                                raise
                            memory_file.write(json.dumps(entry, separators=(",", ":"))+"\n")
                            memory_file.flush()
                            memory_raw.append(entry)
                            memory_processes += 1
                        print(f"completed memory repetition {repetition}/{cfg['repetitions']}", flush=True)
        for name in {case["dataset"] for case in all_requested}:
            if digest(inputs / name) != files[name]["sha256"]:
                raise RuntimeError("input changed during measurement")
        summary = summarize(raw, checkpoints)
        with (out / "summary.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(summary[0]))
            writer.writeheader()
            writer.writerows(summary)
        if memory_raw:
            memory_summary = summarize_memory(memory_raw)
            with (out/"memory-summary.csv").open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=list(memory_summary[0]))
                writer.writeheader()
                writer.writerows(memory_summary)
        manifest.update(status="complete", successful_processes=processes, measurement_points=len(raw), summary_rows=len(summary),
                        successful_memory_processes=memory_processes)
    except BaseException as exc:
        manifest.update(status="failed", error=str(exc), successful_processes=processes, measurement_points=len(raw),
                        successful_memory_processes=memory_processes)
        raise
    finally:
        manifest["ended_utc"] = datetime.now(timezone.utc).isoformat()
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(out)


if __name__ == "__main__":
    main()
