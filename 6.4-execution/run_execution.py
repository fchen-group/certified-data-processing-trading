#!/usr/bin/env python3
"""Run C2/C3 public-fixture compute measurements; never start cloud instances.

C1 attestation and the real protocol must be validated separately before formal
SGX measurements. Formal runs require a separately recorded acceptance decision for this build.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import signal
import statistics
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "6.3-certification"))
from prepare_adult import ROOT, parse_adult, fields


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, obj):
    with path.open("x") as f:
        json.dump(obj, f, indent=2, allow_nan=False)
        f.write("\n")


def positive_seconds(value):
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("timeout must be finite and positive")
    return seconds


def run_task(out, command, *, context, env, timeout, cwd=None, consume=None):
    """Retain diagnostics on any task failure, including invalid result output.

    Direct file output avoids waiting on inherited pipes after a launcher exits.
    Each invocation has its own process group so a timeout also stops its workers.
    """
    stdout, stderr = out / "failure.stdout", out / "failure.stderr"
    proc = None
    try:
        with stdout.open("xb") as output, stderr.open("xb") as errors:
            proc = subprocess.Popen(command, env=env, cwd=cwd, stdout=output,
                                    stderr=errors, start_new_session=True)
            try:
                proc.wait(timeout=timeout)
            except BaseException:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                raise
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, command)
        result = consume(stdout.read_text()) if consume else None
    except (Exception, KeyboardInterrupt) as exc:
        write(out / "failure.json", {
            **context, "command": command, "cwd": str(cwd or Path.cwd()),
            "timeout_seconds": timeout, "timed_out": isinstance(exc, subprocess.TimeoutExpired),
            "returncode": proc.returncode if proc else None,
            "error": f"{type(exc).__name__}: {exc}",
            "stdout_file": stdout.name, "stderr_file": stderr.name,
        })
        raise RuntimeError(f"execution batch stopped; diagnostics: {out / 'failure.json'}") from exc
    stdout.unlink()
    stderr.unlink()
    return result


def reference(case):
    path = ROOT / case["input"]
    rows, _ = parse_adult(path.read_bytes())
    n = case["n"]
    if not 0 < n <= len(rows):
        raise ValueError("invalid subset size")
    if case["task"] == "adult-income-v1":
        model_dir = ROOT / "data/adult/classification"
        manifest = json.loads((model_dir / "manifest.json").read_text())
        for name, expected in manifest["files"].items():
            if sha(model_dir / name) != expected:
                raise ValueError(f"model/reference artifact changed: {name}")
        if sha(model_dir / "transform.json") != sha(ROOT / "pkg/analyzer/adult_transform.json"):
            raise ValueError("reviewed transform differs from trained model")
        ref = json.loads((model_dir / "reference.json").read_text())
        if sha(path) != ref["test_sha256"]:
            raise ValueError("T2 requires the official held-out split in its recorded order")
        return {"count": n, "above_threshold": sum(ref["predictions"][:n])}
    if case["task"] != "adult-statistics-v1":
        raise ValueError("unknown task")
    result = {"count": n}
    for column, name in ((0, "age"), (12, "hours_per_week")):
        values = [int(fields(r)[column]) for r in rows[:n]]
        total, squares = sum(values), sum(v*v for v in values)
        result[name] = {"mean": total/n, "population_variance": (n*squares-total*total)/(n*n)}
    return result


def schedule(cases, repetitions, seed, backends):
    rng = random.Random(seed)
    result = []
    for repeat in range(repetitions):
        order = list(range(len(cases)))
        rng.shuffle(order)
        for i in order:
            modes = list(backends)
            if (repeat + i) % 2:
                modes.reverse()
            result.extend({"case": cases[i]["id"], "repeat": repeat+1, "backend": m} for m in modes)
    return result


def validate_point(point, case, mode, fixture_hash, procs):
    expected_clock = "clock_monotonic_raw" if platform.system() == "Linux" else "go_monotonic"
    if (point["schema"] != "public-fixture-compute-only-v1" or not point["validated"]
            or point.get("diagnostic", False)
            or point.get("clock") != expected_clock
            or point["n"] != case["n"] or point["task"] != case["task"]
            or point["fixture_sha256"] != fixture_hash or point["gomaxprocs"] != procs
            or point["go"] != "go1.26.1" or point["memory_limit"] != 768*1024*1024
            or point["backend"] != ("native" if mode == "native" else "sgx-build")):
        raise ValueError("measurement identity/configuration mismatch")
    phases = point["phases_ns"]
    if set(phases) != {"load_ciphertext", "decrypt_parse", "commitment", "analyze", "encrypt_sign"}:
        raise ValueError("unexpected phase boundaries")
    if min(phases.values()) <= 0 or sum(phases.values()) > point["total_ns"]:
        raise ValueError("invalid phase/total timings")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, default=ROOT / "configs/execution-formal.json")
    p.add_argument("--native-build", type=Path, required=True)
    p.add_argument("--sgx-build", type=Path)
    p.add_argument("--sgx-fixture-root", type=Path, help="host path under the SGX /input mount")
    p.add_argument("--prepare-timeout", type=positive_seconds, default=300,
                   help="wall-clock timeout per fixture preparation, in seconds (default: 300)")
    p.add_argument("--run-timeout", type=positive_seconds, default=300,
                   help="wall-clock timeout per benchmark process, in seconds (default: 300)")
    p.add_argument("--acceptance", type=Path, help="validated protocol/pilot acceptance for a formal run")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    cfg = json.loads(a.config.read_text())
    if cfg["stage"] not in ("pilot", "formal") or cfg["repetitions"] < 1 or cfg["gomaxprocs"] < 1:
        p.error("invalid measurement configuration")
    if cfg["stage"] == "formal" and (cfg["repetitions"] != 30 or not a.sgx_build or not a.acceptance):
        p.error("formal measurements require both backends, 30 repetitions and acceptance evidence")
    cases = {c["id"]: c for c in cfg["cases"]}
    if len(cases) != len(cfg["cases"]) or any("/" in k or ".." in k for k in cases):
        p.error("unique simple case names required")
    builds = {"native": a.native_build.resolve()}
    if a.sgx_build:
        if platform.system() != "Linux" or platform.machine() != "x86_64" or not a.sgx_fixture_root:
            p.error("SGX requires this same Linux x86_64 host and a fixture root mounted at /input")
        if os.environ.get("OE_SIMULATION"):
            p.error("simulation is not an SGX comparison")
        builds["sgx"] = a.sgx_build.resolve()
        if a.sgx_fixture_root.resolve() != builds["sgx"] / "input":
            p.error("the signed benchmark mounts its build-directory input/ at /input")
    manifests = {k: json.loads((v / "manifest.json").read_text()) for k, v in builds.items()}
    for mode, manifest in manifests.items():
        if manifest["mode"] != mode or not manifest.get("execution_benchmark"):
            p.error("use build.py --execution-bench with the matching mode")
        if sha(builds[mode] / "executionbench") != manifest.get("benchmark_sha256"):
            p.error("benchmark executable differs from the recorded build")
        # Fail if local code changed after the recorded build.
        for name, expected in manifest["files"].items():
            if name == "pkg/deployment/runtime.json" and mode == "sgx":
                continue  # production trust anchor is intentionally embedded at build time
            if sha(ROOT / name) != expected:
                p.error(f"source changed since build: {name}")
    if len(builds) == 2:
        for name, expected in manifests["native"]["files"].items():
            if name != "pkg/deployment/runtime.json" and manifests["sgx"]["files"].get(name) != expected:
                p.error("Native and SGX sources differ")
    acceptance = None
    if cfg["stage"] == "formal":
        acceptance = json.loads(a.acceptance.read_text())
        if (acceptance.get("validated") is not True
                or acceptance.get("source_hash") != manifests["sgx"]["source_hash"]
                or acceptance.get("mrenclave") != manifests["sgx"]["tools"]["mrenclave"]
                or acceptance.get("benchmark_sha256") != manifests["sgx"]["benchmark_sha256"]
                or not acceptance.get("protocol_evidence") or not acceptance.get("diagnostic_evidence")):
            p.error("acceptance evidence does not identify this validated build")
    a.out = a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=False)
    jobs = schedule(cfg["cases"], cfg["repetitions"], cfg["seed"], builds)
    write(a.out/"config.json", cfg)
    if acceptance is not None:
        write(a.out/"acceptance.json", acceptance)
    write(a.out/"schedule.json", jobs)
    environment = {"host": platform.platform(), "builds": manifests,
          "input_files": {c["input"]: sha(ROOT/c["input"]) for c in cases.values()},
          "timeouts_seconds": {"prepare": a.prepare_timeout, "measurement": a.run_timeout},
          "cache": "ciphertext verified before timing; host page cache warm",
          "gc": "one pre-timing collection; computation-triggered collections included"}
    write(a.out/"environment.json", environment)
    fixture_root = (a.sgx_fixture_root.resolve() if a.sgx_fixture_root else a.out / "fixtures")
    fixture_root.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, GOMAXPROCS=str(cfg["gomaxprocs"]))
    env.pop("GODEBUG", None)
    env.pop("GOGC", None)
    env.pop("GOMEMLIMIT", None)
    fixture_hashes = {}
    for name, case in cases.items():
        expected = a.out / (name + "-reference.json")
        write(expected, reference(case))
        command = [str(builds["native"] / "executionbench"), "-mode", "prepare", "-fixture", str(fixture_root/name),
                   "-input", str(ROOT/case["input"]), "-n", str(case["n"]), "-expected", str(expected)]
        if case["task"] == "adult-income-v1":
            command += ["-parameters", str(ROOT/"data/adult/classification/parameters.json")]
        fixture_hashes[name] = run_task(a.out, command, env=env, timeout=a.prepare_timeout,
            context={"stage": "prepare", "case": case, "backend": "native", "repeat": None},
            consume=lambda _: sha(fixture_root/name/"fixture.json"))
    environment["fixture_hashes"] = fixture_hashes
    (a.out/"environment.json").write_text(json.dumps(environment, indent=2, allow_nan=False) + "\n")
    groups = defaultdict(list)
    with (a.out/"observations.jsonl").open("x") as log:
        for index, job in enumerate(jobs):
            mode, name = job["backend"], job["case"]
            path = fixture_root/name
            command = [str(builds[mode]/"executionbench"), "-fixture", str(path)]
            if mode == "sgx":
                command = ["ego", "run", str(builds[mode]/"executionbench"), "-fixture", "/input/" + name]
            def consume(stdout):
                points = [json.loads(line) for line in stdout.splitlines() if line.startswith('{"')]
                if len(points) != 1:
                    raise ValueError("expected exactly one computation result")
                point = points[0]
                validate_point(point, cases[name], mode, fixture_hashes[name], cfg["gomaxprocs"])
                return point
            point = run_task(a.out, command, env=env, timeout=a.run_timeout, cwd=builds[mode],
                context={"stage": "measurement", "case": cases[name], "backend": mode,
                         "repeat": job["repeat"], "order": index}, consume=consume)
            point.update(case=name, repeat=job["repeat"], order=index)
            log.write(json.dumps(point, allow_nan=False) + "\n")
            log.flush()
            groups[(name, mode)].append(point)
    summary = []
    for (name, mode), points in groups.items():
        if len(points) != cfg["repetitions"]:
            raise ValueError("incomplete group")
        summary.append({"case": name,"backend": mode,"n": cases[name]["n"],"repetitions":len(points),
                        "mean_ns":statistics.mean(x["total_ns"] for x in points),
                        "mean_phases_ns": {k:statistics.mean(x["phases_ns"][k] for x in points) for k in points[0]["phases_ns"]}})
    write(a.out/"summary.json", summary)
    print(f"Validated {len(jobs)} {cfg['stage']} computations; {a.out}.")


if __name__ == "__main__":
    main()
