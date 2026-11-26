import copy
import contextlib
import io
import json
import os
import platform
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import run_execution
from run_execution import schedule, validate_point


class ExecutionScheduleTests(unittest.TestCase):
    def test_complete_reproducible_balanced_pairs(self):
        cases = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        jobs = schedule(cases, 30, 42, ["native", "sgx"])
        self.assertEqual(jobs, schedule(cases, 30, 42, ["native", "sgx"]))
        self.assertEqual(len(jobs), 180)
        for case in cases:
            pairs = [jobs[i:i+2] for i in range(0, len(jobs), 2) if jobs[i]["case"] == case["id"]]
            self.assertEqual(len(pairs), 30)
            self.assertEqual(sum(p[0]["backend"] == "native" for p in pairs), 15)
            self.assertEqual({p[0]["repeat"] for p in pairs}, set(range(1, 31)))
            self.assertTrue(all(p[0]["case"] == p[1]["case"] and p[0]["repeat"] == p[1]["repeat"] for p in pairs))

    def test_reject_mixed_or_incomplete_measurements(self):
        case = {"task": "adult-income-v1", "n": 1000}
        point = {"schema": "public-fixture-compute-only-v1", "validated": True,
                 "task": case["task"], "n": 1000, "backend": "native", "gomaxprocs": 4,
                 "go": "go1.26.1", "memory_limit": 768*1024*1024,
                 "clock": "clock_monotonic_raw" if platform.system() == "Linux" else "go_monotonic",
                 "fixture_sha256": "hash", "total_ns": 6,
                 "phases_ns": {k: 1 for k in ("load_ciphertext", "decrypt_parse", "commitment", "analyze", "encrypt_sign")}}
        validate_point(point, case, "native", "hash", 4)
        for key, bad in (("n", 999), ("backend", "sgx-build"), ("gomaxprocs", 2), ("validated", False), ("total_ns", 4), ("go", "go1.26.2"), ("memory_limit", -1), ("clock", "unknown")):
            changed = copy.deepcopy(point)
            changed[key] = bad
            with self.assertRaises(ValueError):
                validate_point(changed, case, "native", "hash", 4)


class ExecutionFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.build = self.root / "build"
        self.build.mkdir()
        self.out = self.root / "result"
        self.config = self.root / "config.json"
        self.case = {"id": "small", "task": "adult-statistics-v1", "input": "records", "n": 1}
        self.config.write_text(json.dumps({"stage": "pilot", "seed": 42, "repetitions": 3,
                                           "gomaxprocs": 4, "cases": [self.case]}))
        (self.root / "records").write_text("public test fixture\n")

    def run_batch(self, behavior):
        # An actual subprocess exercises the driver's exit/output handling;
        # cryptographic computation is covered by the separate Go tests.
        exe = self.build / "executionbench"
        exe.write_text(f"#!{sys.executable}\n" + '''
import hashlib, json, sys, platform
from pathlib import Path
args = sys.argv[1:]
fixture = Path(args[args.index('-fixture') + 1])
behavior = BEHAVIOR
print('diagnostic stdout', flush=True)
print('diagnostic stderr', file=sys.stderr, flush=True)
if '-mode' in args:
    if behavior == 'prepare-failure': sys.exit(23)
    fixture.mkdir()
    (fixture / 'fixture.json').write_text('{}')
    sys.exit(0)
counter = Path('calls')
call = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(call))
if call == 2:
    if behavior == 'measurement-failure': sys.exit(24)
    if behavior == 'invalid-json':
        print('{"broken":')
        sys.exit(0)
point = {'schema': 'public-fixture-compute-only-v1', 'validated': True,
         'task': 'adult-statistics-v1', 'n': 1, 'backend': 'native',
         'gomaxprocs': 4, 'go': 'go1.26.1', 'memory_limit': 768*1024*1024,
         'clock': 'clock_monotonic_raw' if platform.system() == 'Linux' else 'go_monotonic',
         'fixture_sha256': hashlib.sha256((fixture / 'fixture.json').read_bytes()).hexdigest(),
         'total_ns': 6,
         'phases_ns': {k: 1 for k in ('load_ciphertext', 'decrypt_parse', 'commitment', 'analyze', 'encrypt_sign')}}
if call == 2 and behavior == 'invalid-result': point['n'] = 2
print(json.dumps(point))
'''.replace('BEHAVIOR', repr(behavior)))
        exe.chmod(0o700)
        (self.build / "manifest.json").write_text(json.dumps({
            "mode": "native", "execution_benchmark": True, "files": {},
            "benchmark_sha256": run_execution.sha(exe)}))
        argv = ["run_execution.py", "--config", str(self.config), "--native-build", str(self.build),
                "--out", str(self.out), "--prepare-timeout", "5", "--run-timeout", "5"]
        with patch.object(run_execution, "ROOT", self.root), patch.object(sys, "argv", argv), \
             patch.object(run_execution, "reference", return_value={"count": 1}), contextlib.redirect_stdout(io.StringIO()):
            run_execution.main()

    def failure(self):
        f = json.loads((self.out / "failure.json").read_text())
        self.assertEqual(f["case"], self.case)
        self.assertEqual(f["backend"], "native")
        self.assertIn("diagnostic stdout", (self.out / f["stdout_file"]).read_text())
        self.assertIn("diagnostic stderr", (self.out / f["stderr_file"]).read_text())
        self.assertTrue((self.out / "config.json").exists())
        self.assertTrue((self.out / "schedule.json").exists())
        self.assertEqual(json.loads((self.out / "environment.json").read_text())["timeouts_seconds"],
                         {"prepare": 5, "measurement": 5})
        self.assertFalse((self.out / "summary.json").exists())
        return f

    def test_preparation_failure_preserves_configuration_and_output(self):
        with self.assertRaises(RuntimeError):
            self.run_batch("prepare-failure")
        f = self.failure()
        self.assertEqual((f["stage"], f["repeat"], f["returncode"]), ("prepare", None, 23))
        self.assertFalse((self.out / "observations.jsonl").exists())

    def test_measurement_failure_preserves_completed_record_and_stops(self):
        with self.assertRaises(RuntimeError):
            self.run_batch("measurement-failure")
        f = self.failure()
        self.assertEqual((f["stage"], f["repeat"], f["order"], f["returncode"]), ("measurement", 2, 1, 24))
        self.assertEqual(len((self.out / "observations.jsonl").read_text().splitlines()), 1)
        self.assertEqual((self.build / "calls").read_text(), "2")

    def test_invalid_output_is_not_counted_as_success(self):
        with self.assertRaises(RuntimeError):
            self.run_batch("invalid-json")
        self.assertEqual(self.failure()["returncode"], 0)
        self.assertEqual(len((self.out / "observations.jsonl").read_text().splitlines()), 1)

    def test_invalid_measurement_is_not_counted_as_success(self):
        with self.assertRaises(RuntimeError):
            self.run_batch("invalid-result")
        self.assertIn("identity/configuration mismatch", self.failure()["error"])
        self.assertEqual(len((self.out / "observations.jsonl").read_text().splitlines()), 1)

    def test_success_keeps_all_results_without_failure_artifacts(self):
        self.run_batch("success")
        self.assertEqual(len((self.out / "observations.jsonl").read_text().splitlines()), 3)
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual((summary[0]["repetitions"], summary[0]["mean_ns"]), (3, 6))
        self.assertEqual(list(self.out.glob("failure.*")), [])

    def test_timeout_stops_child_process_group_and_retains_output(self):
        self.out.mkdir()
        script = '''
import subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
print(child.pid, flush=True)
print('before timeout', file=sys.stderr, flush=True)
time.sleep(60)
'''
        with self.assertRaises(RuntimeError):
            run_execution.run_task(self.out, [sys.executable, "-c", script],
                context={"stage": "measurement", "case": self.case, "backend": "native", "repeat": 1},
                env=os.environ.copy(), timeout=1)
        f = json.loads((self.out / "failure.json").read_text())
        self.assertTrue(f["timed_out"])
        self.assertEqual(f["returncode"], -signal.SIGKILL)
        self.assertIn("before timeout", (self.out / "failure.stderr").read_text())
        child = int((self.out / "failure.stdout").read_text().strip())
        try:
            # A killed child can briefly remain a zombie until adopted/reaped.
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(child)],
                                   capture_output=True, text=True, check=False)
            self.assertTrue(state.returncode == 1 or state.stdout.strip().startswith("Z"), state.stdout)
        finally:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_start_failure_is_recorded(self):
        self.out.mkdir()
        with self.assertRaises(RuntimeError):
            run_execution.run_task(self.out, [str(self.root / "missing-executable")],
                context={"stage": "prepare", "case": self.case, "backend": "native", "repeat": None},
                env=os.environ.copy(), timeout=1)
        f = json.loads((self.out / "failure.json").read_text())
        self.assertIsNone(f["returncode"])
        self.assertIn("FileNotFoundError", f["error"])


if __name__ == "__main__":
    unittest.main()
