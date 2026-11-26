import copy
import json
from pathlib import Path
import unittest

from run_admission_pilot import STAGES, summarize, unpack_measurements, summarize_memory, validate_memory, policy_orders, cases, memory_cases


class AggregationTests(unittest.TestCase):
    def test_formal_order_balance_including_incomplete_blocks(self):
        for count, repeats in ((9, 30), (3, 30), (9, 2), (1, 30)):
            orders = policy_orders(count, repeats, 20261030)
            self.assertEqual(orders, policy_orders(count, repeats, 20261030))
            self.assertEqual(len(orders), repeats)
            self.assertTrue(all(sorted(row) == list(range(count)) for row in orders))
            for policy in range(count):
                counts = [sum(row[pos] == policy for row in orders) for pos in range(count)]
                self.assertLessEqual(max(counts)-min(counts), 1)
        self.assertNotEqual(policy_orders(9,30,1), policy_orders(9,30,2))
        self.assertEqual(policy_orders(3,4), [[0,1,2],[1,2,0],[2,0,1],[0,1,2]])

    def test_formal_grid_and_trajectory_count(self):
        cfg = json.loads((Path(__file__).resolve().parents[1]/'configs/admission-client-formal.json').read_text())
        grid = list(cases(cfg))
        self.assertEqual(len(grid)*cfg['repetitions'], 330)
        self.assertEqual(len(list(memory_cases(cfg)))*cfg['repetitions'], 0)
        self.assertEqual([(r['dataset'],r['n']) for r in grid if r['group']=='B1'],
                         [('adult-full.csv',n) for n in (1000,5000,10000,48842)] +
                         [('synthetic-full.csv',n) for n in (1000,5000,10000,50000,100000)])
        self.assertEqual(len(next(r for r in grid if r['group']=='B2')['policies']),9)
        self.assertEqual([r['audits'] for r in grid if r['group']=='B3'],[10])

    def test_memory_units_and_missing_rss_are_not_silently_zero(self):
        spec = {"dataset":"x", "n":1000}
        measurement = {"stage":"snapshot-memory-preexperiment", "os":"linux", "n":1000,
                       "retained_snapshot_verified":True, "baseline_live_heap_bytes":100,
                       "retained_live_heap_bytes":300, "retained_heap_increment_bytes":200,
                       "baseline_peak_rss_bytes":4096, "preparation_peak_rss_bytes":8192}
        validate_memory(spec, measurement, True)
        raw = [{"case":spec,"measurement":measurement} for _ in range(2)]
        summary = summarize_memory(raw)[0]
        self.assertEqual(summary["preparation_peak_rss_bytes_mean"],8192)
        self.assertEqual(summary["retained_heap_increment_bytes_mean"],200)
        bad = dict(measurement, preparation_peak_rss_bytes=None, baseline_peak_rss_bytes=None)
        with self.assertRaises(ValueError): validate_memory(spec,bad,True)
        with self.assertRaises(ValueError): summarize_memory(raw+[{"case":spec,"measurement":bad}])
        missing = summarize_memory([{"case":spec,"measurement":bad}])[0]
        self.assertEqual(missing["preparation_peak_rss_bytes_mean"], "")
        with self.assertRaises(ValueError): validate_memory(spec,dict(measurement,retained_heap_increment_bytes=42),False)

    def test_sampling_scaling_grid(self):
        cfg = json.loads((Path(__file__).resolve().parents[1]/'configs/admission-sampling-scaling-formal.json').read_text())
        grid = list(cases(cfg))
        self.assertEqual([(c['group'],c['dataset'],c['n']) for c in grid],
                         [('B2','synthetic-full.csv',n) for n in (1000,10000,100000)])
        self.assertEqual(len(grid)*cfg['repetitions'],90)
        self.assertEqual(sum(len(c['policies']) for c in grid)*cfg['repetitions'],810)
        self.assertTrue(cfg['balance_case_order'])
        for groups in ([],['B2','B2'],['B4']):
            with self.assertRaises(ValueError): list(cases(dict(cfg,groups=groups)))

    def test_b2_points_share_process_snapshot_and_remain_distinct_parameters(self):
        spec = {"group": "B2", "dataset": "x", "n": 1000, "audits": 1,
                "policies": [{"rho": .05, "epsilon": .01}, {"rho": .05, "epsilon": .001}]}
        measurements = [{**p, "n": 1000, "commitment": "same", "preparation": {"snapshot_ns": 10}}
                        for p in spec["policies"]]
        points = unpack_measurements(spec, measurements)
        self.assertEqual(len(points), 2)
        self.assertEqual(points[1][0]["epsilon"], .001)
        self.assertNotIn("policies", points[0][0])
        bad = copy.deepcopy(measurements)
        bad[1]["commitment"] = "different"
        with self.assertRaises(ValueError):
            unpack_measurements(spec, bad)
        bad = copy.deepcopy(measurements)
        bad[1]["preparation"]["snapshot_ns"] = 11
        with self.assertRaises(ValueError):
            unpack_measurements(spec, bad)

    def test_reuse_does_not_charge_tree_again_and_prefixes_are_not_repetitions(self):
        raw = []
        for rep, step in ((1, 10), (2, 20)):
            audits = []
            for i in range(1, 4):
                audits.append({**{name: step for name in STAGES}, "cumulative_distinct_records": i+1,
                               "response_wire_bytes": 100, "challenge_wire_bytes": 20})
            raw.append({"case": {"group": "B3", "dataset": "x"}, "repetition": rep,
                        "measurement": {"preparation": {"normalize_ns": 100, "salt_prepare_ns": 20, "snapshot_ns": 80},
                                        "audits": audits, "n": 10, "dimensions": 2, "m": 2, "rho": .1,
                                        "epsilon": .01, "record_bytes": 500, "input_ciphertext_bytes": 1000}})
        rows = summarize(raw, [1, 3])
        reuse = next(r for r in rows if r["mode"] == "reuse" and r["k"] == 3)
        reaudit = next(r for r in rows if r["mode"] == "reaudit" and r["k"] == 3)
        self.assertEqual(reuse["repetitions"], 2)
        self.assertEqual(reuse["total_component_ns_mean"], 200 + 15*len(STAGES))
        self.assertEqual(reaudit["total_component_ns_mean"], 200 + 3*15*len(STAGES))
        self.assertEqual(reuse["response_wire_bytes_mean"], 100)
        self.assertEqual(reaudit["response_wire_bytes_mean"], 300)
        self.assertEqual(reuse["distinct_records_mean"], 2)
        self.assertEqual(reaudit["distinct_records_mean"], 4)
        self.assertEqual(reuse["submitted_records_mean"], 2)
        self.assertEqual(reaudit["submitted_records_mean"], 6)


if __name__ == "__main__":
    unittest.main()
