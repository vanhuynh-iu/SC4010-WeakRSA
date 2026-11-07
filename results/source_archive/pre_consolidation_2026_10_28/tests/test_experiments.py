"""Tests for the shared-prime scalability support runner.

Only tiny saved arithmetic fixtures are used; no RSA-2048 benchmark runs.
"""

import csv
import hashlib
import importlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import tracemalloc
import unittest
from unittest.mock import patch

import experiments
from batch_gcd_attack import scan_moduli_batch
from shared_prime_attack import scan_moduli
from shared_prime_fixtures import save_fixtures


class ScalabilityExperimentTests(unittest.TestCase):
    def save_toy(self, directory):
        public = [
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "B", "n": 253, "e": 17},
            {"key_id": "C", "n": 667, "e": 17},
        ]
        # B and C also share 23, giving a real full-GCD fallback case.
        truth = {
            "A": {"p": 11, "q": 17, "case_type": "shared"},
            "B": {"p": 11, "q": 23, "case_type": "shared"},
            "C": {"p": 23, "q": 29, "case_type": "shared"},
        }
        save_fixtures(directory, public, truth, ["A", "B", "C"], integer_encoding="hex",
                      metadata={"topology_profile": "toy_chain"})
        return Path(directory)

    def read_csv(self, output, name="scalability_results.csv"):
        with (Path(output) / name).open(newline="") as source:
            return list(csv.DictReader(source))

    def test_prepare_tiny_fixed_profiles_reuses_matching_checksum(self):
        with TemporaryDirectory() as root:
            dataset_root = Path(root) / "inputs"
            directories = experiments.prepare_scalability_datasets([10, 20], dataset_root, 32)
            original = {str(path): (path / "public.json").read_bytes() for path in directories}
            with patch("key_generation.generate_scalability_dataset", side_effect=AssertionError("must reuse")):
                reused = experiments.prepare_scalability_datasets([10, 20], dataset_root, 32)
            self.assertEqual(directories, reused)
            for size, directory in zip((10, 20), directories):
                dataset = experiments._load_dataset(directory)
                self.assertEqual(dataset["normalized"]["num_records"], size)
                self.assertEqual(dataset["normalized"]["num_unique_moduli"], size)
                self.assertEqual(dataset["bits"], [32])
                self.assertEqual(len(dataset["reference"]), size // 5)
                self.assertEqual((directory / "public.json").read_bytes(), original[str(directory)])
                self.assertEqual(dataset["dataset_sha256"], hashlib.sha256(original[str(directory)]).hexdigest())

    def test_prepare_rejects_bad_existing_profile_without_overwriting(self):
        with TemporaryDirectory() as root:
            directories = experiments.prepare_scalability_datasets([10], root, 32)
            manifest_path = directories[0] / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["construction_metadata"]["modulus_bits"] = 64
            manifest_path.write_text(json.dumps(manifest))
            original = {p.name: p.read_bytes() for p in directories[0].iterdir()}
            with self.assertRaisesRegex(ValueError, "profile"):
                experiments.prepare_scalability_datasets([10], root, 32)
            self.assertEqual({p.name: p.read_bytes() for p in directories[0].iterdir()}, original)

    def test_counts_checksums_backend_and_json_csv_roundtrip(self):
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "input")
            output = Path(root) / "results"
            summary = experiments.run_scalability_experiment([directory], output, trials=2, warmups=1,
                                                             gcd_backend="math", measure_memory=False)
            rows = self.read_csv(output)
            self.assertEqual(len(rows), 4)
            self.assertTrue(summary["all_runs_ok"])
            expected_sha = hashlib.sha256((directory / "public.json").read_bytes()).hexdigest()
            for row in rows:
                self.assertEqual(row["dataset_sha256"], expected_sha)
                self.assertEqual(row["gcd_backend"], "math")
                self.assertEqual(row["num_records"], "3")
                self.assertEqual(row["num_unique_moduli"], "3")
                self.assertEqual(row["recovered_unique_moduli"], "3")
                self.assertEqual(row["agrees_with_reference"], "True")
                self.assertEqual(row["algorithms_agree"], "True")
                self.assertEqual(row["run_status"], "success")
                self.assertEqual(row["actual_gcd_calls"], row["gcd_calls"])
                if row["algorithm"] == "pairwise":
                    self.assertEqual(row["pairwise_gcd_calls"], "3")
                    self.assertEqual(row["batch_leaf_gcd_calls"], "0")
            self.assertEqual(json.loads((output / "summary.json").read_text()), summary)
            self.assertEqual(self.read_csv(output, "memory_results.csv"), [])
            metadata = json.loads((output / "run_metadata.json").read_text())
            self.assertEqual(metadata["gcd_backend"], "math")
            self.assertEqual(len(metadata["warmup_results"]), 2)
            self.assertEqual(metadata["datasets"][0]["public_sha256"], expected_sha)
            self.assertIn("experiments.py", metadata["source_sha256"])
            self.assertIn("dirty", metadata["git"])
            for stat in summary["statistics"]:
                self.assertEqual(stat["trials_completed"], 2)
                self.assertLessEqual(stat["min_seconds"], stat["median_seconds"])
                self.assertLessEqual(stat["median_seconds"], stat["max_seconds"])

    def test_alternating_trials_warmups_and_memory_are_separate_fresh_calls(self):
        events, result_objects = [], []
        def recording(name, scanner):
            def call(moduli, gcd_fn=None):
                events.append((name, tracemalloc.is_tracing(), id(moduli)))
                result = scanner(moduli, gcd_fn=gcd_fn)
                result_objects.append(result)
                return result
            return call
        scanners = {"pairwise": recording("pairwise", scan_moduli),
                    "batch_with_fallback": recording("batch_with_fallback", scan_moduli_batch)}
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "input")
            output = Path(root) / "results"
            with patch("experiments._scanner_functions", return_value=scanners):
                summary = experiments.run_scalability_experiment([directory], output, trials=3, warmups=1)
            self.assertTrue(summary["all_runs_ok"])
            self.assertEqual([name for name, _, _ in events], [
                "pairwise", "batch_with_fallback",  # Separate warm-up.
                "pairwise", "batch_with_fallback",  # Trial 0.
                "batch_with_fallback", "pairwise",  # Trial 1.
                "pairwise", "batch_with_fallback",  # Trial 2.
                "pairwise", "batch_with_fallback",  # Separate memory pass.
            ])
            self.assertEqual([tracing for _, tracing, _ in events], [False] * 8 + [True] * 2)
            self.assertEqual(len({identity for _, _, identity in events}), 1)
            self.assertEqual(len({id(result) for result in result_objects}), 10)
            self.assertFalse(tracemalloc.is_tracing())
            rows = self.read_csv(output)
            self.assertEqual(len(rows), 6)
            self.assertEqual([row["trial_index"] for row in rows], ["0", "0", "1", "1", "2", "2"])
            memory = self.read_csv(output, "memory_results.csv")
            self.assertEqual(len(memory), 2)
            self.assertTrue(all(row["input_preloaded"] == "True" for row in memory))
            self.assertTrue(all(row["memory_method"] == "tracemalloc_peak_python_allocations" for row in memory))
            self.assertTrue(all(row["topology_profile"] == "toy_chain" for row in memory))
            self.assertTrue(all(int(row["peak_traced_bytes"]) > 0 for row in memory))

    def test_timing_clock_wraps_scans_and_summary_uses_every_successful_trial(self):
        ticks = [100, 200, 300, 600, 700, 1200, 1300, 2000]
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "input")
            output = Path(root) / "results"
            with patch("experiments.perf_counter_ns", side_effect=ticks):
                summary = experiments.run_scalability_experiment([directory], output, trials=2, warmups=0,
                                                                 measure_memory=False)
            rows = self.read_csv(output)
            self.assertEqual([float(row["scan_seconds"]) for row in rows], [1e-7, 3e-7, 5e-7, 7e-7])
            by_algorithm = {stat["algorithm"]: stat for stat in summary["statistics"]}
            self.assertAlmostEqual(by_algorithm["pairwise"]["median_seconds"], 4e-7)
            self.assertAlmostEqual(by_algorithm["batch_with_fallback"]["median_seconds"], 4e-7)
            self.assertEqual(by_algorithm["pairwise"]["trials_completed"], 2)

    def test_mismatch_is_retained_and_never_reported_as_passed_timing(self):
        def wrong_batch(moduli, gcd_fn=None):
            result = scan_moduli_batch(moduli, gcd_fn=gcd_fn)
            for finding in result["findings"].values():
                finding.update(status="no_shared_factor_in_dataset", p=None, q=None,
                               resolution_method=None)
            return result
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "input")
            output = Path(root) / "results"
            with patch("experiments._scanner_functions", return_value={"pairwise": scan_moduli,
                                                                       "batch_with_fallback": wrong_batch}):
                summary = experiments.run_scalability_experiment([directory], output, trials=1, warmups=0,
                                                                 measure_memory=False)
            rows = self.read_csv(output)
            self.assertFalse(summary["all_runs_ok"])
            self.assertEqual({row["run_status"] for row in rows}, {"mismatch"})
            self.assertEqual({row["algorithms_agree"] for row in rows}, {"False"})
            self.assertEqual([row["agrees_with_reference"] for row in rows], ["True", "False"])
            for stat in summary["statistics"]:
                self.assertEqual(stat["trials_completed"], 0)
                self.assertIsNone(stat["median_seconds"])

    def test_error_rows_preserve_missing_measurements_and_incomplete_comparison(self):
        def broken_batch(moduli, gcd_fn=None):
            gcd_fn(moduli[0], moduli[1])
            raise RuntimeError("intentional failure")
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "input")
            output = Path(root) / "results"
            with patch("experiments._scanner_functions", return_value={"pairwise": scan_moduli,
                                                                       "batch_with_fallback": broken_batch}):
                summary = experiments.run_scalability_experiment([directory], output, trials=1, warmups=0,
                                                                 measure_memory=False)
            rows = self.read_csv(output)
            self.assertFalse(summary["all_runs_ok"])
            self.assertEqual(rows[0]["run_status"], "comparison_incomplete")
            self.assertEqual(rows[1]["run_status"], "error")
            self.assertEqual(rows[1]["scan_seconds"], "")
            self.assertEqual(rows[1]["gcd_calls"], "")
            self.assertEqual(rows[1]["actual_gcd_calls"], "1")
            self.assertIn("intentional failure", rows[1]["error"])

    def test_output_files_never_overwritten_or_scanned_again(self):
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "input")
            output = Path(root) / "results"
            experiments.run_scalability_experiment([directory], output, trials=1, warmups=0, measure_memory=False)
            summary = json.loads((output / "summary.json").read_text())
            self.assertTrue(all(stat["stdev_seconds"] is None for stat in summary["statistics"]))
            original = {path.name: path.read_bytes() for path in output.iterdir()}
            with patch("experiments._scanner_functions", side_effect=AssertionError("must not run")):
                with self.assertRaises(FileExistsError):
                    experiments.run_scalability_experiment([directory], output)
            self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, original)

    def test_incorrect_reported_gcd_counter_is_an_error(self):
        def incorrect_counter(moduli, gcd_fn=None):
            result = scan_moduli(moduli, gcd_fn=gcd_fn)
            result["gcd_calls"] += 1
            return result
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "input")
            output = Path(root) / "results"
            with patch("experiments._scanner_functions", return_value={"pairwise": incorrect_counter,
                                                                       "batch_with_fallback": scan_moduli_batch}):
                summary = experiments.run_scalability_experiment([directory], output, trials=1, warmups=0,
                                                                 measure_memory=False)
            self.assertFalse(summary["all_runs_ok"])
            self.assertIn("actual backend calls", self.read_csv(output)[0]["error"])

    def test_complete_batch_rejects_unresolved_controls_and_missing_leaf_calls(self):
        moduli = [187, 667]  # Independent two-prime controls.
        for reported_unresolved in (0, 1):
            with self.subTest(reported_unresolved=reported_unresolved):
                result = scan_moduli_batch(moduli)
                result["findings"][187]["status"] = "unresolved_full_gcd"
                result["unresolved_after_fallback"] = reported_unresolved
                with self.assertRaisesRegex(ValueError, "unresolved"):
                    experiments._factor_map(result, moduli, "batch_with_fallback", result["gcd_calls"])
        result = scan_moduli_batch(moduli)
        # Preserve the total-call equation to isolate the leaf-count guard.
        result.update(batch_leaf_gcd_calls=1, pairwise_gcd_calls=1, fallback_gcd_calls=1)
        with self.assertRaisesRegex(ValueError, "leaf GCD"):
            experiments._factor_map(result, moduli, "batch_with_fallback", result["gcd_calls"])

    def test_import_is_job_free_and_invalid_settings_reject_before_work(self):
        with patch("key_generation.generate_scalability_dataset", side_effect=AssertionError("no generation")), \
             patch("shared_prime_attack.scan_moduli", side_effect=AssertionError("no scans")):
            importlib.reload(experiments)
        importlib.reload(experiments)
        for kwargs in ({"trials": 0}, {"trials": True}, {"warmups": -1},
                       {"gcd_backend": "unknown"}, {"measure_memory": 1}):
            with self.subTest(kwargs=kwargs), TemporaryDirectory() as root:
                with self.assertRaises(ValueError):
                    experiments.run_scalability_experiment([], Path(root) / "output", **kwargs)
        with TemporaryDirectory() as root:
            tracemalloc.start()
            try:
                with self.assertRaisesRegex(RuntimeError, "tracemalloc"):
                    experiments.run_scalability_experiment([], Path(root) / "output")
            finally:
                tracemalloc.stop()


if __name__ == "__main__":
    unittest.main()
