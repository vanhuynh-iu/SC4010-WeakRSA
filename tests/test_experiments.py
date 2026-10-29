"""Checks, benchmarks and plotting tests.

Plotting CSV values are unit fixtures, not measured project results.
"""

from contextlib import redirect_stdout
from copy import deepcopy
import csv
import hashlib
import importlib
import importlib.util
from io import StringIO
import json
import math
from pathlib import Path
from tempfile import TemporaryDirectory
import tracemalloc
import unittest
from unittest.mock import patch

import experiments
from experiments import generate_figures, load_memory_results, load_scalability_results
from batch_gcd_attack import scan_moduli_batch
from generators.shared_prime_cases import generate_shared_prime_keys
from key_recovery import encrypt_message
from shared_prime_attack import scan_moduli
from audit_pipeline import audit_public_keys
from build_dataset import save_dataset


class ScalabilityExperimentTests(unittest.TestCase):
    def save_toy(self, directory):
        public = [
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "B", "n": 253, "e": 17},
            {"key_id": "C", "n": 667, "e": 17},
        ]
        # This chain forces a full-GCD fallback.
        truth = {
            "A": {"p": 11, "q": 17, "case_type": "shared"},
            "B": {"p": 11, "q": 23, "case_type": "shared"},
            "C": {"p": 23, "q": 29, "case_type": "shared"},
        }
        save_dataset(directory, public, truth, ["A", "B", "C"],
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
            with patch("generators.shared_prime_cases.generate_scalability_dataset", side_effect=AssertionError("must reuse")):
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
            original = {str(p.relative_to(directories[0])): p.read_bytes() for p in directories[0].rglob("*") if p.is_file()}
            with self.assertRaisesRegex(ValueError, "profile"):
                experiments.prepare_scalability_datasets([10], root, 32)
            self.assertEqual({str(p.relative_to(directories[0])): p.read_bytes() for p in directories[0].rglob("*") if p.is_file()}, original)

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
        # Keep total calls valid to isolate the leaf-count check.
        result.update(batch_leaf_gcd_calls=1, pairwise_gcd_calls=1, fallback_gcd_calls=1)
        with self.assertRaisesRegex(ValueError, "leaf GCD"):
            experiments._factor_map(result, moduli, "batch_with_fallback", result["gcd_calls"])

    def test_import_is_job_free_and_invalid_settings_reject_before_work(self):
        with patch("generators.shared_prime_cases.generate_scalability_dataset", side_effect=AssertionError("no generation")), \
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


class CorrectnessCoverageCheckTests(unittest.TestCase):
    def toy_case(self):
        return {
            "public_keys": [{"key_id": "A", "n": 187, "e": 17},
                            {"key_id": "B", "n": 253, "e": 17},
                            {"key_id": "C", "n": 1147, "e": 17},
                            {"key_id": "D", "n": 187, "e": 3}],
            "private_truth": {"A": {"p": 11, "q": 17, "case_type": "shared"},
                              "B": {"p": 11, "q": 23, "case_type": "shared"},
                              "C": {"p": 31, "q": 37, "case_type": "control"},
                              "D": {"p": 11, "q": 17, "case_type": "duplicate"}},
            "expected_vulnerable_ids": ["A", "B", "D"],
        }

    def save_case(self, directory, case):
        save_dataset(directory, case["public_keys"], case["private_truth"],
                      case["expected_vulnerable_ids"])
        return Path(directory)

    def coverage_cases(self):
        complete = self.toy_case()
        complete["public_keys"] = complete["public_keys"][:3]
        complete["private_truth"].pop("D")
        complete["expected_vulnerable_ids"] = ["A", "B"]
        before = deepcopy(complete)
        before["public_keys"] = [r for r in before["public_keys"] if r["key_id"] != "B"]
        before["private_truth"].pop("B")
        before["expected_vulnerable_ids"] = []
        return before, complete

    def read_rows(self, output, filename):
        with (Path(output) / filename).open(newline="") as source:
            return list(csv.DictReader(source))

    def test_factor_only_correctness_counts_duplicates_without_claiming_decryption(self):
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "toy", self.toy_case())
            output = Path(root) / "checks"
            summary = experiments.run_shared_prime_correctness([directory], output)
            self.assertTrue(summary["all_runs_ok"])
            rows = self.read_rows(output, "shared_prime_correctness.csv")
            self.assertEqual(len(rows), 2)
            for row in rows:
                self.assertEqual(row["num_records"], "4")
                self.assertEqual(row["num_unique_moduli"], "3")
                self.assertEqual(row["duplicate_extra_records"], "1")
                self.assertEqual(row["recovered_unique_moduli"], "2")
                self.assertEqual(row["recovered_records"], "3")
                self.assertEqual(row["false_positive_moduli"], "0")
                self.assertEqual(row["false_negative_moduli"], "0")
                self.assertEqual(row["factor_products_verified"], "True")
                self.assertEqual(row["decryption_cases_checked"], "0")
                self.assertEqual(row["decryption_cases_passed"], "0")
                self.assertEqual(row["decryption_cases_attempted"], "0")
                self.assertEqual(row["run_status"], "success")
                self.assertIn("not a benchmark", row["measurement_kind"])
            self.assertEqual(rows[0]["gcd_calls"], "3")
            metadata = json.loads((output / "correctness_metadata.json").read_text())
            self.assertEqual(metadata["datasets"][0]["public_sha256"],
                             hashlib.sha256((directory / "public.json").read_bytes()).hexdigest())
            self.assertIn("experiments.py", metadata["source_sha256"])

    def test_oaep_duplicate_records_each_use_their_own_exponent(self):
        # Use 1024-bit keys for wrapper checks.
        case = generate_shared_prime_keys(3, 2, 1024)
        original = case["public_keys"][0]
        truth = case["private_truth"][original["key_id"]]
        phi = (truth["p"] - 1) * (truth["q"] - 1)
        alternate = next(e for e in range(3, 65537, 2) if math.gcd(e, phi) == 1)
        case["public_keys"].append(dict(original, key_id="duplicate", e=alternate))
        case["private_truth"]["duplicate"] = dict(truth)
        case["expected_vulnerable_ids"].append("duplicate")
        for record in case["public_keys"]:
            message = record["key_id"].encode()
            record["ciphertext"] = encrypt_message(message, record["n"], record["e"])
            case["private_truth"][record["key_id"]]["expected_message"] = message
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "oaep", case)
            output = Path(root) / "checks"
            summary = experiments.run_shared_prime_correctness([directory], output)
            self.assertTrue(summary["all_runs_ok"])
            for row in self.read_rows(output, "shared_prime_correctness.csv"):
                self.assertEqual(row["recovered_records"], "3")
                self.assertEqual(row["decryption_cases_checked"], "3")
                self.assertEqual(row["decryption_cases_passed"], "3")

    def test_coverage_four_rows_distinguish_not_checked_from_false(self):
        before, after = self.coverage_cases()
        with TemporaryDirectory() as root:
            before_dir = self.save_case(Path(root) / "before", before)
            after_dir = self.save_case(Path(root) / "after", after)
            output = Path(root) / "coverage"
            summary = experiments.run_coverage_experiment(before_dir, after_dir, "A", output)
            self.assertTrue(summary["all_runs_ok"])
            rows = self.read_rows(output, "coverage_results.csv")
            self.assertEqual(len(rows), 4)
            for row in rows:
                self.assertEqual(row["run_status"], "success")
                self.assertEqual(row["target_decryption_checked"], "False")
                self.assertEqual(row["target_decryption_verified"], "")
                if row["stage"] == "before":
                    self.assertEqual(row["companion_present"], "False")
                    self.assertEqual(row["target_status"], "no_shared_factor_in_dataset")
                    self.assertEqual(row["target_factors_verified"], "")
                    self.assertEqual(row["num_unique_moduli"], "2")
                else:
                    self.assertEqual(row["companion_present"], "True")
                    self.assertEqual(row["target_status"], "factored")
                    self.assertEqual(row["target_factors_verified"], "True")
                    self.assertEqual(row["num_unique_moduli"], "3")
            metadata = json.loads((output / "coverage_metadata.json").read_text())
            self.assertTrue(metadata["before_records_unchanged_in_after"])

    def test_coverage_rejects_changed_target_or_other_existing_record(self):
        for changed_id, extra in (("A", {"e": 3}), ("A", {"ciphertext": b"changed"}),
                                  ("C", {"e": 3})):
            with self.subTest(changed_id=changed_id, change=extra), TemporaryDirectory() as root:
                before, after = self.coverage_cases()
                for record in after["public_keys"]:
                    if record["key_id"] == changed_id:
                        record.update(extra)
                before_dir = self.save_case(Path(root) / "before", before)
                after_dir = self.save_case(Path(root) / "after", after)
                output = Path(root) / "checks"
                with self.assertRaisesRegex(ValueError, "remain identical"):
                    experiments.run_coverage_experiment(before_dir, after_dir, "A", output)
                self.assertFalse(output.exists())

    def test_algorithm_error_is_a_row_and_not_fake_success(self):
        def fail_batch(public, gcd_fn=None, *, algorithm="pairwise"):
            if algorithm == "batch_with_fallback":
                raise RuntimeError("intentional batch failure")
            return audit_public_keys(public, gcd_fn=gcd_fn, algorithm=algorithm)
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "toy", self.toy_case())
            output = Path(root) / "checks"
            with patch("experiments.audit_public_keys", side_effect=fail_batch):
                summary = experiments.run_shared_prime_correctness([directory], output)
            self.assertFalse(summary["all_runs_ok"])
            rows = self.read_rows(output, "shared_prime_correctness.csv")
            self.assertEqual(rows[0]["run_status"], "comparison_incomplete")
            self.assertEqual(rows[1]["run_status"], "error")
            self.assertEqual(rows[1]["scan_seconds"], "")
            self.assertEqual(rows[1]["recovered_unique_moduli"], "")
            self.assertEqual(rows[1]["decryption_cases_checked"], "")
            self.assertIn("intentional batch failure", rows[1]["error"])

    def test_mismatched_observed_labels_are_errors(self):
        case = self.toy_case()
        case["expected_vulnerable_ids"] = []
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "toy", case)
            output = Path(root) / "checks"
            summary = experiments.run_shared_prime_correctness([directory], output)
            self.assertFalse(summary["all_runs_ok"])
            for row in self.read_rows(output, "shared_prime_correctness.csv"):
                self.assertEqual(row["run_status"], "error")
                self.assertIn("observed dataset", row["error"])

    def test_mismatching_algorithms_are_retained_as_failed_checks(self):
        def omit_one(public, gcd_fn=None, *, algorithm="pairwise"):
            result = audit_public_keys(public, gcd_fn=gcd_fn, algorithm=algorithm)
            if algorithm == "batch_with_fallback":
                result["findings"][253].update(status="no_shared_factor_in_dataset", p=None, q=None,
                                                resolution_method=None)
                result["recovered_records"] = [r for r in result["recovered_records"] if r["n"] != 253]
            return result
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "toy", self.toy_case())
            output = Path(root) / "checks"
            with patch("experiments.audit_public_keys", side_effect=omit_one):
                summary = experiments.run_shared_prime_correctness([directory], output)
            self.assertFalse(summary["all_runs_ok"])
            rows = self.read_rows(output, "shared_prime_correctness.csv")
            self.assertEqual({row["run_status"] for row in rows}, {"mismatch"})
            self.assertEqual({row["algorithms_agree"] for row in rows}, {"False"})

    def test_outputs_are_not_overwritten(self):
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "toy", self.toy_case())
            output = Path(root) / "checks"
            experiments.run_shared_prime_correctness([directory], output)
            original = {p.name: p.read_bytes() for p in output.iterdir()}
            with patch("experiments.audit_public_keys", side_effect=AssertionError("must not run")):
                with self.assertRaises(FileExistsError):
                    experiments.run_shared_prime_correctness([directory], output)
            self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, original)

    def test_import_and_cli_modes_do_not_generate_or_benchmark(self):
        with patch("audit_pipeline.audit_public_keys", side_effect=AssertionError("no scan on import")), \
             patch("build_dataset.load_dataset", side_effect=AssertionError("no load on import")):
            importlib.reload(experiments)
        importlib.reload(experiments)
        with patch("experiments.prepare_scalability_datasets", side_effect=AssertionError("no generation")), \
             patch("experiments.run_scalability_experiment", side_effect=AssertionError("no benchmark")), \
             patch("experiments.run_shared_prime_correctness", return_value={"all_runs_ok": True}) as correctness, \
             patch("experiments.run_coverage_experiment", return_value={"all_runs_ok": True}) as coverage, \
             redirect_stdout(StringIO()):
            self.assertEqual(experiments.main(["--mode", "correctness", "--dataset-dirs", "fixture", "--output", "out"]), 0)
            correctness.assert_called_once_with(["fixture"], "out")
            self.assertEqual(experiments.main(["--mode", "coverage", "--before", "before", "--after", "after",
                                               "--target-key-id", "target", "--output", "out"]), 0)
            coverage.assert_called_once_with("before", "after", "target", "out")


SCALABILITY_FIELDS = [
    "num_unique_moduli", "algorithm", "gcd_backend", "modulus_bits",
    "topology_profile", "scan_seconds", "run_status", "agrees_with_reference", "gcd_calls",
]


MEMORY_FIELDS = [
    "num_unique_moduli", "algorithm", "gcd_backend", "modulus_bits",
    "topology_profile", "run_status", "agrees_with_reference", "peak_traced_bytes",
    "memory_method", "input_preloaded",
]


def _scalability_row(**changes):
    row = {
        "num_unique_moduli": 10, "algorithm": "pairwise", "gcd_backend": "euclidean",
        "modulus_bits": 2048, "topology_profile": "unit_fixture_only",
        "scan_seconds": 2, "run_status": "success", "agrees_with_reference": True,
        "gcd_calls": 45,
    }
    row.update(changes)
    return row


def _memory_row(**changes):
    row = {
        "num_unique_moduli": 10, "algorithm": "pairwise", "gcd_backend": "euclidean",
        "modulus_bits": 2048, "topology_profile": "unit_fixture_only",
        "run_status": "success", "agrees_with_reference": True,
        "peak_traced_bytes": 1024,
        "memory_method": "tracemalloc_peak_python_allocations", "input_preloaded": True,
    }
    row.update(changes)
    return row


def _write_csv(path, rows, fields=SCALABILITY_FIELDS):
    with Path(path).open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


class ResultAggregationTests(unittest.TestCase):
    def test_plot_cli_uses_saved_results_without_preparing_datasets(self):
        metadata = {"sources": {"scalability": {"included_rows": 2, "excluded_rows": 0,
                                                "exclusion_reasons": {}}},
                    "charts": [{"paths": ["runtime.png"]}]}
        with patch("experiments.prepare_scalability_datasets", side_effect=AssertionError("no generation")), \
             patch("experiments.run_scalability_experiment", side_effect=AssertionError("no benchmark")), \
             patch("experiments.generate_figures", return_value=metadata) as figures, \
             redirect_stdout(StringIO()):
            self.assertEqual(experiments.main(["--mode", "plot", "--input", "saved-results",
                                               "--output", "figures", "--overwrite-figures"]), 0)
        figures.assert_called_once_with("saved-results", "figures", True)

    def test_known_median_range_and_failed_trial_exclusions(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scalability_results.csv"
            _write_csv(path, [
                _scalability_row(scan_seconds=1),
                _scalability_row(scan_seconds=4),
                _scalability_row(scan_seconds=2),
                _scalability_row(run_status="error", scan_seconds="", gcd_calls=""),
                _scalability_row(scan_seconds=99, agrees_with_reference=False),
            ])
            report = load_scalability_results(path)
            self.assertEqual(len(report["groups"]), 1)
            group = report["groups"][0]
            self.assertEqual(group["trials"], 3)
            self.assertEqual(group["scan_seconds_median"], 2)
            self.assertEqual(group["scan_seconds_min"], 1)
            self.assertEqual(group["scan_seconds_max"], 4)
            self.assertEqual(group["gcd_calls"], 45)
            self.assertEqual(report["source"]["total_rows"], 5)
            self.assertEqual(report["source"]["included_rows"], 3)
            self.assertEqual(report["source"]["excluded_rows"], 2)
            self.assertEqual(report["source"]["exclusion_reasons"], {
                "run_status=error": 1, "reference_disagreement": 1,
            })
            self.assertEqual(report["source"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_backends_sizes_topologies_and_algorithms_remain_separate(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scalability_results.csv"
            _write_csv(path, [
                _scalability_row(),
                _scalability_row(gcd_backend="math.gcd", scan_seconds=6),
                _scalability_row(modulus_bits=1024, scan_seconds=8),
                _scalability_row(modulus_bits="2048;1024", scan_seconds=10),
                _scalability_row(topology_profile="other_unit_fixture", scan_seconds=12),
                _scalability_row(algorithm="batch_with_fallback", gcd_calls=10, scan_seconds=3),
            ])
            groups = load_scalability_results(path)["groups"]
            self.assertEqual(len(groups), 6)
            self.assertEqual(sorted(group["scan_seconds_median"] for group in groups), [2, 3, 6, 8, 10, 12])
            self.assertIn([1024, 2048], [group["modulus_bits"] for group in groups])

    def test_zero_is_kept_only_when_actually_recorded_and_valid(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scalability_results.csv"
            _write_csv(path, [_scalability_row(scan_seconds=0, run_status="ok")])
            self.assertEqual(load_scalability_results(path)["groups"][0]["scan_seconds_median"], 0)
            for invalid in ("", "NaN", "Infinity", -1):
                with self.subTest(scan_seconds=invalid):
                    _write_csv(path, [_scalability_row(scan_seconds=invalid)])
                    with self.assertRaises(ValueError):
                        load_scalability_results(path)

    def test_inconsistent_work_counts_and_missing_fields_are_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scalability_results.csv"
            _write_csv(path, [_scalability_row(gcd_calls=45), _scalability_row(gcd_calls=46)])
            with self.assertRaisesRegex(ValueError, "GCD counts vary"):
                load_scalability_results(path)
            _write_csv(path, [], fields=["num_unique_moduli", "scan_seconds"])
            with self.assertRaisesRegex(ValueError, "missing CSV fields"):
                load_scalability_results(path)

    def test_memory_is_separate_and_preloading_conditions_are_not_mixed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "memory_results.csv"
            _write_csv(path, [
                _memory_row(peak_traced_bytes=1024),
                _memory_row(peak_traced_bytes=3072),
                _memory_row(peak_traced_bytes=8192, input_preloaded=False),
                _memory_row(run_status="error", peak_traced_bytes=""),
                _memory_row(memory_method="process_rss"),
            ], MEMORY_FIELDS)
            report = load_memory_results(path)
            self.assertEqual(len(report["groups"]), 2)
            preloaded = next(group for group in report["groups"] if group["input_preloaded"])
            self.assertEqual(preloaded["peak_traced_bytes_median"], 2048)
            self.assertEqual(preloaded["peak_traced_bytes_min"], 1024)
            self.assertEqual(preloaded["peak_traced_bytes_max"], 3072)
            self.assertEqual(report["source"]["included_rows"], 3)
            self.assertEqual(report["source"]["excluded_rows"], 2)
            self.assertIn("unsupported_memory_method=process_rss", report["source"]["exclusion_reasons"])

    def test_all_failed_rows_cannot_create_figures(self):
        with TemporaryDirectory() as directory:
            results = Path(directory)
            _write_csv(results / "scalability_results.csv", [_scalability_row(run_status="error")])
            with self.assertRaisesRegex(ValueError, "No successful"):
                generate_figures(results)
            self.assertFalse((results / "figures").exists())


@unittest.skipUnless(importlib.util.find_spec("matplotlib") is not None, "optional Matplotlib is not installed")
class PlotOutputTests(unittest.TestCase):
    def test_png_svg_metadata_memory_and_no_overwrite(self):
        with TemporaryDirectory() as directory:
            results = Path(directory)
            _write_csv(results / "scalability_results.csv", [
                _scalability_row(scan_seconds=1),
                _scalability_row(scan_seconds=3),
                _scalability_row(algorithm="batch_with_fallback", gcd_calls=10, scan_seconds=0.5),
                _scalability_row(num_unique_moduli=20, gcd_calls=190, scan_seconds=4),
            ])
            _write_csv(results / "memory_results.csv", [_memory_row()], MEMORY_FIELDS)
            original_csv = (results / "scalability_results.csv").read_bytes()
            metadata = generate_figures(results)
            self.assertEqual(metadata["format"], "weak-rsa-figure-metadata")
            figures = results / "figures"
            for chart in ("runtime_by_unique_moduli", "gcd_calls_by_unique_moduli", "peak_traced_allocations"):
                png = figures / (chart + ".png")
                svg = figures / (chart + ".svg")
                self.assertTrue(png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))
                self.assertIn("<svg", svg.read_text(encoding="utf-8"))
            self.assertEqual(len(metadata["charts"]), 3)
            self.assertEqual(metadata["sources"]["scalability"]["included_rows"], 4)
            saved = json.loads((figures / "figure_metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(saved, metadata)
            self.assertEqual((results / "scalability_results.csv").read_bytes(), original_csv)
            with self.assertRaises(FileExistsError):
                generate_figures(results)
            alternate = results / "alternate_figures"
            generate_figures(results, alternate)
            generate_figures(results, alternate, overwrite=True)
            self.assertTrue((alternate / "figure_metadata.json").exists())


if __name__ == "__main__":
    unittest.main()
