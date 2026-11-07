"""Correctness/coverage checks on toy and 1024-bit test inputs."""

from contextlib import redirect_stdout
from copy import deepcopy
import csv
import hashlib
import importlib
from io import StringIO
import json
import math
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import experiment_checks
import experiments
from key_generation import generate_shared_prime_keys
from key_recovery import encrypt_message
from shared_prime_auditor import audit_public_keys
from shared_prime_fixtures import save_fixtures


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
        save_fixtures(directory, case["public_keys"], case["private_truth"],
                      case["expected_vulnerable_ids"], integer_encoding="hex")
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
            summary = experiment_checks.run_shared_prime_correctness([directory], output)
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
            self.assertIn("experiment_checks.py", metadata["source_sha256"])

    def test_oaep_duplicate_records_each_use_their_own_exponent(self):
        # Wrapper correctness only: explicit small test keys, no 2048-bit job.
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
            summary = experiment_checks.run_shared_prime_correctness([directory], output)
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
            summary = experiment_checks.run_coverage_experiment(before_dir, after_dir, "A", output)
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
                    experiment_checks.run_coverage_experiment(before_dir, after_dir, "A", output)
                self.assertFalse(output.exists())

    def test_algorithm_error_is_a_row_and_not_fake_success(self):
        def fail_batch(public, gcd_fn=None, *, algorithm="pairwise"):
            if algorithm == "batch_with_fallback":
                raise RuntimeError("intentional batch failure")
            return audit_public_keys(public, gcd_fn=gcd_fn, algorithm=algorithm)
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "toy", self.toy_case())
            output = Path(root) / "checks"
            with patch("experiment_checks.audit_public_keys", side_effect=fail_batch):
                summary = experiment_checks.run_shared_prime_correctness([directory], output)
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
            summary = experiment_checks.run_shared_prime_correctness([directory], output)
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
            with patch("experiment_checks.audit_public_keys", side_effect=omit_one):
                summary = experiment_checks.run_shared_prime_correctness([directory], output)
            self.assertFalse(summary["all_runs_ok"])
            rows = self.read_rows(output, "shared_prime_correctness.csv")
            self.assertEqual({row["run_status"] for row in rows}, {"mismatch"})
            self.assertEqual({row["algorithms_agree"] for row in rows}, {"False"})

    def test_outputs_are_not_overwritten(self):
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "toy", self.toy_case())
            output = Path(root) / "checks"
            experiment_checks.run_shared_prime_correctness([directory], output)
            original = {p.name: p.read_bytes() for p in output.iterdir()}
            with patch("experiment_checks.audit_public_keys", side_effect=AssertionError("must not run")):
                with self.assertRaises(FileExistsError):
                    experiment_checks.run_shared_prime_correctness([directory], output)
            self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, original)

    def test_import_and_cli_modes_do_not_generate_or_benchmark(self):
        with patch("shared_prime_auditor.audit_public_keys", side_effect=AssertionError("no scan on import")), \
             patch("shared_prime_fixtures.load_fixtures", side_effect=AssertionError("no load on import")):
            importlib.reload(experiment_checks)
        importlib.reload(experiment_checks)
        with patch("experiments.prepare_scalability_datasets", side_effect=AssertionError("no generation")), \
             patch("experiments.run_scalability_experiment", side_effect=AssertionError("no benchmark")), \
             patch("experiment_checks.run_shared_prime_correctness", return_value={"all_runs_ok": True}) as correctness, \
             patch("experiment_checks.run_coverage_experiment", return_value={"all_runs_ok": True}) as coverage, \
             redirect_stdout(StringIO()):
            self.assertEqual(experiments.main(["--mode", "correctness", "--dataset-dirs", "fixture", "--output", "out"]), 0)
            correctness.assert_called_once_with(["fixture"], "out")
            self.assertEqual(experiments.main(["--mode", "coverage", "--before", "before", "--after", "after",
                                               "--target-key-id", "target", "--output", "out"]), 0)
            coverage.assert_called_once_with("before", "after", "target", "out")


if __name__ == "__main__":
    unittest.main()
