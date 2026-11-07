"""Independent evaluator and fresh three-mode measurement checks.

Small arithmetic fixtures are unit inputs, not project benchmark findings.
"""

from contextlib import redirect_stdout
from copy import deepcopy
import csv
import hashlib
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from rsa_auditor import audit_pipeline
from rsa_auditor.experiments import comparison as compare_modes
from rsa_auditor.experiments import cli as experiments
from rsa_auditor.datasets.storage import save_dataset
from rsa_auditor.evaluation import build_reference, evaluate_audit, expected_moduli


def toy_case():
    pairs = (("A", 11, 17), ("B", 11, 23), ("C", 101, 401),
             ("D", 1009, 1013), ("E", 10007, 20011), ("copy", 11, 17))
    public = [{"key_id": key_id, "n": p * q, "e": 3 if key_id == "copy" else 17}
              for key_id, p, q in pairs]
    truth = {key_id: {"p": p, "q": q, "case_type": "private-label", "actual_gap": q - p}
             for key_id, p, q in pairs}
    return {"public_keys": public, "private_truth": truth, "expected_vulnerable_ids": ["A", "B", "copy"]}


class IndependentEvaluationTests(unittest.TestCase):
    def test_reference_uses_distinct_moduli_and_exact_fermat_budget_boundary(self):
        case = toy_case()
        reference = build_reference(case)
        self.assertEqual(reference["gcd_moduli"], {187, 253})
        self.assertEqual(reference["fermat_candidates"][101 * 401], 50)
        self.assertNotIn(101 * 401, expected_moduli(reference, "fermat", 49))
        self.assertIn(101 * 401, expected_moduli(reference, "fermat", 50))
        self.assertEqual(expected_moduli(reference, "combined", 16), {187, 253, 1009 * 1013})
        self.assertEqual(expected_moduli(reference, "fermat", 0), set())
        self.assertEqual(expected_moduli(reference, "combined", 0), {187, 253})
        duplicate_only = {"public_keys": [case["public_keys"][0], case["public_keys"][-1]],
                          "private_truth": {key: case["private_truth"][key] for key in ("A", "copy")}}
        self.assertEqual(build_reference(duplicate_only)["gcd_moduli"], set())

    def test_reference_rejects_invalid_prime_truth_and_ignores_labels(self):
        case = toy_case()
        case["private_truth"]["C"]["case_type"] = "control"
        self.assertIn(101 * 401, expected_moduli(build_reference(case), "fermat", 50))
        case["public_keys"][0]["n"] = 9 * 17
        case["private_truth"]["A"]["p"] = 9
        with self.assertRaisesRegex(ValueError, "composite"):
            build_reference(case)

    def test_evaluator_checks_original_exponents_duplicate_mapping_and_factors(self):
        case = toy_case()
        report = audit_pipeline.run_audit(case["public_keys"], mode="combined", fermat_budget=16)
        summary = evaluate_audit(case, report, {})
        self.assertTrue(summary["success"])
        self.assertEqual(summary["recovered_unique_moduli"], 3)
        self.assertEqual(summary["recovered_records"], 4)
        self.assertEqual(summary["decryption_cases_checked"], 0)
        self.assertIsNone(summary["all_decryptions_verified"])
        changed = deepcopy(report)
        changed["recovered_records"][-1]["e"] += 2
        with self.assertRaisesRegex(ValueError, "exponent"):
            evaluate_audit(case, changed, {})
        changed = deepcopy(report)
        changed["findings"][187]["p"] = 5
        with self.assertRaisesRegex(ValueError, "factor product"):
            evaluate_audit(case, changed, {})
        changed = deepcopy(report)
        changed["recovered_records"].pop()
        with self.assertRaisesRegex(ValueError, "every factored"):
            evaluate_audit(case, changed, {})

    def test_evaluator_counts_only_actual_verified_plaintexts(self):
        case = toy_case()
        case["public_keys"][0]["ciphertext"] = b"unit ciphertext placeholder"
        case["private_truth"]["A"]["expected_message"] = b"expected"
        report = audit_pipeline.run_audit(case["public_keys"], mode="gcd", fermat_budget=16)
        checked = evaluate_audit(case, report, {"A": b"expected"})
        self.assertEqual(checked["decryption_cases_attempted"], 1)
        self.assertEqual(checked["decryption_cases_checked"], 1)
        self.assertEqual(checked["decryption_cases_passed"], 1)
        failed = evaluate_audit(case, report, {"A": b"wrong"})
        self.assertFalse(failed["success"])
        self.assertEqual(failed["decryption_cases_passed"], 0)
        with self.assertRaisesRegex(ValueError, "decryption outputs"):
            evaluate_audit(case, report, {})

    def test_record_order_is_irrelevant_but_duplicates_and_nonrecords_are_rejected(self):
        case = toy_case()
        report = audit_pipeline.run_audit(case["public_keys"], mode="combined", fermat_budget=16)
        report["record_findings"].reverse()
        report["recovered_records"].reverse()
        self.assertTrue(evaluate_audit(case, report, {})["success"])
        for field in ("record_findings", "recovered_records"):
            with self.subTest(field=field, invalid="duplicate"):
                changed = deepcopy(report)
                changed[field].append(deepcopy(changed[field][0]))
                with self.assertRaises(ValueError):
                    evaluate_audit(case, changed, {})
            with self.subTest(field=field, invalid="nonrecord"):
                changed = deepcopy(report)
                changed[field][0] = None
                with self.assertRaises(ValueError):
                    evaluate_audit(case, changed, {})

    def test_evaluator_rejects_zeroed_counts_even_when_internal_totals_match(self):
        case = toy_case()
        report = audit_pipeline.run_audit(case["public_keys"], mode="fermat", fermat_budget=16)
        self.assertGreater(report["fermat_candidate_tests"], 0)
        report["fermat_candidate_tests"] = 0
        for finding in report["findings"].values():
            finding["fermat_candidate_tests"] = 0
        for record in report["record_findings"]:
            record["fermat_candidate_tests"] = 0
        with self.assertRaisesRegex(ValueError, "independent search distance"):
            evaluate_audit(case, report, {})

    def test_evaluator_rejects_exhaustion_relabelled_as_not_run(self):
        case = toy_case()
        report = audit_pipeline.run_audit(case["public_keys"], mode="combined", fermat_budget=16)
        n = 101 * 401
        self.assertEqual(report["findings"][n]["fermat_status"], "budget_exhausted")
        report["findings"][n].update(fermat_status="not_run", fermat_candidate_tests=0)
        for record in report["record_findings"]:
            if record["n"] == n:
                record.update(fermat_status="not_run", fermat_candidate_tests=0)
        report["fermat_candidate_tests"] -= 16
        report["fermat_attempted_moduli"] -= 1
        report["fermat_exhausted_moduli"] -= 1
        with self.assertRaisesRegex(ValueError, "independent search distance"):
            evaluate_audit(case, report, {})

    def test_evaluator_rejects_wrong_backend_method_and_record_stage_mapping(self):
        case = toy_case()
        report = audit_pipeline.run_audit(case["public_keys"], mode="combined", fermat_budget=16)
        changed = deepcopy(report)
        changed["findings"][187]["resolution_method"] = "pairwise"
        with self.assertRaisesRegex(ValueError, "selected backend"):
            evaluate_audit(case, changed, {})
        changed = deepcopy(report)
        changed["record_findings"][0]["fermat_status"] = "budget_exhausted"
        with self.assertRaisesRegex(ValueError, "per-record"):
            evaluate_audit(case, changed, {})
        changed = deepcopy(report)
        changed["recovered_records"][0]["status"] = "budget_exhausted"
        with self.assertRaisesRegex(ValueError, "per-record"):
            evaluate_audit(case, changed, {})


class ModeComparisonTests(unittest.TestCase):
    def save_toy(self, directory):
        case = toy_case()
        save_dataset(directory, case["public_keys"], case["private_truth"], case["expected_vulnerable_ids"])
        return Path(directory)

    def read_csv(self, directory, name="mode_comparison.csv"):
        with (Path(directory) / name).open(newline="") as source:
            return list(csv.DictReader(source))

    def test_real_scans_compare_fresh_modes_budgets_union_counts_and_gap_rows(self):
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "fixture")
            output = Path(root) / "results"
            original = (directory / "public.json").read_bytes()
            calls = []
            real_run = audit_pipeline.run_audit
            def observed(records, **options):
                self.assertTrue(all(set(record) <= {"key_id", "n", "e", "ciphertext"} for record in records))
                calls.append((records, options.copy()))
                return real_run(records, **options)
            with patch("rsa_auditor.audit_pipeline.run_audit", side_effect=observed):
                summary = compare_modes.run_mode_comparison(directory, output, [16, 256], 3, "batch")
            self.assertTrue(summary["all_runs_ok"])
            self.assertEqual(len(calls), 18)
            self.assertEqual(len({id(records) for records, _ in calls}), 18)
            self.assertEqual((directory / "public.json").read_bytes(), original)
            self.assertTrue(all(item["combined_union_agreement"] for item in summary["comparisons"]))
            rows = self.read_csv(output)
            self.assertEqual(len(rows), 18)
            expected_sha = hashlib.sha256(original).hexdigest()
            self.assertTrue(all(row["dataset_sha256"] == expected_sha for row in rows))
            self.assertEqual(len({row["mode_order"] for row in rows}), 3)
            for row in rows:
                self.assertEqual(row["run_status"], "success")
                self.assertEqual(row["decryption_cases_passed"], "0")
                if row["mode"] == "combined":
                    self.assertEqual(row["recovered_via_gcd_moduli"], "2")
                    self.assertEqual(row["recovered_via_fermat_moduli"], "1" if row["fermat_budget"] == "16" else "2")
            gap_rows = self.read_csv(output, "fermat_gap_budget.csv")
            self.assertEqual(len(gap_rows), 18 * 5)
            c_rows = [row for row in gap_rows if row["modulus_hex"] == hex(101 * 401) and row["mode"] == "fermat"]
            self.assertTrue(all(row["fermat_status"] == "budget_exhausted" for row in c_rows if row["fermat_budget"] == "16"))
            self.assertTrue(all(row["fermat_status"] == "factored" for row in c_rows if row["fermat_budget"] == "256"))
            self.assertTrue(all(row["required_fermat_candidates"] == "50" for row in c_rows))
            metadata = json.loads((output / "run_metadata.json").read_text())
            self.assertIn("rsa_auditor/evaluation.py", metadata["source_sha256"])
            self.assertIn("rsa_auditor/attacks/fermat.py", metadata["source_sha256"])
            self.assertIn("rsa_auditor/datasets/storage.py", metadata["source_sha256"])
            self.assertEqual(metadata["public_sha256"], expected_sha)
            self.assertIn("recovery/OAEP", metadata["excluded_from_timing"])

    def test_candidate_counts_checked_independently_not_just_summed(self):
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "fixture")
            output = Path(root) / "results"
            real_run = audit_pipeline.run_audit
            def wrong_counter(records, **options):
                report = real_run(records, **options)
                if options["mode"] == "fermat":
                    report["findings"][187]["fermat_candidate_tests"] += 1
                    report["fermat_candidate_tests"] += 1
                return report
            with patch("rsa_auditor.audit_pipeline.run_audit", side_effect=wrong_counter):
                summary = compare_modes.run_mode_comparison(directory, output, [16], 1)
            self.assertFalse(summary["all_runs_ok"])
            failed = next(row for row in self.read_csv(output) if row["mode"] == "fermat")
            self.assertEqual(failed["run_status"], "error")
            self.assertIn("independent search distance", failed["error"])

    def test_failures_remain_explicit_and_not_zero_success_measurements(self):
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "fixture")
            output = Path(root) / "results"
            real_run = audit_pipeline.run_audit
            def broken(records, **options):
                if options["mode"] == "fermat":
                    raise RuntimeError("deliberate unit failure")
                return real_run(records, **options)
            with patch("rsa_auditor.audit_pipeline.run_audit", side_effect=broken):
                summary = compare_modes.run_mode_comparison(directory, output, [16], 1)
            self.assertFalse(summary["all_runs_ok"])
            failed = next(row for row in self.read_csv(output) if row["mode"] == "fermat")
            self.assertEqual(failed["run_status"], "error")
            self.assertEqual(failed["scan_seconds"], "")
            self.assertEqual(failed["recovered_unique_moduli"], "")
            self.assertIn("deliberate unit failure", failed["error"])
            self.assertTrue(all(item["scan_seconds_median"] is None for item in summary["statistics"]))

    def test_existing_results_and_bad_settings_rejected_before_scanning(self):
        with TemporaryDirectory() as root:
            directory = self.save_toy(Path(root) / "fixture")
            output = Path(root) / "results"
            output.mkdir()
            (output / "summary.json").write_text("original")
            with patch("rsa_auditor.audit_pipeline.run_audit", side_effect=AssertionError("must not scan")):
                with self.assertRaises(FileExistsError):
                    compare_modes.run_mode_comparison(directory, output)
                for options in ({"trials": 0}, {"budgets": []}, {"budgets": [1, 1]},
                                {"budgets": [True]}, {"gcd_backend": "batch_raw"}):
                    with self.assertRaises(ValueError):
                        compare_modes.run_mode_comparison(directory, Path(root) / "unused", **options)
            self.assertEqual((output / "summary.json").read_text(), "original")

    def test_experiments_compare_route_does_not_generate_or_run_legacy_benchmarks(self):
        with patch("rsa_auditor.experiments.comparison.run_mode_comparison", return_value={"all_runs_ok": True}) as run, \
             patch("rsa_auditor.experiments.cli.prepare_scalability_datasets", side_effect=AssertionError("no generation")), \
             redirect_stdout(StringIO()):
            self.assertEqual(experiments.main(["--mode", "compare", "--dataset", "fixture", "--budgets", "16", "256",
                                               "--trials", "3", "--gcd-backend", "pairwise", "--output", "out"]), 0)
            run.assert_called_once_with("fixture", "out", [16, 256], 3, "pairwise", None)


if __name__ == "__main__":
    unittest.main()
