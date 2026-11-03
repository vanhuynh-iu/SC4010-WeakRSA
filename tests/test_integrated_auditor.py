"""Integration invariants from the shared auditor plan."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from audit_pipeline import run_audit
from shared_prime_attack import scan_moduli
from audit_pipeline import recover_messages
from dataset_io import load_dataset


def records():
    return [
        {"key_id": "shared_a", "n": 101 * 1009, "e": 65537},
        {"key_id": "shared_b", "n": 101 * 1013, "e": 65537},
        {"key_id": "close", "n": 10007 * 10009, "e": 65537},
        {"key_id": "copy", "n": 10007 * 10009, "e": 17},
        {"key_id": "control", "n": 107 * 1019, "e": 65537},
    ]


def recovered(report):
    return {n for n, finding in report["findings"].items() if finding["status"] == "factored"}


class IntegratedModeTests(unittest.TestCase):
    def test_combined_is_union_and_saves_fermat_work_for_both_backends(self):
        for backend in ("pairwise", "batch"):
            with self.subTest(backend=backend):
                reports = {mode: run_audit(records(), mode, backend, 3)
                           for mode in ("gcd", "fermat", "combined")}
                self.assertEqual(recovered(reports["gcd"]), {101 * 1009, 101 * 1013})
                self.assertEqual(recovered(reports["fermat"]), {10007 * 10009})
                self.assertEqual(recovered(reports["combined"]),
                                 recovered(reports["gcd"]) | recovered(reports["fermat"]))
                self.assertLess(reports["combined"]["fermat_candidate_tests"],
                                reports["fermat"]["fermat_candidate_tests"])
                self.assertEqual(reports["combined"]["fermat_attempted_moduli"], 2)
                self.assertEqual(reports["combined"]["fermat_exhausted_moduli"], 1)

    def test_gcd_success_skips_fermat_and_fermat_only_never_scans_gcd(self):
        keys = records()[:2]
        with patch("audit_pipeline.fermat_factor", side_effect=AssertionError("must skip")):
            result = run_audit(keys, "combined", "batch", 3)
        self.assertEqual(result["fermat_candidate_tests"], 0)
        self.assertTrue(all(f["fermat_status"] == "not_run" for f in result["findings"].values()))
        with patch("audit_pipeline.scan_moduli", side_effect=AssertionError("must skip")):
            result = run_audit(keys, "fermat", "pairwise", 3)
        self.assertEqual(result["gcd_calls"], 0)
        self.assertTrue(all(f["gcd_status"] == "not_run" for f in result["findings"].values()))

    def test_overlapping_weakness_records_first_success_without_changing_union(self):
        keys = [{"key_id": "both", "n": 101 * 103, "e": 17},
                {"key_id": "companion", "n": 101 * 1009, "e": 17}]
        gcd = run_audit(keys, "gcd", "pairwise", 1)
        fermat = run_audit(keys, "fermat", "pairwise", 1)
        combined = run_audit(keys, "combined", "pairwise", 1)
        self.assertEqual(recovered(gcd) & recovered(fermat), {101 * 103})
        self.assertEqual(recovered(combined), recovered(gcd) | recovered(fermat))
        finding = combined["findings"][101 * 103]
        self.assertEqual(finding["resolution_method"], "pairwise")
        self.assertEqual(finding["fermat_status"], "not_run")

    def test_duplicates_scanned_once_and_each_exponent_preserved(self):
        result = run_audit(records()[2:4], "combined", "pairwise", 3)
        self.assertEqual(result["num_records"], 2)
        self.assertEqual(result["num_unique_moduli"], 1)
        self.assertEqual(result["duplicate_extra_records"], 1)
        self.assertEqual(result["gcd_calls"], 0)
        self.assertEqual(result["fermat_candidate_tests"], 1)
        self.assertEqual({r["key_id"]: r["e"] for r in result["recovered_records"]},
                         {"close": 65537, "copy": 17})

    def test_stage_outcomes_and_exhaustion_are_distinct(self):
        keys = [records()[-1]]
        gcd = run_audit(keys, "gcd", "pairwise", 0)["record_findings"][0]
        self.assertEqual(gcd["status"], "no_shared_factor_in_dataset")
        self.assertEqual(gcd["fermat_status"], "not_run")
        combined = run_audit(keys, "combined", "pairwise", 0)["record_findings"][0]
        self.assertEqual(combined["status"], "budget_exhausted")
        self.assertEqual(combined["gcd_status"], "no_shared_factor_in_dataset")
        self.assertEqual(combined["fermat_candidate_tests"], 0)
        self.assertIsNone(combined["p"])

    def test_batch_full_gcd_fallback_is_preserved(self):
        keys = [{"key_id": str(i), "n": n, "e": 17}
                for i, n in enumerate((101 * 103, 101 * 107, 103 * 107))]
        result = run_audit(keys, "combined", "batch", 1)
        self.assertEqual(len(recovered(result)), 3)
        self.assertEqual(result["full_gcd_before_fallback"], 3)
        self.assertEqual(result["unresolved_after_fallback"], 0)
        self.assertEqual(result["fermat_attempted_moduli"], 0)

    def test_fresh_calls_and_permutations_do_not_reuse_factors(self):
        first = run_audit(records(), "combined", "batch", 3)
        second = run_audit(reversed(records()), "combined", "batch", 3)
        self.assertEqual(recovered(first), recovered(second))
        self.assertEqual(first["fermat_candidate_tests"], second["fermat_candidate_tests"])
        self.assertEqual(first["gcd_calls"], second["gcd_calls"])
        alone = run_audit(records()[:1], "gcd", "batch", 3)
        self.assertFalse(recovered(alone))

    def test_private_fields_rejected_before_checks_run(self):
        keys = [{**records()[0], "p": 101, "case_type": "shared"}]
        with patch("audit_pipeline.scan_moduli") as gcd:
            with self.assertRaises(ValueError):
                run_audit(keys, "gcd", "pairwise", 3)
        gcd.assert_not_called()

    def test_forged_successful_factors_cannot_skip_fermat(self):
        keys = records()[:2]
        forged = scan_moduli([key["n"] for key in keys])
        forged["findings"][keys[0]["n"]]["p"] = 103
        with patch("audit_pipeline.scan_moduli", return_value=forged):
            with self.assertRaises(ValueError):
                run_audit(keys, "combined", "pairwise", 3)

    def test_invalid_configuration_is_an_error(self):
        for kwargs in ({"mode": "secure"}, {"gcd_backend": "batch_raw"},
                       {"fermat_budget": -1}, {"fermat_budget": True},
                       {"fermat_budget": 1.5}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                run_audit(records(), **kwargs)

    def test_total_scan_time_contains_each_check(self):
        report = run_audit(records(), "combined", "batch", 3)
        self.assertGreaterEqual(report["scan_seconds"],
                                report["gcd_scan_seconds"] + report["fermat_scan_seconds"])
        self.assertEqual(report["fermat_candidate_tests"],
                         sum(f["fermat_candidate_tests"] for f in report["findings"].values()))


class Saved2048AuditorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(__file__).resolve().parents[1] / "data/public/auditor_demo"
        cls.case = load_dataset(cls.directory)

    def test_saved_fixture_recovers_and_decrypts_through_both_attack_branches(self):
        from evaluation import evaluate_audit
        keys = self.case["public_keys"]
        self.assertEqual(len(keys), 8)
        self.assertEqual({record["n"].bit_length() for record in keys}, {2048})
        reports = {mode: run_audit(keys, mode, "batch", 256)
                   for mode in ("gcd", "fermat", "combined")}
        self.assertEqual(recovered(reports["combined"]),
                         recovered(reports["gcd"]) | recovered(reports["fermat"]))
        report = reports["combined"]
        messages = recover_messages(keys, report)
        summary = evaluate_audit(self.case, report, messages)
        self.assertTrue(summary["success"])
        self.assertEqual(summary["false_positive_moduli"], 0)
        self.assertEqual(summary["false_negative_moduli"], 0)
        self.assertGreater(summary["recovered_via_gcd_moduli"], 0)
        self.assertGreater(summary["recovered_via_fermat_moduli"], 0)
        self.assertEqual(summary["decryption_cases_passed"], len(messages))
        methods = {record["resolution_method"] for record in report["recovered_records"]
                   if record["key_id"] in messages}
        self.assertIn("fermat", methods)
        self.assertTrue(methods & {"batch_direct", "batch_fallback"})
        self.assertEqual(report["num_unique_moduli"], 7)
        self.assertEqual(report["duplicate_extra_records"], 1)
        self.assertGreater(report["fermat_exhausted_moduli"], 0)

    def test_integrated_public_only_cli_does_not_load_truth_and_exports_lossless_report(self):
        from demo import main
        with TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with patch("demo.load_dataset", side_effect=AssertionError("must not read truth")):
                with redirect_stdout(StringIO()):
                    code = main(["--public-only", str(self.directory / "public.json"),
                                 "--mode", "combined", "--fermat-budget", "256",
                                 "--output", str(output)])
            self.assertEqual(code, 0)
            document = json.loads(output.read_text())
            self.assertIsNone(document["evaluation"])
            self.assertTrue(document["decrypted_messages_hex"])
            self.assertTrue(all(type(f["n"]) is str and f["n"].startswith("0x")
                                for f in document["unique_moduli"]))
            self.assertEqual({int(f["n"], 16) for f in document["unique_moduli"]},
                             {record["n"] for record in self.case["public_keys"]})
            self.assertNotIn("case_type", output.read_text())
            self.assertNotIn("actual_gap", output.read_text())
            with redirect_stdout(StringIO()), self.assertRaises(SystemExit):
                main(["--mode", "combined", "--output", str(output)])


if __name__ == "__main__":
    unittest.main()
