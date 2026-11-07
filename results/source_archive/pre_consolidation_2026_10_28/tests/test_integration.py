"""Integration and fixture tests for Van's shared-prime path."""

from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
import json
import math
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from demo import evaluate_scan, main, measure_shared_prime_scan, recover_messages
from key_generation import generate_shared_prime_keys, generate_mixed_key_dataset, make_observed_subset
from key_recovery import encrypt_message
from shared_prime_fixtures import load_fixtures, load_public_keys, save_fixtures
from shared_prime_auditor import audit_public_keys


class SharedPrimeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 1024 bits keeps unit tests quick; the real demo is separately run at 2048.
        cls.case = generate_shared_prime_keys(4, 2, 1024)
        cls.message = b"Shared prime -> recovered RSA key"
        for key in cls.case["public_keys"]:
            key["ciphertext"] = encrypt_message(cls.message, key["n"], key["e"])
            cls.case["private_truth"][key["key_id"]]["expected_message"] = cls.message

    def save_case(self, directory):
        save_fixtures(directory, self.case["public_keys"], self.case["private_truth"],
                      self.case["expected_vulnerable_ids"])

    def test_end_to_end_recovers_only_vulnerable_records(self):
        public = self.case["public_keys"]
        result, elapsed = measure_shared_prime_scan(public)
        messages = recover_messages(public, result)
        summary = evaluate_scan(public, self.case["private_truth"],
                                self.case["expected_vulnerable_ids"], result, messages)
        self.assertTrue(summary["success"])
        self.assertEqual(summary["recovered_unique_keys"], 2)
        self.assertEqual(summary["recovered_unique_moduli"], 2)
        self.assertEqual(summary["false_positives"], 0)
        self.assertEqual(summary["missed_vulnerable_keys"], 0)
        self.assertEqual(summary["gcd_comparisons"], 6)
        self.assertEqual(summary["matching_pairs"], 1)
        self.assertGreaterEqual(elapsed, 0)
        self.assertEqual(set(messages.values()), {self.message})

    def test_controls_do_not_fall_back_to_generator_factors(self):
        controls = self.case["public_keys"][2:]
        result, _ = measure_shared_prime_scan(controls)
        self.assertEqual(result["recovered_keys"], [])
        self.assertEqual(recover_messages(controls, result), {})

    def test_rejects_forged_attack_product(self):
        result, _ = measure_shared_prime_scan(self.case["public_keys"])
        result["recovered_keys"][0]["p"] += 2
        with self.assertRaises(ValueError):
            recover_messages(self.case["public_keys"], result)

    def test_corrupted_ciphertext_cannot_be_reported_as_success(self):
        public = deepcopy(self.case["public_keys"])
        public[0]["ciphertext"] = b"\x00" * len(public[0]["ciphertext"])
        result, _ = measure_shared_prime_scan(public)
        with self.assertRaises(ValueError):
            recover_messages(public, result)

    def test_duplicate_modulus_can_recover_two_distinct_ids(self):
        public = deepcopy(self.case["public_keys"])
        duplicate = dict(public[0], key_id="key_005")
        public.append(duplicate)
        truth = deepcopy(self.case["private_truth"])
        truth["key_005"] = dict(truth["key_001"])
        result, _ = measure_shared_prime_scan(public)
        messages = recover_messages(public, result)
        summary = evaluate_scan(public, truth, ["key_001", "key_002", "key_005"], result, messages)
        self.assertTrue(summary["success"])
        self.assertEqual(summary["recovered_unique_keys"], 3)
        self.assertEqual(summary["recovered_unique_moduli"], 2)
        self.assertEqual(summary["duplicate_pairs"], 1)
        # Five records contain four unique moduli: dedup happens BEFORE GCD.
        self.assertEqual(summary["gcd_comparisons"], 6)
        self.assertEqual(summary["num_records"], 5)
        self.assertEqual(summary["num_unique_moduli"], 4)
        self.assertEqual(summary["duplicate_extra_records"], 1)

    def test_same_modulus_different_exponents_scanned_once_and_both_decrypted(self):
        public = deepcopy(self.case["public_keys"])
        truth = deepcopy(self.case["private_truth"])
        factors = truth["key_001"]
        phi = (factors["p"] - 1) * (factors["q"] - 1)
        # phi-1 is always odd and coprime to phi for these distinct odd primes.
        # It also cannot share p or q, and avoids a finite candidate search.
        alternate_e = phi - 1
        duplicate = dict(public[0], key_id="alternate", e=alternate_e)
        duplicate["ciphertext"] = encrypt_message(self.message, duplicate["n"], alternate_e)
        public.append(duplicate)
        truth["alternate"] = dict(factors)
        calls = []

        def counted_gcd(a, b):
            calls.append((a, b))
            return math.gcd(a, b)

        result = audit_public_keys(public, gcd_fn=counted_gcd)
        messages = recover_messages(public, result)
        summary = evaluate_scan(public, truth, ["key_001", "key_002", "alternate"], result, messages)
        self.assertTrue(summary["success"])
        self.assertEqual(len(calls), 6)
        self.assertEqual(messages["alternate"], self.message)
        records = result["normalized"]["records_by_modulus"][public[0]["n"]]
        self.assertEqual([record["e"] for record in records], [65537, alternate_e])
        self.assertEqual(summary["decryption_cases_checked"], 3)
        self.assertEqual(summary["decryption_cases_passed"], 3)

    def test_recovery_rejects_changed_record_exponent(self):
        result, _ = measure_shared_prime_scan(self.case["public_keys"])
        result["recovered_records"][0]["e"] = 3
        with self.assertRaises(ValueError):
            recover_messages(self.case["public_keys"], result)

    def test_missing_companion_then_added_preserves_target_ciphertext(self):
        before = make_observed_subset(self.case, ["key_001", "key_003", "key_004"])
        after = make_observed_subset(self.case, ["key_001", "key_002", "key_003", "key_004"])
        self.assertEqual(before["public_keys"][0], after["public_keys"][0])
        self.assertTrue(before["private_truth"]["key_001"]["intended_weak_generation"])
        self.assertFalse(before["private_truth"]["key_001"]["observable_shared_factor"])
        for case, expected_records in ((before, 0), (after, 2)):
            result, _ = measure_shared_prime_scan(case["public_keys"])
            messages = recover_messages(case["public_keys"], result)
            summary = evaluate_scan(case["public_keys"], case["private_truth"],
                                    case["expected_vulnerable_ids"], result, messages)
            self.assertTrue(summary["success"])
            self.assertEqual(summary["recovered_records"], expected_records)
            self.assertEqual(summary["false_negative_moduli"], 0)
            if expected_records == 0:
                self.assertEqual(summary["decryption_cases_checked"], 0)
                self.assertIsNone(summary["plaintexts_verified"])
            else:
                self.assertEqual(messages["key_001"], self.message)

    def test_evaluator_rejects_population_labels_for_missing_companion(self):
        before = make_observed_subset(self.case, ["key_001", "key_003", "key_004"])
        result, _ = measure_shared_prime_scan(before["public_keys"])
        with self.assertRaises(ValueError):
            evaluate_scan(before["public_keys"], before["private_truth"], ["key_001"], result, {})

    def test_partial_decryption_reports_only_actual_checks(self):
        public = deepcopy(self.case["public_keys"])
        del public[0]["ciphertext"]
        result, _ = measure_shared_prime_scan(public)
        messages = recover_messages(public, result)
        summary = evaluate_scan(public, self.case["private_truth"],
                                self.case["expected_vulnerable_ids"], result, messages)
        self.assertTrue(summary["success"])
        self.assertEqual(summary["decryption_cases_checked"], 1)
        self.assertFalse(summary["all_recovered_records_decrypted"])
        self.assertFalse(summary["all_decryptions_verified"])

    def test_fixture_round_trip_preserves_values_and_separation(self):
        with TemporaryDirectory() as directory:
            self.save_case(directory)
            document = json.loads((Path(directory) / "public.json").read_text())
            for record in document["public_keys"]:
                self.assertEqual(set(record), {"key_id", "n", "e", "ciphertext_hex"})
                self.assertIsInstance(record["n"], str)
                self.assertIsInstance(record["e"], str)
            loaded = load_fixtures(directory)
            self.assertEqual(loaded["public_keys"], self.case["public_keys"])
            self.assertEqual(loaded["private_truth"], self.case["private_truth"])
            self.assertEqual(loaded["expected_vulnerable_ids"], self.case["expected_vulnerable_ids"])
            result, _ = measure_shared_prime_scan(loaded["public_keys"])
            self.assertEqual(set(recover_messages(loaded["public_keys"], result).values()), {self.message})

    def test_public_only_cli_works_when_private_file_is_absent(self):
        with TemporaryDirectory() as directory:
            self.save_case(directory)
            (Path(directory) / "private_truth.json").unlink()
            for algorithm in ("pairwise", "batch"):
                with self.subTest(algorithm=algorithm):
                    output = StringIO()
                    with redirect_stdout(output):
                        code = main(["--public-only", str(Path(directory) / "public.json"),
                                     "--algorithm", algorithm])
                    self.assertEqual(code, 0)
                    self.assertIn(self.message.decode(), output.getvalue())
                    self.assertIn("2 recovered keys", output.getvalue())

    def test_batch_oaep_uses_same_recovery_path(self):
        result, _ = measure_shared_prime_scan(self.case["public_keys"], algorithm="batch")
        messages = recover_messages(self.case["public_keys"], result)
        summary = evaluate_scan(self.case["public_keys"], self.case["private_truth"],
                                self.case["expected_vulnerable_ids"], result, messages)
        self.assertTrue(summary["success"])
        self.assertEqual(summary["algorithm"], "batch_with_fallback")
        self.assertEqual(summary["batch_leaf_gcd_calls"], 4)
        self.assertEqual(summary["fallback_gcd_calls"], 0)
        self.assertEqual(summary["decryption_cases_checked"], 2)

    def test_does_not_overwrite_saved_fixtures(self):
        with TemporaryDirectory() as directory:
            self.save_case(directory)
            original = (Path(directory) / "public.json").read_bytes()
            with self.assertRaises(FileExistsError):
                self.save_case(directory)
            self.assertEqual((Path(directory) / "public.json").read_bytes(), original)

    def test_rejects_lossy_or_invalid_integer_encodings(self):
        for invalid in (187.9, 187, True, "1e200", "-1", "0", "1.5"):
            with self.subTest(value=invalid), TemporaryDirectory() as directory:
                self.save_case(directory)
                path = Path(directory) / "public.json"
                document = json.loads(path.read_text())
                document["public_keys"][0]["n"] = invalid
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    load_public_keys(path)

    def test_rejects_malformed_json_containers(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            for document in ([], {}, {"format": "weak-rsa-public-v1", "encryption": "RSA-OAEP-SHA256",
                                       "public_keys": ["not a record"]}):
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    load_public_keys(path)

    def test_evaluator_rejects_mismatched_truth(self):
        result, _ = measure_shared_prime_scan(self.case["public_keys"])
        messages = recover_messages(self.case["public_keys"], result)
        truth = deepcopy(self.case["private_truth"])
        truth["key_001"]["p"] += 2
        with self.assertRaises(ValueError):
            evaluate_scan(self.case["public_keys"], truth,
                          self.case["expected_vulnerable_ids"], result, messages)

    def test_small_cli_includes_verified_lecture_example(self):
        output = StringIO()
        with redirect_stdout(output):
            code = main(["--small"])
        self.assertEqual(code, 0)
        self.assertIn("recovered d=1553, 4838 -> 1000", output.getvalue())


class PairwiseRecordAuditTests(unittest.TestCase):
    def test_factor_only_fixture_load_does_not_claim_decryption(self):
        case = generate_shared_prime_keys(3, 2, 64)
        with TemporaryDirectory() as directory:
            save_fixtures(directory, case["public_keys"], case["private_truth"],
                          case["expected_vulnerable_ids"])
            loaded = load_fixtures(directory)
            result, _ = measure_shared_prime_scan(loaded["public_keys"])
            messages = recover_messages(loaded["public_keys"], result)
            summary = evaluate_scan(loaded["public_keys"], loaded["private_truth"],
                                    loaded["expected_vulnerable_ids"], result, messages)
            self.assertTrue(summary["success"])
            self.assertEqual(messages, {})
            self.assertEqual(summary["decryption_cases_checked"], 0)
            self.assertIsNone(summary["plaintexts_verified"])
            self.assertFalse(summary["all_decryptions_verified"])
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--public-only", str(Path(directory) / "public.json")]), 0)
            self.assertIn("2 recovered keys", output.getvalue())

    def test_four_records_three_moduli_regression(self):
        records = [
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "B", "n": 253, "e": 17},
            {"key_id": "C", "n": 1147, "e": 17},
            {"key_id": "D", "n": 187, "e": 3},
        ]
        result = audit_public_keys(records)
        self.assertEqual(result["num_records"], 4)
        self.assertEqual(result["num_unique_moduli"], 3)
        self.assertEqual(result["duplicate_extra_records"], 1)
        self.assertEqual(result["gcd_calls"], 3)
        self.assertEqual([record["key_id"] for record in result["recovered_records"]], ["A", "B", "D"])
        self.assertEqual(result["findings"][1147]["status"], "no_shared_factor_in_dataset")

    def test_duplicate_only_requires_no_gcd_and_has_no_recovery(self):
        result = audit_public_keys([
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "B", "n": 187, "e": 3},
        ])
        self.assertEqual(result["gcd_calls"], 0)
        self.assertEqual(result["recovered_records"], [])
        self.assertEqual(result["findings"][187]["status"], "no_shared_factor_in_dataset")

    def test_secrets_rejected_before_scanner_called(self):
        with patch("shared_prime_auditor.scan_moduli") as scanner:
            with self.assertRaises(ValueError):
                audit_public_keys([{"key_id": "A", "n": 187, "e": 17, "p": 11}])
        scanner.assert_not_called()

    def test_all_mixed_topologies_match_independent_generator_truth(self):
        case = generate_mixed_key_dataset(64)
        result = audit_public_keys(case["public_keys"])
        self.assertEqual(result["num_records"], 18)
        self.assertEqual(result["num_unique_moduli"], 16)
        self.assertEqual(result["gcd_calls"], 120)
        factored = {n for n, finding in result["findings"].items() if finding["status"] == "factored"}
        self.assertEqual(factored, set(case["expected_factored_moduli"]))
        self.assertEqual(len(factored), 13)
        self.assertEqual({record["key_id"] for record in result["recovered_records"]},
                         set(case["expected_vulnerable_ids"]))
        for record in result["recovered_records"]:
            truth = case["private_truth"][record["key_id"]]
            self.assertEqual({record["p"], record["q"]}, {truth["p"], truth["q"]})

    def test_permuted_records_keep_modulus_factorizations(self):
        records = [{"key_id": key_id, "n": n, "e": 17}
                   for key_id, n in (("A", 187), ("B", 253), ("C", 1147), ("D", 187))]
        original = audit_public_keys(records)
        reversed_result = audit_public_keys(reversed(records))
        self.assertEqual(original["findings"], reversed_result["findings"])
        self.assertEqual({record["key_id"] for record in original["recovered_records"]},
                         {record["key_id"] for record in reversed_result["recovered_records"]})


class BatchRecordAuditTests(unittest.TestCase):
    def test_dedup_before_batch_and_preserve_each_exponent(self):
        result = audit_public_keys([
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "duplicate", "n": 187, "e": 3},
            {"key_id": "companion", "n": 253, "e": 17},
        ], algorithm="batch")
        self.assertEqual(result["num_records"], 3)
        self.assertEqual(result["num_unique_moduli"], 2)
        self.assertEqual(result["batch_leaf_gcd_calls"], 2)
        self.assertEqual(result["fallback_gcd_calls"], 0)
        self.assertEqual([record["e"] for record in result["recovered_records"]], [17, 3, 17])

    def test_duplicate_only_batch_has_no_false_factorization(self):
        result = audit_public_keys([
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "B", "n": 187, "e": 3},
        ], algorithm="batch")
        self.assertEqual(result["recovered_records"], [])
        self.assertEqual(result["gcd_calls"], 0)

    def test_chain_raw_status_and_complete_fallback(self):
        records = [{"key_id": str(index), "n": n, "e": 17}
                   for index, n in enumerate((187, 253, 493))]
        raw = audit_public_keys(records, algorithm="batch_raw")
        self.assertEqual(raw["findings"][187]["status"], "unresolved_full_gcd")
        self.assertIsNone(raw["findings"][187]["p"])
        self.assertEqual(raw["unresolved_after_fallback"], 1)
        self.assertEqual(len(raw["recovered_records"]), 2)
        resolved = audit_public_keys(records, algorithm="batch")
        self.assertEqual(resolved["full_gcd_before_fallback"], 1)
        self.assertEqual(resolved["unresolved_after_fallback"], 0)
        self.assertEqual(resolved["fallback_gcd_calls"], 1)
        self.assertEqual(len(resolved["recovered_records"]), 3)

    def test_mixed_modulus_and_record_results_agree_with_pairwise(self):
        case = generate_mixed_key_dataset(64)
        pairwise = audit_public_keys(case["public_keys"])
        batch = audit_public_keys(case["public_keys"], algorithm="batch")
        factor_map = lambda result: {n: (finding["p"], finding["q"])
                                     for n, finding in result["findings"].items()
                                     if finding["status"] == "factored"}
        self.assertEqual(factor_map(pairwise), factor_map(batch))
        self.assertEqual(batch["full_gcd_before_fallback"], 4)
        self.assertEqual(batch["unresolved_after_fallback"], 0)
        self.assertGreater(batch["fallback_gcd_calls"], 0)
        self.assertEqual(len(batch["recovered_records"]), 14)
        self.assertIsNone(batch["matching_pair_count"])

    def test_unknown_algorithm_is_rejected(self):
        with self.assertRaises(ValueError):
            audit_public_keys([], algorithm="not-an-algorithm")


if __name__ == "__main__":
    unittest.main()
