"""Pipeline, dataset separation and integrity tests."""

from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import hashlib
from io import StringIO
import json
import math
from pathlib import Path
import random
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from audit_pipeline import audit_public_keys, evaluate_scan, measure_shared_prime_scan, recover_messages
from build_dataset import assemble_dataset, dataset_paths, load_dataset, load_public_keys, save_dataset
from demo import main
from generators.shared_prime_cases import generate_shared_prime_keys, generate_mixed_key_dataset, make_observed_subset
from key_recovery import encrypt_message


def _dataset_file(directory, file_name):
    return dict(zip(("public.json", "private_truth.json", "manifest.json"),
                    dataset_paths(directory)))[file_name]


def _directory_snapshot(directory):
    directory = Path(directory)
    return {str(path.relative_to(directory)): path.read_bytes() if path.is_file() else None
            for path in directory.rglob("*")}


class SharedPrimeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use 1024-bit keys for fast wrapper tests.
        cls.case = generate_shared_prime_keys(4, 2, 1024)
        cls.message = b"Shared prime -> recovered RSA key"
        for key in cls.case["public_keys"]:
            key["ciphertext"] = encrypt_message(cls.message, key["n"], key["e"])
            cls.case["private_truth"][key["key_id"]]["expected_message"] = cls.message

    def save_case(self, directory):
        save_dataset(directory, self.case["public_keys"], self.case["private_truth"],
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
        # Deduplicate five records to four moduli before scanning.
        self.assertEqual(summary["gcd_comparisons"], 6)
        self.assertEqual(summary["num_records"], 5)
        self.assertEqual(summary["num_unique_moduli"], 4)
        self.assertEqual(summary["duplicate_extra_records"], 1)

    def test_same_modulus_different_exponents_scanned_once_and_both_decrypted(self):
        public = deepcopy(self.case["public_keys"])
        truth = deepcopy(self.case["private_truth"])
        factors = truth["key_001"]
        phi = (factors["p"] - 1) * (factors["q"] - 1)
        # phi-1 is odd and coprime to both phi and n.
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
            document = json.loads((dataset_paths(directory)[0]).read_text())
            for record in document["public_keys"]:
                self.assertEqual(set(record), {"key_id", "n", "e", "ciphertext_hex"})
                self.assertIsInstance(record["n"], str)
                self.assertIsInstance(record["e"], str)
            loaded = load_dataset(directory)
            self.assertEqual(loaded["public_keys"], self.case["public_keys"])
            self.assertEqual(loaded["private_truth"], self.case["private_truth"])
            self.assertEqual(loaded["expected_vulnerable_ids"], self.case["expected_vulnerable_ids"])
            result, _ = measure_shared_prime_scan(loaded["public_keys"])
            self.assertEqual(set(recover_messages(loaded["public_keys"], result).values()), {self.message})

    def test_public_only_cli_works_when_private_file_is_absent(self):
        with TemporaryDirectory() as directory:
            self.save_case(directory)
            (dataset_paths(directory)[1]).unlink()
            for algorithm in ("pairwise", "batch"):
                with self.subTest(algorithm=algorithm):
                    output = StringIO()
                    with redirect_stdout(output):
                        code = main(["--public-only", str(dataset_paths(directory)[0]),
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
            original = (dataset_paths(directory)[0]).read_bytes()
            with self.assertRaises(FileExistsError):
                self.save_case(directory)
            self.assertEqual((dataset_paths(directory)[0]).read_bytes(), original)

    def test_rejects_lossy_or_invalid_integer_encodings(self):
        for invalid in (187.9, 187, True, "1e200", "-1", "0", "1.5"):
            with self.subTest(value=invalid), TemporaryDirectory() as directory:
                self.save_case(directory)
                path = dataset_paths(directory)[0]
                document = json.loads(path.read_text())
                document["public_keys"][0]["n"] = invalid
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    load_public_keys(path)

    def test_rejects_malformed_json_containers(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            for document in ([], {}, {"format": "weak-rsa-public", "encryption": "RSA-OAEP-SHA256",
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

class PairwiseRecordAuditTests(unittest.TestCase):
    def test_factor_only_fixture_load_does_not_claim_decryption(self):
        case = generate_shared_prime_keys(3, 2, 64)
        with TemporaryDirectory() as directory:
            save_dataset(directory, case["public_keys"], case["private_truth"],
                          case["expected_vulnerable_ids"])
            loaded = load_dataset(directory)
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
                self.assertEqual(main(["--public-only", str(dataset_paths(directory)[0])]), 0)
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
        with patch("audit_pipeline.scan_moduli") as scanner:
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


class SharedPrimeFixtureTests(unittest.TestCase):
    def setUp(self):
        # Arithmetic fixtures for serialization only.
        self.public = [
            {"key_id": "A", "n": 187, "e": 17, "ciphertext": b"\x00\xff\x01"},
            {"key_id": "B", "n": 253, "e": 17, "ciphertext": b"\x01\x00"},
            {"key_id": "C", "n": 187, "e": 3, "ciphertext": b""},
        ]
        self.truth = {
            "A": {"p": 11, "q": 17, "case_type": "shared_prime",
                  "expected_message": b"A\x00", "intended_weak_generation": True,
                  "observable_shared_factor": True},
            "B": {"p": 11, "q": 23, "case_type": "shared_prime",
                  "expected_message": b"B\xff", "intended_weak_generation": True,
                  "observable_shared_factor": True},
            "C": {"p": 11, "q": 17, "case_type": "duplicate",
                  "expected_message": b"", "intended_weak_generation": False,
                  "observable_shared_factor": True},
        }
        self.expected_ids = ["A", "B", "C"]

    def save(self, directory, **kwargs):
        save_dataset(directory, self.public, self.truth, self.expected_ids, **kwargs)

    def assert_round_trip(self, directory):
        loaded = load_dataset(directory)
        self.assertEqual(loaded["public_keys"], self.public)
        self.assertEqual(loaded["private_truth"], self.truth)
        self.assertEqual(loaded["expected_vulnerable_ids"], self.expected_ids)

    def test_hex_round_trip_and_truth_separation(self):
        with TemporaryDirectory() as directory:
            self.save(directory)
            self.assert_round_trip(directory)
            public = json.loads(dataset_paths(directory)[0].read_text())
            private = json.loads(dataset_paths(directory)[1].read_text())
            self.assertEqual(public["format"], "weak-rsa-public")
            self.assertEqual(private["format"], "weak-rsa-private")
            self.assertEqual(public["public_keys"][0]["n"], "0xbb")
            self.assertEqual(public["public_keys"][0]["e"], "0x11")
            self.assertEqual(private["private_truth"]["A"]["p"], "0xb")
            self.assertEqual(private["private_truth"]["A"]["q"], "0x11")
            self.assertIs(private["private_truth"]["C"]["intended_weak_generation"], False)
            self.assertIs(private["private_truth"]["C"]["observable_shared_factor"], True)
            for record in public["public_keys"]:
                self.assertEqual(set(record), {"key_id", "n", "e", "ciphertext_hex"})

    def test_obsolete_public_private_and_manifest_formats_are_rejected(self):
        obsolete_formats = {
            "public.json": ("weak-rsa-public-v1", "weak-rsa-public-v2"),
            "private_truth.json": ("weak-rsa-private-v1", "weak-rsa-private-v2"),
            "manifest.json": ("weak-rsa-manifest-v1", "weak-rsa-manifest-v2"),
        }
        for file_name, formats in obsolete_formats.items():
            for unsupported in formats:
                with self.subTest(file=file_name, format=unsupported), TemporaryDirectory() as directory:
                    self.save(directory)
                    path = _dataset_file(directory, file_name)
                    document = json.loads(path.read_text())
                    document["format"] = unsupported
                    path.write_text(json.dumps(document))
                    with self.assertRaisesRegex(ValueError, "unsupported"):
                        if file_name == "public.json":
                            load_public_keys(path)
                        else:
                            load_dataset(directory)

    def test_manifest_has_actual_checksums_counts_versions_and_construction(self):
        with TemporaryDirectory() as directory:
            metadata = {"scenario": "toy duplicates", "seeded": False, "parameters": [3, 2]}
            self.save(directory, metadata=metadata)
            manifest = json.loads((dataset_paths(directory)[2]).read_text())
            for file_name, field in (("public.json", "public_sha256"),
                                     ("private_truth.json", "private_sha256")):
                actual = hashlib.sha256((_dataset_file(directory, file_name)).read_bytes()).hexdigest()
                self.assertEqual(manifest[field], actual)
            self.assertEqual(manifest["format"], "weak-rsa-manifest")
            self.assertEqual(manifest["public_format"], "weak-rsa-public")
            self.assertEqual(manifest["private_format"], "weak-rsa-private")
            self.assertNotIn("integer_encoding", manifest)
            self.assertEqual(manifest["num_records"], 3)
            self.assertEqual(manifest["num_unique_moduli"], 2)
            self.assertEqual(manifest["duplicate_extra_records"], 1)
            self.assertEqual(manifest["modulus_bit_lengths"], [8])
            self.assertEqual(manifest["construction_metadata"], metadata)
            for field in ("python_version", "pycryptodome_version", "platform"):
                self.assertTrue(manifest[field])
            self.assertTrue(manifest["created_at_utc"].endswith("+00:00"))

    def test_large_integers_remain_exact_as_hex(self):
        # Preserve integers beyond floating-point precision.
        p, q = (1 << 1024) + 643, (1 << 1024) + 159
        public = [{"key_id": "large", "n": p * q, "e": (1 << 53) + 1,
                   "ciphertext": bytes(range(256))}]
        truth = {"large": {"p": p, "q": q, "case_type": "serialization_only",
                           "expected_message": b"precision"}}
        with TemporaryDirectory() as directory:
            save_dataset(directory, public, truth, [])
            loaded = load_dataset(directory)
            self.assertEqual(loaded["public_keys"], public)
            self.assertEqual(loaded["private_truth"], truth)
            document = json.loads(dataset_paths(directory)[0].read_text())
            self.assertEqual(document["public_keys"][0]["n"], hex(p*q))
            self.assertEqual(document["public_keys"][0]["e"], hex((1 << 53) + 1))

    def test_public_loader_does_not_open_or_require_private_truth(self):
        with TemporaryDirectory() as directory:
            self.save(directory)
            private_path = dataset_paths(directory)[1]
            private_path.write_text("this is deliberately not JSON")
            public_path = dataset_paths(directory)[0]
            self.assertEqual(load_public_keys(public_path), self.public)
            private_path.unlink()
            self.assertEqual(load_public_keys(public_path), self.public)

    def test_dataset_without_manifest_loads(self):
        with TemporaryDirectory() as directory:
            self.save(directory)
            dataset_paths(directory)[2].unlink()
            self.assert_round_trip(directory)
            self.assertFalse(dataset_paths(directory)[2].exists())

    def test_public_and_private_tampering_are_detected(self):
        for file_name, expected in (("public.json", "public checksum"),
                                    ("private_truth.json", "private checksum")):
            with self.subTest(file=file_name), TemporaryDirectory() as directory:
                self.save(directory)
                path = _dataset_file(directory, file_name)
                # Whitespace changes the checksum without invalidating JSON.
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaisesRegex(ValueError, expected):
                    load_dataset(directory)

    def test_manifest_public_metadata_is_verified(self):
        changes = {"num_records": 4, "num_unique_moduli": True,
                   "duplicate_extra_records": 0, "modulus_bit_lengths": [2048],
                   "public_format": "unsupported"}
        for field, value in changes.items():
            with self.subTest(field=field), TemporaryDirectory() as directory:
                self.save(directory)
                path = dataset_paths(directory)[2]
                manifest = json.loads(path.read_text())
                manifest[field] = value
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    load_public_keys(dataset_paths(directory)[0])

    def test_existing_files_are_never_overwritten(self):
        with TemporaryDirectory() as directory:
            self.save(directory)
            original = _directory_snapshot(directory)
            with self.assertRaises(FileExistsError):
                self.save(directory)
            self.assertEqual(_directory_snapshot(directory), original)
        for name in ("public.json", "private_truth.json", "manifest.json"):
            with self.subTest(preexisting=name), TemporaryDirectory() as directory:
                path = _dataset_file(directory, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("preserve me")
                original = _directory_snapshot(directory)
                with self.assertRaises(FileExistsError):
                    self.save(directory)
                self.assertEqual(_directory_snapshot(directory), original)
                self.assertEqual(path.read_text(), "preserve me")

    def test_all_validation_and_serialization_happen_before_writes(self):
        public_bad = deepcopy(self.public)
        public_bad[0]["p"] = 11
        truth_bad = deepcopy(self.truth)
        truth_bad["A"]["expected_message"] = "not bytes"
        attempts = (
            (public_bad, self.truth, self.expected_ids, {}),
            (self.public, truth_bad, self.expected_ids, {}),
            (self.public, self.truth, ["missing"], {}),
            (self.public, self.truth, self.expected_ids, {"metadata": []}),
            (self.public, self.truth, self.expected_ids, {"metadata": {"bad": object()}}),
            (self.public, self.truth, self.expected_ids, {"metadata": {"bad": float("nan")}}),
        )
        for index, (public, truth, expected, kwargs) in enumerate(attempts):
            with self.subTest(attempt=index), TemporaryDirectory() as parent:
                directory = Path(parent) / "new-set"
                with self.assertRaises((ValueError, TypeError)):
                    save_dataset(directory, public, truth, expected, **kwargs)
                self.assertFalse(directory.exists())

    def test_optional_ciphertext_and_expected_message_remain_optional(self):
        public = [{"key_id": "A", "n": 187, "e": 17}]
        truth = {"A": {"p": 11, "q": 17, "case_type": "arithmetic"}}
        with TemporaryDirectory() as directory:
            save_dataset(directory, public, truth, [])
            loaded = load_dataset(directory)
            self.assertEqual(loaded["public_keys"], public)
            self.assertEqual(loaded["private_truth"], truth)

    def test_rejects_malformed_json_containers_and_public_records(self):
        base = {"format": "weak-rsa-public", "encryption": "RSA-OAEP-SHA256",
                "public_keys": [{"key_id": "A", "n": "0xbb", "e": "0x11"}]}
        documents = [[], {}, {"format": []}, dict(base, public_keys={}),
                     dict(base, public_keys=[None]), dict(base, public_keys=[{}]),
                     dict(base, public_keys=[{"key_id": "A", "n": "0xbb", "e": "0x11", "p": "0xb"}])]
        for document in documents:
            with self.subTest(document=document), TemporaryDirectory() as directory:
                path = dataset_paths(directory)[0]
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    load_public_keys(path)
        with TemporaryDirectory() as directory:
            path = dataset_paths(directory)[0]
            path.write_text("{broken JSON")
            with self.assertRaises(ValueError):
                load_public_keys(path)

    def test_rejects_invalid_hex_integers_without_manifest(self):
        invalid = (187.9, 187, True, False, "187", "1e200", "-1", "0", "1.5",
                   "bb", "0x", "-0xbb", "0x0", "0xgg", "0x_b", " 0xbb", "١٨٧")
        for field in ("n", "e"):
            for value in invalid:
                with self.subTest(field=field, value=value), TemporaryDirectory() as directory:
                    record = {"key_id": "A", "n": "0xbb", "e": "0x11"}
                    record[field] = value
                    path = dataset_paths(directory)[0]
                    path.write_text(json.dumps({
                        "format": "weak-rsa-public", "encryption": "RSA-OAEP-SHA256",
                        "public_keys": [record],
                    }))
                    with self.assertRaises(ValueError):
                        load_public_keys(path)

    def test_rejects_invalid_private_records_without_manifest(self):
        for field, bad in (("p", 11.9), ("q", True), ("case_type", None),
                           ("observable_shared_factor", 1), ("expected_message_hex", [1])):
            with self.subTest(field=field), TemporaryDirectory() as directory:
                self.save(directory)
                (dataset_paths(directory)[2]).unlink()
                path = dataset_paths(directory)[1]
                private = json.loads(path.read_text())
                private["private_truth"]["A"][field] = bad
                path.write_text(json.dumps(private))
                with self.assertRaises(ValueError):
                    load_dataset(directory)


class ConsolidatedDatasetLayoutTests(unittest.TestCase):
    def test_standard_paths_separate_public_and_private_siblings(self):
        with TemporaryDirectory() as directory:
            public = Path(directory) / "data" / "public" / "example"
            public_path, private_path, manifest = dataset_paths(public)
            self.assertEqual(public_path, public / "public.json")
            self.assertEqual(private_path, Path(directory) / "data" / "private" / "example" / "private_truth.json")
            self.assertEqual(manifest, public / "manifest.json")
            with self.assertRaises(ValueError):
                dataset_paths(public, public)

    def test_dataset_builder_cli_constructs_separated_mixed_inputs(self):
        from build_dataset import main as build_main
        with TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            self.assertEqual(build_main(["--case", "mixed", "--name", "example", "--bits", "64",
                                         "--data-root", directory]), 0)
            public = Path(directory) / "public" / "example"
            self.assertFalse((public / "private_truth.json").exists())
            self.assertTrue((Path(directory) / "private" / "example" / "private_truth.json").exists())
            case = load_dataset(public)
            result = audit_public_keys(case["public_keys"], algorithm="batch")
            self.assertEqual(result["num_unique_moduli"], 16)
            self.assertEqual(len(result["recovered_records"]), 14)

    def test_dataset_builder_cli_encrypt_attack_recover(self):
        from build_dataset import main as build_main
        with TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            self.assertEqual(build_main(["--case", "shared", "--name", "message_example", "--bits", "1024",
                                         "--num-keys", "2", "--shared-keys", "2", "--message", "hello",
                                         "--data-root", directory]), 0)
            case = load_dataset(Path(directory) / "public" / "message_example")
            result = audit_public_keys(case["public_keys"], algorithm="batch")
            self.assertEqual(set(recover_messages(case["public_keys"], result).values()), {b"hello"})

    def test_dataset_builder_rejects_parent_traversal_before_writing(self):
        from build_dataset import main as build_main
        with TemporaryDirectory() as directory, redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as error:
                build_main(["--name", "../outside", "--data-root", directory])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(list(Path(directory).iterdir()), [])


class DatasetGapSerializationTests(unittest.TestCase):
    def case_with_gap(self):
        public = [{"key_id": "local", "n": 187, "e": 17, "ciphertext": b"\x00\xff"}]
        truth = {"local": {"p": 11, "q": 17, "case_type": "serialization_only",
                           "expected_message": b"message", "actual_gap": 6}}
        return public, truth

    def test_actual_gap_round_trips_as_private_hex_only(self):
        public, truth = self.case_with_gap()
        with TemporaryDirectory() as directory:
            save_dataset(directory, public, truth, [])
            public_path, private_path, _ = dataset_paths(directory)
            public_document = json.loads(public_path.read_text())
            private_document = json.loads(private_path.read_text())
            self.assertNotIn("actual_gap", public_path.read_text())
            self.assertEqual(set(public_document["public_keys"][0]),
                             {"key_id", "n", "e", "ciphertext_hex"})
            self.assertEqual(private_document["private_truth"]["local"]["actual_gap"], "0x6")
            loaded = load_dataset(directory)
            self.assertEqual(loaded["private_truth"], truth)
            self.assertEqual(loaded["public_keys"], public)
            self.assertIs(type(loaded["private_truth"]["local"]["actual_gap"]), int)

    def test_large_actual_gap_stays_exact(self):
        # Serialization values need not be prime.
        p, q = (1 << 1024) + 643, (1 << 512) + 159
        gap = abs(p - q)
        self.assertGreater(gap, 1 << 53)
        public = [{"key_id": "large", "n": p*q, "e": 17}]
        truth = {"large": {"p": p, "q": q, "case_type": "serialization_only", "actual_gap": gap}}
        with TemporaryDirectory() as directory:
            save_dataset(directory, public, truth, [])
            self.assertEqual(load_dataset(directory)["private_truth"]["large"]["actual_gap"], gap)
            private_document = json.loads(dataset_paths(directory)[1].read_text())
            self.assertEqual(private_document["private_truth"]["large"]["actual_gap"], hex(gap))

    def test_invalid_actual_gap_rejected_before_any_write(self):
        public, truth = self.case_with_gap()
        for invalid in (True, False, 0, -6, 7, 6.0, "6", None):
            with self.subTest(gap=invalid), TemporaryDirectory() as parent:
                directory = Path(parent) / "new-dataset"
                changed = deepcopy(truth)
                changed["local"]["actual_gap"] = invalid
                with self.assertRaisesRegex(ValueError, "actual_gap"):
                    save_dataset(directory, public, changed, [])
                self.assertFalse(directory.exists())

    def test_invalid_or_mismatched_stored_actual_gap_rejected_without_manifest(self):
        public, truth = self.case_with_gap()
        for invalid in (True, False, 6, 6.0, "0x0", "0x7", "6", "0x-6", "0x6.0"):
            with self.subTest(gap=invalid), TemporaryDirectory() as directory:
                save_dataset(directory, public, truth, [])
                _, private_path, manifest_path = dataset_paths(directory)
                manifest_path.unlink()  # Exercise gap validation itself.
                document = json.loads(private_path.read_text())
                document["private_truth"]["local"]["actual_gap"] = invalid
                private_path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    load_dataset(directory)


class DatasetAssemblyTests(unittest.TestCase):
    def single_case(self, p=11, q=17, *, exponent=17, key_id="local"):
        return {
            "public_key": {"key_id": key_id, "n": p*q, "e": exponent},
            "private_truth": {"p": p, "q": q, "case_type": "provided_case",
                              "actual_gap": abs(p-q)},
        }

    def collection_case(self):
        return {
            "public_keys": [
                {"key_id": "local", "n": 187, "e": 17},
                {"key_id": "other", "n": 1147, "e": 17},
            ],
            "private_truth": {
                "local": {"p": 11, "q": 17, "case_type": "provided_case", "actual_gap": 6},
                "other": {"p": 31, "q": 37, "case_type": "provided_case", "actual_gap": 6},
            },
            "expected_vulnerable_ids": [],
        }

    def test_colliding_local_ids_are_replaced_and_cross_group_sharing_recomputed(self):
        collection = self.collection_case()
        single = self.single_case(11, 23)
        result = assemble_dataset(iter([collection, single]))
        self.assertEqual([key["key_id"] for key in result["public_keys"]],
                         ["key_001", "key_002", "key_003"])
        self.assertEqual([key["n"] for key in result["public_keys"]], [187, 1147, 253])
        self.assertEqual(result["expected_vulnerable_ids"], ["key_001", "key_003"])
        self.assertEqual([truth["observable_shared_factor"] for truth in result["private_truth"].values()],
                         [True, False, True])
        audit = audit_public_keys(result["public_keys"])
        self.assertEqual([record["key_id"] for record in audit["recovered_records"]],
                         result["expected_vulnerable_ids"])

    def test_duplicate_only_records_do_not_gain_observable_shared_factors(self):
        result = assemble_dataset([self.single_case()], duplicate_indices=(0, 0))
        self.assertEqual(len(result["public_keys"]), 3)
        self.assertEqual(result["expected_vulnerable_ids"], [])
        self.assertTrue(all(not truth["observable_shared_factor"]
                            for truth in result["private_truth"].values()))
        audit = audit_public_keys(result["public_keys"], algorithm="batch")
        self.assertEqual(audit["num_unique_moduli"], 1)
        self.assertEqual(audit["gcd_calls"], 0)
        self.assertEqual(audit["recovered_records"], [])

    def test_duplicate_indices_always_refer_to_original_flattened_records(self):
        result = assemble_dataset([self.collection_case()], duplicate_indices=(1, 0, 1))
        self.assertEqual([key["n"] for key in result["public_keys"]], [187, 1147, 1147, 187, 1147])
        # Newly added duplicates cannot become duplication sources.
        with self.assertRaises(ValueError):
            assemble_dataset([self.collection_case()], duplicate_indices=(0, 2))

    def test_same_modulus_with_different_exponents_is_preserved(self):
        result = assemble_dataset([
            self.single_case(exponent=17), self.single_case(exponent=3), self.single_case(11, 23),
        ])
        self.assertEqual([key["e"] for key in result["public_keys"]], [17, 3, 17])
        audit = audit_public_keys(result["public_keys"])
        self.assertEqual(audit["num_records"], 3)
        self.assertEqual(audit["num_unique_moduli"], 2)
        self.assertEqual(audit["gcd_calls"], 1)
        self.assertEqual([record["e"] for record in audit["recovered_records"]], [17, 3, 17])
        self.assertEqual(result["expected_vulnerable_ids"], ["key_001", "key_002", "key_003"])

    def test_inputs_and_supported_fields_are_preserved_without_aliasing(self):
        case = self.single_case()
        case["public_key"]["ciphertext"] = b"stored ciphertext\x00"
        case["private_truth"]["expected_message"] = b"stored message\xff"
        case["private_truth"]["intended_weak_generation"] = True
        case["private_truth"]["notes"] = {"items": ["original"]}
        original = deepcopy(case)
        result = assemble_dataset([case], duplicate_indices=(0,), shuffle_seed=7)
        self.assertEqual(case, original)
        for public in result["public_keys"]:
            truth = result["private_truth"][public["key_id"]]
            self.assertEqual(public["ciphertext"], original["public_key"]["ciphertext"])
            self.assertEqual(truth["expected_message"], original["private_truth"]["expected_message"])
            self.assertEqual(truth["actual_gap"], 6)
            self.assertTrue(truth["intended_weak_generation"])
        result["public_keys"][0]["e"] = 3
        result["private_truth"]["key_001"]["notes"]["items"].append("changed")
        self.assertEqual(case, original)
        self.assertEqual(result["private_truth"]["key_002"]["notes"], {"items": ["original"]})

    def test_seeded_shuffle_is_repeatable_local_and_relabels_after_ordering(self):
        cases = [self.collection_case(), self.single_case(11, 23)]
        original = deepcopy(cases)
        state = random.getstate()
        first = assemble_dataset(cases, duplicate_indices=(0, 2), shuffle_seed=4010)
        second = assemble_dataset(cases, duplicate_indices=(0, 2), shuffle_seed=4010)
        self.assertEqual(first, second)
        self.assertEqual(random.getstate(), state)
        self.assertEqual(cases, original)
        self.assertEqual([key["key_id"] for key in first["public_keys"]],
                         ["key_{:03d}".format(index) for index in range(1, 6)])
        for public in first["public_keys"]:
            truth = first["private_truth"][public["key_id"]]
            self.assertEqual(public["n"], truth["p"] * truth["q"])

    def test_invalid_indices_and_seeds_are_rejected(self):
        for indices, error in (((True,), TypeError), ((False,), TypeError), ((1.0,), TypeError),
                               (("0",), TypeError), ((-1,), ValueError), ((1,), ValueError),
                               (None, TypeError), ("0", TypeError)):
            with self.subTest(indices=indices):
                with self.assertRaises(error):
                    assemble_dataset([self.single_case()], duplicate_indices=indices)
        for seed in (True, False, 1.0, "4010", []):
            with self.subTest(seed=seed):
                with self.assertRaises(TypeError):
                    assemble_dataset([self.single_case()], shuffle_seed=seed)

    def test_empty_or_malformed_case_shapes_are_rejected(self):
        both_shapes = self.collection_case()
        both_shapes["public_key"] = self.single_case()["public_key"]
        repeated_ids = self.collection_case()
        repeated_ids["public_keys"][1]["key_id"] = "local"
        bad_factors = self.single_case()
        bad_factors["private_truth"]["q"] = 19
        invalid = (
            ([], ValueError), ([{"public_keys": [], "private_truth": {}}], ValueError),
            (None, TypeError), ("case", TypeError), (self.single_case(), TypeError),
            ([None], TypeError), ([{}], ValueError), ([both_shapes], ValueError),
            ([{"public_key": self.single_case()["public_key"]}], ValueError),
            ([{"public_keys": [187], "private_truth": {}}], TypeError),
            ([repeated_ids], ValueError), ([bad_factors], ValueError),
        )
        for cases, error in invalid:
            with self.subTest(cases=cases):
                with self.assertRaises(error):
                    assemble_dataset(cases)

    def test_conflicting_factor_truth_for_same_modulus_is_rejected(self):
        # Invalid factors must not create false prime-sharing labels.
        first = self.single_case(9, 25)
        second = self.single_case(15, 15)
        del second["private_truth"]["actual_gap"]
        with self.assertRaises(ValueError):
            assemble_dataset([first, second])

    def test_assembly_rejects_composite_equal_or_even_factors_and_bad_exponents(self):
        equal = self.single_case(11, 11)
        del equal["private_truth"]["actual_gap"]
        invalid_cases = (
            [self.single_case(9, 5), self.single_case(9, 7)],
            [self.single_case(11, 21)], [equal], [self.single_case(2, 17)],
            [self.single_case(exponent=5)], [self.single_case(exponent=161)],
            [self.single_case(), self.single_case(exponent=5)],
        )
        for cases in invalid_cases:
            with self.subTest(cases=cases):
                with self.assertRaises(ValueError):
                    assemble_dataset(cases)

    def test_assembly_primality_validation_is_cached_across_groups(self):
        from Crypto.Util.number import isPrime
        with patch("build_dataset.isPrime", wraps=isPrime) as primality:
            assemble_dataset([self.collection_case(), self.single_case(11, 23), self.single_case()])
        self.assertEqual(primality.call_count, 5)
        self.assertEqual({call.args[0] for call in primality.call_args_list}, {11, 17, 23, 31, 37})

    def test_merge_cli_saves_new_separated_dataset_and_preserves_sources(self):
        from build_dataset import main as build_main
        with TemporaryDirectory() as directory:
            data = Path(directory) / "data"
            sources = []
            for name, single in (("first", self.single_case()), ("second", self.single_case(11, 23))):
                source = data / "public" / name
                save_dataset(source, [single["public_key"]],
                             {"local": single["private_truth"]}, [])
                sources.append(source)
            before = {str(path): path.read_bytes()
                      for source in sources for path in dataset_paths(source)}
            with redirect_stdout(StringIO()):
                code = build_main(["--merge", *(str(source) for source in sources),
                                   "--name", "combined", "--data-root", str(data),
                                   "--duplicate-index", "0", "--shuffle-seed", "7"])
            self.assertEqual(code, 0)
            merged = data / "public" / "combined"
            loaded = load_dataset(merged)
            self.assertEqual(len(loaded["public_keys"]), 3)
            self.assertEqual(len(loaded["expected_vulnerable_ids"]), 3)
            self.assertTrue((data / "private" / "combined" / "private_truth.json").exists())
            self.assertFalse((merged / "private_truth.json").exists())
            self.assertEqual(len(audit_public_keys(loaded["public_keys"])["recovered_records"]), 3)
            for path, original_bytes in before.items():
                self.assertEqual(Path(path).read_bytes(), original_bytes)
            for public in loaded["public_keys"]:
                truth = loaded["private_truth"][public["key_id"]]
                self.assertEqual(truth["actual_gap"], abs(truth["p"] - truth["q"]))
            saved = _directory_snapshot(merged)
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                build_main(["--merge", *(str(source) for source in sources),
                            "--name", "combined", "--data-root", str(data)])
            self.assertEqual(error.exception.code, 1)
            self.assertEqual(_directory_snapshot(merged), saved)

    def test_merge_and_case_are_mutually_exclusive_before_writes(self):
        from build_dataset import main as build_main
        with TemporaryDirectory() as directory, redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as error:
                build_main(["--merge", "missing", "--case", "shared", "--name", "new",
                            "--data-root", directory])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_builtin_cli_defaults_skip_assembly_but_options_enable_it(self):
        from build_dataset import main as build_main
        with TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            with patch("build_dataset.assemble_dataset", side_effect=AssertionError("default must stay unchanged")):
                self.assertEqual(build_main(["--name", "default", "--data-root", directory,
                                             "--bits", "64", "--num-keys", "2"]), 0)
            self.assertEqual(build_main(["--case", "shared", "--name", "assembled", "--data-root", directory,
                                         "--bits", "64", "--num-keys", "2", "--duplicate-index", "0",
                                         "--shuffle-seed", "4010"]), 0)
            assembled = load_dataset(Path(directory) / "public" / "assembled")
            self.assertEqual(len(assembled["public_keys"]), 3)
            self.assertEqual(len(assembled["expected_vulnerable_ids"]), 3)


if __name__ == "__main__":
    unittest.main()
