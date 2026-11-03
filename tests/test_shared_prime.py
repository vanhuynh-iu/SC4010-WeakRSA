"""GCD, scanner and public-input validation tests."""

import copy
import math
from itertools import combinations, permutations
import unittest
from unittest.mock import patch

from Crypto.Util.number import isPrime

from normalization import normalize_public_keys, validate_public_records
from shared_prime_attack import euclidean_gcd, scan_moduli


class EuclideanGcdTests(unittest.TestCase):
    def test_known_examples(self):
        cases = (
            (187, 253, 11),
            (253, 187, 11),
            (35, 143, 1),
            (187, 187, 187),
            (48, 18, 6),
        )
        for a, b, expected in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(euclidean_gcd(a, b), expected)

    def test_zero_inputs(self):
        for a, b, expected in ((0, 24, 24), (24, 0, 24), (0, 0, 0)):
            with self.subTest(a=a, b=b):
                self.assertEqual(euclidean_gcd(a, b), expected)

    def test_matches_reference_for_small_inputs(self):
        # math.gcd is an independent test reference, not the implementation.
        for a in range(50):
            for b in range(50):
                with self.subTest(a=a, b=b):
                    self.assertEqual(euclidean_gcd(a, b), math.gcd(a, b))

    def test_matches_reference_for_large_integers(self):
        # Large arithmetic checks; no RSA keys are generated.
        cases = (
            ((1 << 2048) - 1, (1 << 1024) - 1),
            ((1 << 2048) + 123, (1 << 1536) + 47),
        )
        for a, b in cases:
            with self.subTest(a_bits=a.bit_length(), b_bits=b.bit_length()):
                self.assertEqual(euclidean_gcd(a, b), math.gcd(a, b))

    def test_rejects_negative_inputs(self):
        for a, b in ((-1, 2), (2, -1), (-1, -1)):
            with self.subTest(a=a, b=b):
                with self.assertRaises(ValueError):
                    euclidean_gcd(a, b)

    def test_rejects_non_integer_inputs(self):
        for invalid in (1.5, "24", None, True, False):
            for a, b in ((invalid, 24), (24, invalid)):
                with self.subTest(a=a, b=b):
                    with self.assertRaises(TypeError):
                        euclidean_gcd(a, b)


class SharedPrimeScannerTests(unittest.TestCase):
    def assert_counters(self, result, expected_calls):
        self.assertEqual(result["algorithm"], "pairwise")
        self.assertEqual(result["gcd_calls"], expected_calls)
        self.assertEqual(result["pairwise_gcd_calls"], expected_calls)
        for name in ("batch_leaf_gcd_calls", "fallback_gcd_calls",
                     "full_gcd_before_fallback", "unresolved_after_fallback"):
            self.assertEqual(result[name], 0)

    def factorizations(self, result):
        return {
            modulus: (finding["p"], finding["q"])
            for modulus, finding in result["findings"].items()
            if finding["status"] == "factored"
        }

    def test_shared_prime_pair_reports_normalized_factorizations(self):
        result = scan_moduli([187, 253])
        self.assertEqual(result, {
            "algorithm": "pairwise",
            "findings": {
                187: {"n": 187, "status": "factored", "p": 11, "q": 17,
                      "resolution_method": "pairwise"},
                253: {"n": 253, "status": "factored", "p": 11, "q": 23,
                      "resolution_method": "pairwise"},
            },
            "gcd_calls": 1,
            "pairwise_gcd_calls": 1,
            "batch_leaf_gcd_calls": 0,
            "fallback_gcd_calls": 0,
            "full_gcd_before_fallback": 0,
            "unresolved_after_fallback": 0,
            "matching_pair_count": 1,
            "optional_debug_evidence": {
                "matching_modulus_pairs": [(187, 253)],
                "matching_pairs_truncated": False,
            },
        })

    def test_unrelated_keys_have_explicit_no_shared_factor_status(self):
        result = scan_moduli([187, 667])  # 11*17 and 23*29.
        self.assertEqual(self.factorizations(result), {})
        for modulus, finding in result["findings"].items():
            self.assertEqual(finding, {
                "n": modulus, "status": "no_shared_factor_in_dataset",
                "p": None, "q": None, "resolution_method": None,
            })
        self.assertEqual(result["matching_pair_count"], 0)
        self.assert_counters(result, 1)

    def test_shared_group_scans_pairs_even_after_factors_are_known(self):
        inputs = [187, 253, 319]  # All three contain prime 11.
        with patch("shared_prime_attack.euclidean_gcd", wraps=euclidean_gcd) as gcd:
            result = scan_moduli(inputs)
        self.assertEqual(gcd.call_args_list, [
            unittest.mock.call(187, 253),
            unittest.mock.call(187, 319),
            unittest.mock.call(253, 319),
        ])
        self.assertEqual(self.factorizations(result), {
            187: (11, 17), 253: (11, 23), 319: (11, 29),
        })
        self.assertEqual(result["matching_pair_count"], 3)
        self.assert_counters(result, 3)

    def test_direct_duplicate_moduli_rejected_before_gcd_work(self):
        # Normalize duplicate moduli before reaching the scanner.
        for inputs in ([187, 187], [187, 187, 253]):
            with self.subTest(inputs=inputs):
                with patch("shared_prime_attack.euclidean_gcd") as gcd:
                    with self.assertRaisesRegex(ValueError, "distinct"):
                        scan_moduli(inputs)
                gcd.assert_not_called()

    def test_empty_and_single_input_do_no_gcd_work(self):
        for inputs in ([], [187]):
            with self.subTest(inputs=inputs):
                with patch("shared_prime_attack.euclidean_gcd") as gcd:
                    result = scan_moduli(inputs)
                gcd.assert_not_called()
                self.assert_counters(result, 0)
                self.assertEqual(set(result["findings"]), set(inputs))
                self.assertEqual(self.factorizations(result), {})
                self.assertEqual(result["matching_pair_count"], 0)

    def test_modulus_generator_consumed_once_without_mutating_input(self):
        inputs = [187, 253, 1147]
        source = iter(inputs)
        result = scan_moduli(source)
        self.assertEqual(list(source), [])
        self.assertEqual(inputs, [187, 253, 1147])
        self.assertEqual(self.factorizations(result), {187: (11, 17), 253: (11, 23)})
        self.assert_counters(result, 3)

    def test_raw_records_and_private_metadata_are_not_scanner_inputs(self):
        class UnusableMetadata:
            def __bool__(self):
                raise AssertionError("private metadata must not be inspected")

        inputs = [{"key_id": "A", "n": 187, "p": UnusableMetadata()}]
        with patch("shared_prime_attack.euclidean_gcd") as gcd:
            with self.assertRaises(TypeError):
                scan_moduli(inputs)
        gcd.assert_not_called()

    def test_composite_and_repeated_prime_factors_are_not_recoveries(self):
        # Odd input validation alone does not prove a two-prime modulus.
        for left, right in ((45, 75), (165, 195), (25, 35)):
            with self.subTest(left=left, right=right):
                result = scan_moduli([left, right])
                self.assertEqual(self.factorizations(result), {})
                self.assertEqual(result["matching_pair_count"], 0)
                self.assert_counters(result, 1)

    def test_whole_modulus_gcd_rejects_unsupported_domain(self):
        # Distinct valid two-prime moduli cannot divide one another.
        with self.assertRaisesRegex(ValueError, "two-distinct-prime RSA domain"):
            scan_moduli([15, 105])

    def test_mixed_set_has_ordered_verified_factors(self):
        result = scan_moduli([187, 253, 551, 119])
        self.assertEqual(self.factorizations(result), {
            187: (11, 17), 253: (11, 23), 119: (7, 17),
        })
        for modulus, finding in result["findings"].items():
            if finding["status"] == "factored":
                self.assertLess(finding["p"], finding["q"])
                self.assertEqual(finding["p"] * finding["q"], modulus)
                self.assertEqual(finding["resolution_method"], "pairwise")
        self.assertEqual(result["matching_pair_count"], 2)
        self.assert_counters(result, 6)

    def test_multiple_disjoint_shared_groups_all_recovered(self):
        # 11*17, 11*23; 31*37, 31*41; independent control 59*61.
        result = scan_moduli([187, 253, 1147, 1271, 3599])
        self.assertEqual(self.factorizations(result), {
            187: (11, 17), 253: (11, 23),
            1147: (31, 37), 1271: (31, 41),
        })
        self.assertEqual(result["findings"][3599]["status"], "no_shared_factor_in_dataset")
        self.assertEqual(result["matching_pair_count"], 2)
        self.assert_counters(result, 10)

    def test_chain_and_triangle_topologies(self):
        for third, factors, matching_pairs in ((493, (17, 29), 2), (391, (17, 23), 3)):
            with self.subTest(third=third):
                result = scan_moduli([187, 253, third])
                self.assertEqual(self.factorizations(result), {
                    187: (11, 17), 253: (11, 23), third: factors,
                })
                self.assertEqual(result["matching_pair_count"], matching_pairs)
                self.assert_counters(result, 3)

    def test_input_permutations_preserve_findings_and_counts(self):
        expected = scan_moduli([187, 253, 493, 1147])
        for inputs in permutations([187, 253, 493, 1147]):
            with self.subTest(inputs=inputs):
                result = scan_moduli(inputs)
                self.assertEqual(result["findings"], expected["findings"])
                self.assertEqual(result["matching_pair_count"], expected["matching_pair_count"])
                self.assert_counters(result, 6)

    def test_injected_gcd_backend_gets_every_unordered_pair_once(self):
        inputs = [187, 253, 319, 1147]
        calls = []

        def observed_gcd(a, b):
            calls.append((a, b))
            return math.gcd(a, b)

        result = scan_moduli(inputs, gcd_fn=observed_gcd)
        self.assertEqual(calls, list(combinations(inputs, 2)))
        self.assert_counters(result, len(calls))
        self.assertEqual(self.factorizations(result), {
            187: (11, 17), 253: (11, 23), 319: (11, 29),
        })

    def test_candidate_primality_checks_are_cached_within_scan(self):
        with patch("shared_prime_attack.isPrime", wraps=isPrime) as primality:
            scan_moduli([187, 253, 319])
        self.assertEqual(primality.call_count, 4)
        self.assertEqual({call.args[0] for call in primality.call_args_list}, {11, 17, 23, 29})

    def test_pair_evidence_is_bounded_while_pair_count_remains_exact(self):
        inputs = [11 * q for q in (13, 17, 19, 23, 29, 31, 37, 41)]
        result = scan_moduli(inputs)
        evidence = result["optional_debug_evidence"]
        self.assertEqual(result["matching_pair_count"], 28)
        self.assertEqual(len(evidence["matching_modulus_pairs"]), 20)
        self.assertTrue(evidence["matching_pairs_truncated"])
        self.assertEqual(len(self.factorizations(result)), 8)
        self.assert_counters(result, 28)

    def test_rejects_invalid_moduli_before_any_gcd_calls(self):
        malformed = (
            (None, TypeError), (123, TypeError), ("187", TypeError),
            ([None], TypeError), ([{}], TypeError), ([True], TypeError),
            ([187.0], TypeError), (["187"], TypeError),
            ([-187], ValueError), ([0], ValueError), ([1], ValueError),
            ([2], ValueError), ([188], ValueError), ([187, 253, 0], ValueError),
        )
        for inputs, expected_error in malformed:
            with self.subTest(inputs=inputs):
                with patch("shared_prime_attack.euclidean_gcd") as gcd:
                    with self.assertRaises(expected_error):
                        scan_moduli(inputs)
                gcd.assert_not_called()

    def test_rejects_noncallable_gcd_backend(self):
        for backend in (1, False, "math.gcd"):
            with self.subTest(backend=backend):
                with self.assertRaises(TypeError):
                    scan_moduli([187, 253], gcd_fn=backend)

    def test_rejects_invalid_gcd_backend_results(self):
        for invalid in (True, False, 11.0, "11", None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(TypeError):
                    scan_moduli([187, 253], gcd_fn=lambda a, b: invalid)
        for invalid in (-11, 0, 188, 1000, 17, 22):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    scan_moduli([187, 253], gcd_fn=lambda a, b: invalid)

    def test_gcd_backend_failure_does_not_return_a_success_result(self):
        def broken_backend(a, b):
            raise RuntimeError("GCD backend failed")

        with self.assertRaisesRegex(RuntimeError, "GCD backend failed"):
            scan_moduli([187, 253], gcd_fn=broken_backend)


class PublicKeyNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "B", "n": 253, "e": 17},
            {"key_id": "C", "n": 1147, "e": 17},
            {"key_id": "D", "n": 187, "e": 3},
        ]

    def test_four_records_have_three_unique_moduli_and_preserve_exponents(self):
        result = normalize_public_keys(self.records)
        self.assertEqual(result["num_records"], 4)
        self.assertEqual(result["num_unique_moduli"], 3)
        self.assertEqual(result["duplicate_extra_records"], 1)
        self.assertEqual(result["unique_moduli"], [187, 253, 1147])
        self.assertEqual(result["public_records"], self.records)
        self.assertEqual(result["records_by_modulus"], {
            187: [self.records[0], self.records[3]],
            253: [self.records[1]],
            1147: [self.records[2]],
        })
        self.assertEqual(result["duplicate_groups"], {
            187: [self.records[0], self.records[3]],
        })
        self.assertEqual([r["e"] for r in result["records_by_modulus"][187]], [17, 3])

    def test_empty_and_single_records(self):
        empty = normalize_public_keys([])
        self.assertEqual(empty, {
            "public_records": [], "unique_moduli": [],
            "records_by_modulus": {}, "duplicate_groups": {},
            "num_records": 0, "num_unique_moduli": 0,
            "duplicate_extra_records": 0,
        })
        single = normalize_public_keys(self.records[:1])
        self.assertEqual(single["unique_moduli"], [187])
        self.assertEqual(single["records_by_modulus"], {187: [self.records[0]]})
        self.assertEqual(single["duplicate_groups"], {})
        self.assertEqual(single["num_records"], 1)
        self.assertEqual(single["num_unique_moduli"], 1)
        self.assertEqual(single["duplicate_extra_records"], 0)

    def test_duplicate_only_set_groups_all_records_without_factors(self):
        records = [
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "B", "n": 187, "e": 17},
            {"key_id": "C", "n": 187, "e": 3},
        ]
        result = normalize_public_keys(records)
        self.assertEqual(result["unique_moduli"], [187])
        self.assertEqual(result["duplicate_groups"], {187: records})
        self.assertEqual(result["duplicate_extra_records"], 2)
        self.assertTrue(all(set(record) == {"key_id", "n", "e"}
                            for record in result["public_records"]))

    def test_does_not_mutate_or_reuse_callers_dictionaries(self):
        original = copy.deepcopy(self.records)
        result = normalize_public_keys(self.records)
        self.assertEqual(self.records, original)
        for actual, source in zip(result["public_records"], self.records):
            self.assertIsNot(actual, source)
        result["records_by_modulus"][187][0]["e"] = 3
        self.assertEqual(self.records, original)
        self.assertEqual(result["public_records"][0]["e"], 3)

    def test_ciphertext_bytes_are_preserved_exactly_in_validated_copies(self):
        ciphertext = bytes(range(256)) + b"\x00\xff"
        source = {"key_id": "A", "n": 187, "e": 17, "ciphertext": ciphertext}
        result = validate_public_records([source])
        self.assertEqual(result, [source])
        self.assertIsNot(result[0], source)
        self.assertEqual(result[0]["ciphertext"], ciphertext)
        self.assertIsInstance(result[0]["ciphertext"], bytes)
        self.assertEqual(normalize_public_keys(result)["public_records"], [source])
        self.assertEqual(validate_public_records([
            {"key_id": "empty", "n": 187, "e": 17, "ciphertext": b""}
        ])[0]["ciphertext"], b"")

    def test_consumes_input_iterable_once(self):
        class OnePassRecords:
            def __init__(self, records):
                self.records = records
                self.iterations = 0

            def __iter__(self):
                self.iterations += 1
                if self.iterations != 1:
                    raise AssertionError("input iterable was consumed twice")
                return iter(self.records)

        source = OnePassRecords(self.records)
        result = normalize_public_keys(source)
        self.assertEqual(source.iterations, 1)
        self.assertEqual(result["public_records"], self.records)
        generated = normalize_public_keys(record for record in self.records)
        self.assertEqual(generated, result)

    def test_permutation_preserves_groups_but_uses_first_seen_order(self):
        reordered = [self.records[2], self.records[3], self.records[1], self.records[0]]
        before = normalize_public_keys(self.records)
        after = normalize_public_keys(reordered)
        self.assertEqual(after["unique_moduli"], [1147, 187, 253])
        for n in before["unique_moduli"]:
            self.assertEqual(
                {r["key_id"] for r in before["records_by_modulus"][n]},
                {r["key_id"] for r in after["records_by_modulus"][n]},
            )
        self.assertEqual(after["num_records"], before["num_records"])
        self.assertEqual(after["num_unique_moduli"], before["num_unique_moduli"])
        self.assertEqual(after["duplicate_extra_records"], before["duplicate_extra_records"])

    def test_rejects_duplicate_and_blank_ids(self):
        for bad_id, error in (("", ValueError), (" \t\n", ValueError),
                              (None, TypeError), (123, TypeError), (True, TypeError)):
            with self.subTest(key_id=bad_id):
                with self.assertRaises(error):
                    normalize_public_keys([{"key_id": bad_id, "n": 187, "e": 17}])
        for n in (187, 253):
            with self.subTest(second_modulus=n):
                with self.assertRaises(ValueError):
                    normalize_public_keys([
                        {"key_id": "A", "n": 187, "e": 17},
                        {"key_id": "A", "n": n, "e": 3},
                    ])

    def test_rejects_invalid_integer_parameters_and_missing_fields(self):
        for field in ("n", "e"):
            for value in (True, False, 187.0, "187", None):
                record = dict(self.records[0], **{field: value})
                with self.subTest(field=field, value=value):
                    with self.assertRaises(TypeError):
                        normalize_public_keys([record])
            for value in (-187, -1, 0, 1, 2, 188):
                record = dict(self.records[0], **{field: value})
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        normalize_public_keys([record])
        for field in ("key_id", "n", "e"):
            record = dict(self.records[0])
            del record[field]
            with self.subTest(missing=field):
                with self.assertRaises(ValueError):
                    normalize_public_keys([record])

    def test_rejects_secret_labels_and_unknown_fields(self):
        for field in ("p", "q", "d", "case_type", "truth", "private_truth",
                      "group_id", "prime_gap", "vulnerable", "owner", "unknown"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    normalize_public_keys([dict(self.records[0], **{field: None})])

    def test_rejects_nonrecords_noniterables_and_nonbytes_ciphertext(self):
        for records in (None, 123, [None], [187], ["record"], "text", {"key_id": "A"}):
            with self.subTest(records=records):
                with self.assertRaises(TypeError):
                    normalize_public_keys(records)
        for ciphertext in (None, "00ff", bytearray(b"cipher"), [1, 2], 123):
            with self.subTest(ciphertext=ciphertext):
                with self.assertRaises(TypeError):
                    normalize_public_keys([dict(self.records[0], ciphertext=ciphertext)])

    def test_public_validation_does_not_claim_semiprimality_or_invertibility(self):
        # Public validation cannot establish semiprimality.
        records = [
            {"key_id": "prime", "n": 101, "e": 3},
            {"key_id": "many_factors", "n": 105, "e": 5},
            {"key_id": "noninvertible", "n": 187, "e": 5},
        ]
        self.assertEqual(validate_public_records(records), records)


if __name__ == "__main__":
    unittest.main()
