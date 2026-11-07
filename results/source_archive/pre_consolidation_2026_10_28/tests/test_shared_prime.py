"""GCD and public-modulus scan tests."""

import math
from itertools import combinations, permutations
import unittest
from unittest.mock import patch

from Crypto.Util.number import isPrime

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
        # These are arithmetic checks, not generated RSA keys or attack results.
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

    def test_shared_prime_pair_has_v2_contract(self):
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
        # The normalizer handles duplicate-only and duplicate+companion cases;
        # the core scanner must not silently accept either raw form.
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


if __name__ == "__main__":
    unittest.main()
