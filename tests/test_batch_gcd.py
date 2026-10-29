"""Batch-GCD tests; direct arithmetic is an independent oracle."""

from itertools import combinations, permutations
import math
import random
import unittest
from unittest.mock import patch

from Crypto.Util.number import isPrime

from batch_gcd_attack import (
    build_product_tree,
    compute_batch_gcds,
    compute_leaf_remainders,
    scan_moduli_batch,
)
from shared_prime_attack import euclidean_gcd, scan_moduli


def factor_map(result):
    return {
        modulus: (finding["p"], finding["q"])
        for modulus, finding in result["findings"].items()
        if finding["status"] == "factored"
    }


class ProductAndRemainderTreeTests(unittest.TestCase):
    def test_product_tree_has_leaves_first_and_odd_carry(self):
        self.assertEqual(build_product_tree([2, 3, 5]), [[2, 3, 5], [6, 5], [30]])

    def test_empty_and_singleton_tree_conventions(self):
        self.assertEqual(build_product_tree([]), [])
        self.assertEqual(compute_leaf_remainders([]), [])
        self.assertEqual(build_product_tree([187]), [[187]])
        self.assertEqual(compute_leaf_remainders([[187]]), [187])

    def test_odd_three_five_seven_leaf_levels_and_direct_remainders(self):
        leaves = [2, 3, 5, 7, 11, 13, 17]
        for count in (3, 5, 7):
            values = leaves[:count]
            with self.subTest(count=count):
                tree = build_product_tree(values)
                self.assertEqual(tree[0], values)
                self.assertEqual(tree[-1], [math.prod(values)])
                for children, parents in zip(tree, tree[1:]):
                    self.assertEqual(len(parents), (len(children) + 1) // 2)
                    for index, parent in enumerate(parents):
                        self.assertEqual(parent, math.prod(children[2*index:2*index+2]))
                product = math.prod(values)
                self.assertEqual(compute_leaf_remainders(tree),
                                 [product % (value * value) for value in values])

    def test_tree_copies_an_iterable_and_allows_repeated_arithmetic_leaves(self):
        values = [3, 3, 5]
        tree = build_product_tree(iter(values))
        self.assertEqual(values, [3, 3, 5])
        self.assertIsNot(tree[0], values)
        self.assertEqual(tree[-1], [45])
        self.assertEqual(compute_leaf_remainders(tree), [0, 0, 20])

    def test_remainder_tree_does_not_mutate_product_levels(self):
        tree = build_product_tree([187, 253, 493, 1147, 1271])
        original = [level[:] for level in tree]
        compute_leaf_remainders(tree)
        self.assertEqual(tree, original)

    def test_zero_leaf_remainder_is_valid(self):
        inputs = [187, 253, 391]
        self.assertEqual(compute_leaf_remainders(build_product_tree(inputs)), [0, 0, 0])

    def test_tree_rejects_invalid_values(self):
        for invalid in (True, False, 1.0, "3", None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(TypeError):
                    build_product_tree([3, invalid])
        for invalid in (-3, 0, 1):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    build_product_tree([3, invalid])

    def test_remainder_helper_rejects_malformed_tree(self):
        for tree in ([[]], [[3, 5]], [[3, 5], [16]], [[3], [3]], [[3, 5, 7], [105]]):
            with self.subTest(tree=tree):
                with self.assertRaises(ValueError):
                    compute_leaf_remainders(tree)
        for tree in (None, 15, [[3, True]]):
            with self.subTest(tree=tree):
                with self.assertRaises(TypeError):
                    compute_leaf_remainders(tree)


class RawBatchGcdTests(unittest.TestCase):
    def test_raw_values_match_other_product_oracle(self):
        fixtures = (
            [], [187], [187, 253], [187, 667, 1147],
            [187, 253, 493], [187, 253, 391],
            [187, 253, 319, 1147, 1271],
            [187, 253, 319, 341, 407, 451, 473],
        )
        for inputs in fixtures:
            with self.subTest(inputs=inputs):
                expected = [math.gcd(n, math.prod(inputs[:i] + inputs[i+1:]))
                            for i, n in enumerate(inputs)]
                self.assertEqual(compute_batch_gcds(inputs), expected)

    def test_chain_and_triangle_raw_regressions(self):
        self.assertEqual(compute_batch_gcds([187, 253, 493]), [187, 11, 17])
        self.assertEqual(compute_batch_gcds([187, 253, 391]), [187, 253, 391])

    def test_zero_quotient_reaches_backend_without_error(self):
        calls = []

        def counted(a, b):
            calls.append((a, b))
            return math.gcd(a, b)

        self.assertEqual(compute_batch_gcds([187, 253, 391], counted), [187, 253, 391])
        self.assertEqual(calls, [(187, 0), (253, 0), (391, 0)])

    def test_empty_singleton_make_no_gcd_calls(self):
        with patch("shared_prime_attack.euclidean_gcd") as gcd:
            self.assertEqual(compute_batch_gcds([]), [])
            self.assertEqual(compute_batch_gcds([187]), [1])
        gcd.assert_not_called()

    def test_calltime_default_uses_shared_euclidean_backend(self):
        with patch("shared_prime_attack.euclidean_gcd", wraps=euclidean_gcd) as gcd:
            self.assertEqual(compute_batch_gcds([187, 253]), [11, 11])
        self.assertEqual(gcd.call_count, 2)

    def test_remainders_must_be_exactly_divisible(self):
        with patch("batch_gcd_attack.compute_leaf_remainders", return_value=[1, 1]):
            with self.assertRaisesRegex(ValueError, "exactly divisible"):
                compute_batch_gcds([187, 253])


class BatchScannerTests(unittest.TestCase):
    def assert_counters(self, result, leaf_calls, fallback_calls):
        self.assertEqual(result["batch_leaf_gcd_calls"], leaf_calls)
        self.assertEqual(result["pairwise_gcd_calls"], fallback_calls)
        self.assertEqual(result["fallback_gcd_calls"], fallback_calls)
        self.assertEqual(result["gcd_calls"], leaf_calls + fallback_calls)
        self.assertIsNone(result["matching_pair_count"])

    def test_shared_pair_is_directly_factored_with_raw_evidence(self):
        result = scan_moduli_batch([187, 253])
        self.assertEqual(result["algorithm"], "batch_with_fallback")
        self.assertEqual(factor_map(result), {187: (11, 17), 253: (11, 23)})
        for modulus, finding in result["findings"].items():
            self.assertEqual(finding["n"], modulus)
            self.assertEqual(finding["raw_batch_gcd"], 11)
            self.assertEqual(finding["resolution_method"], "batch_direct")
        self.assertEqual(result["full_gcd_before_fallback"], 0)
        self.assertEqual(result["unresolved_after_fallback"], 0)
        self.assert_counters(result, 2, 0)

    def test_empty_singleton_shortcuts_match_pairwise_no_work(self):
        for inputs in ([], [187]):
            with self.subTest(inputs=inputs):
                with patch("shared_prime_attack.euclidean_gcd") as gcd:
                    result = scan_moduli_batch(inputs)
                gcd.assert_not_called()
                self.assertEqual(set(result["findings"]), set(inputs))
                self.assertEqual(factor_map(result), {})
                self.assertEqual(result["full_gcd_before_fallback"], 0)
                self.assertEqual(result["unresolved_after_fallback"], 0)
                for finding in result["findings"].values():
                    self.assertEqual(finding["status"], "no_shared_factor_in_dataset")
                    self.assertEqual(finding["raw_batch_gcd"], 1)
                self.assert_counters(result, 0, 0)

    def test_independent_controls_have_no_false_factorizations(self):
        result = scan_moduli_batch([187, 667, 1147])
        self.assertEqual(factor_map(result), {})
        for finding in result["findings"].values():
            self.assertEqual(finding["status"], "no_shared_factor_in_dataset")
            self.assertEqual(finding["raw_batch_gcd"], 1)
            self.assertIsNone(finding["p"])
            self.assertIsNone(finding["q"])
            self.assertIsNone(finding["resolution_method"])
        self.assert_counters(result, 3, 0)

    def test_chain_single_full_gcd_uses_already_resolved_companion(self):
        calls = []

        def counted(a, b):
            calls.append((a, b))
            return math.gcd(a, b)

        inputs = [187, 253, 493]
        result = scan_moduli_batch(inputs, counted)
        product = math.prod(inputs)
        expected_leaf_calls = [(n, (product % (n*n)) // n) for n in inputs]
        self.assertEqual(calls, expected_leaf_calls + [(187, 253)])
        self.assertEqual(factor_map(result), {187: (11, 17), 253: (11, 23), 493: (17, 29)})
        self.assertEqual(result["findings"][187]["raw_batch_gcd"], 187)
        self.assertEqual(result["findings"][187]["resolution_method"], "batch_fallback")
        self.assertEqual(result["findings"][253]["resolution_method"], "batch_direct")
        self.assertEqual(result["full_gcd_before_fallback"], 1)
        self.assertEqual(result["unresolved_after_fallback"], 0)
        self.assert_counters(result, 3, 1)
        self.assertEqual(len(calls), result["gcd_calls"])

    def test_triangle_all_full_gcds_are_resolved(self):
        calls = []

        def counted(a, b):
            calls.append((a, b))
            return math.gcd(a, b)

        result = scan_moduli_batch([187, 253, 391], counted)
        self.assertEqual(factor_map(result), {187: (11, 17), 253: (11, 23), 391: (17, 23)})
        self.assertEqual(result["full_gcd_before_fallback"], 3)
        self.assertEqual(result["unresolved_after_fallback"], 0)
        self.assertTrue(all(f["resolution_method"] == "batch_fallback"
                            for f in result["findings"].values()))
        self.assertEqual(calls, [(187, 0), (253, 0), (391, 0),
                                 (187, 253), (253, 187), (391, 187)])
        self.assert_counters(result, 3, 3)

    def test_raw_diagnostic_leaves_whole_gcds_explicitly_unresolved(self):
        result = scan_moduli_batch([187, 253, 493], resolve_full_gcd=False)
        self.assertEqual(result["algorithm"], "batch_raw")
        self.assertEqual(result["findings"][187], {
            "n": 187, "status": "unresolved_full_gcd", "p": None, "q": None,
            "resolution_method": None, "raw_batch_gcd": 187,
        })
        self.assertEqual(factor_map(result), {253: (11, 23), 493: (17, 29)})
        self.assertEqual(result["full_gcd_before_fallback"], 1)
        self.assertEqual(result["unresolved_after_fallback"], 1)
        self.assert_counters(result, 3, 0)

    def test_raw_triangle_does_not_claim_any_factorization(self):
        result = scan_moduli_batch([187, 253, 391], resolve_full_gcd=False)
        self.assertEqual(factor_map(result), {})
        self.assertEqual(result["unresolved_after_fallback"], 3)
        self.assert_counters(result, 3, 0)

    def test_shared_group_and_dense_valid_topology_agree_with_pairwise(self):
        fixtures = (
            [11*q for q in (13, 17, 19, 23, 29, 31, 37)],
            [p*q for p, q in combinations((3, 5, 7, 11, 13, 17, 19), 2)],
        )
        for inputs in fixtures:
            with self.subTest(num_moduli=len(inputs)):
                result = scan_moduli_batch(inputs)
                self.assertEqual(factor_map(result), factor_map(scan_moduli(inputs)))
                self.assertEqual(result["unresolved_after_fallback"], 0)
                self.assertLessEqual(len(result["optional_debug_evidence"]["fallback_witnesses"]), 20)
        self.assertTrue(result["optional_debug_evidence"]["fallback_witnesses_truncated"])

    def test_permutations_preserve_raw_and_resolved_factor_maps(self):
        inputs = [187, 253, 493, 1147]
        expected_raw = dict(zip(inputs, compute_batch_gcds(inputs)))
        expected_factors = factor_map(scan_moduli(inputs))
        for permuted in permutations(inputs):
            with self.subTest(inputs=permuted):
                result = scan_moduli_batch(iter(permuted))
                self.assertEqual(factor_map(result), expected_factors)
                self.assertEqual({n: f["raw_batch_gcd"] for n, f in result["findings"].items()}, expected_raw)
                self.assertEqual(result["gcd_calls"], result["batch_leaf_gcd_calls"] + result["fallback_gcd_calls"])

    def test_deterministic_random_small_topologies_agree_with_pairwise(self):
        # Seeded toy graphs test topology, not prime generation.
        rng = random.Random(4010)
        possible = [p*q for p, q in combinations((3, 5, 7, 11, 13, 17, 19, 23, 29, 31), 2)]
        for size in (0, 1, 2, 3, 5, 7, 9, 13, 17, 25):
            inputs = rng.sample(possible, size)
            with self.subTest(size=size):
                result = scan_moduli_batch(inputs)
                self.assertEqual(factor_map(result), factor_map(scan_moduli(inputs)))
                self.assertEqual(result["unresolved_after_fallback"], 0)

    def test_candidate_primality_checks_are_cached_per_scan(self):
        with patch("batch_gcd_attack.isPrime", wraps=isPrime) as primality:
            scan_moduli_batch([187, 253, 319])
        self.assertEqual(primality.call_count, 4)
        self.assertEqual({call.args[0] for call in primality.call_args_list}, {11, 17, 23, 29})

    def test_composite_or_equal_factors_are_not_reported_as_success(self):
        for inputs in ([45, 75], [165, 195], [25, 35]):
            with self.subTest(inputs=inputs):
                result = scan_moduli_batch(inputs)
                # A nontrivial GCD alone must not count as factorization.
                for n in inputs:
                    if n in (45, 75, 165, 195, 25):
                        self.assertNotEqual(result["findings"][n]["status"], "factored")

    def test_unresolved_invalid_square_stays_visible_after_full_fallback(self):
        result = scan_moduli_batch([25, 35, 55])
        self.assertEqual(result["findings"][25]["status"], "unresolved_full_gcd")
        self.assertIsNone(result["findings"][25]["p"])
        self.assertEqual(result["full_gcd_before_fallback"], 1)
        self.assertEqual(result["unresolved_after_fallback"], 1)
        self.assert_counters(result, 3, 2)

    def test_fallback_whole_modulus_gcd_rejects_unsupported_domain(self):
        with self.assertRaisesRegex(ValueError, "two-distinct-prime RSA domain"):
            scan_moduli_batch([15, 105])

    def test_never_calls_the_full_pairwise_scanner(self):
        with patch("shared_prime_attack.scan_moduli", side_effect=AssertionError("unexpected full scan")) as pairwise:
            result = scan_moduli_batch([187, 253, 391])
        pairwise.assert_not_called()
        self.assertEqual(len(factor_map(result)), 3)

    def test_trees_are_rebuilt_for_each_attack_run(self):
        with patch("batch_gcd_attack.build_product_tree", wraps=build_product_tree) as builder:
            scan_moduli_batch([187, 253])
            scan_moduli_batch([187, 253, 493])
        self.assertEqual(builder.call_count, 2)

    def test_invalid_moduli_and_duplicates_rejected_before_any_gcd(self):
        malformed = (
            (None, TypeError), (187, TypeError), ([{}], TypeError),
            ([True], TypeError), ([187.0], TypeError), (["187"], TypeError),
            ([0], ValueError), ([1], ValueError), ([-187], ValueError),
            ([2], ValueError), ([188], ValueError), ([187, 187], ValueError),
            ([187, 187, 253], ValueError), ([187, 253, 0], ValueError),
        )
        for function in (compute_batch_gcds, scan_moduli_batch):
            for inputs, expected_error in malformed:
                with self.subTest(function=function.__name__, inputs=inputs):
                    with patch("shared_prime_attack.euclidean_gcd") as gcd:
                        with self.assertRaises(expected_error):
                            function(inputs)
                    gcd.assert_not_called()

    def test_backend_return_values_are_checked_at_leaves(self):
        for function in (compute_batch_gcds, scan_moduli_batch):
            for invalid in (True, False, "11", 11.0, None):
                with self.subTest(function=function.__name__, invalid=invalid):
                    with self.assertRaises(TypeError):
                        function([187, 253], gcd_fn=lambda a, b: invalid)
            for invalid in (-1, 0, 188, 17, 22):
                with self.subTest(function=function.__name__, invalid=invalid):
                    with self.assertRaises(ValueError):
                        function([187, 253], gcd_fn=lambda a, b: invalid)

    def test_backend_return_values_are_checked_in_fallback(self):
        for invalid, error in ((True, TypeError), (0, ValueError), (22, ValueError), (200, ValueError)):
            calls = []

            def broken_fallback(a, b):
                calls.append((a, b))
                return math.gcd(a, b) if len(calls) <= 3 else invalid

            with self.subTest(invalid=invalid):
                with self.assertRaises(error):
                    scan_moduli_batch([187, 253, 493], gcd_fn=broken_fallback)

    def test_invalid_configuration_is_explicit(self):
        for backend in (1, False, "math.gcd"):
            with self.subTest(backend=backend):
                with self.assertRaises(TypeError):
                    compute_batch_gcds([187, 253], gcd_fn=backend)
                with self.assertRaises(TypeError):
                    scan_moduli_batch([187, 253], gcd_fn=backend)
        for resolve in (0, 1, "False", None):
            with self.subTest(resolve=resolve):
                with self.assertRaises(TypeError):
                    scan_moduli_batch([187, 253], resolve_full_gcd=resolve)


if __name__ == "__main__":
    unittest.main()
