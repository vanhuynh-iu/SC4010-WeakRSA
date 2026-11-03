"""Checks for Van's controlled generators."""

import math
import unittest
from collections import Counter
from copy import deepcopy
from itertools import combinations
from unittest.mock import patch

from Crypto.Util.number import isPrime

from generators.control_cases import generate_control_key
from generators.shared_prime_cases import (
    _fresh_factor_pair,
    generate_mixed_key_dataset,
    generate_scalability_dataset,
    generate_shared_prime_keys,
    make_observed_subset,
)


class SharedPrimeGenerationTests(unittest.TestCase):
    def test_controlled_collection_has_exactly_the_intended_reuse(self):
        for modulus_bits in (32, 64, 65, 128):
            with self.subTest(modulus_bits=modulus_bits):
                scenario = generate_shared_prime_keys(
                    num_keys=6, num_shared=3, modulus_bits=modulus_bits
                )
                public = scenario["public_keys"]
                truth = scenario["private_truth"]
                expected = ["key_001", "key_002", "key_003"]
                self.assertEqual(scenario["expected_vulnerable_ids"], expected)
                self.assertEqual(scenario["modulus_bits"], modulus_bits)
                self.assertEqual(len(public), 6)
                self.assertEqual(set(truth), {item["key_id"] for item in public})
                shared_p = truth[expected[0]]["p"]
                all_factors = []

                for index, record in enumerate(public, start=1):
                    self.assertEqual(record["key_id"], f"key_{index:03d}")
                    # Pass public data only.
                    self.assertEqual(set(record), {"key_id", "n", "e"})
                    secret = truth[record["key_id"]]
                    self.assertEqual(set(secret), {"p", "q", "case_type"})
                    p, q = secret["p"], secret["q"]
                    self.assertTrue(isPrime(p))
                    self.assertTrue(isPrime(q))
                    self.assertNotEqual(p, q)
                    self.assertEqual(p % 2, 1)
                    self.assertEqual(q % 2, 1)
                    self.assertEqual(p * q, record["n"])
                    self.assertEqual(record["n"].bit_length(), modulus_bits)
                    self.assertEqual(record["e"], 65537)
                    self.assertEqual(math.gcd(record["e"], (p - 1) * (q - 1)), 1)
                    self.assertEqual(
                        secret["case_type"], "shared_prime" if index <= 3 else "control"
                    )
                    all_factors.extend((p, q))

                counts = Counter(all_factors)
                self.assertEqual(counts[shared_p], 3)
                self.assertEqual(
                    {factor: count for factor, count in counts.items() if count > 1},
                    {shared_p: 3},
                )
                for left, right in combinations(public, 2):
                    expected_gcd = shared_p if (
                        left["key_id"] in expected and right["key_id"] in expected
                    ) else 1
                    self.assertEqual(math.gcd(left["n"], right["n"]), expected_gcd)

    def test_all_keys_may_intentionally_share_a_prime(self):
        scenario = generate_shared_prime_keys(3, 3, 64, 3)
        self.assertEqual(len(scenario["expected_vulnerable_ids"]), 3)
        shared = {secret["p"] for secret in scenario["private_truth"].values()}
        self.assertEqual(len(shared), 1)
        for record in scenario["public_keys"]:
            truth = scenario["private_truth"][record["key_id"]]
            self.assertEqual(math.gcd(3, (truth["p"] - 1) * (truth["q"] - 1)), 1)

    def test_public_records_do_not_alias_private_truth(self):
        scenario = generate_shared_prime_keys(2, 2, 64)
        scenario["private_truth"]["key_001"]["p"] = 0
        self.assertGreater(scenario["public_keys"][0]["n"], 0)
        self.assertEqual(set(scenario["public_keys"][0]), {"key_id", "n", "e"})

    def test_rejects_invalid_collection_parameters(self):
        for kwargs in (
            {"num_keys": 1}, {"num_keys": 0}, {"num_keys": -1},
            {"num_shared": 1}, {"num_shared": 0}, {"num_shared": 5},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    generate_shared_prime_keys(modulus_bits=64, **kwargs)
        for name in ("num_keys", "num_shared"):
            for invalid in (True, False, 2.0, "2", None):
                with self.subTest(name=name, invalid=invalid):
                    with self.assertRaises(TypeError):
                        generate_shared_prime_keys(modulus_bits=64, **{name: invalid})

    def test_rejects_invalid_rsa_parameters_before_generation(self):
        for generator in (generate_shared_prime_keys,):
            for modulus_bits in (0, 16, 31, -32):
                with self.subTest(generator=generator.__name__, bits=modulus_bits):
                    with self.assertRaises(ValueError):
                        generator(modulus_bits=modulus_bits)
            for e in (-3, 0, 1, 2, 4, 1 << 30, (1 << 30) + 1):
                with self.subTest(generator=generator.__name__, e=e):
                    with self.assertRaises(ValueError):
                        generator(modulus_bits=32, e=e)
            for name in ("modulus_bits", "e"):
                for invalid in (True, False, 64.0, "64", None):
                    kwargs = {"modulus_bits": 64, "e": 65537}
                    kwargs[name] = invalid
                    with self.subTest(generator=generator.__name__, kwargs=kwargs):
                        with self.assertRaises(TypeError):
                            generator(**kwargs)

    def test_generation_failure_is_bounded_and_explicit(self):
        # Bound retries even with a stuck prime source.
        with patch("generators.shared_prime_cases._MAX_PRIME_ATTEMPTS", 3):
            with patch("generators.shared_prime_cases.getPrime", return_value=32771) as source:
                with self.assertRaisesRegex(RuntimeError, "3 attempts"):
                    generate_shared_prime_keys(modulus_bits=32)
                self.assertEqual(source.call_count, 3)


    def test_retries_a_prime_dividing_the_public_exponent(self):
        # gcd(e,p-1)=1 does not prevent p=e; reject that library-invalid key.
        with patch("generators.shared_prime_cases.getPrime", side_effect=[65521, 65519, 65497]) as source:
            p, q = _fresh_factor_pair(modulus_bits=32, e=65521, used=set())
        self.assertEqual(source.call_count, 3)
        self.assertEqual(p, 65519)
        self.assertEqual(q, 65497)
        self.assertEqual(math.gcd(p * q, 65521), 1)


class ControlGenerationTests(unittest.TestCase):
    def test_standalone_control_has_valid_public_and_private_records(self):
        for modulus_bits in (1024, 1025):
            with self.subTest(modulus_bits=modulus_bits):
                control = generate_control_key(modulus_bits)
                public, truth = control["public_key"], control["private_truth"]
                self.assertEqual(set(public), {"key_id", "n", "e"})
                self.assertEqual(public["key_id"], "key_001")
                self.assertEqual(truth["case_type"], "control")
                p, q = truth["p"], truth["q"]
                self.assertTrue(isPrime(p))
                self.assertTrue(isPrime(q))
                self.assertNotEqual(p, q)
                self.assertEqual(public["n"], p * q)
                self.assertEqual(public["n"].bit_length(), modulus_bits)
                self.assertEqual(math.gcd(public["e"], (p - 1) * (q - 1)), 1)

    def test_control_library_supports_an_alternate_public_exponent(self):
        control = generate_control_key(1024, 3)
        self.assertEqual(control["public_key"]["e"], 3)
        p, q = control["private_truth"]["p"], control["private_truth"]["q"]
        self.assertEqual(math.gcd(3, (p - 1) * (q - 1)), 1)

    def test_rejects_parameters_outside_the_control_library_domain(self):
        for modulus_bits in (-1024, 0, 32, 65, 1023):
            with self.subTest(modulus_bits=modulus_bits):
                with self.assertRaises(ValueError):
                    generate_control_key(modulus_bits)
        for e in (-3, 0, 1, 2, 4):
            with self.subTest(e=e):
                with self.assertRaises(ValueError):
                    generate_control_key(1024, e)
        for name in ("modulus_bits", "e"):
            for invalid in (True, False, 1024.0, "1024", None):
                kwargs = {"modulus_bits": 1024, "e": 65537}
                kwargs[name] = invalid
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(TypeError):
                        generate_control_key(**kwargs)


class MixedDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = generate_mixed_key_dataset(64)

    def test_exact_sizes_primes_and_exponents_including_odd_bit_sizes(self):
        for modulus_bits in (32, 64, 65):
            dataset = self.dataset if modulus_bits == 64 else generate_mixed_key_dataset(modulus_bits)
            with self.subTest(modulus_bits=modulus_bits):
                self.assertEqual(dataset["modulus_bits"], modulus_bits)
                for index, key in enumerate(dataset["public_keys"], 1):
                    self.assertEqual(key["key_id"], f"key_{index:03d}")
                    self.assertEqual(set(key), {"key_id", "n", "e"})
                    truth = dataset["private_truth"][key["key_id"]]
                    p, q = truth["p"], truth["q"]
                    self.assertTrue(isPrime(p))
                    self.assertTrue(isPrime(q))
                    self.assertNotEqual(p, q)
                    self.assertEqual(p * q, key["n"])
                    self.assertEqual(key["n"].bit_length(), modulus_bits)
                    # Every factor must support both public exponents.
                    for exponent in (65537, 3):
                        self.assertEqual(math.gcd(exponent, (p - 1) * (q - 1)), 1)
                    self.assertEqual(key["e"], 3 if index == 11 else 65537)

    def test_all_topologies_and_no_unintended_prime_reuse(self):
        public = self.dataset["public_keys"]
        truth = self.dataset["private_truth"]
        self.assertEqual(len(public), 18)
        self.assertEqual(len({key["n"] for key in public}), 16)
        self.assertEqual(len({secret[name] for secret in truth.values() for name in ("p", "q")}), 23)
        useful_pairs = {
            (1, 2),
            (3, 4), (3, 5), (4, 5),
            (10, 12), (11, 12),
            (13, 14), (13, 15),
            (16, 17), (16, 18), (17, 18),
        }
        duplicates = {(8, 9), (10, 11)}
        for (left_index, left), (right_index, right) in combinations(enumerate(public, 1), 2):
            common = math.gcd(left["n"], right["n"])
            indices = (left_index, right_index)
            with self.subTest(indices=indices):
                if indices in duplicates:
                    self.assertEqual(left["n"], right["n"])
                    self.assertEqual(common, left["n"])
                elif indices in useful_pairs:
                    self.assertTrue(isPrime(common))
                    self.assertTrue(1 < common < min(left["n"], right["n"]))
                else:
                    self.assertEqual(common, 1)
        # Chain edges use different factors; triangle edges have no common prime.
        factors = lambda index: {truth[f"key_{index:03d}"][name] for name in ("p", "q")}
        self.assertNotEqual(factors(13) & factors(14), factors(13) & factors(15))
        self.assertEqual(factors(16) & factors(17) & factors(18), set())

    def test_expected_truth_uses_distinct_moduli_not_duplicate_record_counts(self):
        dataset = self.dataset
        excluded = {"key_006", "key_007", "key_008", "key_009"}
        expected_ids = [key["key_id"] for key in dataset["public_keys"] if key["key_id"] not in excluded]
        self.assertEqual(dataset["expected_vulnerable_ids"], expected_ids)
        expected_n = list(dict.fromkeys(
            key["n"] for key in dataset["public_keys"] if key["key_id"] in expected_ids
        ))
        self.assertEqual(dataset["expected_factored_moduli"], expected_n)
        self.assertEqual(len(expected_ids), 14)
        self.assertEqual(len(expected_n), 13)
        for key in dataset["public_keys"]:
            truth = dataset["private_truth"][key["key_id"]]
            self.assertEqual(truth["observable_shared_factor"], key["key_id"] in expected_ids)
            self.assertEqual(truth["intended_weak_generation"], key["key_id"] not in {"key_006", "key_007"})

    def test_base_three_uses_five_for_the_alternate_exponent(self):
        dataset = generate_mixed_key_dataset(32, 3)
        for index, key in enumerate(dataset["public_keys"], 1):
            self.assertEqual(key["e"], 5 if index == 11 else 3)
            truth = dataset["private_truth"][key["key_id"]]
            for exponent in (3, 5):
                self.assertEqual(math.gcd(exponent, (truth["p"] - 1) * (truth["q"] - 1)), 1)

    def test_mixed_input_validation_and_retry_budget(self):
        for kwargs, expected_error in (
            ({"modulus_bits": 31}, ValueError),
            ({"modulus_bits": True}, TypeError),
            ({"e": 2}, ValueError),
            ({"e": "65537"}, TypeError),
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(expected_error):
                    generate_mixed_key_dataset(**kwargs)
        # This 17-bit prime exceeds the allowed odd-size range.
        with patch("generators.shared_prime_cases._MAX_PRIME_ATTEMPTS", 3):
            with patch("generators.shared_prime_cases.getPrime", return_value=131071) as source:
                with self.assertRaisesRegex(RuntimeError, "3 attempts"):
                    generate_mixed_key_dataset(33)
                self.assertEqual(source.call_count, 3)


class ObservedSubsetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = generate_mixed_key_dataset(64)

    def test_missing_companion_changes_observable_truth_but_not_construction(self):
        before = make_observed_subset(self.dataset, ["key_001", "key_006"])
        after = make_observed_subset(self.dataset, ["key_001", "key_002", "key_006"])
        self.assertEqual(before["expected_vulnerable_ids"], [])
        self.assertEqual(before["expected_factored_moduli"], [])
        self.assertTrue(before["private_truth"]["key_001"]["intended_weak_generation"])
        self.assertFalse(before["private_truth"]["key_001"]["observable_shared_factor"])
        self.assertEqual(after["expected_vulnerable_ids"], ["key_001", "key_002"])
        self.assertEqual(len(after["expected_factored_moduli"]), 2)
        self.assertTrue(after["private_truth"]["key_001"]["observable_shared_factor"])
        self.assertFalse(after["private_truth"]["key_006"]["intended_weak_generation"])

    def test_duplicates_need_a_distinct_companion_modulus(self):
        alone = make_observed_subset(self.dataset, ["key_010", "key_011"])
        accompanied = make_observed_subset(self.dataset, ["key_010", "key_011", "key_012"])
        self.assertEqual(alone["expected_vulnerable_ids"], [])
        self.assertTrue(all(truth["intended_weak_generation"] for truth in alone["private_truth"].values()))
        self.assertEqual(accompanied["expected_vulnerable_ids"], ["key_010", "key_011", "key_012"])
        self.assertEqual(len(accompanied["expected_factored_moduli"]), 2)

    def test_public_and_evaluator_extras_are_copied_without_mutation(self):
        dataset = deepcopy(self.dataset)
        key = dataset["public_keys"][0]
        key["ciphertext"] = b"ciphertext bytes"
        dataset["private_truth"]["key_001"]["expected_message"] = b"test message"
        dataset["private_truth"]["key_001"]["notes"] = {"items": ["original"]}
        snapshot = deepcopy(dataset)
        subset = make_observed_subset(dataset, ["key_002", "key_001"])
        self.assertEqual([key["key_id"] for key in subset["public_keys"]], ["key_002", "key_001"])
        self.assertEqual(subset["public_keys"][1], key)
        self.assertEqual(subset["private_truth"]["key_001"]["expected_message"], b"test message")
        subset["public_keys"][1]["n"] = 0
        subset["private_truth"]["key_001"]["notes"]["items"].append("changed")
        self.assertEqual(dataset, snapshot)

    def test_legacy_case_retains_population_weakness_when_companion_is_removed(self):
        original = generate_shared_prime_keys(4, 2, 64)
        snapshot = deepcopy(original)
        subset = make_observed_subset(original, ["key_001", "key_003", "key_004"])
        self.assertEqual(subset["expected_vulnerable_ids"], [])
        self.assertTrue(subset["private_truth"]["key_001"]["intended_weak_generation"])
        self.assertFalse(subset["private_truth"]["key_001"]["observable_shared_factor"])
        self.assertFalse(subset["private_truth"]["key_003"]["intended_weak_generation"])
        self.assertEqual(original, snapshot)

    def test_subset_rejects_unknown_or_repeated_ids_and_accepts_empty(self):
        for selected_ids in (["key_999"], ["key_001", "key_001"]):
            with self.subTest(selected_ids=selected_ids):
                with self.assertRaises(ValueError):
                    make_observed_subset(self.dataset, selected_ids)
        for selected_ids in ("key_001", [None], [1]):
            with self.subTest(selected_ids=selected_ids):
                with self.assertRaises(TypeError):
                    make_observed_subset(self.dataset, selected_ids)
        empty = make_observed_subset(self.dataset, [])
        self.assertEqual(empty["public_keys"], [])
        self.assertEqual(empty["private_truth"], {})
        self.assertEqual(empty["expected_vulnerable_ids"], [])
        self.assertEqual(empty["expected_factored_moduli"], [])


class ScalabilityDatasetTests(unittest.TestCase):
    def test_fixed_fraction_disjoint_pairs_and_controls_at_exact_sizes(self):
        for num_moduli in (10, 20):
            for modulus_bits in (32, 64, 65):
                with self.subTest(num_moduli=num_moduli, modulus_bits=modulus_bits):
                    dataset = generate_scalability_dataset(num_moduli, modulus_bits)
                    public, truth = dataset["public_keys"], dataset["private_truth"]
                    expected_count = num_moduli // 5
                    expected_ids = [f"key_{index:03d}" for index in range(1, expected_count + 1)]
                    self.assertEqual(len(public), num_moduli)
                    self.assertEqual(len({key["n"] for key in public}), num_moduli)
                    self.assertEqual(dataset["topology_profile"], "disjoint_shared_pairs_20pct")
                    self.assertEqual(dataset["modulus_bits"], modulus_bits)
                    self.assertEqual(dataset["expected_vulnerable_ids"], expected_ids)
                    self.assertEqual(dataset["expected_factored_moduli"], [key["n"] for key in public[:expected_count]])
                    for index, key in enumerate(public):
                        self.assertEqual(key["key_id"], f"key_{index + 1:03d}")
                        self.assertEqual(set(key), {"key_id", "n", "e"})
                        self.assertEqual(key["n"].bit_length(), modulus_bits)
                        self.assertEqual(key["e"], 65537)
                        secret = truth[key["key_id"]]
                        p, q = secret["p"], secret["q"]
                        self.assertTrue(isPrime(p))
                        self.assertTrue(isPrime(q))
                        self.assertNotEqual(p, q)
                        self.assertEqual(p * q, key["n"])
                        self.assertEqual(math.gcd(key["e"], (p - 1) * (q - 1)), 1)
                        self.assertEqual(math.gcd(key["e"], key["n"]), 1)
                        expected_weak = index < expected_count
                        self.assertEqual(secret["case_type"], "shared_pair" if expected_weak else "control")
                        self.assertEqual(secret["intended_weak_generation"], expected_weak)
                        self.assertEqual(secret["observable_shared_factor"], expected_weak)
                    useful_pairs = 0
                    for (left_index, left), (right_index, right) in combinations(enumerate(public), 2):
                        common = math.gcd(left["n"], right["n"])
                        same_expected_pair = left_index < expected_count and left_index // 2 == right_index // 2
                        if same_expected_pair:
                            self.assertTrue(isPrime(common))
                            self.assertTrue(1 < common < min(left["n"], right["n"]))
                            useful_pairs += 1
                        else:
                            self.assertEqual(common, 1)
                    self.assertEqual(useful_pairs, num_moduli // 10)

    def test_accepts_a_supported_alternate_public_exponent(self):
        dataset = generate_scalability_dataset(10, 32, 3)
        for key in dataset["public_keys"]:
            truth = dataset["private_truth"][key["key_id"]]
            self.assertEqual(key["e"], 3)
            self.assertEqual(math.gcd(3, (truth["p"] - 1) * (truth["q"] - 1)), 1)

    def test_rejects_invalid_sizes_and_rsa_parameters(self):
        for invalid in (True, False, 10.0, "10", None):
            with self.subTest(num_unique_moduli=invalid):
                with self.assertRaises(TypeError):
                    generate_scalability_dataset(invalid, 32)
        for invalid in (-10, 0, 1, 5, 9, 11, 15, 21):
            with self.subTest(num_unique_moduli=invalid):
                with self.assertRaises(ValueError):
                    generate_scalability_dataset(invalid, 32)
        for kwargs, expected_error in (
            ({"modulus_bits": 31}, ValueError),
            ({"modulus_bits": True}, TypeError),
            ({"e": 2}, ValueError),
            ({"e": "65537"}, TypeError),
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(expected_error):
                    generate_scalability_dataset(10, **kwargs)


if __name__ == "__main__":
    unittest.main()
