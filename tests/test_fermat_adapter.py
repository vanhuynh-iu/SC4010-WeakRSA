"""Budget boundaries and public/private separation for the Fermat integration."""

from math import gcd, isqrt
import unittest
from unittest.mock import patch

from Crypto.Util.number import isPrime

from rsa_auditor.attacks.fermat import fermat_factor
from rsa_auditor.datasets.generators.close_primes import generate_close_prime_key


class FermatAdapterTests(unittest.TestCase):
    def test_first_candidate_and_sorted_factors(self):
        self.assertEqual(fermat_factor(11 * 13, 1), {
            "status": "factored", "factors": (11, 13), "candidate_tests": 1,
        })
        with patch("rsa_auditor.attacks.fermat.fermat_attack", return_value=(13, 11, 1)):
            self.assertEqual(fermat_factor(143, 1)["factors"], (11, 13))

    def test_exact_budget_boundary_and_repeatability(self):
        # 59*101 has a0=78 and succeeds at a=80: the third tested candidate.
        n = 59 * 101
        for budget in (1, 2):
            self.assertEqual(fermat_factor(n, budget), {
                "status": "budget_exhausted", "factors": None,
                "candidate_tests": budget,
            })
        expected = {"status": "factored", "factors": (59, 101), "candidate_tests": 3}
        self.assertEqual(fermat_factor(n, 3), expected)
        self.assertEqual(fermat_factor(n, 30), expected)
        self.assertEqual(fermat_factor(n, 3), expected)

    def test_zero_budget_skips_backend(self):
        with patch("rsa_auditor.attacks.fermat.fermat_attack") as backend:
            self.assertEqual(fermat_factor(5959, 0), {
                "status": "budget_exhausted", "factors": None, "candidate_tests": 0,
            })
            backend.assert_not_called()

    def test_invalid_inputs_are_rejected_before_attack(self):
        class IntSubclass(int):
            pass
        with patch("rsa_auditor.attacks.fermat.fermat_attack") as backend:
            for n in (True, False, 15.0, "15", None, IntSubclass(15)):
                with self.subTest(n=n), self.assertRaises(TypeError):
                    fermat_factor(n, 1)
            for n in (-15, 0, 1, 2, 16):
                with self.subTest(n=n), self.assertRaises(ValueError):
                    fermat_factor(n, 1)
            for budget in (True, False, 1.0, "1", None, IntSubclass(1)):
                with self.subTest(budget=budget), self.assertRaises(TypeError):
                    fermat_factor(15, budget)
            with self.assertRaises(ValueError):
                fermat_factor(15, -1)
            backend.assert_not_called()

    def test_backend_must_return_distinct_odd_prime_factors_of_n(self):
        cases = (
            (143, (1, 143, 1)), (143, (11, 11, 1)),
            (143, (11.0, 13, 1)), (143, (True, 143, 1)),
            (45, (5, 9, 1)), (121, (11, 11, 1)),
            (143, (2, 71, 1)), (143, (11, 13)),
            (143, [11, 13, 1]), (143, {"p": 11, "q": 13}),
        )
        for n, result in cases:
            with self.subTest(n=n, result=result):
                with patch("rsa_auditor.attacks.fermat.fermat_attack", return_value=result):
                    with self.assertRaises((TypeError, ValueError)):
                        fermat_factor(n, 3)

    def test_backend_candidate_count_must_be_exact_and_within_budget(self):
        for count in (0, -1, True, 3.0, 2, 4):
            with self.subTest(count=count):
                with patch("rsa_auditor.attacks.fermat.fermat_attack", return_value=(59, 101, count)):
                    with self.assertRaisesRegex(ValueError, "candidate count"):
                        fermat_factor(5959, 3)


class ClosePrimeAdapterTests(unittest.TestCase):
    @staticmethod
    def backend_key(p=50021, q=52069, e=65537):
        return {"p": p, "q": q, "n": p * q, "e": e,
                "d": 123, "phi": (p - 1) * (q - 1), "gap": q - p}

    def test_default_gap_and_private_truth_stay_out_of_public_record(self):
        key = self.backend_key()
        with patch("rsa_auditor.datasets.generators.close_primes._generate_close_prime_key", return_value=key) as backend:
            case = generate_close_prime_key(32)
        backend.assert_called_once_with(bits=32, gap_bits=11, e=65537)
        self.assertEqual(case["public_key"], {"key_id": "key_001", "n": key["n"], "e": 65537})
        self.assertEqual(case["private_truth"], {
            "p": 50021, "q": 52069, "case_type": "close_prime",
            "actual_gap": 2048, "intended_weak_generation": True,
            "observable_shared_factor": False,
        })
        self.assertNotIn("d", case["private_truth"])
        self.assertNotIn("phi", case["private_truth"])

    def test_power_of_two_target_maps_to_minimum_separation(self):
        key = self.backend_key(q=50053)
        with patch("rsa_auditor.datasets.generators.close_primes._generate_close_prime_key", return_value=key) as backend:
            case = generate_close_prime_key(32, target_gap=32)
        backend.assert_called_once_with(bits=32, gap_bits=5, e=65537)
        self.assertEqual(case["private_truth"]["actual_gap"], 32)
        # A requested power of two is a starting separation, not exact q-p.
        key = self.backend_key(q=50023)
        with patch("rsa_auditor.datasets.generators.close_primes._generate_close_prime_key", return_value=key):
            self.assertEqual(generate_close_prime_key(32, target_gap=1)["private_truth"]["actual_gap"], 2)

    def test_invalid_parameters_never_enter_original_retry_loop(self):
        with patch("rsa_auditor.datasets.generators.close_primes._generate_close_prime_key") as backend:
            for bits in (-32, 0, 16, 31, 33, 65):
                with self.subTest(bits=bits), self.assertRaises(ValueError):
                    generate_close_prime_key(bits)
            for name in ("modulus_bits", "e", "target_gap", "gap_bits"):
                for invalid in (True, False, 3.0, "3"):
                    kwargs = {"modulus_bits": 32, name: invalid}
                    with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                        generate_close_prime_key(**kwargs)
            for e in (-3, 0, 1, 2, 4, 1 << 30, (1 << 30) + 1):
                with self.subTest(e=e), self.assertRaises(ValueError):
                    generate_close_prime_key(32, e)
            for gap_bits in (-1, 15, 16, 100):
                with self.subTest(gap_bits=gap_bits), self.assertRaises(ValueError):
                    generate_close_prime_key(32, gap_bits=gap_bits)
            for target_gap in (-2, 0, 3, 6, 1 << 15):
                with self.subTest(target_gap=target_gap), self.assertRaises(ValueError):
                    generate_close_prime_key(32, target_gap=target_gap)
            with self.assertRaises(ValueError):
                generate_close_prime_key(32, gap_bits=5, target_gap=32)
            backend.assert_not_called()

    def test_incompatible_exponent_retry_is_bounded(self):
        key = self.backend_key(p=50021, q=50053, e=50021)
        with patch("rsa_auditor.datasets.generators.close_primes._MAX_GENERATION_ATTEMPTS", 2):
            with patch("rsa_auditor.datasets.generators.close_primes._generate_close_prime_key", return_value=key) as backend:
                with self.assertRaisesRegex(RuntimeError, "2 attempts"):
                    generate_close_prime_key(32, 50021, gap_bits=5)
                self.assertEqual(backend.call_count, 2)

    def test_real_generator_produces_valid_nontrivial_fermat_case(self):
        case = generate_close_prime_key(32)
        public, truth = case["public_key"], case["private_truth"]
        self.assertEqual(set(public), {"key_id", "n", "e"})
        self.assertEqual(public["n"].bit_length(), 32)
        p, q = truth["p"], truth["q"]
        self.assertTrue(isPrime(p) and isPrime(q))
        self.assertLess(p, q)
        self.assertEqual(p * q, public["n"])
        self.assertEqual(gcd(public["e"], (p - 1) * (q - 1)), 1)
        self.assertGreaterEqual(truth["actual_gap"], 1 << 11)
        a0 = isqrt(public["n"])
        if a0 * a0 < public["n"]:
            a0 += 1
        required = (p + q) // 2 - a0 + 1
        self.assertGreater(required, 1)
        self.assertEqual(fermat_factor(public["n"], required - 1)["status"], "budget_exhausted")
        self.assertEqual(fermat_factor(public["n"], required), {
            "status": "factored", "factors": (p, q), "candidate_tests": required,
        })


if __name__ == "__main__":
    unittest.main()
