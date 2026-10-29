"""RSA recovery tests."""

import math
import unittest
from unittest.mock import patch

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA

from key_recovery import (
    decrypt_with_recovered_key,
    encrypt_message,
    extended_gcd,
    mod_inverse,
    recover_private_key,
)


class ExtendedGcdTests(unittest.TestCase):
    def test_gcd_and_bezout_identity(self):
        for a in range(40):
            for b in range(40):
                with self.subTest(a=a, b=b):
                    gcd, x, y = extended_gcd(a, b)
                    self.assertEqual(gcd, math.gcd(a, b))
                    self.assertEqual(a * x + b * y, gcd)

    def test_large_integer_identity(self):
        a, b = (1 << 2048) + 25, (1 << 1024) + 17
        gcd, x, y = extended_gcd(a, b)
        self.assertEqual(gcd, math.gcd(a, b))
        self.assertEqual(a * x + b * y, gcd)

    def test_zero_inputs(self):
        for a, b, expected in ((0, 0, 0), (0, 24, 24), (24, 0, 24)):
            with self.subTest(a=a, b=b):
                gcd, x, y = extended_gcd(a, b)
                self.assertEqual(gcd, expected)
                self.assertEqual(a * x + b * y, expected)

    def test_invalid_inputs(self):
        for a, b in ((-1, 2), (2, -1)):
            with self.subTest(a=a, b=b):
                with self.assertRaises(ValueError):
                    extended_gcd(a, b)
        for invalid in (True, 1.5, "1", None):
            for a, b in ((invalid, 2), (2, invalid)):
                with self.subTest(a=a, b=b):
                    with self.assertRaises(TypeError):
                        extended_gcd(a, b)


class ModularInverseTests(unittest.TestCase):
    def test_known_and_signed_inverses(self):
        for a, modulus, expected in ((3, 11, 4), (-3, 11, 7), (17, 6600, 1553), (1, 2, 1)):
            with self.subTest(a=a, modulus=modulus):
                inverse = mod_inverse(a, modulus)
                self.assertEqual(inverse, expected)
                self.assertEqual((a * inverse) % modulus, 1)
                self.assertTrue(0 <= inverse < modulus)

    def test_noninvertible_values(self):
        for a, modulus in ((6, 9), (0, 11), (11, 11), (-6, 9)):
            with self.subTest(a=a, modulus=modulus):
                with self.assertRaises(ValueError):
                    mod_inverse(a, modulus)

    def test_invalid_modulus(self):
        for modulus in (-5, 0, 1):
            with self.subTest(modulus=modulus):
                with self.assertRaises(ValueError):
                    mod_inverse(3, modulus)

    def test_invalid_types(self):
        for a, modulus in ((True, 11), (3, True), (3.0, 11), (3, "11")):
            with self.subTest(a=a, modulus=modulus):
                with self.assertRaises(TypeError):
                    mod_inverse(a, modulus)


class PrivateExponentTests(unittest.TestCase):
    def test_lecture_example(self):
        d = recover_private_key(67, 101, 17)
        self.assertEqual(d, 1553)
        self.assertEqual(pow(4838, d, 6767), 1000)

    def test_factor_order_does_not_change_exponent(self):
        self.assertEqual(recover_private_key(101, 67, 17), 1553)

    def test_rejects_invalid_factors(self):
        for p, q in ((67, 67), (2, 101), (1, 101), (-67, 101), (9, 101), (67, 102), (67, 121)):
            with self.subTest(p=p, q=q):
                with self.assertRaises(ValueError):
                    recover_private_key(p, q, 17)

    def test_rejects_invalid_exponents(self):
        for e in (-3, 0, 1, 2, 3, 6600, 6601):
            with self.subTest(e=e):
                with self.assertRaises(ValueError):
                    recover_private_key(67, 101, e)

    def test_rejects_non_integer_parameters(self):
        for p, q, e in ((True, 101, 17), (67, 101.0, 17), (67, 101, "17")):
            with self.subTest(p=p, q=q, e=e):
                with self.assertRaises(TypeError):
                    recover_private_key(p, q, e)


class OaepRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Library-generated 1024-bit keys keep wrapper tests fast.
        cls.original_key = RSA.generate(1024)
        cls.n = int(cls.original_key.n)
        cls.e = int(cls.original_key.e)
        cls.p = int(cls.original_key.p)
        cls.q = int(cls.original_key.q)
        cls.message = b"Recovered factors restore the private key."
        cls.ciphertext = PKCS1_OAEP.new(
            cls.original_key.public_key(), hashAlgo=SHA256
        ).encrypt(cls.message)

    def test_decrypts_using_recovered_factors(self):
        plaintext = decrypt_with_recovered_key(
            self.ciphertext, self.n, self.e, self.p, self.q
        )
        self.assertEqual(plaintext, self.message)

    def test_encrypt_helper_uses_sha256_oaep(self):
        ciphertext = encrypt_message(self.message, self.n, self.e)
        plaintext = PKCS1_OAEP.new(
            self.original_key, hashAlgo=SHA256
        ).decrypt(ciphertext)
        self.assertEqual(plaintext, self.message)

    def test_rejects_product_mismatch(self):
        # Reject a wrong modulus before primality checks or inverse arithmetic.
        with patch("key_recovery.recover_private_key") as recover:
            with self.assertRaisesRegex(ValueError, "do not multiply"):
                decrypt_with_recovered_key(
                    self.ciphertext, self.n + 2, self.e, self.p, self.q
                )
        recover.assert_not_called()

    def test_same_modulus_different_exponents_recover_separate_private_keys(self):
        phi = (self.p - 1) * (self.q - 1)
        # Choose an invertible exponent; 3 is not always valid.
        alternate_e = next(
            candidate for candidate in range(3, 65537, 2)
            if candidate != self.e and math.gcd(candidate, phi) == 1
        )
        exponents = (self.e, alternate_e)
        private_exponents = []
        for e in exponents:
            with self.subTest(e=e):
                d = recover_private_key(self.p, self.q, e)
                private_exponents.append(d)
                self.assertEqual((e * d) % phi, 1)
                ciphertext = encrypt_message(self.message, self.n, e)
                plaintext = decrypt_with_recovered_key(
                    ciphertext, self.n, e, self.p, self.q
                )
                self.assertEqual(plaintext, self.message)
        # Compare derived inverses, not the library's private-exponent convention.
        self.assertNotEqual(private_exponents[0], private_exponents[1])

    def test_rejects_noninteger_factors_before_private_exponent_derivation(self):
        for p, q in ((True, self.q), (self.p, False), (float(self.p), self.q),
                     (self.p, str(self.q))):
            with self.subTest(p=p, q=q):
                with patch("key_recovery.recover_private_key") as recover:
                    with self.assertRaises(TypeError):
                        decrypt_with_recovered_key(self.ciphertext, self.n, self.e, p, q)
                recover.assert_not_called()

    def test_rejects_corrupt_ciphertext(self):
        # Zero ciphertext deterministically fails OAEP.
        corrupted = bytes(len(self.ciphertext))
        with self.assertRaises(ValueError):
            decrypt_with_recovered_key(corrupted, self.n, self.e, self.p, self.q)

    def test_rejects_wrong_ciphertext_length(self):
        with self.assertRaises(ValueError):
            decrypt_with_recovered_key(
                self.ciphertext[:-1], self.n, self.e, self.p, self.q
            )

    def test_rejects_other_oaep_hash(self):
        ciphertext = PKCS1_OAEP.new(
            self.original_key.public_key(), hashAlgo=SHA1
        ).encrypt(self.message)
        with self.assertRaises(ValueError):
            decrypt_with_recovered_key(ciphertext, self.n, self.e, self.p, self.q)

    def test_rejects_wrong_input_types(self):
        with self.assertRaises(TypeError):
            encrypt_message("text", self.n, self.e)
        with self.assertRaises(TypeError):
            decrypt_with_recovered_key("text", self.n, self.e, self.p, self.q)
        with self.assertRaises(TypeError):
            encrypt_message(self.message, True, self.e)
        with self.assertRaises(TypeError):
            decrypt_with_recovered_key(self.ciphertext, True, self.e, self.p, self.q)

    def test_rejects_invalid_public_parameters(self):
        for n, e in ((0, self.e), (self.n, 1), (self.n, 2)):
            with self.subTest(n=n, e=e):
                with self.assertRaises(ValueError):
                    encrypt_message(self.message, n, e)

    def test_rejects_oversized_message(self):
        with self.assertRaises(ValueError):
            encrypt_message(bytes(100), self.n, self.e)


if __name__ == "__main__":
    unittest.main()
