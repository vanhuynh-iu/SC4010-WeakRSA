"""Euclidean arithmetic and RSA private-key recovery.

PyCryptodome supplies primality checks, key construction, and OAEP-SHA256.
"""

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.number import isPrime


def _require_integer(value: int, name: str) -> None:
    """Reject booleans and values other than built-in Python integers."""
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")


def validate_factors(n: int, p: int, q: int) -> tuple[int, int]:
    """Return sorted, distinct odd prime factors after checking the public n."""
    for name, value in (("n", n), ("p", p), ("q", q)):
        _require_integer(value, name)
    if n <= 1 or n % 2 == 0:
        raise ValueError("n must be an odd integer greater than one")
    if p <= 2 or q <= 2 or p % 2 == 0 or q % 2 == 0 or p == q:
        raise ValueError("factors must be distinct odd primes")
    if p * q != n:
        raise ValueError(
            "recovered factors do not multiply to public modulus n")
    if not isPrime(p) or not isPrime(q):
        raise ValueError("recovered factors must be prime")
    return tuple(sorted((p, q)))


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) with a*x + b*y = g = gcd(a, b).

    Args:
        a: First nonnegative built-in integer.
        b: Second nonnegative built-in integer.

    Returns:
        The GCD and its two Bezout coefficients. For (0, 0), return (0, 1, 0).
    """
    _require_integer(a, "a")
    _require_integer(b, "b")
    if a < 0 or b < 0:
        raise ValueError("a and b must be nonnegative")

    # Each remainder is stored with its coefficients of the original a and b.
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    return old_r, old_x, old_y


def mod_inverse(a: int, modulus: int) -> int:
    """Return x in [0, modulus) with (a*x) % modulus == 1.

    Signed a is allowed; modulus must exceed one. Raise ValueError when
    gcd(a, modulus) != 1.
    """
    _require_integer(a, "a")
    _require_integer(modulus, "modulus")
    if modulus <= 1:
        raise ValueError("modulus must be greater than one")

    # Reduce signed a for extended_gcd's nonnegative domain.
    divisor, coefficient, _ = extended_gcd(a % modulus, modulus)
    if divisor != 1:
        raise ValueError("a has no modular inverse for this modulus")
    return coefficient % modulus


def recover_private_key(p: int, q: int, e: int) -> int:
    """Return private exponent d from distinct odd primes p and q.

    Args:
        p: First odd prime factor of the RSA modulus.
        q: Second odd prime factor, distinct from p.
        e: Odd public exponent with 1 < e < phi(n), coprime to phi(n).

    Returns:
        d = e**-1 mod phi(n), where phi(n) = (p-1)*(q-1).
    """
    for name, value in (("p", p), ("q", q), ("e", e)):
        _require_integer(value, name)
    if p < 3 or q < 3 or p % 2 == 0 or q % 2 == 0:
        raise ValueError("p and q must be odd primes greater than two")
    if p == q:
        raise ValueError("p and q must be distinct")
    if not isPrime(p) or not isPrime(q):
        raise ValueError("p and q must be prime")

    phi = (p - 1) * (q - 1)
    if e <= 1 or e >= phi or e % 2 == 0:
        raise ValueError("e must be odd and satisfy 1 < e < phi(n)")

    return mod_inverse(e, phi)


def encrypt_message(message: bytes, n: int, e: int) -> bytes:
    """Encrypt bytes with a public key using OAEP-SHA256.

    Oversized messages raise ValueError.
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    _require_integer(n, "n")
    _require_integer(e, "e")
    if n <= 1 or n % 2 == 0:
        raise ValueError("n must be odd and greater than one")
    if e <= 1 or e >= n or e % 2 == 0:
        raise ValueError("e must be odd and satisfy 1 < e < n")
    public_key = RSA.construct((n, e), consistency_check=True)
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(message)


def decrypt_with_recovered_key(ciphertext: bytes, n: int, e: int, p: int,
                               q: int) -> bytes:
    """Decrypt OAEP-SHA256 with a key reconstructed from attack factors.

    Check p*q against the original n before deriving d. Invalid keys, factor
    products, or ciphertexts raise ValueError.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    _require_integer(n, "n")
    if n <= 1:
        raise ValueError("n must be greater than one")

    _require_integer(p, "p")
    _require_integer(q, "q")
    if p * q != n:
        raise ValueError(
            "recovered factors do not multiply to public modulus n")

    d = recover_private_key(p, q, e)
    recovered_key = RSA.construct((n, e, d, p, q), consistency_check=True)
    return PKCS1_OAEP.new(recovered_key, hashAlgo=SHA256).decrypt(ciphertext)


def recover_messages(public_keys, scan_result: dict) -> dict[str, bytes]:
    """Decrypt ciphertexts using attack factors and each record's exponent.

    Args:
        public_keys: The original public records, with optional ciphertexts.
        scan_result: A GCD or integrated audit report with recovered_records.

    Returns:
        Recovered plaintext bytes by key ID. Records without ciphertext are
        skipped. No generator truth or expected messages are used.
    """
    public_by_id = {record["key_id"]: record for record in public_keys}
    messages = {}
    for recovered_record in scan_result["recovered_records"]:
        key_id = recovered_record["key_id"]
        public_record = public_by_id[key_id]
        if recovered_record["e"] != public_record["e"]:
            raise ValueError(
                "recovered record exponent does not match its public record")
        if (recovered_record["n"] != public_record["n"] or
                recovered_record["p"] * recovered_record["q"]
                != public_record["n"]):
            raise ValueError(
                "attack factors do not match the original public modulus")
        if "ciphertext" not in public_record:
            continue
        messages[key_id] = decrypt_with_recovered_key(
            public_record["ciphertext"], public_record["n"], public_record["e"],
            recovered_record["p"], recovered_record["q"])
    return messages
