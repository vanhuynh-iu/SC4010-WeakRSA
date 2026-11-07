"""Van's RSA recovery component.

Euclid's algorithm and private-exponent
arithmetic are implemented here; primality testing, RSA key construction,
randomness, and OAEP are supplied by PyCryptodome.
"""

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.number import isPrime


def _require_integer(value: int, name: str) -> None:
    """Reject booleans and values other than built-in Python integers."""
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) with a*x + b*y = g = gcd(a, b).

    Inputs must be nonnegative built-in integers. For (0, 0), return
    (0, 1, 0), which also satisfies the identity.
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
    """Return x in [0, modulus) such that (a*x) % modulus == 1.

    a may be negative. modulus must exceed one. Raise ValueError if an
    inverse does not exist, which happens when gcd(a, modulus) is not one.
    """
    _require_integer(a, "a")
    _require_integer(modulus, "modulus")
    if modulus <= 1:
        raise ValueError("modulus must be greater than one")

    # Reduction lets extended_gcd keep its nonnegative-input contract.
    gcd, coefficient, _ = extended_gcd(a % modulus, modulus)
    if gcd != 1:
        raise ValueError("a has no modular inverse for this modulus")
    return coefficient % modulus


def recover_private_key(p: int, q: int, e: int) -> int:
    """Recover and return private exponent d from two distinct odd primes.

    The public exponent must be odd and satisfy 1 < e < phi(n), with
    gcd(e, phi(n)) == 1. Invalid factors/exponents raise ValueError.
    PyCryptodome supplies the primality checks.
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

    # An inverse exists only when e and phi are coprime.
    return mod_inverse(e, phi)


def encrypt_message(message: bytes, n: int, e: int) -> bytes:
    """Encrypt bytes with the public key using OAEP with SHA-256.

    Encryption randomness and padding are supplied by PyCryptodome. A
    message that is too long for the modulus raises ValueError.
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


def decrypt_with_recovered_key(
    ciphertext: bytes, n: int, e: int, p: int, q: int
) -> bytes:
    """Reconstruct a private key from recovered factors and decrypt OAEP.

    n is the original public modulus. Check the recovered factors multiply
    to n before deriving the private exponent. No original private key or
    generator data is used here. Invalid factors, a mismatched modulus, or
    invalid OAEP ciphertext raise
    ValueError. OAEP uses SHA-256 for both hashing and mask generation.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    _require_integer(n, "n")
    if n <= 1:
        raise ValueError("n must be greater than one")

    _require_integer(p, "p")
    _require_integer(q, "q")
    if p * q != n:
        raise ValueError("recovered factors do not multiply to public modulus n")

    d = recover_private_key(p, q, e)
    recovered_key = RSA.construct((n, e, d, p, q), consistency_check=True)
    return PKCS1_OAEP.new(recovered_key, hashAlgo=SHA256).decrypt(ciphertext)
