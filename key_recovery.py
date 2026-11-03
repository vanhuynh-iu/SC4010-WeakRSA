"""Van's Euclidean arithmetic and RSA private-key recovery.

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


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) with a*x + b*y = g = gcd(a, b).

    Inputs are nonnegative built-in integers; (0, 0) returns (0, 1, 0).
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
    gcd, coefficient, _ = extended_gcd(a % modulus, modulus)
    if gcd != 1:
        raise ValueError("a has no modular inverse for this modulus")
    return coefficient % modulus


def recover_private_key(p: int, q: int, e: int) -> int:
    """Return private exponent d from distinct odd primes p and q.

    Require odd 1 < e < phi(n) and gcd(e, phi(n)) == 1; invalid values raise
    ValueError.
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


def decrypt_with_recovered_key(
    ciphertext: bytes, n: int, e: int, p: int, q: int
) -> bytes:
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
        raise ValueError("recovered factors do not multiply to public modulus n")

    d = recover_private_key(p, q, e)
    recovered_key = RSA.construct((n, e, d, p, q), consistency_check=True)
    return PKCS1_OAEP.new(recovered_key, hashAlgo=SHA256).decrypt(ciphertext)
