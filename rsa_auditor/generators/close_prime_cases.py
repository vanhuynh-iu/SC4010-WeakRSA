"""Adapt Krystal's unchanged close-prime generator to separated records."""

from math import gcd
from typing import Optional

from ..contracts import GeneratedKeyCase
from legacy.close_primes.key_generation import generate_close_prime_key as _generate_close_prime_key
from ..key_recovery import validate_factors


_MAX_GENERATION_ATTEMPTS = 100


def generate_close_prime_key(modulus_bits: int = 2048, e: int = 65537, *,
                             target_gap: Optional[int] = None,
                             gap_bits: Optional[int] = None) -> GeneratedKeyCase:
    """Return a public key and separate truth using Krystal's generator.

    gap_bits selects its starting separation 2**gap_bits; the actual prime gap
    can be larger because q is the next prime. target_gap is an alternative
    power-of-two starting separation, not a promise of an exact prime gap.
    The default exponent, modulus_bits//4 + 3, gives more than the first Fermat
    candidate for the supported sizes. Odd sizes and excessive separations are
    rejected before calling the original generator's retry loop.
    """
    if type(modulus_bits) is not int or type(e) is not int:
        raise TypeError("modulus_bits and e must be built-in Python integers")
    if modulus_bits < 32 or modulus_bits % 2:
        raise ValueError("modulus_bits must be even and at least 32")
    if e <= 1 or e % 2 == 0:
        raise ValueError("e must be odd and greater than one")
    if e >= 1 << (modulus_bits - 2):
        raise ValueError("e must be smaller than 2**(modulus_bits - 2)")
    if target_gap is not None and gap_bits is not None:
        raise ValueError("use either target_gap or gap_bits, not both")
    if target_gap is not None:
        if type(target_gap) is not int:
            raise TypeError("target_gap must be a built-in Python integer")
        if target_gap < 1 or target_gap & (target_gap - 1):
            raise ValueError("target_gap must be a positive power of two")
        gap_bits = target_gap.bit_length() - 1
    if gap_bits is None:
        gap_bits = modulus_bits // 4 + 3
    if type(gap_bits) is not int:
        raise TypeError("gap_bits must be a built-in Python integer")
    if not 0 <= gap_bits <= modulus_bits // 2 - 2:
        raise ValueError("gap_bits must be between zero and modulus_bits//2 - 2")

    for _ in range(_MAX_GENERATION_ATTEMPTS):
        key = _generate_close_prime_key(bits=modulus_bits, gap_bits=gap_bits, e=e)
        if not isinstance(key, dict) or not {"n", "e", "p", "q"}.issubset(key):
            raise RuntimeError("close-prime generator returned a malformed key")
        n = key["n"]
        p, q = validate_factors(n, key["p"], key["q"])
        if n.bit_length() != modulus_bits or type(key["e"]) is not int or key["e"] != e:
            raise RuntimeError("close-prime generator returned inconsistent RSA parameters")
        if q - p < 1 << gap_bits:
            raise RuntimeError("close-prime generator returned less than the requested gap")
        # The original checks gcd(e, phi), but p=e or q=e can still produce a
        # key rejected by RSA recovery. Retry these rare cases without editing it.
        if gcd(e, n) != 1 or gcd(e, (p - 1) * (q - 1)) != 1:
            continue
        return {
            "public_key": {"key_id": "key_001", "n": n, "e": e},
            "private_truth": {
                "p": p, "q": q, "case_type": "close_prime",
                "actual_gap": q - p,
                "intended_weak_generation": True,
                "observable_shared_factor": False,
            },
        }
    raise RuntimeError(
        "Could not generate an RSA-compatible close-prime key within "
        f"{_MAX_GENERATION_ATTEMPTS} attempts"
    )
