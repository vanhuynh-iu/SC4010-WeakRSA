"""Pairwise GCD scanning for shared factors in distinct public moduli.

Candidate primality checks use PyCryptodome; no private truth is accepted.
"""

from Crypto.Util.number import isPrime


def euclidean_gcd(a: int, b: int) -> int:
    """Return the greatest common divisor of two nonnegative Python integers."""
    if type(a) is not int or type(b) is not int:
        raise TypeError("a and b must be integers")
    if a < 0 or b < 0:
        raise ValueError("a and b must be nonnegative")

    while b:
        a, b = b, a % b
    return a


def scan_moduli(unique_moduli, gcd_fn=None) -> dict:
    """Find shared-prime factors by checking every unordered pair of moduli.

    All m*(m-1)//2 pairs are checked, even after factors are found. Negative
    findings describe only this dataset.

    Args:
        unique_moduli: Distinct built-in odd integers greater than one.
        gcd_fn: A GCD callable, defaulting to euclidean_gcd at call time.

    Returns:
        Findings with ordered factors, GCD counts, and matching-pair count.
    """
    if gcd_fn is None:
        gcd_fn = euclidean_gcd
    if not callable(gcd_fn):
        raise TypeError("gcd_fn must be callable")

    # Consume an iterable once and validate it fully before any GCD calls.
    moduli = []
    seen_moduli = set()
    for modulus in unique_moduli:
        if type(modulus) is not int:
            raise TypeError(
                "moduli must be built-in integers, excluding booleans")
        if modulus <= 1 or modulus % 2 == 0:
            raise ValueError("moduli must be odd integers greater than one")
        if modulus in seen_moduli:
            raise ValueError(
                "moduli must be distinct; normalize records before scanning")
        seen_moduli.add(modulus)
        moduli.append(modulus)

    findings = {
        modulus: {
            "n": modulus,
            "status": "no_shared_factor_in_dataset",
            "p": None,
            "q": None,
            "resolution_method": None,
        } for modulus in moduli
    }
    matching_pair_count = 0
    gcd_calls = 0
    prime_cache = {}

    def is_candidate_prime(candidate):
        if candidate not in prime_cache:
            prime_cache[candidate] = bool(isPrime(candidate))
        return prime_cache[candidate]

    for left_index, left in enumerate(moduli):
        for right_index in range(left_index + 1, len(moduli)):
            right = moduli[right_index]
            gcd_calls += 1
            shared = gcd_fn(left, right)
            if type(shared) is not int:
                raise TypeError("gcd_fn must return a built-in integer")
            if not 1 <= shared <= min(left, right):
                raise ValueError(
                    "gcd_fn returned a value outside the valid GCD range")
            if left % shared != 0 or right % shared != 0:
                raise ValueError(
                    "gcd_fn returned a value that does not divide both moduli")
            if shared == 1:
                continue
            if shared == left or shared == right:
                raise ValueError(
                    "whole-modulus GCD between distinct inputs violates the "
                    "two-distinct-prime RSA domain")

            left_cofactor = left // shared
            right_cofactor = right // shared
            # Divisibility was checked above; each split must use two primes.
            if shared == left_cofactor or shared == right_cofactor:
                continue
            # A nontrivial GCD need not be prime for malformed RSA inputs.
            if not all(
                    is_candidate_prime(candidate)
                    for candidate in (shared, left_cofactor, right_cofactor)):
                continue

            matching_pair_count += 1
            for modulus, other_factor in ((left, left_cofactor),
                                          (right, right_cofactor)):
                p, q = sorted((shared, other_factor))
                findings[modulus] = {
                    "n": modulus,
                    "status": "factored",
                    "p": p,
                    "q": q,
                    "resolution_method": "pairwise",
                }

    return {
        "algorithm": "pairwise",
        "findings": findings,
        "gcd_calls": gcd_calls,
        "pairwise_gcd_calls": gcd_calls,
        "batch_leaf_gcd_calls": 0,
        "fallback_gcd_calls": 0,
        "full_gcd_before_fallback": 0,
        "unresolved_after_fallback": 0,
        "matching_pair_count": matching_pair_count,
    }
