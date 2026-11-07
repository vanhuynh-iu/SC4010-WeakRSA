"""Van's pairwise shared-prime auditor.

Its input is distinct public moduli,
without record IDs, exponents, ciphertexts, or evaluator truth. PyCryptodome
supplies candidate primality checks; Euclidean GCD is implemented below.
"""

from Crypto.Util.number import isPrime


_MAX_DEBUG_PAIRS = 20


def euclidean_gcd(a: int, b: int) -> int:
    """Return the greatest common divisor of two nonnegative Python integers."""
    if type(a) is not int or type(b) is not int:
        raise TypeError("a and b must be integers")
    if a < 0 or b < 0:
        raise ValueError("a and b must be nonnegative")

    # Taking a remainder preserves the GCD: gcd(a, b) = gcd(b, a % b).
    while b != 0:
        remainder = a % b
        a = b
        b = remainder

    # When b is zero, the remaining a is the greatest common divisor.
    return a


def scan_moduli(unique_moduli, gcd_fn=None):
    """Return one finding per distinct public modulus using a full pair scan.

    Inputs must be distinct built-in odd integers greater than one. Normalize
    public records and remove duplicate moduli before calling this function.
    Every unordered pair is checked exactly once, including pairs whose
    moduli have already been factored. With m inputs, the baseline therefore
    makes m*(m-1)//2 GCD calls.

    A successful finding has status ``factored``, ordered primes ``p < q``,
    and ``resolution_method='pairwise'``. Other findings have status
    ``no_shared_factor_in_dataset`` and null factors/method. This status says
    only that this scan found no useful factor; it is not a security claim.

    gcd_fn defaults to euclidean_gcd at call time. Invalid backend return
    values raise an explicit error. A whole-modulus GCD between distinct
    inputs violates the supported two-distinct-prime RSA domain and also
    raises ValueError. Candidate factorizations are checked with isPrime.

    The result includes actual GCD counters and at most 20 useful pair
    witnesses. It never stores an unbounded graph of all matching pairs.
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
            raise TypeError("moduli must be built-in integers, excluding booleans")
        if modulus <= 1 or modulus % 2 == 0:
            raise ValueError("moduli must be odd integers greater than one")
        if modulus in seen_moduli:
            raise ValueError("moduli must be distinct; normalize records before scanning")
        seen_moduli.add(modulus)
        moduli.append(modulus)

    findings = {
        modulus: {
            "n": modulus,
            "status": "no_shared_factor_in_dataset",
            "p": None,
            "q": None,
            "resolution_method": None,
        }
        for modulus in moduli
    }
    matching_modulus_pairs = []
    matching_pair_count = 0
    matching_pairs_truncated = False
    gcd_calls = 0
    prime_cache = {}

    def is_candidate_prime(candidate):
        if candidate not in prime_cache:
            prime_cache[candidate] = bool(isPrime(candidate))
        return prime_cache[candidate]

    for left_index in range(len(moduli)):
        left = moduli[left_index]
        for right_index in range(left_index + 1, len(moduli)):
            right = moduli[right_index]
            gcd_calls += 1
            shared = gcd_fn(left, right)
            if type(shared) is not int:
                raise TypeError("gcd_fn must return a built-in integer")
            if not 1 <= shared <= min(left, right):
                raise ValueError("gcd_fn returned a value outside the valid GCD range")
            if left % shared != 0 or right % shared != 0:
                raise ValueError("gcd_fn returned a value that does not divide both moduli")
            if shared == 1:
                continue
            if shared == left or shared == right:
                raise ValueError(
                    "whole-modulus GCD between distinct inputs violates the "
                    "two-distinct-prime RSA domain"
                )

            left_other = left // shared
            right_other = right // shared
            if (
                shared * left_other != left
                or shared * right_other != right
                or shared == left_other
                or shared == right_other
            ):
                continue
            # A nontrivial GCD can itself be composite for malformed RSA
            # inputs. Report a recovery only for two distinct prime factors.
            if not all(
                is_candidate_prime(candidate)
                for candidate in (shared, left_other, right_other)
            ):
                continue

            matching_pair_count += 1
            if len(matching_modulus_pairs) < _MAX_DEBUG_PAIRS:
                matching_modulus_pairs.append((left, right))
            else:
                matching_pairs_truncated = True
            for modulus, other_factor in ((left, left_other), (right, right_other)):
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
        "optional_debug_evidence": {
            "matching_modulus_pairs": matching_modulus_pairs,
            "matching_pairs_truncated": matching_pairs_truncated,
        },
    }
