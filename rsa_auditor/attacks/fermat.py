"""Krystal's Fermat algorithms and the shared budgeted audit interface."""

from bisect import bisect_left
import math
import time

from rsa_auditor.key_recovery import validate_factors

SQUARE_RESIDUES_64 = {(x * x) % 64 for x in range(64)}


def fermat_attack(N, max_iterations):
    """Try each Fermat position from ceil(sqrt(N)), counting the first as one.

    Args:
        N: Odd RSA modulus to factor.
        max_iterations: Maximum number of consecutive positions to test.

    Returns:
        A (p, q, positions) tuple on success, or None when the budget runs out.
    """
    i = 1
    a = math.isqrt(N)
    if a * a < N:
        a += 1

    while i <= max_iterations:
        result = a**2 - N
        potential_b = math.isqrt(result)
        if potential_b**2 == result:
            p = a - potential_b
            q = a + potential_b
            return p, q, i
        a += 1
        i += 1

    return None


def improved_fermat_attack(N, max_iterations):
    """Skip square-root checks when the difference is not a square modulo 64.

    Args:
        N: Odd RSA modulus to factor.
        max_iterations: Maximum number of consecutive positions to cover.

    Returns:
        Tuple (p, q, positions, square_checks); factors are None on exhaustion.
        Positions counts all covered positions, including skipped checks.
    """
    i = 1
    a = math.isqrt(N)
    if a * a < N:
        a += 1

    perfect_square_checks = 0
    while i <= max_iterations:
        result = a**2 - N
        if result % 64 in SQUARE_RESIDUES_64:
            perfect_square_checks += 1
            potential_b = math.isqrt(result)
            if potential_b**2 == result:
                p = a - potential_b
                q = a + potential_b
                return p, q, i, perfect_square_checks
        a += 1
        i += 1

    return None, None, i - 1, perfect_square_checks


def fermat_sieved(N, max_iterations, moduli=(64, 3, 5, 7)):
    """Jump between Fermat positions allowed by a modular residue wheel.

    Args:
        N: Odd integer greater than one.
        max_iterations: Positive number of consecutive positions to cover.
        moduli: Pairwise coprime wheel moduli, each at least two.

    Returns:
        A (p, q, positions, square_checks, preprocessing_seconds) tuple.
        Factors are None on exhaustion. Positions measures the search interval;
        square_checks measures the actual square roots taken.

    Raises:
        ValueError: N, max_iterations, or the wheel configuration is invalid.
    """
    if N <= 1 or N % 2 == 0:
        raise ValueError("N must be an odd integer greater than 1")
    if max_iterations < 1:
        raise ValueError("max_iterations must be positive")
    if not moduli or any(m < 2 for m in moduli):
        raise ValueError("moduli must contain integers >= 2")
    if any(
            math.gcd(moduli[i], moduli[j]) != 1
            for i in range(len(moduli))
            for j in range(i + 1, len(moduli))):
        raise ValueError("Wheel moduli must be pairwise coprime")

    a0 = math.isqrt(N)
    if a0 * a0 < N:
        a0 += 1

    preprocessing_start = time.perf_counter()
    modulus = math.prod(moduli)
    square_residues = {m: {(x * x) % m for x in range(m)} for m in moduli}
    valid = [
        r for r in range(modulus)
        if all((r * r - N) % m in square_residues[m] for m in moduli)
    ]
    preprocessing_time = time.perf_counter() - preprocessing_start
    if not valid:
        return None, None, max_iterations, 0, preprocessing_time

    remainder = a0 % modulus
    pos = bisect_left(valid, remainder)
    if pos < len(valid):
        a = a0 + valid[pos] - remainder
    else:
        a = a0 + modulus - remainder + valid[0]
        pos = 0

    square_checks = 0
    end = a0 + max_iterations
    while a < end:
        difference = a * a - N
        square_checks += 1
        b = math.isqrt(difference)
        if b * b == difference:
            p = a - b
            q = a + b
            positions_examined = a - a0 + 1
            return (
                p,
                q,
                positions_examined,
                square_checks,
                preprocessing_time,
            )

        pos += 1
        if pos == len(valid):
            a += modulus - valid[-1] + valid[0]
            pos = 0
        else:
            a += valid[pos] - valid[pos - 1]

    return None, None, max_iterations, square_checks, preprocessing_time


def fermat_factor(n: int, max_candidates: int) -> dict:
    """Test at most B consecutive a values, beginning at ceil(sqrt(n)).

    The first candidate counts as one, including an immediate factorisation.
    Exhaustion describes this finite search only. No generator truth or other
    moduli enter the attack. Malformed backend successes are explicit errors.

    Args:
        n: Built-in odd integer greater than one.
        max_candidates: Nonnegative candidate budget for this modulus.

    Returns:
        Validated factors and the number of tested candidates, or an explicit
        budget_exhausted result. A zero budget performs no search.

    Raises:
        TypeError: An input is not a built-in integer.
        ValueError: An input or the returned factors/count is invalid.
    """
    if type(n) is not int:
        raise TypeError("n must be a built-in Python integer")
    if n <= 1 or n % 2 == 0:
        raise ValueError("n must be odd and greater than one")
    if type(max_candidates) is not int:
        raise TypeError("max_candidates must be a built-in Python integer")
    if max_candidates < 0:
        raise ValueError("max_candidates must be nonnegative")
    if max_candidates == 0:
        return {
            "status": "budget_exhausted",
            "factors": None,
            "candidate_tests": 0,
        }

    result = fermat_attack(n, max_iterations=max_candidates)
    if result is None:
        return {
            "status": "budget_exhausted",
            "factors": None,
            "candidate_tests": max_candidates,
        }
    if not isinstance(result, tuple) or len(result) != 3:
        raise ValueError("Fermat backend returned a malformed result")
    p, q, candidate_tests = result
    p, q = validate_factors(n, p, q)
    if (type(candidate_tests) is not int or
            not 1 <= candidate_tests <= max_candidates):
        raise ValueError("Fermat backend returned an invalid candidate count")
    a0 = math.isqrt(n)
    if a0 * a0 < n:
        a0 += 1
    if candidate_tests != (p + q) // 2 - a0 + 1:
        raise ValueError(
            "Fermat backend candidate count does not match its factors")
    return {
        "status": "factored",
        "factors": (p, q),
        "candidate_tests": candidate_tests,
    }
