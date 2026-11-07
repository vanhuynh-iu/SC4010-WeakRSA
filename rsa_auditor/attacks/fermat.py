"""A budgeted public-only interface to Krystal's unchanged Fermat baseline."""

from math import isqrt

from ..records import FermatResult
from legacy.close_primes.fermat_attack import fermat_attack
from ..key_recovery import validate_factors


def fermat_factor(n: int, max_candidates: int) -> FermatResult:
    """Test at most B consecutive a values, beginning at ceil(sqrt(n)).

    The first candidate counts as one, including an immediate factorisation.
    Exhaustion describes this finite search only. No generator truth or other
    moduli enter the attack. Malformed backend successes are explicit errors.
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
        return {"status": "budget_exhausted", "factors": None, "candidate_tests": 0}

    result = fermat_attack(n, max_iterations=max_candidates)
    if result is None:
        return {
            "status": "budget_exhausted", "factors": None,
            "candidate_tests": max_candidates,
        }
    if not isinstance(result, tuple) or len(result) != 3:
        raise ValueError("Fermat backend returned a malformed result")
    p, q, candidate_tests = result
    p, q = validate_factors(n, p, q)
    if type(candidate_tests) is not int or not 1 <= candidate_tests <= max_candidates:
        raise ValueError("Fermat backend returned an invalid candidate count")
    a0 = isqrt(n)
    if a0 * a0 < n:
        a0 += 1
    if candidate_tests != (p + q) // 2 - a0 + 1:
        raise ValueError("Fermat backend candidate count does not match its factors")
    return {
        "status": "factored", "factors": (p, q),
        "candidate_tests": candidate_tests,
    }
