"""
Batch GCD using product/remainder trees and whole-GCD fallback.
Algorithm: https://facthacks.cr.yp.to/batchgcd.html
Remainders: https://facthacks.cr.yp.to/remainder.html
Only distinct public moduli enter; candidate primality uses PyCryptodome.
"""

from Crypto.Util.number import isPrime

from rsa_auditor.attacks import pairwise_gcd as shared_prime_attack


def _integer_values(values):
    """Copy tree integers > 1; even and repeated values are allowed."""
    copied = []
    for value in values:
        if type(value) is not int:
            raise TypeError("tree values must be built-in integers")
        if value <= 1:
            raise ValueError("tree values must be greater than one")
        copied.append(value)
    return copied


def build_product_tree(values):
    """Build leaves-first product levels, carrying an odd last node unchanged.

    Empty input returns []. Tree values are integers > 1; scanner entry points
    additionally require distinct odd moduli.
    """
    leaves = _integer_values(values)
    if not leaves:
        return []
    levels = [leaves]
    while len(levels[-1]) > 1:
        current_level = levels[-1]
        parents = []
        for index in range(0, len(current_level), 2):
            product = current_level[index]
            if index + 1 < len(current_level):
                product *= current_level[index + 1]
            parents.append(product)
        levels.append(parents)
    return levels


def compute_leaf_remainders(product_tree):
    """Return leaf-aligned P % n_i**2 for a tree from build_product_tree.

    The input must be an unchanged output of build_product_tree.
    Each child product divides its parent, so its square divides the parent's
    square. Reduce each parent remainder modulo its child product squares.
    """
    if not product_tree:
        return []

    # P > 1, so P % P**2 = P.
    remainders = [product_tree[-1][0]]
    for children in reversed(product_tree[:-1]):
        remainders = [
            remainders[index // 2] % (child_product * child_product)
            for index, child_product in enumerate(children)
        ]
    return remainders


def _checked_gcd(gcd_fn, left, right, maximum):
    """Call the backend once and check its integer range and divisibility."""
    shared = gcd_fn(left, right)
    if type(shared) is not int:
        raise TypeError("gcd_fn must return a built-in integer")
    if not 1 <= shared <= maximum:
        raise ValueError("gcd_fn returned a value outside the valid GCD range")
    if left % shared != 0 or right % shared != 0:
        raise ValueError(
            "gcd_fn returned a value that does not divide both inputs")
    return shared


def compute_batch_gcds(unique_moduli, gcd_fn=None):
    """Compute gcd(n_i, product(other n)) with product and remainder trees.

    Args:
        unique_moduli: Distinct built-in odd integers greater than one.
        gcd_fn: A GCD callable, defaulting to the shared Euclidean function.

    Returns:
        Raw GCDs in input order. Empty/singleton inputs return []/[1] without
        GCD calls. A result equal to its modulus still needs resolution.
    """
    if gcd_fn is None:
        gcd_fn = shared_prime_attack.euclidean_gcd
    if not callable(gcd_fn):
        raise TypeError("gcd_fn must be callable")

    # Validate every modulus before building trees or making GCD calls.
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
        moduli.append(modulus)
        seen_moduli.add(modulus)

    if not moduli:
        return []
    if len(moduli) == 1:
        return [1]
    product_tree = build_product_tree(moduli)
    remainders = compute_leaf_remainders(product_tree)
    raw_gcds = []
    for modulus, remainder in zip(moduli, remainders):
        if remainder % modulus != 0:
            raise ValueError(
                "leaf remainder must be exactly divisible by its modulus")
        quotient = remainder // modulus
        # A zero remainder is valid: gcd(n, 0) = n.
        raw_gcds.append(_checked_gcd(gcd_fn, modulus, quotient, modulus))
    return raw_gcds


def scan_moduli_batch(unique_moduli,
                      gcd_fn=None,
                      resolve_full_gcd=True) -> dict:
    """Return batch findings with optional whole-GCD resolution.

    For raw g == n, fallback searches other moduli for a verified prime split.

    Args:
        unique_moduli: Distinct built-in odd integers greater than one.
        gcd_fn: A GCD callable, defaulting to the shared Euclidean function.
        resolve_full_gcd: Resolve whole-modulus GCDs; False is diagnostic only.

    Returns:
        Findings and separate leaf/fallback GCD counts.
    """
    if type(resolve_full_gcd) is not bool:
        raise TypeError("resolve_full_gcd must be a boolean")
    if gcd_fn is None:
        gcd_fn = shared_prime_attack.euclidean_gcd
    if not callable(gcd_fn):
        raise TypeError("gcd_fn must be callable")
    moduli = list(unique_moduli)
    raw_gcds = compute_batch_gcds(moduli, gcd_fn)
    leaf_gcd_calls = len(moduli) if len(moduli) > 1 else 0
    prime_cache = {}

    def is_candidate_prime(candidate):
        if candidate not in prime_cache:
            prime_cache[candidate] = bool(isPrime(candidate))
        return prime_cache[candidate]

    def candidate_factors(modulus, shared):
        if not 1 < shared < modulus or modulus % shared != 0:
            return None
        cofactor = modulus // shared
        if shared == cofactor:
            return None
        if not is_candidate_prime(shared) or not is_candidate_prime(cofactor):
            return None
        return tuple(sorted((shared, cofactor)))

    findings = {}
    unresolved_moduli = []
    for modulus, shared in zip(moduli, raw_gcds):
        finding = {
            "n": modulus,
            "status": "no_shared_factor_in_dataset",
            "p": None,
            "q": None,
            "resolution_method": None,
            "raw_batch_gcd": shared,
        }
        if shared == modulus:
            finding["status"] = "unresolved_full_gcd"
            unresolved_moduli.append(modulus)
        elif shared > 1:
            factors = candidate_factors(modulus, shared)
            if factors is not None:
                finding.update(status="factored",
                               p=factors[0],
                               q=factors[1],
                               resolution_method="batch_direct")
        findings[modulus] = finding

    fallback_gcd_calls = 0
    if resolve_full_gcd:
        for modulus in unresolved_moduli:
            for companion in moduli:
                if companion == modulus:
                    continue
                fallback_gcd_calls += 1
                shared = _checked_gcd(gcd_fn, modulus, companion,
                                      min(modulus, companion))
                if shared == 1:
                    continue
                if shared == modulus or shared == companion:
                    raise ValueError(
                        "whole-modulus GCD between distinct inputs violates "
                        "the two-distinct-prime RSA domain")
                factors = candidate_factors(modulus, shared)
                # A useful witness splits both moduli into distinct primes.
                if factors is None or candidate_factors(companion,
                                                        shared) is None:
                    continue
                findings[modulus].update(
                    status="factored",
                    p=factors[0],
                    q=factors[1],
                    resolution_method="batch_fallback",
                )
                break

    unresolved_after_fallback = sum(finding["status"] == "unresolved_full_gcd"
                                    for finding in findings.values())
    return {
        "algorithm": "batch_with_fallback" if resolve_full_gcd else "batch_raw",
        "findings": findings,
        "gcd_calls": leaf_gcd_calls + fallback_gcd_calls,
        "pairwise_gcd_calls": fallback_gcd_calls,
        "batch_leaf_gcd_calls": leaf_gcd_calls,
        "fallback_gcd_calls": fallback_gcd_calls,
        "full_gcd_before_fallback": len(unresolved_moduli),
        "unresolved_after_fallback": unresolved_after_fallback,
        "matching_pair_count": None,
    }
