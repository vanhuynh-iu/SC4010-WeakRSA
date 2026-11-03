"""Van's batch GCD using product/remainder trees and whole-GCD fallback.

Algorithm: https://facthacks.cr.yp.to/batchgcd.html
Remainders: https://facthacks.cr.yp.to/remainder.html
Only distinct public moduli enter; candidate primality uses PyCryptodome.
"""

from Crypto.Util.number import isPrime

from contracts import ScanResult
import shared_prime_attack


_MAX_DEBUG_WITNESSES = 20


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
        current = levels[-1]
        parents = []
        for index in range(0, len(current), 2):
            if index + 1 < len(current):
                parents.append(current[index] * current[index + 1])
            else:
                parents.append(current[index])
        levels.append(parents)
    return levels


def compute_leaf_remainders(product_tree):
    """Return leaf-aligned P % n_i**2 from a validated product tree.

    Each child product divides its parent, so its square divides the parent's
    square. Reduce each parent remainder modulo its child product squares.
    """
    if not isinstance(product_tree, (list, tuple)):
        raise TypeError("product_tree must be a sequence of product levels")
    if not product_tree:
        return []
    levels = [_integer_values(level) for level in product_tree]
    if any(not level for level in levels) or len(levels[-1]) != 1:
        raise ValueError("product_tree must have nonempty levels and one root")
    for index, children in enumerate(levels[:-1]):
        parents = levels[index + 1]
        if len(children) <= 1 or len(parents) != (len(children) + 1) // 2:
            raise ValueError("product_tree has an invalid level shape")
        for parent_index, child_index in enumerate(range(0, len(children), 2)):
            expected = children[child_index]
            if child_index + 1 < len(children):
                expected *= children[child_index + 1]
            if parents[parent_index] != expected:
                raise ValueError("product_tree parent does not match its children")

    # P > 1, so P % P**2 = P.
    remainders = [levels[-1][0]]
    for children in reversed(levels[:-1]):
        remainders = [
            remainders[index // 2] % (product * product)
            for index, product in enumerate(children)
        ]
    return remainders


def _validated_moduli(unique_moduli):
    """Validate every public modulus before any GCD work begins."""
    moduli = []
    seen = set()
    for modulus in unique_moduli:
        if type(modulus) is not int:
            raise TypeError("moduli must be built-in integers, excluding booleans")
        if modulus <= 1 or modulus % 2 == 0:
            raise ValueError("moduli must be odd integers greater than one")
        if modulus in seen:
            raise ValueError("moduli must be distinct; normalize records before scanning")
        moduli.append(modulus)
        seen.add(modulus)
    return moduli


def _backend(gcd_fn):
    if gcd_fn is None:
        # Resolve the shared backend at call time.
        gcd_fn = shared_prime_attack.euclidean_gcd
    if not callable(gcd_fn):
        raise TypeError("gcd_fn must be callable")
    return gcd_fn


def _checked_gcd(gcd_fn, left, right, maximum):
    """Call the backend once and check its integer range and divisibility."""
    shared = gcd_fn(left, right)
    if type(shared) is not int:
        raise TypeError("gcd_fn must return a built-in integer")
    if not 1 <= shared <= maximum:
        raise ValueError("gcd_fn returned a value outside the valid GCD range")
    if left % shared != 0 or right % shared != 0:
        raise ValueError("gcd_fn returned a value that does not divide both inputs")
    return shared


def _raw_gcds(moduli, gcd_fn):
    """Compute raw values; empty/singleton inputs need no GCD calls."""
    if not moduli:
        return []
    if len(moduli) == 1:
        return [1]
    tree = build_product_tree(moduli)
    remainders = compute_leaf_remainders(tree)
    raw_gcds = []
    for modulus, remainder in zip(moduli, remainders):
        if remainder % modulus != 0:
            raise ValueError("leaf remainder must be exactly divisible by its modulus")
        quotient = remainder // modulus
        # A zero remainder is valid: gcd(n, 0) = n.
        raw_gcds.append(_checked_gcd(gcd_fn, modulus, quotient, modulus))
    return raw_gcds


def compute_batch_gcds(unique_moduli, gcd_fn=None):
    """Return raw gcd(n_i, product(other n)) in input order.

    Product/remainder trees give gcd(n_i, (P % n_i**2) // n_i). Inputs are
    distinct odd integers > 1; empty/singleton inputs return []/[1] without
    GCD calls. Whole-modulus results still require factor resolution.
    """
    gcd_fn = _backend(gcd_fn)
    return _raw_gcds(_validated_moduli(unique_moduli), gcd_fn)


def scan_moduli_batch(unique_moduli, gcd_fn=None, resolve_full_gcd=True) -> ScanResult:
    """Return batch findings with optional whole-GCD resolution.

    Proper factors must split n into distinct primes. For each raw g == n,
    fallback checks ALL other unique moduli, including resolved ones, and
    stops at the first verified pair.

    Counters include leaf and fallback GCD calls. matching_pair_count is None;
    no full pair graph is built, and evidence is capped at 20 witnesses.
    resolve_full_gcd=False returns batch_raw diagnostics with unresolved
    whole-GCD statuses, not a completed auditor benchmark.
    """
    if type(resolve_full_gcd) is not bool:
        raise TypeError("resolve_full_gcd must be a boolean")
    gcd_fn = _backend(gcd_fn)
    moduli = _validated_moduli(unique_moduli)
    raw_gcds = _raw_gcds(moduli, gcd_fn)
    leaf_gcd_calls = len(moduli) if len(moduli) > 1 else 0
    prime_cache = {}

    def is_candidate_prime(candidate):
        if candidate not in prime_cache:
            prime_cache[candidate] = bool(isPrime(candidate))
        return prime_cache[candidate]

    def candidate_factors(modulus, shared):
        if not 1 < shared < modulus or modulus % shared != 0:
            return None
        other = modulus // shared
        if shared * other != modulus or shared == other:
            return None
        if not is_candidate_prime(shared) or not is_candidate_prime(other):
            return None
        return tuple(sorted((shared, other)))

    findings = {}
    unresolved = []
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
            unresolved.append(modulus)
        elif shared > 1:
            factors = candidate_factors(modulus, shared)
            if factors is not None:
                finding.update(status="factored", p=factors[0], q=factors[1],
                               resolution_method="batch_direct")
        findings[modulus] = finding

    fallback_calls = 0
    witnesses = []
    witnesses_truncated = False
    if resolve_full_gcd:
        for modulus in unresolved:
            for companion in moduli:
                if companion == modulus:
                    continue
                fallback_calls += 1
                shared = _checked_gcd(gcd_fn, modulus, companion, min(modulus, companion))
                if shared == 1:
                    continue
                if shared == modulus or shared == companion:
                    raise ValueError(
                        "whole-modulus GCD between distinct inputs violates the "
                        "two-distinct-prime RSA domain"
                    )
                factors = candidate_factors(modulus, shared)
                # A useful witness splits both moduli into distinct primes.
                if factors is None or candidate_factors(companion, shared) is None:
                    continue
                findings[modulus].update(
                    status="factored", p=factors[0], q=factors[1],
                    resolution_method="batch_fallback",
                )
                if len(witnesses) < _MAX_DEBUG_WITNESSES:
                    witnesses.append((modulus, companion))
                else:
                    witnesses_truncated = True
                break

    remaining = sum(finding["status"] == "unresolved_full_gcd" for finding in findings.values())
    return {
        "algorithm": "batch_with_fallback" if resolve_full_gcd else "batch_raw",
        "findings": findings,
        "gcd_calls": leaf_gcd_calls + fallback_calls,
        "pairwise_gcd_calls": fallback_calls,
        "batch_leaf_gcd_calls": leaf_gcd_calls,
        "fallback_gcd_calls": fallback_calls,
        "full_gcd_before_fallback": len(unresolved),
        "unresolved_after_fallback": remaining,
        "matching_pair_count": None,
        "optional_debug_evidence": {
            "fallback_witnesses": witnesses,
            "fallback_witnesses_truncated": witnesses_truncated,
        },
    }
