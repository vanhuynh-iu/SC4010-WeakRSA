"""Tree-based batch GCD with an explicit whole-GCD fallback.

The mathematics
follows the batch-GCD construction described in the project brief and
https://facthacks.cr.yp.to/batchgcd.html and
https://facthacks.cr.yp.to/remainder.html.
PyCryptodome supplies primality checks.

Attack inputs are distinct public moduli only. No records, exponents, labels,
generator state, or original factors enter the computation.
"""

from Crypto.Util.number import isPrime

import shared_prime_attack


_MAX_DEBUG_WITNESSES = 20


def _integer_values(values):
    """Copy positive integer tree leaves; tree helpers also accept even values."""
    copied = []
    for value in values:
        if type(value) is not int:
            raise TypeError("tree values must be built-in integers")
        if value <= 1:
            raise ValueError("tree values must be greater than one")
        copied.append(value)
    return copied


def build_product_tree(values):
    """Return product levels, beginning with copied leaves and ending at P.

    Empty input returns []. Pair adjacent nodes at each level; carry an odd
    last node unchanged. This arithmetic helper accepts integers greater than
    one, including even or repeated values. Attack entry points additionally
    require distinct odd moduli.
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
    """Return P % (n_i*n_i) in leaf order using a remainder tree.

    product_tree must follow build_product_tree's leaves-first contract.
    Parent/child relations are checked before descent, so a malformed tree
    cannot silently provide an arithmetic result. Each child product divides
    its parent product; consequently its square divides the parent's square,
    allowing a parent's remainder to be reduced again at the child.
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

    # P > 1, so P % P**2 is P itself. No huge decimal output is needed.
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
        # Resolve at call time, so both algorithms can use the same backend.
        gcd_fn = shared_prime_attack.euclidean_gcd
    if not callable(gcd_fn):
        raise TypeError("gcd_fn must be callable")
    return gcd_fn


def _checked_gcd(gcd_fn, left, right, maximum):
    """Call the chosen backend once and validate its public arithmetic output."""
    shared = gcd_fn(left, right)
    if type(shared) is not int:
        raise TypeError("gcd_fn must return a built-in integer")
    if not 1 <= shared <= maximum:
        raise ValueError("gcd_fn returned a value outside the valid GCD range")
    if left % shared != 0 or right % shared != 0:
        raise ValueError("gcd_fn returned a value that does not divide both inputs")
    return shared


def _raw_gcds(moduli, gcd_fn):
    """Compute raw values for validated inputs; a singleton needs no GCD call."""
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
        # A zero remainder gives quotient zero: gcd(n, 0) == n is valid.
        raw_gcds.append(_checked_gcd(gcd_fn, modulus, quotient, modulus))
    return raw_gcds


def compute_batch_gcds(unique_moduli, gcd_fn=None):
    """Return raw g_i = gcd(n_i, product(other n)) aligned with input order.

    Compute P with a product tree and r_i = P % n_i**2 with a remainder tree;
    the actual leaf GCD is gcd(n_i, r_i // n_i). Raw whole-modulus results do
    not yet recover factors. Empty/singleton inputs return []/[1] without
    calling the GCD backend. Inputs are distinct built-in odd integers > 1.
    """
    gcd_fn = _backend(gcd_fn)
    return _raw_gcds(_validated_moduli(unique_moduli), gcd_fn)


def scan_moduli_batch(unique_moduli, gcd_fn=None, resolve_full_gcd=True):
    """Factor distinct public RSA moduli with batch GCD and optional fallback.

    Proper raw factors are verified as two distinct primes. A raw GCD equal
    to n is ``unresolved_full_gcd`` until a useful pairwise witness splits it.
    Fallback compares that modulus against all other unique moduli, including
    those already resolved, and stops at its first verified factorization.

    All actual leaf/fallback GCD calls are counted. No full pair scan is run
    to construct a matching-pair graph. ``matching_pair_count`` is therefore
    None; optional fallback evidence is limited to 20 witnesses. Setting
    resolve_full_gcd=False labels the result ``batch_raw`` for diagnostics,
    not a completed auditor benchmark.
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
                # Preserve the baseline's requirement that a useful pair
                # splits BOTH public moduli into two distinct primes.
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
