"""Build the private answer sheet used to grade completed audits.

This evaluator-only reference is never passed into an attack.
"""

import math
from Crypto.Util.number import isPrime
from ..public_inputs import normalize_public_keys

MODES = ("gcd", "fermat", "combined")


def build_reference(case):
    """Validate evaluator truth and independently derive observable weaknesses."""
    normalized = normalize_public_keys(case["public_keys"])
    truth = case["private_truth"]
    public_ids = {record["key_id"] for record in normalized["public_records"]}
    if not isinstance(truth, dict) or set(truth) != public_ids:
        raise ValueError("public and private evaluator IDs must match")
    factors, owners, candidates, primality = {}, {}, {}, {}
    for record in normalized["public_records"]:
        item = truth[record["key_id"]]
        pair = (item.get("p"), item.get("q"))
        if any(type(value) is not int or value <= 2 or value % 2 == 0 for value in pair):
            raise ValueError("evaluator factors must be distinct odd primes")
        p, q = sorted(pair)
        n = record["n"]
        if p == q or p * q != n:
            raise ValueError("evaluator factors do not match the public modulus")
        for prime in (p, q):
            if prime not in primality:
                primality[prime] = bool(isPrime(prime))
            if not primality[prime]:
                raise ValueError("evaluator truth contains a composite factor")
            owners.setdefault(prime, set()).add(n)
        if n in factors and factors[n] != (p, q):
            raise ValueError("duplicate modulus has conflicting evaluator truth")
        factors[n] = (p, q)
        a0 = math.isqrt(n)
        if a0 * a0 < n:
            a0 += 1
        candidates[n] = (p + q) // 2 - a0 + 1
        if candidates[n] < 1:
            raise ValueError("invalid Fermat reference distance")
    gcd_moduli = {n for n, pair in factors.items()
                  if any(len(owners[prime]) > 1 for prime in pair)}
    full_gcd_moduli = {n for n, pair in factors.items()
                       if all(len(owners[prime]) > 1 for prime in pair)}
    return {"factors": factors, "gcd_moduli": gcd_moduli,
            "batch_full_gcd_moduli": full_gcd_moduli,
            "fermat_candidates": candidates, "normalized": normalized}


def expected_moduli(reference, mode, fermat_budget):
    """Return the independently predicted recovery set for one fixed budget."""
    if mode not in MODES:
        raise ValueError("mode must be gcd, fermat, or combined")
    if type(fermat_budget) is not int or fermat_budget < 0:
        raise ValueError("fermat_budget must be a nonnegative integer")
    gcd_set = set(reference["gcd_moduli"])
    fermat_set = {n for n, count in reference["fermat_candidates"].items()
                  if count <= fermat_budget}
    return gcd_set if mode == "gcd" else fermat_set if mode == "fermat" else gcd_set | fermat_set
