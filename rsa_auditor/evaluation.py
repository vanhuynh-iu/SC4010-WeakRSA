"""Private post-attack evaluation, separate from public-key scanning.

Expected recoveries are derived from prime ownership and exact Fermat search
distance, never from scenario labels or an attack's own reported factors.
"""

import math

from Crypto.Util.number import isPrime

from .contracts import SCAN_COUNTERS
from .normalization import normalize_public_keys


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


def _validate_execution(reference, report):
    """Check stage claims against independent observability/search-distance truth."""
    mode, budget, backend = report["mode"], report["fermat_budget"], report.get("gcd_backend")
    if backend not in ("pairwise", "batch"):
        raise ValueError("audit GCD backend must be pairwise or batch")
    expected_candidates = expected_attempted = expected_exhausted = 0
    for n, finding in report["findings"].items():
        gcd_success = mode != "fermat" and n in reference["gcd_moduli"]
        gcd_status = "not_run" if mode == "fermat" else "factored" if gcd_success else "no_shared_factor_in_dataset"
        should_attempt = mode == "fermat" or (mode == "combined" and not gcd_success)
        required = reference["fermat_candidates"][n]
        fermat_success = should_attempt and required <= budget
        fermat_status = ("factored" if fermat_success else "budget_exhausted") if should_attempt else "not_run"
        candidates = min(required, budget) if should_attempt else 0
        actual_candidates = finding.get("fermat_candidate_tests")
        if (type(actual_candidates) is not int or actual_candidates != candidates
                or finding.get("gcd_status") != gcd_status or finding.get("fermat_status") != fermat_status):
            raise ValueError("stage status/candidate tests disagree with independent search distance, ownership, or budget")
        expected_status = "factored" if gcd_success or fermat_success else "budget_exhausted" if should_attempt else gcd_status
        if finding.get("status") != expected_status:
            raise ValueError("overall finding status disagrees with its independently predicted stages")
        if gcd_success:
            method = "pairwise" if backend == "pairwise" else (
                "batch_fallback" if n in reference["batch_full_gcd_moduli"] else "batch_direct")
        else:
            method = "fermat" if fermat_success else None
        if finding.get("resolution_method") != method:
            raise ValueError("successful method disagrees with selected backend and GCD-first stages")
        expected_candidates += candidates
        expected_attempted += should_attempt
        expected_exhausted += fermat_status == "budget_exhausted"
    for name, expected in (("fermat_candidate_tests", expected_candidates),
                           ("fermat_attempted_moduli", expected_attempted),
                           ("fermat_exhausted_moduli", expected_exhausted)):
        if type(report.get(name)) is not int or report[name] != expected:
            raise ValueError("aggregate {} disagrees with independent per-modulus execution".format(name))
    for name in SCAN_COUNTERS:
        if type(report.get(name)) is not int or report[name] < 0:
            raise ValueError("{} must be a nonnegative integer".format(name))
    if mode == "fermat":
        if any(report[name] for name in SCAN_COUNTERS):
            raise ValueError("Fermat-only mode cannot report GCD work")
    else:
        count = reference["normalized"]["num_unique_moduli"]
        if report["gcd_calls"] != report["pairwise_gcd_calls"] + report["batch_leaf_gcd_calls"]:
            raise ValueError("GCD total does not match its work counters")
        if report["unresolved_after_fallback"]:
            raise ValueError("complete GCD backends cannot retain unresolved shared-prime cases")
        if backend == "pairwise":
            if (report["pairwise_gcd_calls"] != count * (count - 1) // 2
                    or any(report[name] for name in ("batch_leaf_gcd_calls", "fallback_gcd_calls", "full_gcd_before_fallback"))):
                raise ValueError("pairwise backend counters do not describe a complete pair scan")
        elif (report["batch_leaf_gcd_calls"] != (count if count > 1 else 0)
              or report["fallback_gcd_calls"] != report["pairwise_gcd_calls"]
              or report["full_gcd_before_fallback"] != len(reference["batch_full_gcd_moduli"])):
            raise ValueError("batch counters disagree with independent ownership and selected backend")


def _validate_record_findings(reference, report):
    records = reference["normalized"]["public_records"]
    originals = {record["key_id"]: record for record in records}
    mapped = report.get("record_findings")
    if not isinstance(mapped, list):
        raise ValueError("audit record_findings must map every original record")
    ids = [record.get("key_id") for record in mapped]
    if len(ids) != len(set(ids)) or set(ids) != set(originals):
        raise ValueError("record_findings must map every original record exactly once")
    for record in mapped:
        original = originals[record["key_id"]]
        if record.get("n") != original["n"] or record.get("e") != original["e"]:
            raise ValueError("record finding changed original public modulus/exponent")
        finding = report["findings"][original["n"]]
        for field in ("status", "p", "q", "resolution_method", "gcd_status", "fermat_status", "fermat_candidate_tests"):
            if record.get(field) != finding.get(field):
                raise ValueError("per-record {} disagrees with its modulus finding".format(field))


def evaluate_audit(case, report, messages, *, reference=None):
    """Check factors, per-record mapping, expected recovery, and actual plaintexts.

    Call only after scanning/recovery. Zero checked plaintexts is reported as
    zero checks, never as evidence of successful decryption. A reusable reference
    may be prepared outside scan timing by the experiment runner.
    """
    reference = build_reference(case) if reference is None else reference
    normalized = reference["normalized"]
    records = normalized["public_records"]
    public_by_id = {record["key_id"]: record for record in records}
    truth = case["private_truth"]
    mode = report["mode"]
    budget = report["fermat_budget"]
    expected = expected_moduli(reference, mode, budget)
    findings = report.get("findings")
    if not isinstance(findings, dict) or set(findings) != set(reference["factors"]):
        raise ValueError("audit must report exactly one finding per unique modulus")
    for field in ("num_records", "num_unique_moduli", "duplicate_extra_records"):
        if report.get(field) != normalized[field]:
            raise ValueError("audit {} disagrees with public input".format(field))
    _validate_execution(reference, report)
    recovered, by_method = set(), {"gcd": set(), "fermat": set()}
    for n, finding in findings.items():
        if finding.get("n") != n:
            raise ValueError("finding does not match its public modulus")
        p, q = finding.get("p"), finding.get("q")
        if finding.get("status") == "factored":
            if type(p) is not int or type(q) is not int or not 1 < p < q < n or p * q != n:
                raise ValueError("reported factor product is invalid")
            if (p, q) != reference["factors"][n]:
                raise ValueError("reported factors disagree with independent evaluator truth")
            method = finding.get("resolution_method")
            if method not in ("pairwise", "batch_direct", "batch_fallback", "fermat"):
                raise ValueError("factored finding needs a recognized successful method")
            expected_gcd_method = mode != "fermat" and n in reference["gcd_moduli"]
            if (method != "fermat") != expected_gcd_method:
                raise ValueError("successful method disagrees with selected mode and GCD-first execution")
            if method == "fermat" and reference["fermat_candidates"][n] > budget:
                raise ValueError("Fermat recovery exceeds the configured candidate budget")
            recovered.add(n)
            by_method["fermat" if method == "fermat" else "gcd"].add(n)
        else:
            if finding.get("status") not in ("no_shared_factor_in_dataset", "budget_exhausted",
                                              "unresolved_full_gcd", "not_run"):
                raise ValueError("finding has an unrecognized unfactored status")
            if p is not None or q is not None:
                raise ValueError("unfactored finding cannot contain recovered factors")
    _validate_record_findings(reference, report)
    recovered_records = report.get("recovered_records")
    if not isinstance(recovered_records, list):
        raise ValueError("audit recovered_records must be a list")
    expected_ids = {record["key_id"] for record in records if record["n"] in recovered}
    ids = [record.get("key_id") for record in recovered_records]
    if len(ids) != len(set(ids)) or set(ids) != expected_ids:
        raise ValueError("recovered records do not map every factored public record exactly once")
    for recovered_record in recovered_records:
        original = public_by_id[recovered_record["key_id"]]
        n = original["n"]
        if (recovered_record.get("n") != n or recovered_record.get("e") != original["e"]
                or (recovered_record.get("p"), recovered_record.get("q")) != reference["factors"][n]):
            raise ValueError("recovered record changed public modulus/exponent or factors")
        finding = findings[n]
        for field in ("status", "resolution_method", "gcd_status", "fermat_status", "fermat_candidate_tests"):
            if recovered_record.get(field) != finding.get(field):
                raise ValueError("recovered per-record {} disagrees with its modulus finding".format(field))
    ciphertext_ids = {key_id for key_id in expected_ids if "ciphertext" in public_by_id[key_id]}
    if not isinstance(messages, dict) or set(messages) != ciphertext_ids:
        raise ValueError("decryption outputs must match recovered records with ciphertext")
    if any(not isinstance(message, bytes) for message in messages.values()):
        raise ValueError("decryption outputs must be bytes")
    checked_ids = [key_id for key_id in messages if "expected_message" in truth[key_id]]
    checked = len(checked_ids)
    passed = sum(messages[key_id] == truth[key_id]["expected_message"] for key_id in checked_ids)
    false_positive, false_negative = recovered - expected, expected - recovered
    return {
        "mode": mode, "fermat_budget": budget,
        "num_records": normalized["num_records"],
        "num_unique_moduli": normalized["num_unique_moduli"],
        "duplicate_extra_records": normalized["duplicate_extra_records"],
        "expected_recovered_unique_moduli": len(expected),
        "recovered_unique_moduli": len(recovered), "recovered_records": len(recovered_records),
        "recovered_via_gcd_moduli": len(by_method["gcd"]),
        "recovered_via_fermat_moduli": len(by_method["fermat"]),
        "false_positive_moduli": len(false_positive), "false_negative_moduli": len(false_negative),
        "factors_verified": True if recovered else None,
        "agrees_with_reference": not false_positive and not false_negative,
        "decryption_cases_attempted": len(messages),
        "decryption_cases_checked": checked, "decryption_cases_passed": passed,
        "decryption_cases_unchecked": len(messages) - checked,
        "all_decryptions_verified": passed == checked == len(messages) if messages else None,
        "success": not false_positive and not false_negative and passed == checked,
    }
