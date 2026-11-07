"""Public-only audit orchestration for the three operating modes.

This module accepts public records and configuration. Answer-sheet loading and
post-attack grading live in datasets.storage and evaluation, outside scanning.
"""

from time import perf_counter_ns

from rsa_auditor.attacks.batch_gcd import scan_moduli_batch
from rsa_auditor.attacks.fermat import fermat_factor
from rsa_auditor.attacks.pairwise_gcd import scan_moduli
from rsa_auditor.constants import SCAN_COUNTERS
from rsa_auditor.key_recovery import validate_factors
from rsa_auditor.public_inputs import normalize_public_keys


def run_audit(public_records,
              mode="combined",
              gcd_backend="batch",
              fermat_budget=256,
              *,
              gcd_fn=None) -> dict:
    """Run GCD, bounded Fermat, or GCD followed by Fermat on unresolved keys.

    Each modulus gets its own Fermat budget. Timings cover attack work and
    factor validation, excluding normalization, mapping, decryption and grading.

    Args:
        public_records: Records containing key_id, n, e and optional ciphertext.
        mode: One of "gcd", "fermat", or "combined".
        gcd_backend: Either "pairwise" or "batch".
        fermat_budget: Maximum candidate positions per unique modulus.
        gcd_fn: Optional GCD implementation used by instrumented experiments.

    Returns:
        Findings for each modulus and record, with timing and work counters.
    """
    if mode not in ("gcd", "fermat", "combined"):
        raise ValueError("mode must be gcd, fermat, or combined")
    if gcd_backend not in ("pairwise", "batch"):
        raise ValueError("gcd_backend must be pairwise or batch")
    if type(fermat_budget) is not int or fermat_budget < 0:
        raise ValueError("fermat_budget must be a nonnegative integer")
    if gcd_fn is not None and not callable(gcd_fn):
        raise TypeError("gcd_fn must be callable")

    start = perf_counter_ns()
    normalized = normalize_public_keys(public_records)
    preprocessing_seconds = (perf_counter_ns() - start) / 1_000_000_000
    moduli = normalized["unique_moduli"]
    counts = {name: 0 for name in SCAN_COUNTERS}
    gcd_seconds = 0.0
    fermat_seconds = 0.0

    scan_start = perf_counter_ns()
    gcd_findings = {}
    if mode in ("gcd", "combined"):
        start = perf_counter_ns()
        if gcd_backend == "pairwise":
            gcd_result = scan_moduli(moduli, gcd_fn=gcd_fn)
        else:
            gcd_result = scan_moduli_batch(moduli,
                                           gcd_fn=gcd_fn,
                                           resolve_full_gcd=True)
        gcd_seconds = (perf_counter_ns() - start) / 1_000_000_000
        counts.update({name: gcd_result[name] for name in SCAN_COUNTERS})
        gcd_findings = gcd_result["findings"]

    findings = {}
    for n in moduli:
        gcd_finding = gcd_findings.get(n)
        finding = {
            "n": n,
            "status": "budget_exhausted",
            "p": None,
            "q": None,
            "resolution_method": None,
            "gcd_status": "not_run",
            "fermat_status": "not_run",
            "fermat_candidate_tests": 0,
            "fermat_scan_seconds": 0.0,
        }
        if gcd_finding is not None:
            for field in ("status", "p", "q", "resolution_method"):
                finding[field] = gcd_finding[field]
            finding["gcd_status"] = gcd_finding["status"]
        # Validate before deciding to skip the other check.
        if finding["status"] == "factored":
            finding["p"], finding["q"] = validate_factors(
                n, finding["p"], finding["q"])
        elif mode in ("fermat", "combined"):
            start = perf_counter_ns()
            result = fermat_factor(n, fermat_budget)
            elapsed = (perf_counter_ns() - start) / 1_000_000_000
            finding["fermat_scan_seconds"] = elapsed
            fermat_seconds += elapsed
            finding["fermat_status"] = result["status"]
            finding["fermat_candidate_tests"] = result["candidate_tests"]
            finding["status"] = result["status"]
            if result["status"] == "factored":
                p, q = validate_factors(n, *result["factors"])
                finding.update(p=p, q=q, resolution_method="fermat")
        findings[n] = finding
    scan_seconds = (perf_counter_ns() - scan_start) / 1_000_000_000

    # Propagate one factorization to every ID, retaining its own exponent.
    record_findings = []
    for record in normalized["public_records"]:
        record_findings.append({
            **findings[record["n"]],
            "key_id": record["key_id"],
            "e": record["e"],
        })
    recovered = [
        record for record in record_findings if record["status"] == "factored"
    ]
    return {
        "mode": mode,
        "gcd_backend": gcd_backend,
        "fermat_budget": fermat_budget,
        "findings": findings,
        "normalized": normalized,
        "record_findings": record_findings,
        "recovered_records": recovered,
        "num_records": normalized["num_records"],
        "num_unique_moduli": len(moduli),
        "duplicate_extra_records": normalized["duplicate_extra_records"],
        "preprocessing_seconds": preprocessing_seconds,
        "scan_seconds": scan_seconds,
        "gcd_scan_seconds": gcd_seconds,
        "fermat_scan_seconds": fermat_seconds,
        **counts,
        "fermat_candidate_tests": sum(
            finding["fermat_candidate_tests"] for finding in findings.values()),
        "fermat_attempted_moduli": sum(finding["fermat_status"] != "not_run"
                                       for finding in findings.values()),
        "fermat_exhausted_moduli": sum(
            finding["fermat_status"] == "budget_exhausted"
            for finding in findings.values()),
    }
