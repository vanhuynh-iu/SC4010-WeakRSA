"""Public-only audit orchestration for the three operating modes.

This module accepts public records and configuration. Answer-sheet loading and
post-attack grading live in datasets.storage and evaluation, outside scanning.
"""

from time import perf_counter_ns
from typing import Iterable, Optional

from .records import (
    AuditReport, GCDAlgorithmInput, GCDBackend, PublicKeyRecord,
    IntegratedAuditReport, SCAN_COUNTERS,
)
from .key_recovery import validate_factors
from .public_inputs import normalize_public_keys
from .attacks.pairwise_gcd import scan_moduli
from .attacks.fermat import fermat_factor


def run_audit(public_records, mode="combined", gcd_backend="batch",
              fermat_budget=256, *, gcd_fn=None) -> IntegratedAuditReport:
    """Audit public records using GCD, bounded Fermat, or both in that order.

    Every call owns fresh state. Combined mode skips Fermat only after validated
    GCD success. The same candidate budget applies independently to each unique
    modulus. Scan time includes both selected checks and factor validation;
    normalization, record mapping, decryption and evaluation are outside it.
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
            from .attacks.batch_gcd import scan_moduli_batch
            gcd_result = scan_moduli_batch(moduli, gcd_fn=gcd_fn, resolve_full_gcd=True)
        gcd_seconds = (perf_counter_ns() - start) / 1_000_000_000
        counts.update({name: gcd_result[name] for name in SCAN_COUNTERS})
        gcd_findings = gcd_result["findings"]

    findings = {}
    for n in moduli:
        gcd_finding = gcd_findings.get(n)
        finding = {
            "n": n,
            "status": gcd_finding["status"] if gcd_finding else "budget_exhausted",
            "p": gcd_finding["p"] if gcd_finding else None,
            "q": gcd_finding["q"] if gcd_finding else None,
            "resolution_method": gcd_finding["resolution_method"] if gcd_finding else None,
            "gcd_status": gcd_finding["status"] if gcd_finding else "not_run",
            "fermat_status": "not_run",
            "fermat_candidate_tests": 0,
            "fermat_scan_seconds": 0.0,
        }
        # Validate before deciding to skip the other check.
        if finding["status"] == "factored":
            finding["p"], finding["q"] = validate_factors(n, finding["p"], finding["q"])
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
    records = [{**findings[record["n"]], "key_id": record["key_id"], "e": record["e"]}
               for record in normalized["public_records"]]
    recovered = [record for record in records if record["status"] == "factored"]
    return {
        "mode": mode, "gcd_backend": gcd_backend, "fermat_budget": fermat_budget,
        "findings": findings, "normalized": normalized,
        "record_findings": records, "recovered_records": recovered, "recovered_keys": recovered,
        "num_records": normalized["num_records"], "num_unique_moduli": len(moduli),
        "duplicate_extra_records": normalized["duplicate_extra_records"],
        "preprocessing_seconds": preprocessing_seconds, "scan_seconds": scan_seconds,
        "gcd_scan_seconds": gcd_seconds, "fermat_scan_seconds": fermat_seconds,
        **counts,
        "fermat_candidate_tests": sum(f["fermat_candidate_tests"] for f in findings.values()),
        "fermat_attempted_moduli": sum(f["fermat_status"] != "not_run" for f in findings.values()),
        "fermat_exhausted_moduli": sum(f["fermat_status"] == "budget_exhausted" for f in findings.values()),
    }


def audit_public_keys(public_records: Iterable[PublicKeyRecord],
                      gcd_fn: Optional[GCDBackend] = None, *,
                      algorithm: GCDAlgorithmInput = "pairwise") -> AuditReport:
    """Run a GCD audit and map findings to every original record ID.

    Duplicates retain their exponents and add no GCD calls. AuditReport defines
    the per-modulus counters and record aliases.
    """
    if algorithm == "batch":
        algorithm = "batch_with_fallback"
    if algorithm not in ("pairwise", "batch_with_fallback", "batch_raw"):
        raise ValueError("unknown audit algorithm")
    if algorithm != "pairwise":
        from .attacks.batch_gcd import scan_moduli_batch

    start = perf_counter_ns()
    normalized = normalize_public_keys(public_records)
    preprocessing_seconds = (perf_counter_ns() - start) / 1_000_000_000

    start = perf_counter_ns()
    if algorithm == "pairwise":
        scan_result = scan_moduli(normalized["unique_moduli"], gcd_fn=gcd_fn)
    else:
        scan_result = scan_moduli_batch(normalized["unique_moduli"], gcd_fn=gcd_fn,
                                       resolve_full_gcd=algorithm != "batch_raw")
    scan_seconds = (perf_counter_ns() - start) / 1_000_000_000

    record_findings = []
    for record in normalized["public_records"]:
        finding = scan_result["findings"][record["n"]]
        record_findings.append({
            "key_id": record["key_id"],
            "n": record["n"],
            "e": record["e"],
            "status": finding["status"],
            "p": finding["p"],
            "q": finding["q"],
            "resolution_method": finding["resolution_method"],
        })
    recovered = [record for record in record_findings if record["status"] == "factored"]
    return {
        **scan_result,
        "normalized": normalized,
        "record_findings": record_findings,
        "recovered_records": recovered,
        "recovered_keys": recovered,
        "num_records": normalized["num_records"],
        "num_unique_moduli": normalized["num_unique_moduli"],
        "duplicate_extra_records": normalized["duplicate_extra_records"],
        "preprocessing_seconds": preprocessing_seconds,
        "scan_seconds": scan_seconds,
        "gcd_comparisons": scan_result["gcd_calls"],
    }


def measure_shared_prime_scan(public_keys, algorithm="pairwise") -> tuple[AuditReport, float]:
    """Return the audit report and scan-only seconds.

    Preprocessing is timed separately; propagation, I/O, generation, OAEP and
    evaluation are outside the scan.
    """
    result = audit_public_keys(public_keys, algorithm=algorithm)
    return result, result["scan_seconds"]
