"""Public-record orchestration for Van's pairwise and batch auditors.

This module never accepts truth.
Normalization, scanning, and record propagation have separate timing boundaries.
"""

from time import perf_counter_ns

from key_dataset import normalize_public_keys
from shared_prime_attack import scan_moduli


def audit_public_keys(public_records, gcd_fn=None, *, algorithm="pairwise"):
    """Normalize records, scan unique moduli, and propagate findings to IDs.

    Each record keeps its own exponent. Duplicate records never introduce
    another GCD call. The bare scanner's per-modulus findings/counters remain
    available; recovered_keys and gcd_comparisons are transitional aliases.
    """
    if algorithm == "batch":
        algorithm = "batch_with_fallback"
    if algorithm not in ("pairwise", "batch_with_fallback", "batch_raw"):
        raise ValueError("unknown audit algorithm")
    if algorithm != "pairwise":
        from batch_gcd_attack import scan_moduli_batch

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
