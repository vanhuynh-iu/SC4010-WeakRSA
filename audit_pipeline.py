"""Public-key audit, recovery, and explicit post-attack evaluation.

Only evaluate_scan accepts private truth; generation and storage stay separate.
"""

from time import perf_counter_ns
from typing import Iterable, Optional

from contracts import AuditReport, GCDAlgorithmInput, GCDBackend, PublicKeyRecord
from key_recovery import decrypt_with_recovered_key
from normalization import normalize_public_keys
from shared_prime_attack import scan_moduli



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


def measure_shared_prime_scan(public_keys, algorithm="pairwise") -> tuple[AuditReport, float]:
    """Return the audit report and scan-only seconds.

    Preprocessing is timed separately; propagation, I/O, generation, OAEP and
    evaluation are outside the scan.
    """
    result = audit_public_keys(public_keys, algorithm=algorithm)
    return result, result["scan_seconds"]


def recover_messages(public_keys, scan_result: AuditReport) -> dict[str, bytes]:
    """Decrypt using only factors returned by the attack, without ground truth."""
    public_by_id = {key["key_id"]: key for key in public_keys}
    messages = {}
    for factors in scan_result["recovered_records"]:
        key_id = factors["key_id"]
        key = public_by_id[key_id]
        if factors["e"] != key["e"]:
            raise ValueError("recovered record exponent does not match its public record")
        if factors["n"] != key["n"] or factors["p"] * factors["q"] != key["n"]:
            raise ValueError("attack factors do not match the original public modulus")
        if "ciphertext" not in key:
            continue
        messages[key_id] = decrypt_with_recovered_key(
            key["ciphertext"], key["n"], key["e"], factors["p"], factors["q"]
        )
    return messages


def evaluate_scan(public_keys, private_truth, expected_ids, result, messages):
    """Evaluate GCD results after recovery/decryption.

    expected_ids describes observable prime sharing, not budgeted Fermat
    recoverability. Fermat and combined modes need separate evaluation.
    """
    public_by_id = {key["key_id"]: key for key in public_keys}
    if set(public_by_id) != set(private_truth):
        raise ValueError("public and private fixture IDs do not match")
    expected = set(expected_ids)
    if not expected.issubset(public_by_id):
        raise ValueError("expected vulnerable IDs are missing from public inputs")
    for key_id, truth in private_truth.items():
        if truth["p"] * truth["q"] != public_by_id[key_id]["n"]:
            raise ValueError("evaluator factors do not match the public fixture")
    # Observability requires another distinct modulus, not a duplicate record.
    moduli_by_prime = {}
    for key_id, truth in private_truth.items():
        for prime in (truth["p"], truth["q"]):
            moduli_by_prime.setdefault(prime, set()).add(public_by_id[key_id]["n"])
    observable = {
        key_id for key_id, truth in private_truth.items()
        if any(len(moduli_by_prime[prime]) > 1 for prime in (truth["p"], truth["q"]))
    }
    if expected != observable:
        raise ValueError("expected IDs must describe recoverability in the observed dataset")
    recovered = {record["key_id"] for record in result["recovered_records"]}
    recovered_moduli = {record["n"] for record in result["recovered_records"]}
    expected_moduli = {public_by_id[key_id]["n"] for key_id in expected}
    factors_verified = all(
        {record["p"], record["q"]}
        == {private_truth[record["key_id"]]["p"], private_truth[record["key_id"]]["q"]}
        for record in result["recovered_records"]
    )
    available_ciphertext_ids = {key_id for key_id in recovered if "ciphertext" in public_by_id[key_id]}
    if set(messages) != available_ciphertext_ids:
        raise ValueError("decryption results do not match the available recovered ciphertexts")
    checked_ids = [key_id for key_id in messages if "expected_message" in private_truth[key_id]]
    checked = len(checked_ids)
    passed = sum(messages[key_id] == private_truth[key_id]["expected_message"] for key_id in checked_ids)
    plaintexts_verified = passed == checked
    normalized = result["normalized"]
    summary = {
        "algorithm": result["algorithm"],
        "num_records": len(public_keys),
        "num_unique_moduli": result["num_unique_moduli"],
        "duplicate_extra_records": result["duplicate_extra_records"],
        "duplicate_groups": len(normalized["duplicate_groups"]),
        "expected_observable_factored_moduli": len(expected_moduli),
        "recovered_records": len(recovered),
        "false_positive_moduli": len(recovered_moduli - expected_moduli),
        "false_negative_moduli": len(expected_moduli - recovered_moduli),
        "decryption_cases_checked": checked,
        "decryption_cases_passed": passed,
        "decryption_cases_attempted": len(messages),
        "all_recovered_records_decrypted": len(messages) == len(recovered) if recovered else None,
        "all_decryptions_verified": checked == len(recovered) and passed == checked if recovered else None,
        "preprocessing_seconds": result["preprocessing_seconds"],
        "scan_seconds": result["scan_seconds"],
        "num_keys": len(public_keys),
        "expected_vulnerable_keys": len(expected),
        "recovered_unique_keys": len(recovered),
        "recovered_unique_moduli": len(recovered_moduli),
        "false_positives": len(recovered - expected),
        "missed_vulnerable_keys": len(expected - recovered),
        "gcd_comparisons": result["gcd_comparisons"],
        "matching_pairs": result["matching_pair_count"],
        "duplicate_pairs": sum(len(group) * (len(group) - 1) // 2
                               for group in normalized["duplicate_groups"].values()),
        "factors_verified": factors_verified if recovered else None,
        "plaintexts_verified": plaintexts_verified if checked else None,
    }
    for counter in ("gcd_calls", "pairwise_gcd_calls", "batch_leaf_gcd_calls",
                    "fallback_gcd_calls", "full_gcd_before_fallback", "unresolved_after_fallback"):
        summary[counter] = result[counter]
    summary["success"] = (
        recovered == expected and factors_verified and plaintexts_verified
    )
    return summary
