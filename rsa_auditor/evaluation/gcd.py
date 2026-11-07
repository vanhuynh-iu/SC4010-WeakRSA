"""Original GCD-only evaluation, retained for the standalone experiments."""


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
