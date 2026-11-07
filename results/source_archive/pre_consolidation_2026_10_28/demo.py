"""Runnable demonstration of Van's shared-prime path only.

The shared-prime experiment
runner lives in experiments.py; Krystal retains ownership of her Fermat path.
"""

import argparse
import json
from time import perf_counter

from key_generation import generate_shared_prime_keys, generate_mixed_key_dataset, make_observed_subset
from key_recovery import decrypt_with_recovered_key, encrypt_message, recover_private_key
from shared_prime_auditor import audit_public_keys
from shared_prime_fixtures import load_fixtures, load_public_keys, save_fixtures


def measure_shared_prime_scan(public_keys, algorithm="pairwise"):
    """Compatibility helper: return the v2 audit report and scan-only seconds.

    Validation/deduplication are separately reported as preprocessing_seconds.
    Record propagation, generation, I/O, OAEP and evaluation are outside scan.
    """
    result = audit_public_keys(public_keys, algorithm=algorithm)
    return result, result["scan_seconds"]


def recover_messages(public_keys, scan_result):
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
    """Compare attack results with truth only after factor recovery/decryption."""
    public_by_id = {key["key_id"]: key for key in public_keys}
    if set(public_by_id) != set(private_truth):
        raise ValueError("public and private fixture IDs do not match")
    expected = set(expected_ids)
    if not expected.issubset(public_by_id):
        raise ValueError("expected vulnerable IDs are missing from public inputs")
    for key_id, truth in private_truth.items():
        if truth["p"] * truth["q"] != public_by_id[key_id]["n"]:
            raise ValueError("evaluator factors do not match the public fixture")
    # Derive observable ground truth from prime membership in DISTINCT n.
    # A duplicate alone is not a companion modulus. This stays in evaluation.
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


def demo_small_arithmetic(algorithm="pairwise"):
    """Use tiny textbook arithmetic to make every recovery step readable."""
    print("SMALL ARITHMETIC EXERCISE (textbook RSA; no OAEP)")
    public_keys = [
        {"key_id": "key_001", "n": 187, "e": 17},
        {"key_id": "key_002", "n": 253, "e": 17},
        {"key_id": "key_003", "n": 899, "e": 17},
    ]
    plaintext = 42
    for key in public_keys:
        key["ciphertext"] = pow(plaintext, key["e"], key["n"])
        print("  {}: n={}, e={}, ciphertext={}".format(
            key["key_id"], key["n"], key["e"], key["ciphertext"]
        ))
    # Toy ciphertexts are integers; the public OAEP record schema uses bytes.
    # The scanner needs only IDs/n/e, while the arithmetic ciphertexts stay here.
    result, elapsed = measure_shared_prime_scan([
        {field: key[field] for field in ("key_id", "n", "e")} for key in public_keys
    ], algorithm=algorithm)
    keys_by_id = {key["key_id"]: key for key in public_keys}
    for factors in result["recovered_keys"]:
        key = keys_by_id[factors["key_id"]]
        p, q = factors["p"], factors["q"]
        d = recover_private_key(p, q, key["e"])
        recovered = pow(key["ciphertext"], d, key["n"])
        if recovered != plaintext:
            raise ValueError("small example decryption failed")
        print("  RECOVERED {}: p={}, q={}, phi={}, d={}, plaintext={}".format(
            factors["key_id"], p, q, (p - 1) * (q - 1), d, recovered
        ))
    if {record["key_id"] for record in result["recovered_keys"]} != {"key_001", "key_002"}:
        raise ValueError("small example recovered the wrong key set")
    print("  Unrelated key_003: no shared factor found")
    print("  GCD comparisons: {}; attack seconds: {:.6f}".format(
        result["gcd_comparisons"], elapsed
    ))

    d = recover_private_key(67, 101, 17)
    recovered = pow(4838, d, 6767)
    if d != 1553 or recovered != 1000:
        raise ValueError("lecture example failed")
    print("  Lecture check: n=6767, e=17, recovered d={}, 4838 -> {}".format(d, recovered))
    return result


def demo_shared_prime_attack(num_keys=6, num_shared=2, modulus_bits=2048,
                             message=b"Van's shared-prime RSA demo.",
                             save_directory=None, load_directory=None, *,
                             mixed=False, fixture_encoding="decimal", algorithm="pairwise"):
    """Run generation/loading -> public-only scan -> recovery -> OAEP check."""
    if load_directory is not None:
        case = load_fixtures(load_directory)
        print("Loaded saved educational fixtures from {}".format(load_directory))
    else:
        # SHA-256 OAEP needs at least 66 bytes of overhead plus the message.
        # Restrict this real-size demo; smaller arithmetic belongs to --small.
        if modulus_bits < 2048:
            raise ValueError("the OAEP demo requires --bits >= 2048; use --small for arithmetic")
        if len(message) > (modulus_bits + 7) // 8 - 66:
            raise ValueError("message is too long for this modulus and OAEP SHA-256")
        profile = "a mixed dataset of" if mixed else str(num_keys)
        print("Preparing {} educational {}-bit keys (outside attack timing)...".format(
            profile, modulus_bits
        ), flush=True)
        case = (generate_mixed_key_dataset(modulus_bits)
                if mixed else generate_shared_prime_keys(num_keys, num_shared, modulus_bits))
        for key in case["public_keys"]:
            key["ciphertext"] = encrypt_message(message, key["n"], key["e"])
            case["private_truth"][key["key_id"]]["expected_message"] = message

    public_keys = case["public_keys"]
    if save_directory is not None:
        save_fixtures(save_directory, public_keys, case["private_truth"],
                      case["expected_vulnerable_ids"], integer_encoding=fixture_encoding,
                      metadata={"profile": "loaded" if load_directory is not None
                                else "mixed" if mixed else "shared_group"})
        print("Saved public.json and separate private_truth.json to {}".format(save_directory))

    # Only public records go into the attack; no factors or case labels.
    pipeline_start = perf_counter()
    result, elapsed = measure_shared_prime_scan(public_keys, algorithm=algorithm)
    messages = recover_messages(public_keys, result)
    summary = evaluate_scan(public_keys, case["private_truth"],
                            case["expected_vulnerable_ids"], result, messages)
    summary["attack_seconds"] = elapsed
    summary["modulus_bits"] = sorted({key["n"].bit_length() for key in public_keys})
    summary["end_to_end_seconds"] = perf_counter() - pipeline_start
    summary["end_to_end_boundary"] = "in-memory records -> normalize -> scan -> recovery/decryption -> evaluation"
    for key_id, recovered_message in messages.items():
        print("  {}: factors recovered; OAEP plaintext = {!r}".format(
            key_id, recovered_message.decode("utf-8", errors="replace")
        ))
    print(json.dumps(summary, indent=2))
    print("PASS" if summary["success"] else "FAIL")
    return summary


def demo_coverage_attack(modulus_bits=2048, message=b"Same target, added companion.",
                         save_directory=None, fixture_encoding="decimal", algorithm="pairwise"):
    """Hold target n/e/ciphertext fixed while removing/adding its companion.

    This is an executable correctness/coverage demonstration, not a repeated
    benchmark runner. Krystal can reuse the cases and counters in experiments.
    """
    if modulus_bits < 2048:
        raise ValueError("the coverage OAEP demo requires --bits >= 2048")
    if len(message) > (modulus_bits + 7) // 8 - 66:
        raise ValueError("message is too long for this modulus and OAEP SHA-256")
    print("Preparing a target, companion, and controls (outside attack timing)...", flush=True)
    population = generate_shared_prime_keys(4, 2, modulus_bits)
    for key in population["public_keys"]:
        key["ciphertext"] = encrypt_message(message, key["n"], key["e"])
        population["private_truth"][key["key_id"]]["expected_message"] = message
    before = make_observed_subset(population, ["key_001", "key_003", "key_004"])
    after = make_observed_subset(population, ["key_001", "key_002", "key_003", "key_004"])
    target_preserved = before["public_keys"][0] == after["public_keys"][0]
    summaries = {}
    for label, case in (("before", before), ("after", after)):
        if save_directory is not None:
            from pathlib import Path
            save_fixtures(Path(save_directory) / label, case["public_keys"], case["private_truth"],
                          case["expected_vulnerable_ids"], integer_encoding=fixture_encoding,
                          metadata={"profile": "coverage_" + label, "target_key_id": "key_001"})
        result, _ = measure_shared_prime_scan(case["public_keys"], algorithm=algorithm)
        messages = recover_messages(case["public_keys"], result)
        summary = evaluate_scan(case["public_keys"], case["private_truth"],
                                case["expected_vulnerable_ids"], result, messages)
        summary["target_status"] = result["findings"][case["public_keys"][0]["n"]]["status"]
        summary["companion_present"] = label == "after"
        summary["target_decryption_checked"] = "key_001" in messages
        summary["target_decryption_verified"] = (
            messages["key_001"] == message if "key_001" in messages else None
        )
        summaries[label] = summary
    summaries["target_ciphertext_preserved"] = target_preserved
    summaries["coverage_passed"] = (
        target_preserved and summaries["before"]["success"] and summaries["after"]["success"]
        and summaries["before"]["target_status"] == "no_shared_factor_in_dataset"
        and summaries["after"]["target_decryption_verified"] is True
    )
    print(json.dumps(summaries, indent=2))
    print("PASS" if summaries["coverage_passed"] else "FAIL")
    if save_directory is not None:
        from pathlib import Path
        with (Path(save_directory) / "coverage_result.json").open("x", encoding="utf-8") as output:
            json.dump(summaries, output, indent=2)
            output.write("\n")
    return summaries


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--small", action="store_true", help="trace small textbook RSA examples")
    mode.add_argument("--load-fixtures", metavar="DIR", help="rerun a saved OAEP fixture set")
    mode.add_argument("--public-only", metavar="PUBLIC_JSON", help="attack/decrypt without any truth file")
    mode.add_argument("--mixed", action="store_true", help="generate all pairwise edge-case topologies")
    mode.add_argument("--coverage", action="store_true", help="remove then add a target's companion")
    parser.add_argument("--num-keys", type=int, default=6)
    parser.add_argument("--shared-keys", type=int, default=2)
    parser.add_argument("--bits", type=int, default=2048)
    parser.add_argument("--message", default="Van's shared-prime RSA demo.")
    parser.add_argument("--save-fixtures", metavar="DIR")
    parser.add_argument("--fixture-encoding", choices=("decimal", "hex"), default="decimal")
    parser.add_argument("--algorithm", choices=("pairwise", "batch", "batch_with_fallback", "batch_raw"),
                        default="pairwise", help="batch_raw is diagnostic: full-GCD cases stay unresolved")
    args = parser.parse_args(argv)
    if args.small and args.save_fixtures:
        parser.error("--save-fixtures is for OAEP scenarios; --small is an arithmetic exercise")
    if args.public_only and args.save_fixtures:
        parser.error("--public-only cannot save evaluator truth")
    try:
        if args.small:
            demo_small_arithmetic(args.algorithm)
            return 0
        if args.coverage:
            summary = demo_coverage_attack(args.bits, args.message.encode("utf-8"),
                                           args.save_fixtures, args.fixture_encoding, args.algorithm)
            return 0 if summary["coverage_passed"] else 1
        if args.public_only:
            public_keys = load_public_keys(args.public_only)
            result, elapsed = measure_shared_prime_scan(public_keys, algorithm=args.algorithm)
            messages = recover_messages(public_keys, result)
            print("Public-only scan: {} comparisons, {} recovered keys, {:.6f} seconds".format(
                result["gcd_comparisons"], len(result["recovered_keys"]), elapsed
            ))
            print("  {} records, {} unique moduli, {} duplicate extra records".format(
                result["num_records"], result["num_unique_moduli"], result["duplicate_extra_records"]
            ))
            for key_id, message in messages.items():
                print("  {}: {!r}".format(key_id, message.decode("utf-8", errors="replace")))
            print("No private truth loaded; detections were not evaluated against expected labels.")
            return 0
        summary = demo_shared_prime_attack(
            args.num_keys, args.shared_keys, args.bits, args.message.encode("utf-8"),
            args.save_fixtures, args.load_fixtures,
            mixed=args.mixed, fixture_encoding=args.fixture_encoding, algorithm=args.algorithm,
        )
        return 0 if summary["success"] else 1
    except (ValueError, TypeError, OSError, KeyError, RuntimeError) as error:
        parser.exit(1, "Error: {}\n".format(error))


if __name__ == "__main__":
    raise SystemExit(main())
