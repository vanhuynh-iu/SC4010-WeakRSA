"""Run shared-prime RSA demos and verify OAEP decryption."""

import argparse
import json
from time import perf_counter

from generators.shared_prime_cases import (
    generate_shared_prime_keys, generate_mixed_key_dataset, make_observed_subset,
)
from key_recovery import encrypt_message
from audit_pipeline import measure_shared_prime_scan, recover_messages, evaluate_scan
from build_dataset import load_dataset, load_public_keys, save_dataset, dataset_paths


def demo_shared_prime_attack(num_keys=6, num_shared=2, modulus_bits=2048,
                             message=b"Van's shared-prime RSA demo.",
                             save_directory=None, load_directory=None, *,
                             mixed=False, algorithm="pairwise"):
    """Run generation/loading -> public-only scan -> recovery -> OAEP check."""
    if load_directory is not None:
        case = load_dataset(load_directory)
        print("Loaded saved educational dataset from {}".format(load_directory))
    else:
        # SHA-256 OAEP needs at least 66 bytes of overhead plus the message.
        if modulus_bits < 2048:
            raise ValueError("the OAEP demo requires --bits >= 2048")
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
        save_dataset(save_directory, public_keys, case["private_truth"],
                      case["expected_vulnerable_ids"],
                      metadata={"profile": "loaded" if load_directory is not None
                                else "mixed" if mixed else "shared_group"})
        public_path, private_path, _ = dataset_paths(save_directory)
        print("Saved public inputs to {} and evaluator truth to {}".format(public_path, private_path))

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
                         save_directory=None, algorithm="pairwise"):
    """Compare the same target before and after adding its shared-prime companion."""
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
            save_dataset(Path(save_directory) / label, case["public_keys"], case["private_truth"],
                          case["expected_vulnerable_ids"],
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
        report_path = Path("results") / "coverage_demos" / Path(save_directory).name / "coverage_result.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x", encoding="utf-8") as output:
            json.dump(summaries, output, indent=2)
            output.write("\n")
    return summaries


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dataset", dest="load_dataset", metavar="PUBLIC_DIR",
                      help="load saved public inputs and separate evaluator truth")
    mode.add_argument("--public-only", metavar="PUBLIC_JSON", help="attack/decrypt without any truth file")
    mode.add_argument("--mixed", action="store_true", help="generate all pairwise edge-case topologies")
    mode.add_argument("--coverage", action="store_true", help="remove then add a target's companion")
    parser.add_argument("--num-keys", type=int, default=6)
    parser.add_argument("--shared-keys", type=int, default=2)
    parser.add_argument("--bits", type=int, default=2048)
    parser.add_argument("--message", default="Van's shared-prime RSA demo.")
    parser.add_argument("--save-dataset", dest="save_dataset", metavar="PUBLIC_DIR")
    parser.add_argument("--algorithm", choices=("pairwise", "batch"), default="pairwise",
                        help="GCD method; batch includes full-GCD fallback")
    args = parser.parse_args(argv)
    if args.public_only and args.save_dataset:
        parser.error("--public-only cannot save evaluator truth")
    try:
        if args.coverage:
            summary = demo_coverage_attack(args.bits, args.message.encode("utf-8"),
                                           args.save_dataset, args.algorithm)
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
            args.save_dataset, args.load_dataset,
            mixed=args.mixed, algorithm=args.algorithm,
        )
        return 0 if summary["success"] else 1
    except (ValueError, TypeError, OSError, KeyError, RuntimeError) as error:
        parser.exit(1, "Error: {}\n".format(error))


if __name__ == "__main__":
    raise SystemExit(main())
