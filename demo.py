"""Audit one saved public dataset with GCD, Fermat, or their combination."""

import argparse
from collections import Counter
import json
from pathlib import Path
from time import perf_counter

from audit_pipeline import run_audit, recover_messages
from dataset_io import load_dataset, load_public_keys


def report_document(report, messages, evaluation=None, recovery_seconds=0.0):
    """Build a lossless JSON report without exposing evaluator-only labels."""
    def encode(finding):
        return {key: hex(value) if key in ("n", "e", "p", "q") and value is not None else value
                for key, value in finding.items()}

    fields = (
        "mode", "gcd_backend", "fermat_budget", "num_records", "num_unique_moduli",
        "duplicate_extra_records", "preprocessing_seconds", "scan_seconds",
        "gcd_scan_seconds", "fermat_scan_seconds", "gcd_calls", "pairwise_gcd_calls",
        "batch_leaf_gcd_calls", "fallback_gcd_calls", "full_gcd_before_fallback",
        "unresolved_after_fallback", "fermat_candidate_tests", "fermat_attempted_moduli",
        "fermat_exhausted_moduli",
    )
    return {
        "format": "weak-rsa-audit-report",
        **{field: report[field] for field in fields},
        "recovered_unique_moduli": sum(f["status"] == "factored" for f in report["findings"].values()),
        "recovered_records": len(report["recovered_records"]),
        "status_counts": dict(Counter(f["status"] for f in report["findings"].values())),
        "unique_moduli": [encode(finding) for finding in report["findings"].values()],
        "records": [encode(finding) for finding in report["record_findings"]],
        "decryption_cases_attempted": len(messages),
        "decrypted_messages_hex": {key: message.hex() for key, message in messages.items()},
        "recovery_decryption_seconds": recovery_seconds,
        "evaluation": evaluation,
        "timing_boundary": "scan includes selected GCD/Fermat work and factor validation; excludes normalization, record mapping, recovery/OAEP, I/O and evaluation",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--dataset", metavar="PUBLIC_DIR", help="default: data/public/auditor_demo")
    source.add_argument("--public-only", metavar="PUBLIC_JSON", help="never load evaluator truth")
    parser.add_argument("--mode", choices=("gcd", "fermat", "combined"), default="gcd")
    parser.add_argument("--gcd-backend", "--algorithm", dest="gcd_backend",
                        choices=("pairwise", "batch"), default="batch")
    parser.add_argument("--fermat-budget", type=int, default=256,
                        help="candidate tests per unique modulus (default: 256)")
    parser.add_argument("--evaluate", action="store_true", help="load separate truth only after the audit")
    parser.add_argument("--private-dir", help="optional evaluator-truth directory; requires --evaluate")
    parser.add_argument("--output", metavar="REPORT_JSON", help="save a new lossless JSON report")
    args = parser.parse_args(argv)
    if args.evaluate and args.public_only:
        parser.error("--public-only cannot load evaluator truth")
    if args.private_dir and not args.evaluate:
        parser.error("--private-dir requires --evaluate")
    if args.fermat_budget < 0:
        parser.error("--fermat-budget must be nonnegative")
    try:
        if args.output and Path(args.output).exists():
            raise FileExistsError("report already exists; choose a new --output path")
        directory = Path(args.dataset or "data/public/auditor_demo")
        public_path = Path(args.public_only) if args.public_only else directory / "public.json"
        records = load_public_keys(public_path)
        report = run_audit(records, args.mode, args.gcd_backend, args.fermat_budget)
        start = perf_counter()
        messages = recover_messages(records, report)
        recovery_seconds = perf_counter() - start
        evaluation = None
        if args.evaluate:
            from evaluation import evaluate_audit
            case = load_dataset(directory, args.private_dir)
            evaluation = evaluate_audit(case, report, messages)
        document = report_document(report, messages, evaluation, recovery_seconds)
        print("{} audit: {} recovered moduli; {} recovered keys".format(
            args.mode, document["recovered_unique_moduli"], document["recovered_records"]))
        print("{} records / {} unique moduli / {} duplicate extra records".format(
            report["num_records"], report["num_unique_moduli"], report["duplicate_extra_records"]))
        print("GCD backend: {}; {} GCD calls".format(args.gcd_backend, report["gcd_calls"]))
        print("Fermat budget: {}; {} candidate tests; {} attempted; {} exhausted".format(
            args.fermat_budget, report["fermat_candidate_tests"], report["fermat_attempted_moduli"],
            report["fermat_exhausted_moduli"]))
        print("Scan: {:.6f}s; recovery/decryption: {:.6f}s".format(report["scan_seconds"], recovery_seconds))
        by_id = {finding["key_id"]: finding for finding in report["record_findings"]}
        for key_id, message in messages.items():
            print("  {} via {}: OAEP plaintext = {!r}".format(
                key_id, by_id[key_id]["resolution_method"], message.decode("utf-8", errors="replace")))
        print("Unique-modulus outcomes: " + json.dumps(document["status_counts"], sort_keys=True))
        if evaluation is None:
            print("No private truth loaded; recovered plaintexts were not compared with expected messages.")
        else:
            print("Evaluation: " + json.dumps(evaluation, sort_keys=True))
            print("PASS" if evaluation["success"] else "FAIL")
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("x", encoding="utf-8") as destination:
                json.dump(document, destination, indent=2, allow_nan=False)
                destination.write("\n")
            print("Report: " + str(output))
        return 0 if evaluation is None or evaluation["success"] else 1
    except (ValueError, TypeError, OSError, KeyError, RuntimeError) as error:
        parser.exit(1, "Error: {}\n".format(error))


if __name__ == "__main__":
    raise SystemExit(main())
