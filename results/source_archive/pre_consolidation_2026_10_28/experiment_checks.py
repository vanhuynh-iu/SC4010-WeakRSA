"""E1/E2 supporting checks for Van's shared-prime auditor.

Krystal remains lead owner of the shared experiment framework. These saved-
fixture correctness/coverage checks implement no Fermat algorithm and make
no timing-performance claim. Truth is used only outside public-key attacks.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid

from demo import evaluate_scan, recover_messages
from experiments import ALGORITHMS, COUNTERS, _code_metadata, _csv_text, _factor_map, _load_dataset
from shared_prime_attack import euclidean_gcd
from shared_prime_auditor import audit_public_keys


CORRECTNESS_FIELDS = (
    "run_id", "dataset_id", "algorithm", "num_records", "num_unique_moduli",
    "duplicate_extra_records", "expected_observable_factored_moduli", "recovered_unique_moduli",
    "recovered_records", "false_positive_moduli", "false_negative_moduli", "factor_products_verified",
    "full_gcd_before_fallback", "unresolved_after_fallback", "decryption_cases_checked",
    "decryption_cases_passed", "decryption_cases_attempted", "gcd_calls", "pairwise_gcd_calls",
    "batch_leaf_gcd_calls", "fallback_gcd_calls", "agrees_with_reference", "algorithms_agree",
    "scan_seconds", "measurement_kind", "dataset_sha256", "run_status", "error",
)
COVERAGE_FIELDS = (
    "run_id", "dataset_id", "algorithm", "target_key_id", "companion_present",
    "num_unique_moduli", "target_status", "target_factors_verified",
    "target_decryption_checked", "target_decryption_verified", "target_decryption_attempted",
    "stage", "num_records", "duplicate_extra_records", "gcd_calls", "pairwise_gcd_calls",
    "batch_leaf_gcd_calls", "fallback_gcd_calls", "full_gcd_before_fallback", "unresolved_after_fallback",
    "agrees_with_reference", "algorithms_agree", "scan_seconds", "measurement_kind",
    "dataset_sha256", "run_status", "error",
)


def _new_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8]


def _check_output(directory, names):
    directory = Path(directory)
    if any((directory / name).exists() or (directory / name).is_symlink() for name in names):
        raise FileExistsError("check output files already exist; use a new directory")
    return directory


def _metadata(run_id, mode, datasets):
    environment = _code_metadata()
    root = Path(__file__).resolve().parent
    for name in ("experiment_checks.py", "shared_prime_auditor.py", "demo.py", "key_recovery.py"):
        environment["source_sha256"][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    return {"run_id": run_id, "mode": mode, **environment,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "algorithms": list(ALGORITHMS), "gcd_backend": "euclidean",
            "measurement_kind": "single correctness check; not a benchmark",
            "scan_timing_boundary": "complete scanner call; normalization/recovery/evaluation excluded",
            "truth_access": "fixture evaluation outside public-key attack only",
            "datasets": [{"dataset_id": d["dataset_id"], "directory": str(d["directory"].resolve()),
                          "public_sha256": d["dataset_sha256"], "modulus_bit_lengths": d["bits"],
                          "num_records": d["normalized"]["num_records"],
                          "num_unique_moduli": d["normalized"]["num_unique_moduli"]} for d in datasets]}


def _run_both(dataset):
    outcomes = {}
    for algorithm in ALGORITHMS:
        actual_calls = 0
        def counted_gcd(a, b):
            nonlocal actual_calls
            actual_calls += 1
            return euclidean_gcd(a, b)
        outcome = {"result": None, "factor_map": None, "evaluation": None,
                   "messages": {}, "error": None, "reference_ok": None}
        try:
            case = dataset["case"]
            result = audit_public_keys(case["public_keys"], gcd_fn=counted_gcd, algorithm=algorithm)
            outcome["result"] = result
            factors = _factor_map(result, dataset["moduli"], algorithm, actual_calls)
            outcome["factor_map"] = factors
            outcome["reference_ok"] = factors == dataset["reference"]
            messages = recover_messages(case["public_keys"], result)
            outcome["messages"] = messages
            outcome["evaluation"] = evaluate_scan(case["public_keys"], case["private_truth"],
                                                  case["expected_vulnerable_ids"], result, messages)
        except Exception as error:
            outcome["error"] = "{}: {}".format(type(error).__name__, error)
        outcomes[algorithm] = outcome
    complete = all(outcome["error"] is None for outcome in outcomes.values())
    agree = outcomes[ALGORITHMS[0]]["factor_map"] == outcomes[ALGORITHMS[1]]["factor_map"] if complete else None
    for outcome in outcomes.values():
        outcome["algorithms_agree"] = agree
        outcome["run_status"] = (
            "error" if outcome["error"] else "comparison_incomplete" if not complete else
            "success" if outcome["reference_ok"] and agree and outcome["evaluation"]["success"] else "mismatch"
        )
    return outcomes


def _base_row(run_id, dataset, algorithm, outcome):
    result = outcome["result"]
    if not isinstance(result, dict):
        result = None
    return {"run_id": run_id, "dataset_id": dataset["dataset_id"], "algorithm": algorithm,
            **{field: dataset["normalized"][field] for field in
               ("num_records", "num_unique_moduli", "duplicate_extra_records")},
            **{field: result.get(field) if result is not None else None for field in COUNTERS},
            "agrees_with_reference": outcome["reference_ok"], "algorithms_agree": outcome["algorithms_agree"],
            "scan_seconds": result.get("scan_seconds") if result is not None else None,
            "measurement_kind": "single correctness check; not a benchmark",
            "dataset_sha256": dataset["dataset_sha256"], "run_status": outcome["run_status"],
            "error": outcome["error"]}


def _write_results(output, csv_name, metadata_name, rows, fields, metadata):
    # Serialize both outputs before creating anything; use exclusive writes.
    contents = (_csv_text(rows, fields), json.dumps(metadata, indent=2, allow_nan=False) + "\n")
    output.mkdir(parents=True, exist_ok=True)
    for name, content in zip((csv_name, metadata_name), contents):
        with (output / name).open("x", encoding="utf-8", newline="") as destination:
            destination.write(content)


def run_shared_prime_correctness(dataset_directories, output_directory):
    """Check both algorithms against saved independent truth and each other.

    Decryption is attempted only where a recovered public record contains a
    ciphertext. Zero checked cases means no expected plaintext comparison was
    performed, rather than claiming decryption success for factor-only data.
    """
    names = ("shared_prime_correctness.csv", "correctness_metadata.json")
    output = _check_output(output_directory, names)
    directories = list(dataset_directories)
    if not directories or len({str(Path(p).resolve()) for p in directories}) != len(directories):
        raise ValueError("provide at least one fixture directory without duplicates")
    datasets = [_load_dataset(directory) for directory in directories]
    if len({d["dataset_id"] for d in datasets}) != len(datasets):
        raise ValueError("dataset directory names must be unique")
    run_id, rows = _new_run_id(), []
    for dataset in datasets:
        for algorithm, outcome in _run_both(dataset).items():
            row = _base_row(run_id, dataset, algorithm, outcome)
            evaluation, factors = outcome["evaluation"], outcome["factor_map"]
            row.update({"expected_observable_factored_moduli": len(dataset["reference"]),
                        "recovered_unique_moduli": len(factors) if factors is not None else None,
                        "recovered_records": len(outcome["result"]["recovered_records"])
                            if isinstance(outcome["result"], dict)
                            and isinstance(outcome["result"].get("recovered_records"), list) else None,
                        "factor_products_verified": True if factors else None})
            for field in ("false_positive_moduli", "false_negative_moduli", "decryption_cases_checked",
                          "decryption_cases_passed", "decryption_cases_attempted"):
                row[field] = evaluation[field] if evaluation is not None else None
            rows.append(row)
    summary = {"run_id": run_id, "all_runs_ok": all(row["run_status"] == "success" for row in rows),
               "num_datasets": len(datasets), "rows_written": len(rows), "checks": rows}
    metadata = _metadata(run_id, "correctness", datasets)
    metadata["summary"] = {field: value for field, value in summary.items() if field != "checks"}
    _write_results(output, *names, rows, CORRECTNESS_FIELDS, metadata)
    return summary


def _coverage_inputs(before, after, target_key_id):
    if not isinstance(target_key_id, str) or not target_key_id.strip():
        raise ValueError("target_key_id must be a nonblank string")
    before_by_id = {record["key_id"]: record for record in before["case"]["public_keys"]}
    after_by_id = {record["key_id"]: record for record in after["case"]["public_keys"]}
    if target_key_id not in before_by_id or target_key_id not in after_by_id:
        raise ValueError("target must be present before and after adding a companion")
    if any(after_by_id.get(key_id) != record for key_id, record in before_by_id.items()):
        raise ValueError("every before public record, including target n/e/ciphertext, must remain identical")
    target_n = before_by_id[target_key_id]["n"]
    if target_n in before["reference"]:
        raise ValueError("before fixture already contains an observable target companion")
    if target_n not in after["reference"]:
        raise ValueError("after fixture must add an observable target companion modulus")
    return target_n


def run_coverage_experiment(before_directory, after_directory, target_key_id, output_directory):
    """Check an unchanged target before/after expanding the observed dataset."""
    names = ("coverage_results.csv", "coverage_metadata.json")
    output = _check_output(output_directory, names)
    before, after = _load_dataset(before_directory), _load_dataset(after_directory)
    target_n = _coverage_inputs(before, after, target_key_id)
    run_id, rows = _new_run_id(), []
    for stage, dataset in (("before", before), ("after", after)):
        for algorithm, outcome in _run_both(dataset).items():
            row = _base_row(run_id, dataset, algorithm, outcome)
            result = outcome["result"]
            finding = result.get("findings", {}).get(target_n) if isinstance(result, dict) else None
            factored = isinstance(finding, dict) and finding.get("status") == "factored"
            attempted = target_key_id in outcome["messages"]
            truth = dataset["case"]["private_truth"][target_key_id]
            checked = attempted and "expected_message" in truth
            row.update({"target_key_id": target_key_id, "stage": stage,
                        "companion_present": target_n in dataset["reference"],
                        "target_status": finding.get("status") if isinstance(finding, dict) else None,
                        "target_factors_verified": (finding["p"], finding["q"])
                            == tuple(sorted((truth["p"], truth["q"]))) if factored else None,
                        "target_decryption_attempted": attempted if outcome["error"] is None else None,
                        "target_decryption_checked": checked if outcome["error"] is None else None,
                        "target_decryption_verified": outcome["messages"][target_key_id]
                            == truth["expected_message"] if checked else None})
            rows.append(row)
    summary = {"run_id": run_id, "all_runs_ok": all(row["run_status"] == "success" for row in rows),
               "target_key_id": target_key_id, "rows_written": len(rows), "checks": rows}
    metadata = _metadata(run_id, "coverage", [before, after])
    metadata["target_key_id"] = target_key_id
    metadata["before_records_unchanged_in_after"] = True
    metadata["summary"] = {field: value for field, value in summary.items() if field != "checks"}
    _write_results(output, *names, rows, COVERAGE_FIELDS, metadata)
    return summary
