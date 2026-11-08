"""Shared-prime correctness, OAEP checks, and observation coverage."""

from pathlib import Path

from rsa_auditor.attacks.pairwise_gcd import euclidean_gcd
from rsa_auditor.audit_pipeline import run_audit
from rsa_auditor.constants import COMPLETE_ALGORITHMS as ALGORITHMS
from rsa_auditor.constants import SCAN_COUNTERS as COUNTERS
from rsa_auditor.evaluation import evaluate_audit
from rsa_auditor.experiments.common import _check_output
from rsa_auditor.experiments.common import _load_dataset
from rsa_auditor.experiments.common import _metadata
from rsa_auditor.experiments.common import _new_run_id
from rsa_auditor.experiments.common import _write_results
from rsa_auditor.key_recovery import recover_messages

CORRECTNESS_FIELDS = (
    "run_id",
    "dataset_id",
    "algorithm",
    "num_records",
    "num_unique_moduli",
    "duplicate_extra_records",
    "expected_observable_factored_moduli",
    "recovered_unique_moduli",
    "recovered_records",
    "false_positive_moduli",
    "false_negative_moduli",
    "factor_products_verified",
    "full_gcd_before_fallback",
    "unresolved_after_fallback",
    "decryption_cases_checked",
    "decryption_cases_passed",
    "decryption_cases_attempted",
    "gcd_calls",
    "pairwise_gcd_calls",
    "batch_leaf_gcd_calls",
    "fallback_gcd_calls",
    "agrees_with_reference",
    "algorithms_agree",
    "scan_seconds",
    "measurement_kind",
    "dataset_sha256",
    "run_status",
    "error",
)

COVERAGE_FIELDS = (
    "run_id",
    "dataset_id",
    "algorithm",
    "target_key_id",
    "companion_present",
    "num_unique_moduli",
    "target_status",
    "target_factors_verified",
    "target_decryption_checked",
    "target_decryption_verified",
    "target_decryption_attempted",
    "stage",
    "num_records",
    "duplicate_extra_records",
    "gcd_calls",
    "pairwise_gcd_calls",
    "batch_leaf_gcd_calls",
    "fallback_gcd_calls",
    "full_gcd_before_fallback",
    "unresolved_after_fallback",
    "agrees_with_reference",
    "algorithms_agree",
    "scan_seconds",
    "measurement_kind",
    "dataset_sha256",
    "run_status",
    "error",
)


def _run_both(dataset):
    """Run and evaluate both GCD algorithms with separate call counters."""
    outcomes = {}
    for algorithm in ALGORITHMS:
        actual_calls = 0

        def counted_gcd(a, b):
            nonlocal actual_calls
            actual_calls += 1
            return euclidean_gcd(a, b)

        outcome = {
            "result": None,
            "factor_map": None,
            "evaluation": None,
            "messages": {},
            "error": None,
            "reference_ok": None,
        }
        try:
            case = dataset["case"]
            backend = "pairwise" if algorithm == "pairwise" else "batch"
            result = run_audit(case["public_keys"],
                               mode="gcd",
                               gcd_backend=backend,
                               gcd_fn=counted_gcd)
            outcome["result"] = result
            if result["gcd_calls"] != actual_calls:
                raise ValueError(
                    "GCD counter disagrees with actual backend calls")
            factors = {
                n: (finding["p"], finding["q"])
                for n, finding in result["findings"].items()
                if finding["status"] == "factored"
            }
            outcome["factor_map"] = factors
            outcome["reference_ok"] = factors == dataset["reference"]
            messages = recover_messages(case["public_keys"], result)
            outcome["messages"] = messages
            outcome["evaluation"] = evaluate_audit(case, result, messages)
        except Exception as error:
            outcome["error"] = "{}: {}".format(type(error).__name__, error)
        outcomes[algorithm] = outcome
    complete = all(outcome["error"] is None for outcome in outcomes.values())
    agree = None
    if complete:
        first_factors = outcomes[ALGORITHMS[0]]["factor_map"]
        second_factors = outcomes[ALGORITHMS[1]]["factor_map"]
        agree = first_factors == second_factors
    for outcome in outcomes.values():
        outcome["algorithms_agree"] = agree
        if outcome["error"]:
            outcome["run_status"] = "error"
        elif not complete:
            outcome["run_status"] = "comparison_incomplete"
        elif outcome["reference_ok"] and agree and outcome["evaluation"][
                "success"]:
            outcome["run_status"] = "success"
        else:
            outcome["run_status"] = "mismatch"
    return outcomes


def _base_row(run_id, dataset, algorithm, outcome):
    result = outcome["result"]
    if not isinstance(result, dict):
        result = None
    row = {
        "run_id": run_id,
        "dataset_id": dataset["dataset_id"],
        "algorithm": algorithm,
    }
    for field in ("num_records", "num_unique_moduli",
                  "duplicate_extra_records"):
        row[field] = dataset["normalized"][field]
    for field in COUNTERS:
        row[field] = None
        if result is not None:
            row[field] = result.get(field)
    scan_seconds = None
    if result is not None:
        scan_seconds = result.get("scan_seconds")
    row.update({
        "agrees_with_reference": outcome["reference_ok"],
        "algorithms_agree": outcome["algorithms_agree"],
        "scan_seconds": scan_seconds,
        "measurement_kind": "single correctness check; not a benchmark",
        "dataset_sha256": dataset["dataset_sha256"],
        "run_status": outcome["run_status"],
        "error": outcome["error"],
    })
    return row


def run_shared_prime_correctness(dataset_directories, output_directory):
    """Check both algorithms against private truth and each other.

    Only recovered ciphertexts are decrypted; zero checked cases means no
    plaintext comparison was performed.
    """
    names = ("shared_prime_correctness.csv", "correctness_metadata.json")
    output = _check_output(output_directory, names)
    directories = list(dataset_directories)
    if not directories or len({str(Path(p).resolve()) for p in directories
                              }) != len(directories):
        raise ValueError(
            "provide at least one fixture directory without duplicates")
    datasets = [_load_dataset(directory) for directory in directories]
    if len({d["dataset_id"] for d in datasets}) != len(datasets):
        raise ValueError("dataset directory names must be unique")
    run_id = _new_run_id()
    rows = []
    for dataset in datasets:
        for algorithm, outcome in _run_both(dataset).items():
            row = _base_row(run_id, dataset, algorithm, outcome)
            evaluation = outcome["evaluation"]
            factors = outcome["factor_map"]
            recovered_count = None
            if factors is not None:
                recovered_count = len(factors)
            recovered_records = None
            if isinstance(outcome["result"], dict):
                record_list = outcome["result"].get("recovered_records")
                if isinstance(record_list, list):
                    recovered_records = len(record_list)
            factors_verified = None
            if evaluation is not None:
                factors_verified = evaluation["factors_verified"]
            row.update({
                "expected_observable_factored_moduli": len(dataset["reference"]
                                                          ),
                "recovered_unique_moduli": recovered_count,
                "recovered_records": recovered_records,
                "factor_products_verified": factors_verified,
            })
            for field in ("false_positive_moduli", "false_negative_moduli",
                          "decryption_cases_checked", "decryption_cases_passed",
                          "decryption_cases_attempted"):
                row[field] = None
                if evaluation is not None:
                    row[field] = evaluation[field]
            rows.append(row)
    summary = {
        "run_id": run_id,
        "all_runs_ok": all(row["run_status"] == "success" for row in rows),
        "num_datasets": len(datasets),
        "rows_written": len(rows),
        "checks": rows,
    }
    metadata = _metadata(run_id, "correctness", datasets)
    metadata["scan_timing_boundary"] = (
        "run_audit selected GCD work and common factor validation; "
        "normalization, mapping, recovery/OAEP and evaluation excluded")
    metadata["summary"] = {
        field: value for field, value in summary.items() if field != "checks"
    }
    _write_results(output, *names, rows, CORRECTNESS_FIELDS, metadata)
    return summary


def _coverage_inputs(before, after, target_key_id):
    if not isinstance(target_key_id, str) or not target_key_id.strip():
        raise ValueError("target_key_id must be a nonblank string")
    before_by_id = {
        record["key_id"]: record for record in before["case"]["public_keys"]
    }
    after_by_id = {
        record["key_id"]: record for record in after["case"]["public_keys"]
    }
    if target_key_id not in before_by_id or target_key_id not in after_by_id:
        raise ValueError(
            "target must be present before and after adding a companion")
    if any(
            after_by_id.get(key_id) != record
            for key_id, record in before_by_id.items()):
        raise ValueError(
            "every before public record, including target n/e/ciphertext, "
            "must remain identical")
    target_n = before_by_id[target_key_id]["n"]
    if target_n in before["reference"]:
        raise ValueError(
            "before fixture already contains an observable target companion")
    if target_n not in after["reference"]:
        raise ValueError(
            "after fixture must add an observable target companion modulus")
    return target_n


def run_coverage_experiment(before_directory, after_directory, target_key_id,
                            output_directory):
    """Check an unchanged target before/after expanding the observed dataset."""
    names = ("coverage_results.csv", "coverage_metadata.json")
    output = _check_output(output_directory, names)
    before = _load_dataset(before_directory)
    after = _load_dataset(after_directory)
    target_n = _coverage_inputs(before, after, target_key_id)
    run_id = _new_run_id()
    rows = []
    for stage, dataset in (("before", before), ("after", after)):
        for algorithm, outcome in _run_both(dataset).items():
            row = _base_row(run_id, dataset, algorithm, outcome)
            result = outcome["result"]
            finding = None
            if isinstance(result, dict):
                finding = result.get("findings", {}).get(target_n)
            factored = isinstance(finding,
                                  dict) and finding.get("status") == "factored"
            attempted = target_key_id in outcome["messages"]
            truth = dataset["case"]["private_truth"][target_key_id]
            checked = attempted and "expected_message" in truth
            target_status = None
            if isinstance(finding, dict):
                target_status = finding.get("status")
            factors_verified = None
            if factored:
                recovered_factors = (finding["p"], finding["q"])
                expected_factors = tuple(sorted((truth["p"], truth["q"])))
                factors_verified = recovered_factors == expected_factors
            decryption_verified = None
            if checked:
                message = outcome["messages"][target_key_id]
                decryption_verified = message == truth["expected_message"]
            row.update({
                "target_key_id": target_key_id,
                "stage": stage,
                "companion_present": target_n in dataset["reference"],
                "target_status": target_status,
                "target_factors_verified": factors_verified,
                "target_decryption_attempted": None,
                "target_decryption_checked": None,
                "target_decryption_verified": decryption_verified,
            })
            if outcome["error"] is None:
                row["target_decryption_attempted"] = attempted
                row["target_decryption_checked"] = checked
            rows.append(row)
    summary = {
        "run_id": run_id,
        "all_runs_ok": all(row["run_status"] == "success" for row in rows),
        "target_key_id": target_key_id,
        "rows_written": len(rows),
        "checks": rows,
    }
    metadata = _metadata(run_id, "coverage", [before, after])
    metadata["scan_timing_boundary"] = (
        "run_audit selected GCD work and common factor validation; "
        "normalization, mapping, recovery/OAEP and evaluation excluded")
    metadata["target_key_id"] = target_key_id
    metadata["before_records_unchanged_in_after"] = True
    metadata["summary"] = {
        field: value for field, value in summary.items() if field != "checks"
    }
    _write_results(output, *names, rows, COVERAGE_FIELDS, metadata)
    return summary
