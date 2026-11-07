"""Repeat independent GCD, Fermat, and combined scans of one saved fixture.

No key generation or plotting occurs here. Private truth is used only to check
completed scans and to export explicitly labelled evaluator-only gap results.
"""

from copy import deepcopy
from datetime import datetime
from datetime import timezone
import hashlib
import json
import math
from pathlib import Path
from statistics import median
import uuid

from rsa_auditor import audit_pipeline
from rsa_auditor.constants import SCAN_COUNTERS
from rsa_auditor.datasets.storage import dataset_paths
from rsa_auditor.datasets.storage import load_dataset
from rsa_auditor.evaluation import build_reference
from rsa_auditor.evaluation import evaluate_audit
from rsa_auditor.evaluation import expected_moduli
from rsa_auditor.evaluation import MODES
from rsa_auditor.experiments.common import _code_metadata
from rsa_auditor.experiments.common import _csv_text
from rsa_auditor.key_recovery import recover_messages

OUTPUT_NAMES = ("mode_comparison.csv", "fermat_gap_budget.csv", "summary.json",
                "run_metadata.json")
TIMING_FIELDS = ("scan_seconds", "preprocessing_seconds", "gcd_scan_seconds",
                 "fermat_scan_seconds")
FERMAT_COUNTERS = ("fermat_candidate_tests", "fermat_attempted_moduli",
                   "fermat_exhausted_moduli")
EVALUATION_FIELDS = (
    "expected_recovered_unique_moduli",
    "recovered_unique_moduli",
    "recovered_records",
    "recovered_via_gcd_moduli",
    "recovered_via_fermat_moduli",
    "false_positive_moduli",
    "false_negative_moduli",
    "factors_verified",
    "agrees_with_reference",
    "decryption_cases_attempted",
    "decryption_cases_checked",
    "decryption_cases_passed",
    "decryption_cases_unchecked",
    "all_decryptions_verified",
)
COMPARISON_FIELDS = (
    "run_id",
    "dataset_id",
    "dataset_sha256",
    "trial_index",
    "mode_order",
    "mode",
    "gcd_backend",
    "fermat_budget",
    "modulus_bits",
    "num_records",
    "num_unique_moduli",
    "duplicate_extra_records",
    *EVALUATION_FIELDS,
    *TIMING_FIELDS,
    *SCAN_COUNTERS,
    *FERMAT_COUNTERS,
    "overlap_unique_moduli",
    "additional_combined_beyond_gcd",
    "standalone_union_unique_moduli",
    "combined_union_agreement",
    "run_status",
    "error",
)
GAP_FIELDS = (
    "run_id",
    "dataset_id",
    "dataset_sha256",
    "trial_index",
    "mode",
    "gcd_backend",
    "fermat_budget",
    "modulus_hex",
    "modulus_bits",
    "record_ids_json",
    "actual_gap_hex",
    "required_fermat_candidates",
    "expected_gcd_recovery",
    "expected_fermat_recovery",
    "status",
    "resolution_method",
    "gcd_status",
    "fermat_status",
    "fermat_candidate_tests",
    "fermat_scan_seconds",
    "run_status",
    "error",
)


def _positive_integer(value, label):
    if type(value) is not int or value < 1:
        raise ValueError("{} must be a positive integer".format(label))


def _finite_seconds(value, label):
    if isinstance(value, bool) or not isinstance(
            value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("{} must be finite nonnegative seconds".format(label))
    return value


def _gap_rows(base, reference, report):
    """Add evaluator-only gaps without changing the attack's public inputs."""
    findings = {}
    if isinstance(report, dict):
        findings = report.get("findings", {})
    if not isinstance(findings, dict):
        findings = {}
    rows = []
    for n, (p, q) in reference["factors"].items():
        finding = findings.get(n, {})
        if not isinstance(finding, dict):
            finding = {}
        per_modulus_seconds = finding.get("fermat_scan_seconds")
        if per_modulus_seconds is not None:
            try:
                per_modulus_seconds = _finite_seconds(
                    per_modulus_seconds, "per-modulus Fermat time")
            except ValueError:
                per_modulus_seconds = None
        row = {}
        for name in ("run_id", "dataset_id", "dataset_sha256", "trial_index",
                     "mode", "gcd_backend", "fermat_budget", "run_status",
                     "error"):
            row[name] = base[name]
        public_records = reference["normalized"]["records_by_modulus"][n]
        record_ids = [record["key_id"] for record in public_records]
        row.update({
            "modulus_hex": hex(n),
            "modulus_bits": n.bit_length(),
            "record_ids_json": json.dumps(record_ids),
            "actual_gap_hex": hex(q - p),
            "required_fermat_candidates": reference["fermat_candidates"][n],
            "expected_gcd_recovery": n in reference["gcd_moduli"],
            "expected_fermat_recovery": reference["fermat_candidates"][n] <=
                                        base["fermat_budget"],
        })
        for name in ("status", "resolution_method", "gcd_status",
                     "fermat_status", "fermat_candidate_tests"):
            row[name] = finding.get(name)
        row["fermat_scan_seconds"] = per_modulus_seconds
        rows.append(row)
    return rows


def run_mode_comparison(dataset_directory,
                        output_directory,
                        budgets=(16, 256),
                        trials=3,
                        gcd_backend="batch",
                        private_directory=None):
    """Measure fresh three-mode scans at each budget on the same saved bytes.

    Budget is per unique modulus, not a global allowance. Repeated trials rotate
    mode order. Scan times come from the auditor and exclude all evaluator
    truth, fixture I/O, normalization, per-record mapping, recovery/OAEP, and
    reporting.
    """
    _positive_integer(trials, "trials")
    budgets = list(budgets)
    if not budgets or len(set(budgets)) != len(budgets):
        raise ValueError("budgets must be nonempty without duplicates")
    for budget in budgets:
        if type(budget) is not int or budget < 0:
            raise ValueError("budget must be a nonnegative integer")
    if gcd_backend not in ("pairwise", "batch"):
        raise ValueError("gcd_backend must be pairwise or batch")
    output = Path(output_directory)
    for name in OUTPUT_NAMES:
        path = output / name
        if path.exists() or path.is_symlink():
            raise FileExistsError(
                "comparison output files already exist; use a new directory")
    case = load_dataset(dataset_directory, private_directory=private_directory)
    reference = build_reference(case)
    public_path, truth_path, manifest_path = dataset_paths(
        dataset_directory, private_directory)
    dataset_sha256 = hashlib.sha256(public_path.read_bytes()).hexdigest()
    source_metadata = _code_metadata()
    normalized = reference["normalized"]
    run_id = datetime.now(
        timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8]
    rows = []
    gap_rows = []
    comparisons = []
    bit_lengths = sorted({n.bit_length() for n in reference["factors"]})
    common = {
        "run_id": run_id,
        "dataset_id": Path(dataset_directory).name,
        "dataset_sha256": dataset_sha256,
        "gcd_backend": gcd_backend,
        "modulus_bits": ";".join(map(str, bit_lengths)),
    }
    for name in ("num_records", "num_unique_moduli", "duplicate_extra_records"):
        common[name] = normalized[name]
    for budget_index, budget in enumerate(budgets):
        for trial in range(trials):
            offset = (budget_index + trial) % len(MODES)
            order = MODES[offset:] + MODES[:offset]
            outcomes = {}
            for mode in order:
                expected_recoveries = expected_moduli(reference, mode, budget)
                row = {
                    **common,
                    "trial_index": trial,
                    "mode_order": ";".join(order),
                    "mode": mode,
                    "fermat_budget": budget,
                    "expected_recovered_unique_moduli":
                        len(expected_recoveries),
                    "run_status": "error",
                    "error": "",
                }
                report = None
                recovered = None
                try:
                    # Attacks receive fresh public records and configuration.
                    records = deepcopy(case["public_keys"])
                    report = audit_pipeline.run_audit(records,
                                                      mode=mode,
                                                      gcd_backend=gcd_backend,
                                                      fermat_budget=budget)
                    if (report["mode"], report["gcd_backend"],
                            report["fermat_budget"]) != (mode, gcd_backend,
                                                         budget):
                        raise ValueError(
                            "auditor returned a different mode/backend/budget")
                    messages = recover_messages(records, report)
                    evaluation = evaluate_audit(case,
                                                report,
                                                messages,
                                                reference=reference)
                    for name in EVALUATION_FIELDS:
                        row[name] = evaluation[name]
                    metrics = {
                        name: _finite_seconds(report[name], name)
                        for name in TIMING_FIELDS
                    }
                    # The independent evaluator has already checked counters.
                    for name in (*SCAN_COUNTERS, *FERMAT_COUNTERS):
                        metrics[name] = report[name]
                    row.update(metrics)
                    recovered = {
                        n for n, finding in report["findings"].items()
                        if finding["status"] == "factored"
                    }
                    if evaluation["success"]:
                        row["run_status"] = "success"
                    else:
                        row["run_status"] = "mismatch"
                except Exception as error:
                    row["error"] = "{}: {}".format(type(error).__name__, error)
                outcomes[mode] = {
                    "row": row,
                    "report": report,
                    "recovered": recovered,
                }
            complete = all(
                outcomes[mode]["recovered"] is not None for mode in MODES)
            comparison = {
                "fermat_budget": budget,
                "trial_index": trial,
                "overlap_unique_moduli": None,
                "additional_combined_beyond_gcd": None,
                "standalone_union_unique_moduli": None,
                "combined_union_agreement": None,
            }
            if complete:
                gcd_set = outcomes["gcd"]["recovered"]
                fermat_set = outcomes["fermat"]["recovered"]
                combined_set = outcomes["combined"]["recovered"]
                comparison.update({
                    "overlap_unique_moduli": len(gcd_set & fermat_set),
                    "additional_combined_beyond_gcd": len(combined_set -
                                                          gcd_set),
                    "standalone_union_unique_moduli": len(gcd_set | fermat_set),
                    "combined_union_agreement": combined_set ==
                                                gcd_set | fermat_set,
                })
            for mode in order:
                row = outcomes[mode]["row"]
                for key, value in comparison.items():
                    if key not in ("fermat_budget", "trial_index"):
                        row[key] = value
                if row["run_status"] == "success" and not complete:
                    row["run_status"] = "comparison_incomplete"
                elif row["run_status"] == "success" and not comparison[
                        "combined_union_agreement"]:
                    row["run_status"] = "mismatch"
                    row["error"] = (
                        "combined recovery differs from the standalone "
                        "union")
                rows.append(row)
                gap_rows.extend(
                    _gap_rows(row, reference, outcomes[mode]["report"]))
            comparisons.append(comparison)
    statistics = []
    for budget in budgets:
        for mode in MODES:
            accepted = []
            for row in rows:
                if (row["fermat_budget"] == budget and row["mode"] == mode and
                        row["run_status"] == "success"):
                    accepted.append(row)
            stat = {
                "mode": mode,
                "fermat_budget": budget,
                "trials_requested": trials,
                "trials_completed": len(accepted),
            }
            for field in ("scan_seconds", "fermat_candidate_tests",
                          "fermat_exhausted_moduli", "recovered_unique_moduli",
                          "decryption_cases_passed", "gcd_calls"):
                values = [row[field] for row in accepted]
                for suffix, operation in (("median", median), ("min", min),
                                          ("max", max)):
                    statistic_name = field + "_" + suffix
                    stat[statistic_name] = None
                    if values:
                        stat[statistic_name] = operation(values)
            statistics.append(stat)
    summary = {
        "run_id": run_id,
        "dataset_sha256": dataset_sha256,
        "gcd_backend": gcd_backend,
        "budgets": budgets,
        "trials_requested": trials,
        "timing_rows": len(rows),
        "gap_budget_rows": len(gap_rows),
        "all_runs_ok": all(row["run_status"] == "success" for row in rows),
        "statistics": statistics,
        "comparisons": comparisons,
    }
    manifest_sha256 = None
    if manifest_path.is_file():
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    metadata = {
        "format": "weak-rsa-three-mode-comparison",
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        **source_metadata,
        "dataset_directory": str(Path(dataset_directory).resolve()),
        "public_sha256": dataset_sha256,
        "private_truth_sha256": hashlib.sha256(truth_path.read_bytes()
                                              ).hexdigest(),
        "manifest_sha256": manifest_sha256,
        "modulus_bit_lengths": bit_lengths,
        "gcd_backend": gcd_backend,
        "budgets": budgets,
        "trials": trials,
        "warmups": 0,
        "mode_order":
            ("rotate gcd/fermat/combined by budget index plus trial index"),
        "fresh_state":
            "new public-record copy and independent auditor call for every "
            "mode/budget/trial; no recovered-factor cache",
        "timing_clock": "auditor perf_counter_ns",
        "timing_boundary":
            "complete selected scan work including GCD trees/fallback, "
            "Fermat calls and common factor validation",
        "per_modulus_fermat_timing_boundary":
            "individual Fermat adapter call; common factor validation is "
            "included in aggregate scan time",
        "excluded_from_timing": [
            "generation", "fixture I/O", "normalization", "record mapping",
            "private truth/reference construction", "recovery/OAEP",
            "evaluation", "reporting", "plotting"
        ],
        "reference":
            "distinct-modulus prime ownership for GCD; exact (p+q)/2 minus "
            "ceil(sqrt(n)) plus one for Fermat",
        "gap_budget_csv":
            "evaluator-only private gaps; budget-exhausted rows are failures "
            "to recover within budget, not factorisations at the cap",
        "memory_measurement": "not measured by this comparison runner",
    }
    contents = (_csv_text(rows,
                          COMPARISON_FIELDS), _csv_text(gap_rows, GAP_FIELDS),
                json.dumps(summary, indent=2, allow_nan=False) + "\n",
                json.dumps(metadata, indent=2, allow_nan=False) + "\n")
    output.mkdir(parents=True, exist_ok=True)
    for name, content in zip(OUTPUT_NAMES, contents):
        with (output / name).open("x", encoding="utf-8",
                                  newline="") as destination:
            destination.write(content)
    return summary
