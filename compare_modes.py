"""Repeat independent GCD, Fermat, and combined scans of one saved fixture.

No key generation or plotting occurs here. Private truth is used only to check
completed scans and to export explicitly labelled evaluator-only gap results.
"""

import argparse
from copy import deepcopy
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path
import platform
from statistics import median
import subprocess
import uuid

import Crypto

import audit_pipeline
from build_dataset import dataset_paths, load_dataset
from contracts import SCAN_COUNTERS
from evaluation import MODES, build_reference, evaluate_audit, expected_moduli


OUTPUT_NAMES = ("mode_comparison.csv", "fermat_gap_budget.csv", "summary.json", "run_metadata.json")
TIMING_FIELDS = ("scan_seconds", "preprocessing_seconds", "gcd_scan_seconds", "fermat_scan_seconds")
FERMAT_COUNTERS = ("fermat_candidate_tests", "fermat_attempted_moduli", "fermat_exhausted_moduli")
EVALUATION_FIELDS = (
    "expected_recovered_unique_moduli", "recovered_unique_moduli", "recovered_records",
    "recovered_via_gcd_moduli", "recovered_via_fermat_moduli", "false_positive_moduli",
    "false_negative_moduli", "factors_verified", "agrees_with_reference",
    "decryption_cases_attempted", "decryption_cases_checked", "decryption_cases_passed",
    "decryption_cases_unchecked", "all_decryptions_verified",
)
COMPARISON_FIELDS = (
    "run_id", "dataset_id", "dataset_sha256", "trial_index", "mode_order", "mode",
    "gcd_backend", "fermat_budget", "modulus_bits", "num_records", "num_unique_moduli",
    "duplicate_extra_records", *EVALUATION_FIELDS, *TIMING_FIELDS, *SCAN_COUNTERS,
    *FERMAT_COUNTERS, "overlap_unique_moduli", "additional_combined_beyond_gcd",
    "standalone_union_unique_moduli", "combined_union_agreement", "run_status", "error",
)
GAP_FIELDS = (
    "run_id", "dataset_id", "dataset_sha256", "trial_index", "mode", "gcd_backend",
    "fermat_budget", "modulus_hex", "modulus_bits", "record_ids_json", "actual_gap_hex",
    "required_fermat_candidates", "expected_gcd_recovery", "expected_fermat_recovery",
    "status", "resolution_method", "gcd_status", "fermat_status",
    "fermat_candidate_tests", "fermat_scan_seconds", "run_status", "error",
)


def _positive_integer(value, label):
    if type(value) is not int or value < 1:
        raise ValueError("{} must be a positive integer".format(label))


def _finite_seconds(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("{} must be finite nonnegative seconds".format(label))
    return value


def _csv_text(rows, fields):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def _source_metadata():
    root = Path(__file__).resolve().parent
    names = ("compare_modes.py", "evaluation.py", "audit_pipeline.py", "fermat_attack.py", "fermat_adapter.py",
             "shared_prime_attack.py", "batch_gcd_attack.py", "normalization.py",
             "key_recovery.py", "contracts.py", "build_dataset.py", "dataset_io.py",
             "generators/shared_prime_cases.py", "generators/close_prime_cases.py", "generators/control_cases.py")
    revision, dirty = None, None
    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True,
                                           stderr=subprocess.DEVNULL).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True))
    except (OSError, subprocess.CalledProcessError):
        pass
    return {
        "python_version": platform.python_version(), "platform": platform.platform(),
        "pycryptodome_version": Crypto.__version__, "git": {"revision": revision, "dirty": dirty},
        "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                          for name in names if (root / name).is_file()},
    }


def _report_metrics(report):
    """Collect finite measurements after the independent evaluator has passed."""
    result = {name: _finite_seconds(report[name], name) for name in TIMING_FIELDS}
    for name in (*SCAN_COUNTERS, *FERMAT_COUNTERS):
        value = report[name]
        if type(value) is not int or value < 0:
            raise ValueError("{} must be a nonnegative integer".format(name))
        result[name] = value
    return result


def _gap_rows(base, reference, report):
    findings = report.get("findings", {}) if isinstance(report, dict) else {}
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
                per_modulus_seconds = _finite_seconds(per_modulus_seconds, "per-modulus Fermat time")
            except ValueError:
                per_modulus_seconds = None
        rows.append({
            **{name: base[name] for name in ("run_id", "dataset_id", "dataset_sha256", "trial_index",
                                           "mode", "gcd_backend", "fermat_budget", "run_status", "error")},
            "modulus_hex": hex(n), "modulus_bits": n.bit_length(),
            "record_ids_json": json.dumps([record["key_id"] for record in
                                           reference["normalized"]["records_by_modulus"][n]]),
            "actual_gap_hex": hex(q - p),
            "required_fermat_candidates": reference["fermat_candidates"][n],
            "expected_gcd_recovery": n in reference["gcd_moduli"],
            "expected_fermat_recovery": reference["fermat_candidates"][n] <= base["fermat_budget"],
            **{name: finding.get(name) for name in ("status", "resolution_method", "gcd_status",
                                                   "fermat_status", "fermat_candidate_tests")},
            "fermat_scan_seconds": per_modulus_seconds,
        })
    return rows


def run_mode_comparison(dataset_directory, output_directory, budgets=(16, 256), trials=3,
                        gcd_backend="batch", private_directory=None):
    """Measure fresh three-mode scans at each budget on the same saved bytes.

    Budget is per unique modulus, not a global allowance. Repeated trials rotate
    mode order. Scan times come from the auditor and exclude all evaluator truth,
    fixture I/O, normalization, per-record mapping, recovery/OAEP, and reporting.
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
    if any((output / name).exists() or (output / name).is_symlink() for name in OUTPUT_NAMES):
        raise FileExistsError("comparison output files already exist; use a new directory")
    case = load_dataset(dataset_directory, private_directory=private_directory)
    reference = build_reference(case)
    public_path, truth_path, manifest_path = dataset_paths(dataset_directory, private_directory)
    dataset_sha256 = hashlib.sha256(public_path.read_bytes()).hexdigest()
    source_metadata = _source_metadata()
    normalized = reference["normalized"]
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8]
    rows, gap_rows, comparisons = [], [], []
    common = {"run_id": run_id, "dataset_id": Path(dataset_directory).name,
              "dataset_sha256": dataset_sha256, "gcd_backend": gcd_backend,
              "modulus_bits": ";".join(map(str, sorted({n.bit_length() for n in reference["factors"]}))),
              **{name: normalized[name] for name in ("num_records", "num_unique_moduli", "duplicate_extra_records")}}
    for budget_index, budget in enumerate(budgets):
        for trial in range(trials):
            offset = (budget_index + trial) % len(MODES)
            order = MODES[offset:] + MODES[:offset]
            outcomes = {}
            for mode in order:
                row = {**common, "trial_index": trial, "mode_order": ";".join(order),
                       "mode": mode, "fermat_budget": budget,
                       "expected_recovered_unique_moduli": len(expected_moduli(reference, mode, budget)),
                       "run_status": "error", "error": ""}
                report, recovered = None, None
                try:
                    # The only attack inputs are fresh copies of public records and configuration.
                    records = deepcopy(case["public_keys"])
                    report = audit_pipeline.run_audit(records, mode=mode, gcd_backend=gcd_backend,
                                                       fermat_budget=budget)
                    if (report["mode"], report["gcd_backend"], report["fermat_budget"]) != (mode, gcd_backend, budget):
                        raise ValueError("auditor returned a different mode/backend/budget")
                    messages = audit_pipeline.recover_messages(records, report)
                    evaluation = evaluate_audit(case, report, messages, reference=reference)
                    row.update({name: evaluation[name] for name in EVALUATION_FIELDS})
                    row.update(_report_metrics(report))
                    recovered = {n for n, finding in report["findings"].items() if finding["status"] == "factored"}
                    row["run_status"] = "success" if evaluation["success"] else "mismatch"
                except Exception as error:
                    row["error"] = "{}: {}".format(type(error).__name__, error)
                outcomes[mode] = {"row": row, "report": report, "recovered": recovered}
            complete = all(outcomes[mode]["recovered"] is not None for mode in MODES)
            comparison = {"fermat_budget": budget, "trial_index": trial,
                          "overlap_unique_moduli": None, "additional_combined_beyond_gcd": None,
                          "standalone_union_unique_moduli": None, "combined_union_agreement": None}
            if complete:
                gcd_set, fermat_set, combined_set = (outcomes[mode]["recovered"] for mode in MODES)
                comparison.update({
                    "overlap_unique_moduli": len(gcd_set & fermat_set),
                    "additional_combined_beyond_gcd": len(combined_set - gcd_set),
                    "standalone_union_unique_moduli": len(gcd_set | fermat_set),
                    "combined_union_agreement": combined_set == gcd_set | fermat_set,
                })
            for mode in order:
                row = outcomes[mode]["row"]
                row.update({key: value for key, value in comparison.items() if key not in ("fermat_budget", "trial_index")})
                if row["run_status"] == "success" and not complete:
                    row["run_status"] = "comparison_incomplete"
                elif row["run_status"] == "success" and not comparison["combined_union_agreement"]:
                    row["run_status"] = "mismatch"
                    row["error"] = "combined recovery differs from the standalone union"
                rows.append(row)
                gap_rows.extend(_gap_rows(row, reference, outcomes[mode]["report"]))
            comparisons.append(comparison)
    statistics = []
    for budget in budgets:
        for mode in MODES:
            accepted = [row for row in rows if row["fermat_budget"] == budget and row["mode"] == mode
                        and row["run_status"] == "success"]
            stat = {"mode": mode, "fermat_budget": budget, "trials_requested": trials,
                    "trials_completed": len(accepted)}
            for field in ("scan_seconds", "fermat_candidate_tests", "fermat_exhausted_moduli",
                          "recovered_unique_moduli", "decryption_cases_passed", "gcd_calls"):
                values = [row[field] for row in accepted]
                for suffix, operation in (("median", median), ("min", min), ("max", max)):
                    stat[field + "_" + suffix] = operation(values) if values else None
            statistics.append(stat)
    summary = {"run_id": run_id, "dataset_sha256": dataset_sha256, "gcd_backend": gcd_backend,
               "budgets": budgets, "trials_requested": trials, "timing_rows": len(rows),
               "gap_budget_rows": len(gap_rows), "all_runs_ok": all(row["run_status"] == "success" for row in rows),
               "statistics": statistics, "comparisons": comparisons}
    metadata = {
        "format": "weak-rsa-three-mode-comparison", "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(), **source_metadata,
        "dataset_directory": str(Path(dataset_directory).resolve()),
        "public_sha256": dataset_sha256, "private_truth_sha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.is_file() else None,
        "modulus_bit_lengths": sorted({n.bit_length() for n in reference["factors"]}),
        "gcd_backend": gcd_backend, "budgets": budgets, "trials": trials, "warmups": 0,
        "mode_order": "rotate gcd/fermat/combined by budget index plus trial index",
        "fresh_state": "new public-record copy and independent auditor call for every mode/budget/trial; no recovered-factor cache",
        "timing_clock": "auditor perf_counter_ns",
        "timing_boundary": "complete selected scan work including GCD trees/fallback, Fermat calls and common factor validation",
        "per_modulus_fermat_timing_boundary": "individual Fermat adapter call; common factor validation is included in aggregate scan time",
        "excluded_from_timing": ["generation", "fixture I/O", "normalization", "record mapping",
                                 "private truth/reference construction", "recovery/OAEP", "evaluation", "reporting", "plotting"],
        "reference": "distinct-modulus prime ownership for GCD; exact (p+q)/2 minus ceil(sqrt(n)) plus one for Fermat",
        "gap_budget_csv": "evaluator-only private gaps; budget-exhausted rows are failures to recover within budget, not factorisations at the cap",
        "memory_measurement": "not measured by this comparison runner",
    }
    contents = (_csv_text(rows, COMPARISON_FIELDS), _csv_text(gap_rows, GAP_FIELDS),
                json.dumps(summary, indent=2, allow_nan=False) + "\n",
                json.dumps(metadata, indent=2, allow_nan=False) + "\n")
    output.mkdir(parents=True, exist_ok=True)
    for name, content in zip(OUTPUT_NAMES, contents):
        with (output / name).open("x", encoding="utf-8", newline="") as destination:
            destination.write(content)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="data/public/auditor_demo")
    parser.add_argument("--private-directory")
    parser.add_argument("--output", required=True)
    parser.add_argument("--budgets", nargs="+", type=int, default=[16, 256])
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--gcd-backend", choices=("pairwise", "batch"), default="batch")
    args = parser.parse_args(argv)
    try:
        summary = run_mode_comparison(args.dataset, args.output, args.budgets, args.trials,
                                      args.gcd_backend, args.private_directory)
    except (ValueError, TypeError, OSError, RuntimeError) as error:
        parser.exit(1, "Error: {}\n".format(error))
    print(json.dumps(summary, indent=2))
    return 0 if summary["all_runs_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
