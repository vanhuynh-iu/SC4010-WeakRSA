"""Shared-prime checks, benchmarks and plots for Van.

Krystal leads the shared framework and its Fermat integration. Importing this
module runs no experiments; Matplotlib loads only for plots.
"""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
from statistics import median
import statistics
import subprocess
from time import perf_counter_ns
import tracemalloc
import uuid

import Crypto
from Crypto.Util.number import isPrime

from contracts import COMPLETE_ALGORITHMS as ALGORITHMS, SCAN_COUNTERS as COUNTERS
from normalization import normalize_public_keys
from shared_prime_attack import euclidean_gcd, scan_moduli
from build_dataset import load_dataset, save_dataset
from audit_pipeline import audit_public_keys, evaluate_scan, recover_messages


PROFILE = "disjoint_shared_pairs_20pct_controls_80pct"


SCALABILITY_FIELDS = (
    "run_id", "dataset_id", "trial_index", "algorithm", "gcd_backend", "modulus_bits",
    "num_records", "num_unique_moduli", "duplicate_extra_records", "topology_profile",
    "scan_seconds", *COUNTERS, "recovered_unique_moduli", "agrees_with_reference", "run_status",
    "dataset_sha256", "trial_algorithm_order", "algorithms_agree", "actual_gcd_calls",
    "code_revision", "error", "attempt_seconds",
)


MEMORY_FIELDS = (
    "run_id", "dataset_id", "algorithm", "gcd_backend", "memory_method", "peak_traced_bytes",
    "input_preloaded", "run_status", "num_unique_moduli", "modulus_bits", "dataset_sha256",
    "agrees_with_reference", "topology_profile", "error",
)


OUTPUT_NAMES = ("scalability_results.csv", "memory_results.csv", "summary.json", "run_metadata.json")


def _integer(value, name, minimum):
    if type(value) is not int or value < minimum:
        raise ValueError("{} must be an integer >= {}".format(name, minimum))


def _truth_reference(case, moduli):
    """Infer observability independently using evaluator prime ownership."""
    factors, owners, prime_cache = {}, {}, {}
    for record in case["public_keys"]:
        n = record["n"]
        truth = case["private_truth"][record["key_id"]]
        p, q = sorted((truth["p"], truth["q"]))
        if p == q or p * q != n or p <= 2 or p % 2 == 0 or q % 2 == 0:
            raise ValueError("experiment truth must describe two distinct odd primes")
        for prime in (p, q):
            if prime not in prime_cache:
                prime_cache[prime] = bool(isPrime(prime))
            if not prime_cache[prime]:
                raise ValueError("experiment truth contains a composite factor")
            owners.setdefault(prime, set()).add(n)
        if n in factors and factors[n] != (p, q):
            raise ValueError("duplicate modulus has conflicting private truth")
        factors[n] = (p, q)
    expected = {n: factors[n] for n in moduli
                if any(len(owners[p]) > 1 for p in factors[n])}
    return expected, owners


def _load_dataset(directory):
    directory = Path(directory)
    case = load_dataset(directory)
    normalized = normalize_public_keys(case["public_keys"])
    moduli = tuple(normalized["unique_moduli"])
    reference, owners = _truth_reference(case, moduli)
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    if not isinstance(manifest.get("construction_metadata", {}), dict):
        raise ValueError("construction metadata must be a dictionary")
    bits = sorted({n.bit_length() for n in moduli})
    return {"directory": directory, "case": case, "normalized": normalized,
            "moduli": moduli, "reference": reference, "prime_owners": owners,
            "manifest": manifest, "bits": bits,
            "dataset_id": directory.name,
            "dataset_sha256": hashlib.sha256((directory / "public.json").read_bytes()).hexdigest(),
            "topology_profile": manifest.get("construction_metadata", {}).get("topology_profile", "custom")}


def prepare_scalability_datasets(sizes, dataset_root, modulus_bits=2048):
    """Save/reuse profile-checked fixtures before timing, without overwrites.

    Sizes must be multiples of 10 and >=10: 20% shared-pair moduli, 80% controls.
    """
    _integer(modulus_bits, "modulus_bits", 32)
    sizes = list(sizes)
    if not sizes or len(set(sizes)) != len(sizes):
        raise ValueError("sizes must be a nonempty collection without duplicates")
    for size in sizes:
        _integer(size, "size", 10)
        if size % 10:
            raise ValueError("scalability sizes must be multiples of ten")
    from generators.shared_prime_cases import generate_scalability_dataset
    directories = []
    for size in sizes:
        directory = Path(dataset_root) / "m{}_bits{}".format(size, modulus_bits)
        metadata = {"topology_profile": PROFILE, "num_unique_moduli": size,
                    "modulus_bits": modulus_bits, "e": 65537}
        if not directory.exists():
            case = generate_scalability_dataset(size, modulus_bits=modulus_bits)
            save_dataset(directory, case["public_keys"], case["private_truth"],
                          case["expected_vulnerable_ids"], metadata=metadata)
        loaded = _load_dataset(directory)
        normalized = loaded["normalized"]
        if (
            loaded["manifest"].get("construction_metadata") != metadata
            or normalized["num_unique_moduli"] != size
            or normalized["num_records"] != size
            or loaded["bits"] != [modulus_bits]
            or any(record["e"] != 65537 for record in normalized["public_records"])
            or len(loaded["reference"]) != size // 5
            or any(len(group) > 2 for group in loaded["prime_owners"].values())
            or any(sum(len(loaded["prime_owners"][p]) > 1 for p in pair) != 1
                   for pair in loaded["reference"].values())
        ):
            raise ValueError("saved dataset does not match requested fixed scalability profile")
        directories.append(directory)
    return directories


def _scanner_functions():
    # Import outside scan timing.
    from batch_gcd_attack import scan_moduli_batch
    return {"pairwise": scan_moduli, "batch_with_fallback": scan_moduli_batch}


def _factor_map(result, moduli, algorithm, actual_calls):
    if not isinstance(result, dict) or result.get("algorithm") != algorithm:
        raise ValueError("scanner returned the wrong algorithm/result shape")
    findings = result.get("findings")
    if not isinstance(findings, dict) or set(findings) != set(moduli):
        raise ValueError("scanner must report exactly one finding per unique modulus")
    for field in COUNTERS:
        if type(result.get(field)) is not int or result[field] < 0:
            raise ValueError("invalid scanner counter: " + field)
    if (result["gcd_calls"] != actual_calls
            or result["gcd_calls"] != result["pairwise_gcd_calls"] + result["batch_leaf_gcd_calls"]):
        raise ValueError("scanner counters disagree with actual backend calls")
    if algorithm == "pairwise":
        if (actual_calls != len(moduli) * (len(moduli) - 1) // 2
                or result["batch_leaf_gcd_calls"] or result["fallback_gcd_calls"]):
            raise ValueError("pairwise baseline did not perform the full scan")
    else:
        if result["pairwise_gcd_calls"] != result["fallback_gcd_calls"]:
            raise ValueError("batch pairwise calls must equal fallback calls")
        if result["batch_leaf_gcd_calls"] != (len(moduli) if len(moduli) > 1 else 0):
            raise ValueError("batch must perform one leaf GCD per modulus except empty/singleton shortcuts")
    recovered = {}
    for n, finding in findings.items():
        if not isinstance(finding, dict) or finding.get("n") != n:
            raise ValueError("finding does not match original public modulus")
        if finding.get("status") == "factored":
            p, q = finding.get("p"), finding.get("q")
            if type(p) is not int or type(q) is not int or not 1 < p < q < n or p * q != n:
                raise ValueError("invalid factorization in scanner result")
            recovered[n] = (p, q)
        elif finding.get("status") not in ("no_shared_factor_in_dataset", "unresolved_full_gcd"):
            raise ValueError("unrecognized finding status")
        elif finding.get("p") is not None or finding.get("q") is not None:
            raise ValueError("nonfactored findings must have null factors")
    unresolved = sum(finding["status"] == "unresolved_full_gcd" for finding in findings.values())
    if unresolved != result["unresolved_after_fallback"]:
        raise ValueError("unresolved counter does not match finding statuses")
    if unresolved:
        raise ValueError("complete pairwise/batch comparison cannot retain unresolved findings")
    return recovered


def _execute_scan(scanner, dataset, algorithm, backend, *, timed=False, memory=False):
    actual_calls = 0
    def counted_gcd(a, b):
        nonlocal actual_calls
        actual_calls += 1
        return backend(a, b)
    result, error, elapsed, peak = None, None, None, None
    if memory:
        tracemalloc.start()
    start = perf_counter_ns() if timed else None
    try:
        result = scanner(dataset["moduli"], gcd_fn=counted_gcd)
    except Exception as exception:
        error = "{}: {}".format(type(exception).__name__, exception)
    finally:
        if timed:
            elapsed = (perf_counter_ns() - start) / 1_000_000_000
        if memory:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
    factor_map = None
    if error is None:
        try:
            factor_map = _factor_map(result, dataset["moduli"], algorithm, actual_calls)
        except Exception as exception:
            error = "{}: {}".format(type(exception).__name__, exception)
    return {"result": result, "factor_map": factor_map, "actual_calls": actual_calls,
            "error": error, "elapsed": elapsed, "peak": peak}


def _code_metadata():
    root = Path(__file__).resolve().parent
    sources = ("experiments.py", "shared_prime_attack.py", "batch_gcd_attack.py",
               "contracts.py", "normalization.py", "generators/shared_prime_cases.py",
               "generators/control_cases.py", "build_dataset.py", "audit_pipeline.py", "key_recovery.py")
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
              for name in sources if (root / name).exists()}
    git = {"revision": None, "dirty": None}
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                                  capture_output=True, text=True, check=False)
        status = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                                capture_output=True, text=True, check=False)
        if revision.returncode == 0:
            git["revision"] = revision.stdout.strip()
        if status.returncode == 0:
            git["dirty"] = bool(status.stdout.strip())
    except OSError:
        pass
    return {"python_version": platform.python_version(), "platform": platform.platform(),
            "pycryptodome_version": Crypto.__version__, "source_sha256": hashes, "git": git}


def _csv_text(rows, fieldnames):
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def run_scalability_experiment(dataset_directories, output_directory, trials=5, warmups=1,
                               gcd_backend="euclidean", measure_memory=True):
    """Compare fresh complete scans on identical preloaded input.

    Timing includes batch trees/fallback; preparation, OAEP and evaluation are
    excluded. Memory uses a separate traced-allocation pass, not RSS. Failed or
    incomplete rows are retained but excluded from successful timing statistics.
    """
    _integer(trials, "trials", 1)
    _integer(warmups, "warmups", 0)
    if gcd_backend not in ("euclidean", "math") or type(measure_memory) is not bool:
        raise ValueError("choose backend euclidean/math and a boolean measure_memory")
    if tracemalloc.is_tracing():
        raise RuntimeError("disable existing tracemalloc tracing before timing experiments")
    output = Path(output_directory)
    if any((output / name).exists() or (output / name).is_symlink() for name in OUTPUT_NAMES):
        raise FileExistsError("experiment output files already exist; use a new directory")
    directories = list(dataset_directories)
    if not directories or len({str(Path(p).resolve()) for p in directories}) != len(directories):
        raise ValueError("provide at least one dataset without duplicate directories")
    datasets = [_load_dataset(directory) for directory in directories]
    if len({dataset["dataset_id"] for dataset in datasets}) != len(datasets):
        raise ValueError("dataset directory names must be unique")
    scanners = _scanner_functions()
    backend = euclidean_gcd if gcd_backend == "euclidean" else math.gcd
    environment = _code_metadata()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8]
    rows, memory_rows, warmup_results = [], [], []
    for dataset in datasets:
        normalized = dataset["normalized"]
        bit_field = dataset["bits"][0] if len(dataset["bits"]) == 1 else ";".join(map(str, dataset["bits"]))
        base = {"run_id": run_id, "dataset_id": dataset["dataset_id"], "gcd_backend": gcd_backend,
                "dataset_sha256": dataset["dataset_sha256"], "modulus_bits": bit_field,
                **{field: normalized[field] for field in ("num_records", "num_unique_moduli", "duplicate_extra_records")},
                "topology_profile": dataset["topology_profile"], "code_revision": environment["git"]["revision"]}
        for index in range(warmups):
            for algorithm in ALGORITHMS if index % 2 == 0 else ALGORITHMS[::-1]:
                observed = _execute_scan(scanners[algorithm], dataset, algorithm, backend)
                warmup_results.append({"dataset_id": dataset["dataset_id"], "warmup_index": index,
                                       "algorithm": algorithm, "error": observed["error"],
                                       "agrees_with_reference": observed["factor_map"] == dataset["reference"]})
        for trial in range(trials):
            order = ALGORITHMS if trial % 2 == 0 else ALGORITHMS[::-1]
            observed = {algorithm: _execute_scan(scanners[algorithm], dataset, algorithm, backend, timed=True)
                        for algorithm in order}
            complete = all(observed[a]["error"] is None for a in ALGORITHMS)
            agree = observed[ALGORITHMS[0]]["factor_map"] == observed[ALGORITHMS[1]]["factor_map"] if complete else None
            for algorithm in order:
                scan = observed[algorithm]
                reference_ok = scan["factor_map"] == dataset["reference"] if scan["error"] is None else None
                status = "error" if scan["error"] else ("comparison_incomplete" if not complete else
                         ("success" if reference_ok and agree else "mismatch"))
                row = {**base, "trial_index": trial, "algorithm": algorithm,
                       "trial_algorithm_order": ";".join(order), "run_status": status,
                       "scan_seconds": scan["elapsed"] if scan["error"] is None else None,
                       "attempt_seconds": scan["elapsed"], "actual_gcd_calls": scan["actual_calls"],
                       "agrees_with_reference": reference_ok, "algorithms_agree": agree,
                       "recovered_unique_moduli": len(scan["factor_map"]) if scan["factor_map"] is not None else None,
                       "error": scan["error"]}
                row.update({field: scan["result"][field] if scan["error"] is None else None for field in COUNTERS})
                rows.append(row)
        if measure_memory:
            for algorithm in ALGORITHMS:
                scan = _execute_scan(scanners[algorithm], dataset, algorithm, backend, memory=True)
                reference_ok = scan["factor_map"] == dataset["reference"] if scan["error"] is None else None
                memory_rows.append({"run_id": run_id, "dataset_id": dataset["dataset_id"],
                    "algorithm": algorithm, "gcd_backend": gcd_backend, "memory_method": "tracemalloc_peak_python_allocations",
                    "peak_traced_bytes": scan["peak"], "input_preloaded": True,
                    "run_status": "error" if scan["error"] else ("success" if reference_ok else "mismatch"),
                    "num_unique_moduli": normalized["num_unique_moduli"], "modulus_bits": bit_field,
                    "dataset_sha256": dataset["dataset_sha256"], "agrees_with_reference": reference_ok,
                    "topology_profile": dataset["topology_profile"],
                    "error": scan["error"]})
    stats = []
    for dataset in datasets:
        for algorithm in ALGORITHMS:
            successful = [row["scan_seconds"] for row in rows if row["dataset_id"] == dataset["dataset_id"]
                          and row["algorithm"] == algorithm and row["run_status"] == "success"]
            stats.append({"dataset_id": dataset["dataset_id"], "algorithm": algorithm,
                          "num_unique_moduli": len(dataset["moduli"]), "gcd_backend": gcd_backend,
                          "trials_completed": len(successful), "trials_requested": trials,
                          "median_seconds": statistics.median(successful) if successful else None,
                          "min_seconds": min(successful) if successful else None,
                          "max_seconds": max(successful) if successful else None,
                          "stdev_seconds": statistics.stdev(successful) if len(successful) > 1 else None})
    summary = {"run_id": run_id, "all_runs_ok": all(row["run_status"] == "success" for row in rows + memory_rows)
               and all(row["error"] is None and row["agrees_with_reference"] for row in warmup_results),
               "num_datasets": len(datasets), "trials_requested": trials, "timing_rows": len(rows),
               "memory_rows": len(memory_rows), "statistics": stats}
    metadata = {"run_id": run_id, "created_at_utc": datetime.now(timezone.utc).isoformat(),
                **environment, "gcd_backend": gcd_backend, "trials": trials, "warmups": warmups,
                "algorithm_order": "pairwise then batch on even trial index; reversed on odd index",
                "timing_clock": "perf_counter_ns", "timing_boundary": "complete scanner call, including batch trees and fallback",
                "gcd_call_tracking": "same counted wrapper around the selected backend for both algorithms",
                "excluded_from_timing": ["generation", "fixture I/O", "normalization", "truth verification", "OAEP", "reporting"],
                "memory_measurement": "separate tracemalloc pass; peak traced Python allocations; inputs preloaded; includes scanner trees/output; not RSS",
                "measure_memory": measure_memory, "warmup_results": warmup_results,
                "datasets": [{"dataset_id": d["dataset_id"], "directory": str(d["directory"].resolve()),
                              "public_sha256": d["dataset_sha256"], "num_unique_moduli": len(d["moduli"]),
                              "modulus_bit_lengths": d["bits"], "topology_profile": d["topology_profile"]} for d in datasets]}
    contents = (_csv_text(rows, SCALABILITY_FIELDS), _csv_text(memory_rows, MEMORY_FIELDS),
                json.dumps(summary, indent=2, allow_nan=False) + "\n", json.dumps(metadata, indent=2, allow_nan=False) + "\n")
    output.mkdir(parents=True, exist_ok=True)
    for name, content in zip(OUTPUT_NAMES, contents):
        with (output / name).open("x", encoding="utf-8", newline="") as destination:
            destination.write(content)
    return summary


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
    # Serialize before exclusive writes.
    contents = (_csv_text(rows, fields), json.dumps(metadata, indent=2, allow_nan=False) + "\n")
    output.mkdir(parents=True, exist_ok=True)
    for name, content in zip((csv_name, metadata_name), contents):
        with (output / name).open("x", encoding="utf-8", newline="") as destination:
            destination.write(content)


def run_shared_prime_correctness(dataset_directories, output_directory):
    """Check both algorithms against private truth and each other.

    Only recovered ciphertexts are decrypted; zero checked cases means no
    plaintext comparison was performed.
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


_SUCCESS_STATUSES = {"success", "ok"}


_SCALABILITY_FIELDS = {
    "num_unique_moduli", "algorithm", "gcd_backend", "modulus_bits",
    "scan_seconds", "run_status", "agrees_with_reference", "gcd_calls",
}


_MEMORY_FIELDS = {
    "num_unique_moduli", "algorithm", "gcd_backend", "modulus_bits",
    "run_status", "agrees_with_reference", "peak_traced_bytes", "memory_method",
    "input_preloaded",
}


def _boolean(value, field, line):
    normalized = str(value).strip().lower()
    if normalized in ("true", "1"):
        return True
    if normalized in ("false", "0"):
        return False
    raise ValueError(f"CSV line {line}: {field} must be True or False")


def _plot_integer(value, field, line, minimum=0):
    text = str(value).strip()
    if not text.isascii() or not text.isdecimal():
        raise ValueError(f"CSV line {line}: {field} must be an integer >= {minimum}")
    number = int(text)
    if number < minimum:
        raise ValueError(f"CSV line {line}: {field} must be >= {minimum}")
    return number


def _finite_seconds(value, line):
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"CSV line {line}: scan_seconds must be a finite nonnegative number") from error
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"CSV line {line}: scan_seconds must be a finite nonnegative number")
    return number


def _dimensions(row, line):
    # Mixed bit lengths use a separate panel; the runner joins them with ';'.
    bit_lengths = tuple(sorted({
        _plot_integer(value, "modulus_bits", line, minimum=1)
        for value in str(row["modulus_bits"]).split(";")
    }))
    algorithm = str(row["algorithm"]).strip()
    backend = str(row["gcd_backend"]).strip()
    profile = str(row.get("topology_profile", "unspecified")).strip() or "unspecified"
    if not algorithm or not backend:
        raise ValueError(f"CSV line {line}: algorithm and gcd_backend must be nonempty")
    return bit_lengths, backend, profile, algorithm, _plot_integer(
        row["num_unique_moduli"], "num_unique_moduli", line, minimum=1
    )


def _read_rows(path, required_fields):
    path = Path(path)
    raw = path.read_bytes()
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
    if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)):
        raise ValueError(f"{path}: CSV needs unique column headers")
    missing = required_fields - set(reader.fieldnames)
    if missing:
        raise ValueError(f"{path}: missing CSV fields: {', '.join(sorted(missing))}")
    rows = []
    for line, row in enumerate(reader, 2):
        if None in row:
            raise ValueError(f"{path}: CSV line {line} has too many values")
        rows.append((line, row))
    return rows, {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "total_rows": len(rows),
        "included_rows": 0,
        "excluded_rows": 0,
        "exclusion_reasons": {},
    }


def _included_row(row, line, reasons):
    status = str(row["run_status"]).strip().lower()
    if status not in _SUCCESS_STATUSES:
        reasons["run_status=" + (status or "blank")] += 1
        return False
    if not _boolean(row["agrees_with_reference"], "agrees_with_reference", line):
        reasons["reference_disagreement"] += 1
        return False
    return True


def _finish_source(source, reasons):
    source["excluded_rows"] = sum(reasons.values())
    source["included_rows"] = source["total_rows"] - source["excluded_rows"]
    source["exclusion_reasons"] = dict(sorted(reasons.items()))


def load_scalability_results(path):
    """Aggregate successful, reference-verified timings by workload.

    Keep bit length, backend, topology, algorithm and size separate. Report
    median/min/max; GCD counts within a group must match. Failed rows are counted
    and excluded; malformed successful measurements raise an error.
    """
    rows, source = _read_rows(path, _SCALABILITY_FIELDS)
    reasons = Counter()
    groups = defaultdict(list)
    for line, row in rows:
        if not _included_row(row, line, reasons):
            continue
        dimensions = _dimensions(row, line)
        groups[dimensions].append((
            _finite_seconds(row["scan_seconds"], line),
            _plot_integer(row["gcd_calls"], "gcd_calls", line),
        ))
    aggregated = []
    for dimensions, trials in sorted(groups.items()):
        bits, backend, profile, algorithm, count = dimensions
        seconds, calls = zip(*trials)
        if len(set(calls)) != 1:
            raise ValueError(
                f"GCD counts vary within {algorithm}/{backend}/{bits}, "
                f"m={count}, profile={profile}; separate the differing workloads"
            )
        aggregated.append({
            "modulus_bits": list(bits), "gcd_backend": backend,
            "topology_profile": profile, "algorithm": algorithm,
            "num_unique_moduli": count, "trials": len(trials),
            "scan_seconds_median": median(seconds),
            "scan_seconds_min": min(seconds), "scan_seconds_max": max(seconds),
            "gcd_calls": calls[0],
        })
    _finish_source(source, reasons)
    return {"source": source, "groups": aggregated}


def load_memory_results(path):
    """Aggregate separate tracemalloc peaks by workload and preloading condition.

    Other memory methods are excluded; these peaks are not process RSS.
    """
    rows, source = _read_rows(path, _MEMORY_FIELDS)
    reasons = Counter()
    groups = defaultdict(list)
    for line, row in rows:
        if not _included_row(row, line, reasons):
            continue
        method = str(row["memory_method"]).strip()
        if method != "tracemalloc_peak_python_allocations":
            reasons["unsupported_memory_method=" + (method or "blank")] += 1
            continue
        preloaded = _boolean(row["input_preloaded"], "input_preloaded", line)
        dimensions = _dimensions(row, line) + (method, preloaded)
        groups[dimensions].append(_plot_integer(row["peak_traced_bytes"], "peak_traced_bytes", line))
    aggregated = []
    for dimensions, values in sorted(groups.items()):
        bits, backend, profile, algorithm, count, method, preloaded = dimensions
        aggregated.append({
            "modulus_bits": list(bits), "gcd_backend": backend,
            "topology_profile": profile, "algorithm": algorithm,
            "num_unique_moduli": count, "trials": len(values),
            "memory_method": method, "input_preloaded": preloaded,
            "peak_traced_bytes_median": median(values),
            "peak_traced_bytes_min": min(values), "peak_traced_bytes_max": max(values),
        })
    _finish_source(source, reasons)
    return {"source": source, "groups": aggregated}


def _pyplot():
    if "MPLCONFIGDIR" not in os.environ:
        cache = Path(__file__).resolve().parent / ".cache" / "matplotlib"
        cache.mkdir(parents=True, exist_ok=True)
        os.environ["MPLCONFIGDIR"] = str(cache)
    try:
        import matplotlib
    except ImportError as error:
        raise RuntimeError("Figure generation requires the optional Matplotlib dependency") from error
    matplotlib.use("Agg", force=True)
    from matplotlib import pyplot
    return pyplot


def _panel_key(group, memory=False):
    key = (tuple(group["modulus_bits"]), group["gcd_backend"], group["topology_profile"])
    return key + (group["memory_method"], group["input_preloaded"]) if memory else key


def _panel_title(key, memory=False):
    bits, backend, profile = key[:3]
    sizes = f"{bits[0]}-bit moduli" if len(bits) == 1 else "Modulus bits: " + ", ".join(map(str, bits))
    title = f"{sizes} | GCD backend: {backend}\nTopology: {profile}"
    if memory:
        title += "\ntracemalloc; inputs preloaded: " + ("yes" if key[4] else "no")
    return title


def _save_chart(pyplot, groups, kind, output_directory):
    memory = kind == "peak_traced_allocations"
    panels = defaultdict(list)
    for group in groups:
        panels[_panel_key(group, memory)].append(group)
    figure, axes = pyplot.subplots(len(panels), 1, squeeze=False, figsize=(8.6, 4.5 * len(panels)))
    for axis, (key, values) in zip(axes.flat, sorted(panels.items())):
        by_algorithm = defaultdict(list)
        for group in values:
            by_algorithm[group["algorithm"]].append(group)
        for algorithm, trials in sorted(by_algorithm.items()):
            trials.sort(key=lambda group: group["num_unique_moduli"])
            x = [group["num_unique_moduli"] for group in trials]
            if kind == "gcd_calls_by_unique_moduli":
                axis.plot(x, [group["gcd_calls"] for group in trials], marker="o", label=algorithm)
            else:
                prefix = "peak_traced_bytes" if memory else "scan_seconds"
                scale = 1 / (1024 * 1024) if memory else 1
                medians = [group[prefix + "_median"] * scale for group in trials]
                lower = [(group[prefix + "_median"] - group[prefix + "_min"]) * scale for group in trials]
                upper = [(group[prefix + "_max"] - group[prefix + "_median"]) * scale for group in trials]
                axis.errorbar(x, medians, yerr=[lower, upper], marker="o", capsize=4, label=algorithm)
        axis.set_title(_panel_title(key, memory), fontsize=10)
        axis.set_xlabel("Unique public moduli (count)")
        axis.set_ylabel({
            "runtime_by_unique_moduli": "Scan time (seconds)\nmedian; whiskers: observed min/max",
            "gcd_calls_by_unique_moduli": "GCD calls per scan (count)",
            "peak_traced_allocations": "Peak traced Python allocations (MiB)\nmedian; whiskers: observed min/max",
        }[kind])
        axis.grid(True, alpha=0.25)
        axis.legend(title="Algorithm")
        axis.set_ylim(bottom=0)
    figure.tight_layout()
    paths = []
    try:
        for extension in ("png", "svg"):
            path = output_directory / f"{kind}.{extension}"
            figure.savefig(path, dpi=180, bbox_inches="tight")
            paths.append(str(path.resolve()))
    finally:
        pyplot.close(figure)
    return paths


def generate_figures(results_directory, output_directory=None, overwrite=False):
    """Plot saved CSV measurements as PNG/SVG with aggregation metadata.

    Preserve existing figures unless overwrite=True; run no experiments.
    """
    results_directory = Path(results_directory)
    output_directory = Path(output_directory) if output_directory is not None else results_directory / "figures"
    scalability = load_scalability_results(results_directory / "scalability_results.csv")
    if not scalability["groups"]:
        source = scalability["source"]
        raise ValueError(
            "No successful, reference-verified scalability rows are available to plot; "
            f"{source['excluded_rows']} of {source['total_rows']} rows excluded: "
            + json.dumps(source["exclusion_reasons"], sort_keys=True)
        )
    memory_path = results_directory / "memory_results.csv"
    memory = load_memory_results(memory_path) if memory_path.exists() else None
    kinds = ["runtime_by_unique_moduli", "gcd_calls_by_unique_moduli"]
    if memory is not None and memory["groups"]:
        kinds.append("peak_traced_allocations")
    targets = [output_directory / f"{kind}.{extension}" for kind in kinds for extension in ("png", "svg")]
    metadata_path = output_directory / "figure_metadata.json"
    if not overwrite and any(path.exists() or path.is_symlink() for path in targets + [metadata_path]):
        raise FileExistsError("figure outputs already exist; choose a new directory or use --overwrite")
    pyplot = _pyplot()
    output_directory.mkdir(parents=True, exist_ok=True)
    charts = []
    for kind in kinds:
        groups = memory["groups"] if kind == "peak_traced_allocations" else scalability["groups"]
        charts.append({"chart": kind, "paths": _save_chart(pyplot, groups, kind, output_directory)})
    metadata = {
        "format": "weak-rsa-figure-metadata",
        "accepted_run_statuses": sorted(_SUCCESS_STATUSES),
        "acceptance_rule": "successful status and agrees_with_reference=True; finite nonnegative measurements",
        "runtime_aggregation": "median of accepted scan_seconds; whiskers are observed minimum and maximum, not confidence intervals",
        "work_aggregation": "identical measured gcd_calls required within each workload group",
        "memory_aggregation": "separate tracemalloc CSV; median peak Python allocations with observed min/max, not total process RSS",
        "grouping": ["modulus_bits", "gcd_backend", "topology_profile", "algorithm", "num_unique_moduli"],
        "memory_additional_grouping": ["memory_method", "input_preloaded"],
        "sources": {"scalability": scalability["source"]},
        "scalability_groups": scalability["groups"],
        "memory_groups": memory["groups"] if memory is not None else [],
        "charts": charts,
    }
    if memory is not None:
        metadata["sources"]["memory"] = memory["source"]
    with metadata_path.open("w" if overwrite else "x", encoding="utf-8") as destination:
        json.dump(metadata, destination, indent=2, allow_nan=False)
        destination.write("\n")
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("scalability", "correctness", "coverage", "plot"), default="scalability")
    parser.add_argument("--dataset-dirs", nargs="+", default=["data/public/van_mixed"])
    parser.add_argument("--before", default="data/public/van_coverage/before")
    parser.add_argument("--after", default="data/public/van_coverage/after")
    parser.add_argument("--target-key-id", default="key_001")
    parser.add_argument("--sizes", nargs="+", type=int, default=[20, 50, 100])
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--bits", type=int, default=2048)
    parser.add_argument("--dataset-root", default="data/public/scalability")
    parser.add_argument("--output", help="result directory, or optional figure directory in plot mode")
    parser.add_argument("--input", help="existing result directory for plot mode")
    parser.add_argument("--overwrite-figures", action="store_true")
    parser.add_argument("--skip-memory", action="store_true")
    parser.add_argument("--backend", choices=("euclidean", "math"), default="euclidean")
    args = parser.parse_args(argv)
    if args.mode == "plot" and args.input is None:
        parser.error("--input RESULTS_DIR is required for --mode plot")
    output = args.output or "results/van_batch_pilot"
    try:
        if args.mode == "plot":
            metadata = generate_figures(args.input, args.output, args.overwrite_figures)
            for name, source in metadata["sources"].items():
                print("{}: {} rows included; {} excluded".format(name, source["included_rows"], source["excluded_rows"]))
                for reason, count in source["exclusion_reasons"].items():
                    print("  {}: {}".format(reason, count))
            for chart in metadata["charts"]:
                for path in chart["paths"]:
                    print(path)
            return 0
        if args.mode == "correctness":
            summary = run_shared_prime_correctness(args.dataset_dirs, output)
        elif args.mode == "coverage":
            summary = run_coverage_experiment(args.before, args.after, args.target_key_id, output)
        else:
            directories = prepare_scalability_datasets(args.sizes, args.dataset_root, args.bits)
            summary = run_scalability_experiment(directories, output, args.trials, args.warmups,
                                                 args.backend, not args.skip_memory)
    except (ValueError, TypeError, OSError, RuntimeError) as error:
        parser.exit(1, "Error: {}\n".format(error))
    print(json.dumps(summary, indent=2))
    return 0 if summary["all_runs_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
