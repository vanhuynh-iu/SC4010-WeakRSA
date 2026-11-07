"""Controlled pairwise-versus-batch datasets and repeated scan measurements."""

from datetime import datetime
from datetime import timezone
import json
import math
from pathlib import Path
import statistics
import tracemalloc
import uuid

from rsa_auditor.attacks.pairwise_gcd import euclidean_gcd
from rsa_auditor.constants import COMPLETE_ALGORITHMS as ALGORITHMS
from rsa_auditor.constants import SCAN_COUNTERS as COUNTERS
from rsa_auditor.datasets.storage import save_dataset
from rsa_auditor.experiments.common import _code_metadata
from rsa_auditor.experiments.common import _csv_text
from rsa_auditor.experiments.common import _execute_scan
from rsa_auditor.experiments.common import _integer
from rsa_auditor.experiments.common import _load_dataset
from rsa_auditor.experiments.common import _scanner_functions

PROFILE = "disjoint_shared_pairs_20pct_controls_80pct"

SCALABILITY_FIELDS = (
    "run_id",
    "dataset_id",
    "trial_index",
    "algorithm",
    "gcd_backend",
    "modulus_bits",
    "num_records",
    "num_unique_moduli",
    "duplicate_extra_records",
    "topology_profile",
    "scan_seconds",
    *COUNTERS,
    "recovered_unique_moduli",
    "agrees_with_reference",
    "run_status",
    "dataset_sha256",
    "trial_algorithm_order",
    "algorithms_agree",
    "actual_gcd_calls",
    "code_revision",
    "error",
    "attempt_seconds",
)

MEMORY_FIELDS = (
    "run_id",
    "dataset_id",
    "algorithm",
    "gcd_backend",
    "memory_method",
    "peak_traced_bytes",
    "input_preloaded",
    "run_status",
    "num_unique_moduli",
    "modulus_bits",
    "dataset_sha256",
    "agrees_with_reference",
    "topology_profile",
    "error",
)

OUTPUT_NAMES = ("scalability_results.csv", "memory_results.csv", "summary.json",
                "run_metadata.json")


def prepare_scalability_datasets(sizes, dataset_root, modulus_bits=2048):
    """Save/reuse profile-checked fixtures before timing, without overwrites.

    Sizes must be multiples of 10 and >=10: 20% shared-pair moduli and 80%
    controls.
    """
    _integer(modulus_bits, "modulus_bits", 32)
    sizes = list(sizes)
    if not sizes or len(set(sizes)) != len(sizes):
        raise ValueError(
            "sizes must be a nonempty collection without duplicates")
    for size in sizes:
        _integer(size, "size", 10)
        if size % 10:
            raise ValueError("scalability sizes must be multiples of ten")
    from rsa_auditor.datasets.generators.shared_primes import generate_scalability_dataset
    directories = []
    for size in sizes:
        directory = Path(dataset_root) / "m{}_bits{}".format(size, modulus_bits)
        metadata = {
            "topology_profile": PROFILE,
            "num_unique_moduli": size,
            "modulus_bits": modulus_bits,
            "e": 65537
        }
        if not directory.exists():
            case = generate_scalability_dataset(size, modulus_bits=modulus_bits)
            save_dataset(directory,
                         case["public_keys"],
                         case["private_truth"],
                         case["expected_vulnerable_ids"],
                         metadata=metadata)
        loaded = _load_dataset(directory)
        normalized = loaded["normalized"]
        profile_error = ("saved dataset does not match requested fixed "
                         "scalability profile")
        if (loaded["manifest"].get("construction_metadata") != metadata or
                normalized["num_unique_moduli"] != size or
                normalized["num_records"] != size or
                loaded["bits"] != [modulus_bits] or
                any(record["e"] != 65537
                    for record in normalized["public_records"]) or
                len(loaded["reference"]) != size // 5):
            raise ValueError(profile_error)
        for owners in loaded["prime_owners"].values():
            if len(owners) > 2:
                raise ValueError(profile_error)
        for pair in loaded["reference"].values():
            shared_prime_count = 0
            for prime in pair:
                if len(loaded["prime_owners"][prime]) > 1:
                    shared_prime_count += 1
            if shared_prime_count != 1:
                raise ValueError(profile_error)
        directories.append(directory)
    return directories


def run_scalability_experiment(dataset_directories,
                               output_directory,
                               trials=5,
                               warmups=1,
                               gcd_backend="euclidean",
                               measure_memory=True):
    """Compare fresh complete scans on identical preloaded inputs.

    Batch trees and fallback are timed. Preparation, OAEP and evaluation are
    excluded. Memory uses a separate traced-allocation pass, not process RSS.
    Failed rows remain in the CSV but are excluded from successful statistics.
    """
    _integer(trials, "trials", 1)
    _integer(warmups, "warmups", 0)
    if gcd_backend not in ("euclidean",
                           "math") or type(measure_memory) is not bool:
        raise ValueError(
            "choose backend euclidean/math and a boolean measure_memory")
    if tracemalloc.is_tracing():
        raise RuntimeError(
            "disable existing tracemalloc tracing before timing experiments")

    output = Path(output_directory)
    for name in OUTPUT_NAMES:
        path = output / name
        if path.exists() or path.is_symlink():
            raise FileExistsError(
                "experiment output files already exist; use a new directory")
    directories = list(dataset_directories)
    resolved_directories = {
        str(Path(directory).resolve()) for directory in directories
    }
    if not directories or len(resolved_directories) != len(directories):
        raise ValueError(
            "provide at least one dataset without duplicate directories")
    datasets = [_load_dataset(directory) for directory in directories]
    dataset_ids = {dataset["dataset_id"] for dataset in datasets}
    if len(dataset_ids) != len(datasets):
        raise ValueError("dataset directory names must be unique")

    scanners = _scanner_functions()
    backend = euclidean_gcd
    if gcd_backend == "math":
        backend = math.gcd
    environment = _code_metadata()
    run_id = datetime.now(
        timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8]
    rows = []
    memory_rows = []
    warmup_results = []

    for dataset in datasets:
        normalized = dataset["normalized"]
        if len(dataset["bits"]) == 1:
            bit_field = dataset["bits"][0]
        else:
            bit_field = ";".join(map(str, dataset["bits"]))
        base = {
            "run_id": run_id,
            "dataset_id": dataset["dataset_id"],
            "gcd_backend": gcd_backend,
            "dataset_sha256": dataset["dataset_sha256"],
            "modulus_bits": bit_field,
            "topology_profile": dataset["topology_profile"],
            "code_revision": environment["git"]["revision"],
        }
        for field in ("num_records", "num_unique_moduli",
                      "duplicate_extra_records"):
            base[field] = normalized[field]

        for warmup_index in range(warmups):
            warmup_order = ALGORITHMS
            if warmup_index % 2:
                warmup_order = ALGORITHMS[::-1]
            for algorithm in warmup_order:
                scan = _execute_scan(scanners[algorithm], dataset, algorithm,
                                     backend)
                warmup_results.append({
                    "dataset_id": dataset["dataset_id"],
                    "warmup_index": warmup_index,
                    "algorithm": algorithm,
                    "error": scan["error"],
                    "agrees_with_reference": scan["factor_map"] ==
                                             dataset["reference"],
                })

        for trial in range(trials):
            order = ALGORITHMS
            if trial % 2:
                order = ALGORITHMS[::-1]
            observed = {}
            for algorithm in order:
                observed[algorithm] = _execute_scan(scanners[algorithm],
                                                    dataset,
                                                    algorithm,
                                                    backend,
                                                    timed=True)
            complete = all(
                observed[name]["error"] is None for name in ALGORITHMS)
            agree = None
            if complete:
                first_factors = observed[ALGORITHMS[0]]["factor_map"]
                second_factors = observed[ALGORITHMS[1]]["factor_map"]
                agree = first_factors == second_factors

            for algorithm in order:
                scan = observed[algorithm]
                reference_ok = None
                scan_seconds = None
                recovered_count = None
                if scan["error"] is None:
                    reference_ok = scan["factor_map"] == dataset["reference"]
                    scan_seconds = scan["elapsed"]
                if scan["factor_map"] is not None:
                    recovered_count = len(scan["factor_map"])
                if scan["error"]:
                    status = "error"
                elif not complete:
                    status = "comparison_incomplete"
                elif reference_ok and agree:
                    status = "success"
                else:
                    status = "mismatch"
                row = {
                    **base,
                    "trial_index": trial,
                    "algorithm": algorithm,
                    "trial_algorithm_order": ";".join(order),
                    "run_status": status,
                    "scan_seconds": scan_seconds,
                    "attempt_seconds": scan["elapsed"],
                    "actual_gcd_calls": scan["actual_calls"],
                    "agrees_with_reference": reference_ok,
                    "algorithms_agree": agree,
                    "recovered_unique_moduli": recovered_count,
                    "error": scan["error"],
                }
                for field in COUNTERS:
                    row[field] = None
                    if scan["error"] is None:
                        row[field] = scan["result"][field]
                rows.append(row)

        if measure_memory:
            for algorithm in ALGORITHMS:
                scan = _execute_scan(scanners[algorithm],
                                     dataset,
                                     algorithm,
                                     backend,
                                     memory=True)
                reference_ok = None
                if scan["error"] is None:
                    reference_ok = scan["factor_map"] == dataset["reference"]
                if scan["error"]:
                    status = "error"
                elif reference_ok:
                    status = "success"
                else:
                    status = "mismatch"
                memory_rows.append({
                    "run_id": run_id,
                    "dataset_id": dataset["dataset_id"],
                    "algorithm": algorithm,
                    "gcd_backend": gcd_backend,
                    "memory_method": "tracemalloc_peak_python_allocations",
                    "peak_traced_bytes": scan["peak"],
                    "input_preloaded": True,
                    "run_status": status,
                    "num_unique_moduli": normalized["num_unique_moduli"],
                    "modulus_bits": bit_field,
                    "dataset_sha256": dataset["dataset_sha256"],
                    "agrees_with_reference": reference_ok,
                    "topology_profile": dataset["topology_profile"],
                    "error": scan["error"],
                })

    statistics_rows = []
    for dataset in datasets:
        for algorithm in ALGORITHMS:
            successful_seconds = []
            for row in rows:
                if (row["dataset_id"] == dataset["dataset_id"] and
                        row["algorithm"] == algorithm and
                        row["run_status"] == "success"):
                    successful_seconds.append(row["scan_seconds"])
            median_seconds = None
            min_seconds = None
            max_seconds = None
            stdev_seconds = None
            if successful_seconds:
                median_seconds = statistics.median(successful_seconds)
                min_seconds = min(successful_seconds)
                max_seconds = max(successful_seconds)
            if len(successful_seconds) > 1:
                stdev_seconds = statistics.stdev(successful_seconds)
            statistics_rows.append({
                "dataset_id": dataset["dataset_id"],
                "algorithm": algorithm,
                "num_unique_moduli": len(dataset["moduli"]),
                "gcd_backend": gcd_backend,
                "trials_completed": len(successful_seconds),
                "trials_requested": trials,
                "median_seconds": median_seconds,
                "min_seconds": min_seconds,
                "max_seconds": max_seconds,
                "stdev_seconds": stdev_seconds,
            })
    all_runs_ok = all(
        row["run_status"] == "success" for row in rows + memory_rows)
    if all_runs_ok:
        all_runs_ok = all(row["error"] is None and row["agrees_with_reference"]
                          for row in warmup_results)
    summary = {
        "run_id": run_id,
        "all_runs_ok": all_runs_ok,
        "num_datasets": len(datasets),
        "trials_requested": trials,
        "timing_rows": len(rows),
        "memory_rows": len(memory_rows),
        "statistics": statistics_rows,
    }
    input_metadata = []
    for dataset in datasets:
        input_metadata.append({
            "dataset_id": dataset["dataset_id"],
            "directory": str(dataset["directory"].resolve()),
            "public_sha256": dataset["dataset_sha256"],
            "num_unique_moduli": len(dataset["moduli"]),
            "modulus_bit_lengths": dataset["bits"],
            "topology_profile": dataset["topology_profile"],
        })
    metadata = {
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        **environment,
        "gcd_backend": gcd_backend,
        "trials": trials,
        "warmups": warmups,
        "algorithm_order":
            ("pairwise then batch on even trial index; reversed on odd index"),
        "timing_clock": "perf_counter_ns",
        "timing_boundary":
            ("complete scanner call, including batch trees and fallback"),
        "gcd_call_tracking":
            "same counted wrapper around the selected backend for both "
            "algorithms",
        "excluded_from_timing": [
            "generation", "fixture I/O", "normalization", "truth verification",
            "OAEP", "reporting"
        ],
        "memory_measurement":
            "separate tracemalloc pass; peak traced Python allocations; "
            "inputs preloaded; includes scanner trees/output; not RSS",
        "measure_memory": measure_memory,
        "warmup_results": warmup_results,
        "datasets": input_metadata,
    }
    contents = (
        _csv_text(rows, SCALABILITY_FIELDS),
        _csv_text(memory_rows, MEMORY_FIELDS),
        json.dumps(summary, indent=2, allow_nan=False) + "\n",
        json.dumps(metadata, indent=2, allow_nan=False) + "\n",
    )
    output.mkdir(parents=True, exist_ok=True)
    for name, content in zip(OUTPUT_NAMES, contents):
        with (output / name).open("x", encoding="utf-8",
                                  newline="") as destination:
            destination.write(content)
    return summary
