"""Controlled pairwise-versus-batch datasets and repeated scan measurements."""

from datetime import datetime, timezone
import json
import math
from pathlib import Path
import statistics
import tracemalloc
import uuid

from ..records import COMPLETE_ALGORITHMS as ALGORITHMS, SCAN_COUNTERS as COUNTERS
from ..attacks.pairwise_gcd import euclidean_gcd
from ..datasets.storage import save_dataset
from .common import (_integer, _load_dataset, _scanner_functions, _execute_scan,
                     _code_metadata, _csv_text)


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
    from ..datasets.generators.shared_primes import generate_scalability_dataset
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
