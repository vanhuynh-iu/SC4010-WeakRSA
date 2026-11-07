"""Support runner for Van's shared-prime scalability experiments.

Krystal remains lead owner of the shared experiment framework. This scoped
support module runs pairwise/batch factor recovery only; it implements no
Fermat algorithm. Importing it generates no keys and runs no experiments.
"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path
import platform
import statistics
import subprocess
from time import perf_counter_ns
import tracemalloc
import uuid

import Crypto
from Crypto.Util.number import isPrime

from key_dataset import normalize_public_keys
from shared_prime_attack import euclidean_gcd, scan_moduli
from shared_prime_fixtures import load_fixtures, save_fixtures


PROFILE = "disjoint_shared_pairs_20pct_controls_80pct"
ALGORITHMS = ("pairwise", "batch_with_fallback")
COUNTERS = ("gcd_calls", "pairwise_gcd_calls", "batch_leaf_gcd_calls", "fallback_gcd_calls",
            "full_gcd_before_fallback", "unresolved_after_fallback")
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
    case = load_fixtures(directory)
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
    """Save/reuse fixed-profile inputs before measurement; never overwrite.

    Each requested size is >=10 and divisible by ten, permitting exactly
    20% unique moduli in disjoint shared pairs and 80% independent controls.
    Existing datasets must match the profile, checksum, size and bit length.
    """
    _integer(modulus_bits, "modulus_bits", 32)
    sizes = list(sizes)
    if not sizes or len(set(sizes)) != len(sizes):
        raise ValueError("sizes must be a nonempty collection without duplicates")
    for size in sizes:
        _integer(size, "size", 10)
        if size % 10:
            raise ValueError("scalability sizes must be multiples of ten")
    from key_generation import generate_scalability_dataset
    directories = []
    for size in sizes:
        directory = Path(dataset_root) / "m{}_bits{}".format(size, modulus_bits)
        metadata = {"topology_profile": PROFILE, "num_unique_moduli": size,
                    "modulus_bits": modulus_bits, "e": 65537}
        if not directory.exists():
            case = generate_scalability_dataset(size, modulus_bits=modulus_bits)
            save_fixtures(directory, case["public_keys"], case["private_truth"],
                          case["expected_vulnerable_ids"], integer_encoding="hex", metadata=metadata)
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
    # Import before warm-ups/timing, so import cost is never timed as a scan.
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
               "key_dataset.py", "key_generation.py", "shared_prime_fixtures.py")
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
    """Compare complete fresh scans on identical preloaded normalized inputs.

    Timed scans include scanner validation/output, batch tree construction,
    leaf GCDs and fallback. Generation, I/O, normalization, independent truth
    checking and reporting are outside timing. Memory is a separate pass of
    peak traced Python allocations with inputs already loaded; it is not RSS.
    Failed/mismatched/incomplete comparisons remain rows and are excluded from
    successful timing statistics. No result file is overwritten.
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("scalability", "correctness", "coverage"), default="scalability")
    parser.add_argument("--dataset-dirs", nargs="+", default=["fixtures/van_mixed_v2"])
    parser.add_argument("--before", default="fixtures/van_coverage_v2/before")
    parser.add_argument("--after", default="fixtures/van_coverage_v2/after")
    parser.add_argument("--target-key-id", default="key_001")
    parser.add_argument("--sizes", nargs="+", type=int, default=[20, 50, 100])
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--bits", type=int, default=2048)
    parser.add_argument("--dataset-root", default="fixtures/scalability_v2")
    parser.add_argument("--output", default="results/van_batch_pilot_v2")
    parser.add_argument("--skip-memory", action="store_true")
    parser.add_argument("--backend", choices=("euclidean", "math"), default="euclidean")
    args = parser.parse_args(argv)
    try:
        if args.mode == "correctness":
            from experiment_checks import run_shared_prime_correctness
            summary = run_shared_prime_correctness(args.dataset_dirs, args.output)
        elif args.mode == "coverage":
            from experiment_checks import run_coverage_experiment
            summary = run_coverage_experiment(args.before, args.after, args.target_key_id, args.output)
        else:
            directories = prepare_scalability_datasets(args.sizes, args.dataset_root, args.bits)
            summary = run_scalability_experiment(directories, args.output, args.trials, args.warmups,
                                                 args.backend, not args.skip_memory)
    except (ValueError, TypeError, OSError, RuntimeError) as error:
        parser.exit(1, "Error: {}\n".format(error))
    print(json.dumps(summary, indent=2))
    return 0 if summary["all_runs_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
