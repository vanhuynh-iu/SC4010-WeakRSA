"""Shared fixture loading, reference checks, scan execution, and run provenance."""

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
from time import perf_counter_ns
import tracemalloc
import uuid

import Crypto
from Crypto.Util.number import isPrime

from ..records import COMPLETE_ALGORITHMS as ALGORITHMS, SCAN_COUNTERS as COUNTERS
from ..public_inputs import normalize_public_keys
from ..attacks.pairwise_gcd import scan_moduli
from ..datasets.storage import load_dataset


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


def _scanner_functions():
    # Import outside scan timing.
    from ..attacks.batch_gcd import scan_moduli_batch
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
    """Fingerprint current source paths without rewriting historical run metadata."""
    root = Path(__file__).resolve().parents[2]
    paths = sorted((root / "rsa_auditor").rglob("*.py"))
    paths.extend(root / name for name in ("legacy/close_primes/fermat_attack.py",
                                         "legacy/close_primes/key_generation.py"))
    hashes = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in paths if path.is_file()}
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


def _write_results(output, csv_name, metadata_name, rows, fields, metadata):
    # Serialize before exclusive writes.
    contents = (_csv_text(rows, fields), json.dumps(metadata, indent=2, allow_nan=False) + "\n")
    output.mkdir(parents=True, exist_ok=True)
    for name, content in zip((csv_name, metadata_name), contents):
        with (output / name).open("x", encoding="utf-8", newline="") as destination:
            destination.write(content)
