"""Paired, bounded measurements of the preserved Fermat implementations.

Generate and save keys before measuring. Only n, a position budget and fixed
wheel settings reach a kernel; private gaps/factors grade its completed output.
"""

from collections import Counter
from datetime import datetime
from datetime import timezone
import hashlib
import json
from math import gcd
from math import isqrt
from math import prod
from pathlib import Path
from statistics import median
from time import get_clock_info
from time import perf_counter_ns

from rsa_auditor.attacks.fermat import fermat_attack
from rsa_auditor.attacks.fermat import fermat_sieved
from rsa_auditor.attacks.fermat import improved_fermat_attack
from rsa_auditor.datasets.builder import assemble_dataset
from rsa_auditor.datasets.generators.close_primes import generate_close_prime_key
from rsa_auditor.datasets.storage import dataset_paths
from rsa_auditor.datasets.storage import load_dataset
from rsa_auditor.datasets.storage import save_dataset
from rsa_auditor.evaluation import build_reference
from rsa_auditor.experiments.common import _code_metadata
from rsa_auditor.experiments.common import _csv_text
from rsa_auditor.experiments.common import _integer
from rsa_auditor.experiments.common import _new_run_id

KERNELS = {
    "original": (fermat_attack, None),
    "mod64": (improved_fermat_attack, None),
    "wheel_960": (fermat_sieved, (64, 3, 5)),
    "wheel_6720": (fermat_sieved, (64, 3, 5, 7)),
}
OUTPUT_NAMES = ("fermat_results.csv", "summary.json", "run_metadata.json")
FIELDS = (
    "run_id",
    "dataset_sha256",
    "key_id",
    "trial_index",
    "gap_bits",
    "actual_gap_hex",
    "modulus_hex",
    "modulus_bits",
    "position_budget",
    "method",
    "method_order",
    "reference_required_positions",
    "status",
    "positions_covered",
    "square_checks",
    "preprocessing_seconds",
    "kernel_seconds",
    "attempt_seconds",
    "factors_verified",
    "agrees_with_reference",
    "run_status",
    "error",
)
_MAX_PRIME_REUSE_ATTEMPTS = 100


def _profile(gap_bits, keys_per_gap, modulus_bits):
    """Validate settings and describe the saved paired-key collection."""
    gaps = list(gap_bits)
    _integer(keys_per_gap, "keys_per_gap", 1)
    if type(modulus_bits) is not int or modulus_bits < 32 or modulus_bits % 2:
        raise ValueError("modulus_bits must be even and at least 32")
    if not gaps or any(
            type(gap) is not int or not 0 <= gap <= modulus_bits // 2 - 2
            for gap in gaps):
        raise ValueError("gap_bits must be nonempty valid integer separations")
    if len(set(gaps)) != len(gaps):
        raise ValueError("gap_bits cannot contain duplicates")
    return {
        "study": "paired_fermat_pilot",
        "gap_bits": gaps,
        "keys_per_gap": keys_per_gap,
        "modulus_bits": modulus_bits,
        "e": 65537
    }


def _validate_fixture(case, profile, expected_profile=None):
    """Check one answer sheet before saving keys or measuring their kernels."""
    if profile != _profile(profile.get("gap_bits", []),
                           profile.get("keys_per_gap"),
                           profile.get("modulus_bits")):
        raise ValueError("saved fixture does not describe this Fermat pilot")
    if expected_profile is not None and profile != expected_profile:
        raise ValueError(
            "saved Fermat fixture does not match requested settings")
    reference = build_reference(case)
    normalized = reference["normalized"]
    if normalized["num_records"] != normalized[
            "num_unique_moduli"] or reference["gcd_moduli"]:
        raise ValueError(
            "Fermat pilot requires unique moduli with no shared prime factors")
    groups = Counter()
    for record in case["public_keys"]:
        truth = case["private_truth"][record["key_id"]]
        prefix, _, gap_text = truth["case_type"].rpartition("_")
        if (prefix != "close_prime_gap" or not gap_text.isascii() or
                not gap_text.isdecimal()):
            raise ValueError(
                "private Fermat case label must retain the configured gap")
        gap = int(gap_text)
        p, q = reference["factors"][record["n"]]
        if (gap not in profile["gap_bits"] or q - p < 1 << gap or
                record["n"].bit_length() != profile["modulus_bits"] or
                record["e"] != 65537 or gcd(record["e"],
                                            (p - 1) * (q - 1)) != 1):
            raise ValueError(
                "saved Fermat case violates its configured RSA/gap settings")
        groups[gap] += 1
    if groups != Counter(
        {gap: profile["keys_per_gap"] for gap in profile["gap_bits"]}):
        raise ValueError(
            "saved Fermat fixture has the wrong number of keys per gap")
    if case["expected_vulnerable_ids"]:
        raise ValueError(
            "independent Fermat pilot cannot claim GCD-observable records")
    return reference


def prepare_fermat_dataset(directory,
                           gap_bits=(515, 518, 520),
                           keys_per_gap=3,
                           modulus_bits=2048):
    """Save independent keys once, or validate and reuse the same saved bytes.

    The fixed shuffle controls record order, not the generated primes.
    """
    directory = Path(directory)
    profile = _profile(gap_bits, keys_per_gap, modulus_bits)
    paths = dataset_paths(directory)
    if any(path.exists() or path.is_symlink() for path in paths):
        if not all(path.is_file() for path in paths):
            raise FileExistsError(
                "incomplete Fermat fixture exists; use a new directory")
        case = load_dataset(directory)
        saved = json.loads(paths[2].read_text()).get("construction_metadata",
                                                     {})
        _validate_fixture(case, saved, profile)
        return directory
    cases, used = [], set()
    for gap in profile["gap_bits"]:
        for _ in range(keys_per_gap):
            for _attempt in range(_MAX_PRIME_REUSE_ATTEMPTS):
                candidate = generate_close_prime_key(modulus_bits,
                                                     65537,
                                                     gap_bits=gap)
                truth = candidate["private_truth"]
                primes = {truth["p"], truth["q"]}
                if primes & used:
                    continue
                used.update(primes)
                truth["case_type"] = "close_prime_gap_{}".format(gap)
                truth["actual_gap"] = abs(truth["q"] - truth["p"])
                cases.append(candidate)
                break
            else:
                raise RuntimeError(
                    "could not generate independent Fermat keys within the "
                    "retry limit")
    case = assemble_dataset(cases, shuffle_seed=4010)
    _validate_fixture(case, profile)
    save_dataset(directory,
                 case["public_keys"],
                 case["private_truth"], [],
                 metadata=profile)
    return directory


def _expected_square_checks(n, positions, method):
    """Count eligible residues arithmetically, outside the measured kernel."""
    if method == "original":
        return positions
    moduli = (64,) if method == "mod64" else KERNELS[method][1]
    period = prod(moduli)
    squares = {m: {value * value % m for value in range(m)} for m in moduli}
    a0 = isqrt(n)
    if a0 * a0 < n:
        a0 += 1
    count = 0
    for residue in range(period):
        if all((residue * residue - n) % m in squares[m] for m in moduli):
            offset = (residue - a0) % period
            if offset < positions:
                count += 1 + (positions - 1 - offset) // period
    return count


def _validate_result(raw, method, n, budget, factors, required):
    """Grade a completed kernel call outside the measured interval."""
    if method == "original" and raw is None:
        p = q = None
        positions = checks = budget
        preprocessing = None
    else:
        size = 3 if method == "original" else 4 if method == "mod64" else 5
        if not isinstance(raw, tuple) or len(raw) != size:
            raise ValueError("Fermat kernel returned a malformed result")
        p, q, positions = raw[:3]
        checks = positions if method == "original" else raw[3]
        preprocessing = raw[4] if size == 5 else None
    success = p is not None or q is not None
    expected_success = required <= budget
    if success != expected_success:
        raise ValueError(
            "Fermat status disagrees with independent search distance and "
            "budget")
    if success and (type(p) is not int or type(q) is not int or p * q != n or
                    tuple(sorted((p, q))) != factors):
        raise ValueError(
            "Fermat factors do not match public n and independent prime truth")
    if type(positions) is not int or positions != min(required, budget):
        raise ValueError(
            "reported position count disagrees with independent search distance"
        )
    if type(checks) is not int or checks != _expected_square_checks(
            n, positions, method):
        raise ValueError(
            "reported square checks disagree with independent residue counts")
    if preprocessing is not None and (isinstance(preprocessing, bool) or
                                      not isinstance(preprocessing,
                                                     (int, float)) or
                                      not 0 <= preprocessing < float("inf")):
        raise ValueError(
            "preprocessing time must be finite nonnegative seconds")
    return {
        "status": "factored" if success else "budget_exhausted",
        "positions_covered": positions,
        "square_checks": checks,
        "preprocessing_seconds": preprocessing,
        "factors_verified": True if success else None,
        "agrees_with_reference": True
    }


def _stats(values):
    """Summarize observed values, keeping an empty sample explicit."""
    return {
        "n": len(values),
        "median": median(values),
        "min": min(values),
        "max": max(values)
    } if values else None


def run_fermat_pilot(dataset_dir, out, budgets=(16, 65536)):
    """Pair all methods on saved public moduli using positive position budgets.

    Only the kernel call is timed. Private validation follows it; exhausted
    searches and errors remain distinct from successful factorizations.
    """
    budgets = list(budgets)
    if not budgets or len(set(budgets)) != len(budgets):
        raise ValueError("budgets must be nonempty and unique")
    for budget in budgets:
        _integer(budget, "position budget", 1)
    output = Path(out)
    if any((output / name).exists() or (output / name).is_symlink()
           for name in OUTPUT_NAMES):
        raise FileExistsError(
            "Fermat outputs already exist; use a new directory")
    public_path, private_path, manifest_path = dataset_paths(dataset_dir)
    case = load_dataset(dataset_dir)
    profile = json.loads(manifest_path.read_text()).get("construction_metadata",
                                                        {})
    reference = _validate_fixture(case, profile)
    input_sha = hashlib.sha256(public_path.read_bytes()).hexdigest()
    source_metadata = _code_metadata()
    run_id = _new_run_id()
    methods = tuple(KERNELS)
    trials, rows, pairings = Counter(), [], []
    for key_index, record in enumerate(case["public_keys"]):
        n, key_id = record["n"], record["key_id"]
        truth = case["private_truth"][key_id]
        gap = int(truth["case_type"][len("close_prime_gap_"):])
        trial = trials[gap]
        trials[gap] += 1
        required = reference["fermat_candidates"][n]
        for budget_index, budget in enumerate(budgets):
            offset = (key_index + budget_index) % len(methods)
            order = methods[offset:] + methods[:offset]
            paired = []
            for method in order:
                row = {
                    "run_id": run_id,
                    "dataset_sha256": input_sha,
                    "key_id": key_id,
                    "trial_index": trial,
                    "gap_bits": gap,
                    "actual_gap_hex": hex(abs(truth["q"] - truth["p"])),
                    "modulus_hex": hex(n),
                    "modulus_bits": n.bit_length(),
                    "position_budget": budget,
                    "method": method,
                    "method_order": ";".join(order),
                    "reference_required_positions": required,
                    "run_status": "error",
                    "error": ""
                }
                kernel, moduli = KERNELS[method]
                options = {} if moduli is None else {"moduli": moduli}
                raw, error = None, None
                start = perf_counter_ns()
                try:
                    raw = kernel(n, budget, **options)
                except Exception as exception:
                    error = exception
                elapsed = (perf_counter_ns() - start) / 1_000_000_000
                row["attempt_seconds"] = elapsed
                try:
                    if error is not None:
                        raise error
                    measurement = _validate_result(raw, method, n, budget,
                                                   reference["factors"][n],
                                                   required)
                    if elapsed < 0 or not elapsed < float("inf"):
                        raise ValueError(
                            "kernel duration must be finite nonnegative seconds"
                        )
                    preprocessing = measurement["preprocessing_seconds"]
                    tolerance = 2 * max(
                        1e-9,
                        get_clock_info("perf_counter").resolution)
                    if (preprocessing is not None and
                            preprocessing > elapsed + tolerance):
                        raise ValueError(
                            "reported preprocessing time exceeds enclosing "
                            "kernel duration")
                    row.update(measurement,
                               kernel_seconds=elapsed,
                               run_status="success")
                except Exception as exception:
                    row["error"] = "{}: {}".format(
                        type(exception).__name__, exception)
                rows.append(row)
                paired.append(row)
            complete = all(row["run_status"] == "success" for row in paired)
            pairings.append({
                "key_id": key_id,
                "position_budget": budget,
                "all_methods_agree": complete and len(
                    {row["status"] for row in paired}) == 1
            })
    baselines = {
        (row["key_id"], row["position_budget"]): row
        for row in rows
        if row["method"] == "original"
    }
    groups = []
    for gap in profile["gap_bits"]:
        for budget in budgets:
            for method in methods:
                selected = [
                    row for row in rows
                    if (row["gap_bits"], row["position_budget"],
                        row["method"]) == (gap, budget, method)
                ]
                accepted = [
                    row for row in selected if row["run_status"] == "success"
                ]
                successful = [
                    row for row in accepted if row["status"] == "factored"
                ]
                ratios = []
                for row in successful:
                    baseline = baselines[row["key_id"], budget]
                    if baseline["run_status"] == "success" and baseline[
                            "status"] == "factored" and row[
                                "kernel_seconds"] > 0:
                        ratios.append(baseline["kernel_seconds"] /
                                      row["kernel_seconds"])
                groups.append({
                    "gap_bits": gap,
                    "position_budget": budget,
                    "method": method,
                    "keys": len(selected),
                    "accepted_runs": len(accepted),
                    "errors": len(selected) - len(accepted),
                    "factored_keys": len(successful),
                    "exhausted_keys": sum(
                        row["status"] == "budget_exhausted" for row in accepted
                    ),
                    "successful_factorization_seconds": _stats(
                        [row["kernel_seconds"] for row in successful]),
                    "accepted_scan_seconds": _stats(
                        [row["kernel_seconds"] for row in accepted]),
                    "square_checks": _stats(
                        [row["square_checks"] for row in accepted]),
                    "paired_success_speedup": _stats(ratios)
                })
    summary = {
        "run_id": run_id,
        "dataset_sha256": input_sha,
        "position_budgets": budgets,
        "gap_bits": profile["gap_bits"],
        "keys_per_gap": profile["keys_per_gap"],
        "num_keys": len(case["public_keys"]),
        "timing_rows": len(rows),
        "groups": groups,
        "pairing_checks": pairings,
        "all_runs_ok": all(row["run_status"] == "success" for row in rows)
                       and all(item["all_methods_agree"] for item in pairings)
    }
    metadata = {
        "format": "weak-rsa-paired-fermat-pilot",
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        **source_metadata, "dataset_directory": str(
            Path(dataset_dir).resolve()),
        "public_sha256": input_sha,
        "private_truth_sha256": hashlib.sha256(private_path.read_bytes()
                                              ).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()
                                         ).hexdigest(),
        "configuration": profile,
        "position_budgets": budgets,
        "methods": list(methods),
        "method_order": "rotate by saved key index plus budget index",
        "warmups": 0,
        "sampling":
            "independent saved keys per gap; each same key paired across "
            "methods/budgets; one call per combination",
        "timing_boundary":
            "external perf_counter_ns around kernel call, including its "
            "per-call preprocessing",
        "excluded_from_timing": [
            "generation", "fixture I/O", "module imports",
            "private reference construction", "factor validation",
            "residue/count checks", "decryption", "reporting"
        ],
        "position_semantics":
            "B bounds consecutive a positions from ceil(sqrt(n)); "
            "square_checks counts actual isqrt tests",
        "preprocessing":
            "wheel kernels report their measured preparation; blank for "
            "kernels without a separate measure",
        "aggregation":
            "successful factorization times separate from accepted scan "
            "attempts; speedups pair successful same-key calls only",
        "decryption": "not measured in this component pilot"
    }
    contents = (_csv_text(rows, FIELDS),
                json.dumps(summary, indent=2, allow_nan=False) + "\n",
                json.dumps(metadata, indent=2, allow_nan=False) + "\n")
    output.mkdir(parents=True, exist_ok=True)
    for name, content in zip(OUTPUT_NAMES, contents):
        with (output / name).open("x", encoding="utf-8",
                                  newline="") as destination:
            destination.write(content)
    return summary
