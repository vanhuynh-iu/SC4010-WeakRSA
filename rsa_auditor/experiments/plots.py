"""Validate, aggregate, and draw saved measurements without running attacks."""

from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
from statistics import median


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
        cache = Path(__file__).resolve().parents[2] / ".cache" / "matplotlib"
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
