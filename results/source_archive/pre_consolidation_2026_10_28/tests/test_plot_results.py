"""Plotting checks using miniature unit fixtures, not benchmarks.

The made-up CSV values below exist only to verify arithmetic and file handling.
They are never written into project results or used as measured RSA evidence.
"""

import csv
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from plot_results import generate_figures, load_memory_results, load_scalability_results


SCALABILITY_FIELDS = [
    "num_unique_moduli", "algorithm", "gcd_backend", "modulus_bits",
    "topology_profile", "scan_seconds", "run_status", "agrees_with_reference", "gcd_calls",
]
MEMORY_FIELDS = [
    "num_unique_moduli", "algorithm", "gcd_backend", "modulus_bits",
    "topology_profile", "run_status", "agrees_with_reference", "peak_traced_bytes",
    "memory_method", "input_preloaded",
]


def _scalability_row(**changes):
    row = {
        "num_unique_moduli": 10, "algorithm": "pairwise", "gcd_backend": "euclidean",
        "modulus_bits": 2048, "topology_profile": "unit_fixture_only",
        "scan_seconds": 2, "run_status": "success", "agrees_with_reference": True,
        "gcd_calls": 45,
    }
    row.update(changes)
    return row


def _memory_row(**changes):
    row = {
        "num_unique_moduli": 10, "algorithm": "pairwise", "gcd_backend": "euclidean",
        "modulus_bits": 2048, "topology_profile": "unit_fixture_only",
        "run_status": "success", "agrees_with_reference": True,
        "peak_traced_bytes": 1024,
        "memory_method": "tracemalloc_peak_python_allocations", "input_preloaded": True,
    }
    row.update(changes)
    return row


def _write_csv(path, rows, fields=SCALABILITY_FIELDS):
    with Path(path).open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


class ResultAggregationTests(unittest.TestCase):
    def test_known_median_range_and_failed_trial_exclusions(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scalability_results.csv"
            _write_csv(path, [
                _scalability_row(scan_seconds=1),
                _scalability_row(scan_seconds=4),
                _scalability_row(scan_seconds=2),
                _scalability_row(run_status="error", scan_seconds="", gcd_calls=""),
                _scalability_row(scan_seconds=99, agrees_with_reference=False),
            ])
            report = load_scalability_results(path)
            self.assertEqual(len(report["groups"]), 1)
            group = report["groups"][0]
            self.assertEqual(group["trials"], 3)
            self.assertEqual(group["scan_seconds_median"], 2)
            self.assertEqual(group["scan_seconds_min"], 1)
            self.assertEqual(group["scan_seconds_max"], 4)
            self.assertEqual(group["gcd_calls"], 45)
            self.assertEqual(report["source"]["total_rows"], 5)
            self.assertEqual(report["source"]["included_rows"], 3)
            self.assertEqual(report["source"]["excluded_rows"], 2)
            self.assertEqual(report["source"]["exclusion_reasons"], {
                "run_status=error": 1, "reference_disagreement": 1,
            })
            self.assertEqual(report["source"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_backends_sizes_topologies_and_algorithms_remain_separate(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scalability_results.csv"
            _write_csv(path, [
                _scalability_row(),
                _scalability_row(gcd_backend="math.gcd", scan_seconds=6),
                _scalability_row(modulus_bits=1024, scan_seconds=8),
                _scalability_row(modulus_bits="2048;1024", scan_seconds=10),
                _scalability_row(topology_profile="other_unit_fixture", scan_seconds=12),
                _scalability_row(algorithm="batch_with_fallback", gcd_calls=10, scan_seconds=3),
            ])
            groups = load_scalability_results(path)["groups"]
            self.assertEqual(len(groups), 6)
            self.assertEqual(sorted(group["scan_seconds_median"] for group in groups), [2, 3, 6, 8, 10, 12])
            self.assertIn([1024, 2048], [group["modulus_bits"] for group in groups])

    def test_zero_is_kept_only_when_actually_recorded_and_valid(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scalability_results.csv"
            _write_csv(path, [_scalability_row(scan_seconds=0, run_status="ok")])
            self.assertEqual(load_scalability_results(path)["groups"][0]["scan_seconds_median"], 0)
            for invalid in ("", "NaN", "Infinity", -1):
                with self.subTest(scan_seconds=invalid):
                    _write_csv(path, [_scalability_row(scan_seconds=invalid)])
                    with self.assertRaises(ValueError):
                        load_scalability_results(path)

    def test_inconsistent_work_counts_and_missing_fields_are_rejected(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "scalability_results.csv"
            _write_csv(path, [_scalability_row(gcd_calls=45), _scalability_row(gcd_calls=46)])
            with self.assertRaisesRegex(ValueError, "GCD counts vary"):
                load_scalability_results(path)
            _write_csv(path, [], fields=["num_unique_moduli", "scan_seconds"])
            with self.assertRaisesRegex(ValueError, "missing CSV fields"):
                load_scalability_results(path)

    def test_memory_is_separate_and_preloading_conditions_are_not_mixed(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "memory_results.csv"
            _write_csv(path, [
                _memory_row(peak_traced_bytes=1024),
                _memory_row(peak_traced_bytes=3072),
                _memory_row(peak_traced_bytes=8192, input_preloaded=False),
                _memory_row(run_status="error", peak_traced_bytes=""),
                _memory_row(memory_method="process_rss"),
            ], MEMORY_FIELDS)
            report = load_memory_results(path)
            self.assertEqual(len(report["groups"]), 2)
            preloaded = next(group for group in report["groups"] if group["input_preloaded"])
            self.assertEqual(preloaded["peak_traced_bytes_median"], 2048)
            self.assertEqual(preloaded["peak_traced_bytes_min"], 1024)
            self.assertEqual(preloaded["peak_traced_bytes_max"], 3072)
            self.assertEqual(report["source"]["included_rows"], 3)
            self.assertEqual(report["source"]["excluded_rows"], 2)
            self.assertIn("unsupported_memory_method=process_rss", report["source"]["exclusion_reasons"])

    def test_all_failed_rows_cannot_create_figures(self):
        with TemporaryDirectory() as directory:
            results = Path(directory)
            _write_csv(results / "scalability_results.csv", [_scalability_row(run_status="error")])
            with self.assertRaisesRegex(ValueError, "No successful"):
                generate_figures(results)
            self.assertFalse((results / "figures").exists())


@unittest.skipUnless(importlib.util.find_spec("matplotlib") is not None, "optional Matplotlib is not installed")
class PlotOutputTests(unittest.TestCase):
    def test_png_svg_metadata_memory_and_no_overwrite(self):
        with TemporaryDirectory() as directory:
            results = Path(directory)
            _write_csv(results / "scalability_results.csv", [
                _scalability_row(scan_seconds=1),
                _scalability_row(scan_seconds=3),
                _scalability_row(algorithm="batch_with_fallback", gcd_calls=10, scan_seconds=0.5),
                _scalability_row(num_unique_moduli=20, gcd_calls=190, scan_seconds=4),
            ])
            _write_csv(results / "memory_results.csv", [_memory_row()], MEMORY_FIELDS)
            original_csv = (results / "scalability_results.csv").read_bytes()
            metadata = generate_figures(results)
            figures = results / "figures"
            for chart in ("runtime_by_unique_moduli", "gcd_calls_by_unique_moduli", "peak_traced_allocations"):
                png = figures / (chart + ".png")
                svg = figures / (chart + ".svg")
                self.assertTrue(png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))
                self.assertIn("<svg", svg.read_text(encoding="utf-8"))
            self.assertEqual(len(metadata["charts"]), 3)
            self.assertEqual(metadata["sources"]["scalability"]["included_rows"], 4)
            saved = json.loads((figures / "figure_metadata.json").read_text(encoding="utf-8"))
            self.assertEqual(saved, metadata)
            self.assertEqual((results / "scalability_results.csv").read_bytes(), original_csv)
            with self.assertRaises(FileExistsError):
                generate_figures(results)
            # An explicit output directory and overwrite flag are honored.
            alternate = results / "alternate_figures"
            generate_figures(results, alternate)
            generate_figures(results, alternate, overwrite=True)
            self.assertTrue((alternate / "figure_metadata.json").exists())


if __name__ == "__main__":
    unittest.main()
