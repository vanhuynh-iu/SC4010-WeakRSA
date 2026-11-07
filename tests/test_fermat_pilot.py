"""Small arithmetic fixtures test the pilot; these are not project findings."""

from contextlib import redirect_stdout
from copy import deepcopy
import csv
import hashlib
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from rsa_auditor.datasets.storage import load_dataset, save_dataset
from rsa_auditor.experiments import cli, fermat_pilot as pilot


def generated(p, q):
    return {"public_key": {"key_id": "generator_label", "n": p * q, "e": 65537},
            "private_truth": {"p": p, "q": q, "case_type": "close_prime", "actual_gap": q - p}}


class FermatPilotTests(unittest.TestCase):
    def save_case(self, directory, p=40009, q=60013, gap=13):
        metadata = {"study": "paired_fermat_pilot", "gap_bits": [gap], "keys_per_gap": 1,
                    "modulus_bits": 32, "e": 65537}
        public = [{"key_id": "key_001", "n": p * q, "e": 65537}]
        truth = {"key_001": {"p": p, "q": q, "actual_gap": q - p,
                              "case_type": "close_prime_gap_{}".format(gap)}}
        save_dataset(directory, public, truth, [], metadata=metadata)
        return Path(directory)

    def rows(self, directory):
        with (Path(directory) / "fermat_results.csv").open(newline="") as source:
            return list(csv.DictReader(source))

    def test_prepare_saves_neutral_public_inputs_and_reuses_exact_bytes(self):
        with TemporaryDirectory() as root:
            directory = Path(root) / "public" / "pilot"
            cases = [generated(65519, 65521), generated(65519, 65521), generated(65479, 65497)]
            with patch.object(pilot, "generate_close_prime_key", side_effect=deepcopy(cases)) as generate:
                self.assertEqual(pilot.prepare_fermat_dataset(directory, [1], 2, 32), directory)
            self.assertEqual(generate.call_count, 3)  # Reused primes were retried.
            document = json.loads((directory / "public.json").read_text())
            self.assertEqual({record["key_id"] for record in document["public_keys"]}, {"key_001", "key_002"})
            self.assertTrue(all(set(record) == {"key_id", "n", "e"} for record in document["public_keys"]))
            case = load_dataset(directory)
            self.assertTrue(all(item["case_type"] == "close_prime_gap_1" for item in case["private_truth"].values()))
            originals = {path: path.read_bytes() for path in (directory / "public.json", directory / "manifest.json",
                                                              Path(root) / "private" / "pilot" / "private_truth.json")}
            with patch.object(pilot, "generate_close_prime_key", side_effect=AssertionError("must reuse saved input")):
                pilot.prepare_fermat_dataset(directory, [1], 2, 32)
                with self.assertRaisesRegex(ValueError, "requested settings"):
                    pilot.prepare_fermat_dataset(directory, [2], 2, 32)
            self.assertTrue(all(path.read_bytes() == value for path, value in originals.items()))

    def test_prepare_collision_limit_and_bad_parameters_create_no_files(self):
        with TemporaryDirectory() as root:
            directory = Path(root) / "input"
            with patch.object(pilot, "generate_close_prime_key", return_value=generated(65519, 65521)), \
                 patch.object(pilot, "_MAX_PRIME_REUSE_ATTEMPTS", 1):
                with self.assertRaisesRegex(RuntimeError, "independent"):
                    pilot.prepare_fermat_dataset(directory, [1], 2, 32)
            self.assertFalse(directory.exists())
            with patch.object(pilot, "generate_close_prime_key", side_effect=AssertionError("invalid parameters must not generate")):
                for options in (([], 1, 32), ([1, 1], 1, 32), ([True], 1, 32), ([1], 0, 32), ([1], 1, 31)):
                    with self.assertRaises(ValueError):
                        pilot.prepare_fermat_dataset(directory, *options)

    def test_paired_kernels_respect_exact_budget_boundary_and_same_public_n(self):
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "input")
            output = Path(root) / "output"
            calls = []
            real = pilot.KERNELS.copy()
            def observed(name, kernel):
                def run(n, budget, **options):
                    self.assertIs(type(n), int)
                    self.assertTrue(set(options) <= {"moduli"})
                    calls.append((name, n, budget))
                    return kernel(n, budget, **options)
                return run
            kernels = {name: (observed(name, kernel), moduli) for name, (kernel, moduli) in real.items()}
            original = (directory / "public.json").read_bytes()
            with patch.object(pilot, "KERNELS", kernels), \
                 patch.object(pilot, "generate_close_prime_key", side_effect=AssertionError("no generation while measuring")):
                summary = pilot.run_fermat_pilot(directory, output, [1010, 1011])
            self.assertTrue(summary["all_runs_ok"])
            self.assertEqual(len(calls), 8)
            self.assertEqual({n for _, n, _ in calls}, {40009 * 60013})
            self.assertEqual((directory / "public.json").read_bytes(), original)
            rows = self.rows(output)
            self.assertEqual({row["status"] for row in rows if row["position_budget"] == "1010"}, {"budget_exhausted"})
            self.assertEqual({row["status"] for row in rows if row["position_budget"] == "1011"}, {"factored"})
            self.assertTrue(all(row["positions_covered"] == row["position_budget"] for row in rows))
            self.assertTrue(all(row["reference_required_positions"] == "1011" for row in rows))
            self.assertTrue(all(row["factors_verified"] == "True" for row in rows if row["status"] == "factored"))
            self.assertTrue(all(group["successful_factorization_seconds"] is None for group in summary["groups"] if group["position_budget"] == 1010))
            self.assertTrue(all(group["paired_success_speedup"] is None for group in summary["groups"] if group["position_budget"] == 1010))
            self.assertEqual(len({row["method_order"] for row in rows}), 2)
            metadata = json.loads((output / "run_metadata.json").read_text())
            self.assertEqual(metadata["public_sha256"], hashlib.sha256(original).hexdigest())
            self.assertIn("rsa_auditor/attacks/fermat.py", metadata["source_sha256"])
            self.assertIn("factor validation", metadata["excluded_from_timing"])

    def test_first_candidate_counts_as_one_for_every_method(self):
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "input", 65519, 65521, 1)
            output = Path(root) / "output"
            summary = pilot.run_fermat_pilot(directory, output, [1])
            self.assertTrue(summary["all_runs_ok"])
            self.assertTrue(all(row["positions_covered"] == row["square_checks"] == "1" for row in self.rows(output)))

    def test_fabricated_position_and_square_check_counts_are_rejected(self):
        for method, index in (("original", 2), ("mod64", 3), ("wheel_6720", 4)):
            with self.subTest(method=method), TemporaryDirectory() as root:
                directory = self.save_case(Path(root) / "input")
                output = Path(root) / "output"
                kernels = pilot.KERNELS.copy()
                kernel, moduli = kernels[method]
                def wrong(n, budget, **options):
                    result = list(kernel(n, budget, **options))
                    result[index] = 1000 if index == 4 else result[index] + 1
                    return tuple(result)
                kernels[method] = (wrong, moduli)
                with patch.object(pilot, "KERNELS", kernels):
                    summary = pilot.run_fermat_pilot(directory, output, [1011])
                self.assertFalse(summary["all_runs_ok"])
                failed = next(row for row in self.rows(output) if row["method"] == method)
                self.assertEqual(failed["run_status"], "error")
                self.assertEqual(failed["kernel_seconds"], "")
                self.assertNotEqual(failed["attempt_seconds"], "")
                self.assertIn("preprocessing" if index == 4 else "independent", failed["error"])

    def test_output_protection_invalid_budgets_and_corrupt_fixture(self):
        with TemporaryDirectory() as root:
            directory = self.save_case(Path(root) / "input")
            output = Path(root) / "output"
            output.mkdir()
            (output / "summary.json").write_text("preserve")
            blocked_kernel = Mock(side_effect=AssertionError("must not measure"))
            kernels = {name: (blocked_kernel, moduli)
                       for name, (_, moduli) in pilot.KERNELS.items()}
            with patch.object(pilot, "KERNELS", kernels):
                with self.assertRaises(FileExistsError):
                    pilot.run_fermat_pilot(directory, output)
                for budgets in ([], [1, 1], [0], [True], [-1]):
                    with self.assertRaises(ValueError):
                        pilot.run_fermat_pilot(directory, Path(root) / "unused", budgets)
                public_path = directory / "public.json"
                public_path.write_text(public_path.read_text() + " ")
                with self.assertRaisesRegex(ValueError, "checksum"):
                    pilot.run_fermat_pilot(directory, Path(root) / "unused", [1])
            blocked_kernel.assert_not_called()
            self.assertEqual((output / "summary.json").read_text(), "preserve")

    def test_cli_pilot_and_stress_routes_use_fresh_defaults_without_fixed_profile_generation(self):
        with patch.object(pilot, "prepare_fermat_dataset") as prepare, \
             patch.object(pilot, "run_fermat_pilot", return_value={"all_runs_ok": True}) as run, \
             redirect_stdout(StringIO()):
            self.assertEqual(cli.main(["--mode", "fermat-pilot", "--fermat-dataset", "fixture"]), 0)
            prepare.assert_called_once_with("fixture", [515, 518, 520], 3, 2048)
            run.assert_called_once_with("fixture", "results/fermat", [16, 65536])
        with patch.object(cli, "run_scalability_experiment", return_value={"all_runs_ok": True}) as stress, \
             patch.object(cli, "prepare_scalability_datasets", side_effect=AssertionError("stress must reuse mixed input")), \
             redirect_stdout(StringIO()):
            self.assertEqual(cli.main(["--mode", "stress"]), 0)
            stress.assert_called_once_with(["data/public/gcd_mixed"], "results/gcd/stress", 5, 1, "euclidean", True)


if __name__ == "__main__":
    unittest.main()
