"""Common mixed fixtures retain the public/private boundary and intended sharing."""

from collections import Counter, defaultdict
from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import random
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from rsa_auditor import build_dataset
from rsa_auditor import dataset_io
from rsa_auditor.build_dataset import generate_auditor_dataset
from rsa_auditor.generators.close_prime_cases import generate_close_prime_key
from rsa_auditor.generators.shared_prime_cases import generate_shared_prime_keys
from rsa_auditor.normalization import normalize_public_keys


class AuditorDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = generate_shared_prime_keys(4, 2, 64)
        used = {prime for truth in cls.base["private_truth"].values()
                for prime in (truth["p"], truth["q"])}
        cls.close_cases = []
        for gap_bits in (19, 21, 24):
            while True:
                case = generate_close_prime_key(64, gap_bits=gap_bits)
                truth = case["private_truth"]
                primes = {truth["p"], truth["q"]}
                if not primes & used:
                    used.update(primes)
                    cls.close_cases.append(case)
                    break

    def generate_fixed(self, **kwargs):
        with patch("rsa_auditor.generators.shared_prime_cases.generate_shared_prime_keys", return_value=deepcopy(self.base)), \
             patch("rsa_auditor.generators.close_prime_cases.generate_close_prime_key", side_effect=deepcopy(self.close_cases)):
            return generate_auditor_dataset(64, **kwargs)

    def test_default_composition_has_only_intended_shared_factors(self):
        case = generate_auditor_dataset(64)
        normalized = normalize_public_keys(case["public_keys"])
        self.assertEqual(normalized["num_records"], 8)
        self.assertEqual(normalized["num_unique_moduli"], 7)
        self.assertEqual(normalized["duplicate_extra_records"], 1)
        self.assertEqual([record["key_id"] for record in case["public_keys"]],
                         ["key_{:03d}".format(index) for index in range(1, 9)])
        self.assertEqual(Counter(truth["case_type"] for truth in case["private_truth"].values()),
                         {"shared_prime": 3, "control": 2, "close_prime": 3})
        prime_moduli = defaultdict(set)
        for record in case["public_keys"]:
            self.assertEqual(set(record), {"key_id", "n", "e"})
            self.assertEqual(record["n"].bit_length(), 64)
            truth = case["private_truth"][record["key_id"]]
            self.assertEqual(truth["actual_gap"], abs(truth["p"] - truth["q"]))
            for prime in (truth["p"], truth["q"]):
                prime_moduli[prime].add(record["n"])
            self.assertEqual(truth["observable_shared_factor"], truth["case_type"] == "shared_prime")
        self.assertEqual(sorted(len(moduli) for moduli in prime_moduli.values() if len(moduli) > 1), [2])
        expected = {record["key_id"] for record in case["public_keys"]
                    if case["private_truth"][record["key_id"]]["case_type"] == "shared_prime"}
        self.assertEqual(set(case["expected_vulnerable_ids"]), expected)

    def test_fixed_shuffle_is_repeatable_without_changing_global_random_state(self):
        state = random.getstate()
        first = self.generate_fixed()
        second = self.generate_fixed()
        self.assertEqual(first, second)
        self.assertEqual(random.getstate(), state)
        unshuffled = self.generate_fixed(shuffle_seed=None)
        self.assertNotEqual(first["public_keys"], unshuffled["public_keys"])
        self.assertEqual(Counter(record["n"] for record in first["public_keys"]),
                         Counter(record["n"] for record in unshuffled["public_keys"]))

    def test_duplicate_can_be_omitted_or_selected_from_original_records(self):
        case = self.generate_fixed(duplicate_indices=(), shuffle_seed=None)
        self.assertEqual(len(case["public_keys"]), 7)
        self.assertEqual(len({record["n"] for record in case["public_keys"]}), 7)
        copied = self.generate_fixed(duplicate_indices=(6,), shuffle_seed=None)
        self.assertEqual(copied["public_keys"][6]["n"], copied["public_keys"][7]["n"])
        self.assertEqual(copied["private_truth"]["key_008"]["case_type"], "close_prime")
        self.assertEqual(len(copied["expected_vulnerable_ids"]), 2)

    def collision(self):
        public = deepcopy(self.base["public_keys"][0])
        truth = deepcopy(self.base["private_truth"][public["key_id"]])
        truth.update(case_type="close_prime", actual_gap=abs(truth["p"] - truth["q"]))
        return {"public_key": public, "private_truth": truth}

    def test_accidental_cross_source_sharing_is_retried(self):
        cases = [self.collision()] + deepcopy(self.close_cases)
        with patch("rsa_auditor.generators.shared_prime_cases.generate_shared_prime_keys", return_value=deepcopy(self.base)), \
             patch("rsa_auditor.generators.close_prime_cases.generate_close_prime_key", side_effect=cases) as close:
            case = generate_auditor_dataset(64)
        self.assertEqual(close.call_count, 4)
        self.assertEqual(len({record["n"] for record in case["public_keys"]}), 7)

    def test_repeated_collisions_fail_with_a_bounded_retry_count(self):
        with patch("rsa_auditor.generators.shared_prime_cases.generate_shared_prime_keys", return_value=deepcopy(self.base)), \
             patch("rsa_auditor.generators.close_prime_cases.generate_close_prime_key", return_value=self.collision()) as close, \
             patch("rsa_auditor.build_dataset._MAX_AUDITOR_CASE_ATTEMPTS", 3):
            with self.assertRaisesRegex(RuntimeError, "within 3 attempts"):
                generate_auditor_dataset(64)
        self.assertEqual(close.call_count, 3)

    def test_wrong_modulus_length_is_not_silently_accepted(self):
        malformed = {"public_key": {"key_id": "local", "n": 65537 * 65539, "e": 65537},
                     "private_truth": {"p": 65537, "q": 65539, "case_type": "close_prime"}}
        with patch("rsa_auditor.generators.shared_prime_cases.generate_shared_prime_keys", return_value=deepcopy(self.base)), \
             patch("rsa_auditor.generators.close_prime_cases.generate_close_prime_key", return_value=malformed):
            with self.assertRaisesRegex(ValueError, "incompatible RSA parameters"):
                generate_auditor_dataset(64)

    def test_invalid_assembly_options_fail_before_generation(self):
        attempts = (
            {"modulus_bits": True}, {"modulus_bits": 32}, {"modulus_bits": 65},
            {"shuffle_seed": True}, {"duplicate_indices": "0"},
            {"duplicate_indices": (True,)}, {"duplicate_indices": (-1,)},
            {"duplicate_indices": (7,)},
        )
        with patch("rsa_auditor.generators.shared_prime_cases.generate_shared_prime_keys") as generate:
            for options in attempts:
                with self.subTest(options=options), self.assertRaises((TypeError, ValueError)):
                    generate_auditor_dataset(**options)
        generate.assert_not_called()

    def test_cli_saves_common_fixture_and_records_default_ordering(self):
        with TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            self.assertEqual(build_dataset.main([
                "--case", "auditor", "--bits", "64", "--name", "auditor_test", "--data-root", directory,
            ]), 0)
            public_directory = Path(directory) / "public" / "auditor_test"
            public_path, private_path, manifest_path = dataset_io.dataset_paths(public_directory)
            self.assertEqual(private_path.parent, Path(directory) / "private" / "auditor_test")
            case = dataset_io.load_dataset(public_directory)
            self.assertEqual(len(case["public_keys"]), 8)
            self.assertEqual(len(dataset_io.load_public_keys(public_path)), 8)
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["construction_metadata"], {
                "profile": "auditor", "duplicate_indices": [0], "shuffle_seed": 4010,
            })
            self.assertEqual(manifest["modulus_bit_lengths"], [64])
            for record in json.loads(public_path.read_text())["public_keys"]:
                self.assertEqual(set(record), {"key_id", "n", "e"})

    def test_legacy_dataset_io_exports_refer_to_the_shared_implementation(self):
        for name in ("dataset_paths", "save_dataset", "load_dataset", "load_public_keys"):
            self.assertIs(getattr(build_dataset, name), getattr(dataset_io, name))


if __name__ == "__main__":
    unittest.main()
