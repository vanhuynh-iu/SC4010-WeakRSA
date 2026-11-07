"""Fixture serialization, separation, and integrity tests."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from shared_prime_fixtures import load_fixtures, load_public_keys, save_fixtures


class SharedPrimeFixtureTests(unittest.TestCase):
    def setUp(self):
        # Arithmetic-only serialization fixtures, not OAEP test keys.
        self.public = [
            {"key_id": "A", "n": 187, "e": 17, "ciphertext": b"\x00\xff\x01"},
            {"key_id": "B", "n": 253, "e": 17, "ciphertext": b"\x01\x00"},
            {"key_id": "C", "n": 187, "e": 3, "ciphertext": b""},
        ]
        self.truth = {
            "A": {"p": 11, "q": 17, "case_type": "shared_prime",
                  "expected_message": b"A\x00", "intended_weak_generation": True,
                  "observable_shared_factor": True},
            "B": {"p": 11, "q": 23, "case_type": "shared_prime",
                  "expected_message": b"B\xff", "intended_weak_generation": True,
                  "observable_shared_factor": True},
            "C": {"p": 11, "q": 17, "case_type": "duplicate",
                  "expected_message": b"", "intended_weak_generation": False,
                  "observable_shared_factor": True},
        }
        self.expected_ids = ["A", "B", "C"]

    def save(self, directory, **kwargs):
        save_fixtures(directory, self.public, self.truth, self.expected_ids, **kwargs)

    def assert_round_trip(self, directory):
        loaded = load_fixtures(directory)
        self.assertEqual(loaded["public_keys"], self.public)
        self.assertEqual(loaded["private_truth"], self.truth)
        self.assertEqual(loaded["expected_vulnerable_ids"], self.expected_ids)

    def test_default_v1_decimal_round_trip_and_truth_separation(self):
        with TemporaryDirectory() as directory:
            self.save(directory)
            self.assert_round_trip(directory)
            public = json.loads((Path(directory) / "public.json").read_text())
            private = json.loads((Path(directory) / "private_truth.json").read_text())
            self.assertEqual(public["format"], "weak-rsa-public-v1")
            self.assertEqual(private["format"], "weak-rsa-private-v1")
            self.assertEqual(public["public_keys"][0]["n"], "187")
            self.assertEqual(public["public_keys"][0]["e"], "17")
            self.assertEqual(private["private_truth"]["A"]["p"], "11")
            for record in public["public_keys"]:
                self.assertEqual(set(record), {"key_id", "n", "e", "ciphertext_hex"})

    def test_v2_hex_round_trip_preserves_flags_and_bytes(self):
        with TemporaryDirectory() as directory:
            self.save(directory, integer_encoding="hex")
            self.assert_round_trip(directory)
            public = json.loads((Path(directory) / "public.json").read_text())
            private = json.loads((Path(directory) / "private_truth.json").read_text())
            self.assertEqual(public["format"], "weak-rsa-public-v2")
            self.assertEqual(private["format"], "weak-rsa-private-v2")
            self.assertEqual(public["public_keys"][0]["n"], "0xbb")
            self.assertEqual(public["public_keys"][0]["e"], "0x11")
            self.assertEqual(private["private_truth"]["A"]["p"], "0xb")
            self.assertEqual(private["private_truth"]["A"]["q"], "0x11")
            self.assertIs(private["private_truth"]["C"]["intended_weak_generation"], False)
            self.assertIs(private["private_truth"]["C"]["observable_shared_factor"], True)

    def test_manifest_has_actual_checksums_counts_versions_and_construction(self):
        with TemporaryDirectory() as directory:
            metadata = {"scenario": "toy duplicates", "seeded": False, "parameters": [3, 2]}
            self.save(directory, integer_encoding="hex", metadata=metadata)
            manifest = json.loads((Path(directory) / "manifest.json").read_text())
            for file_name, field in (("public.json", "public_sha256"),
                                     ("private_truth.json", "private_sha256")):
                actual = hashlib.sha256((Path(directory) / file_name).read_bytes()).hexdigest()
                self.assertEqual(manifest[field], actual)
            self.assertEqual(manifest["format"], "weak-rsa-manifest-v1")
            self.assertEqual(manifest["public_format"], "weak-rsa-public-v2")
            self.assertEqual(manifest["private_format"], "weak-rsa-private-v2")
            self.assertEqual(manifest["integer_encoding"], "hex")
            self.assertEqual(manifest["num_records"], 3)
            self.assertEqual(manifest["num_unique_moduli"], 2)
            self.assertEqual(manifest["duplicate_extra_records"], 1)
            self.assertEqual(manifest["modulus_bit_lengths"], [8])
            self.assertEqual(manifest["construction_metadata"], metadata)
            for field in ("python_version", "pycryptodome_version", "platform"):
                self.assertTrue(manifest[field])
            self.assertTrue(manifest["created_at_utc"].endswith("+00:00"))

    def test_large_integers_remain_exact_in_both_encodings(self):
        # Integers well beyond IEEE-754 precision; no RSA-generation cost.
        p, q = (1 << 1024) + 643, (1 << 1024) + 159
        public = [{"key_id": "large", "n": p * q, "e": (1 << 53) + 1,
                   "ciphertext": bytes(range(256))}]
        truth = {"large": {"p": p, "q": q, "case_type": "serialization_only",
                           "expected_message": b"precision"}}
        for encoding in ("decimal", "hex"):
            with self.subTest(encoding=encoding), TemporaryDirectory() as directory:
                save_fixtures(directory, public, truth, [], integer_encoding=encoding)
                loaded = load_fixtures(directory)
                self.assertEqual(loaded["public_keys"], public)
                self.assertEqual(loaded["private_truth"], truth)

    def test_public_loader_does_not_open_or_require_private_truth(self):
        with TemporaryDirectory() as directory:
            self.save(directory)
            private_path = Path(directory) / "private_truth.json"
            private_path.write_text("this is deliberately not JSON")
            public_path = Path(directory) / "public.json"
            self.assertEqual(load_public_keys(public_path), self.public)
            private_path.unlink()
            self.assertEqual(load_public_keys(public_path), self.public)

    def test_old_v1_without_manifest_still_loads(self):
        with TemporaryDirectory() as directory:
            self.save(directory)
            (Path(directory) / "manifest.json").unlink()
            self.assert_round_trip(directory)
            self.assertFalse((Path(directory) / "manifest.json").exists())

    def test_public_and_private_tampering_are_detected(self):
        for file_name, expected in (("public.json", "public checksum"),
                                    ("private_truth.json", "private checksum")):
            with self.subTest(file=file_name), TemporaryDirectory() as directory:
                self.save(directory)
                path = Path(directory) / file_name
                # A whitespace-only change preserves JSON validity but changes
                # the actual bytes covered by the recorded checksum.
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaisesRegex(ValueError, expected):
                    load_fixtures(directory)

    def test_manifest_public_metadata_is_verified(self):
        changes = {"num_records": 4, "num_unique_moduli": True,
                   "duplicate_extra_records": 0, "modulus_bit_lengths": [2048],
                   "integer_encoding": "decimal", "public_format": "weak-rsa-public-v1"}
        for field, value in changes.items():
            with self.subTest(field=field), TemporaryDirectory() as directory:
                self.save(directory, integer_encoding="hex")
                path = Path(directory) / "manifest.json"
                manifest = json.loads(path.read_text())
                manifest[field] = value
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    load_public_keys(Path(directory) / "public.json")

    def test_existing_files_are_never_overwritten(self):
        with TemporaryDirectory() as directory:
            self.save(directory)
            original = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
            with self.assertRaises(FileExistsError):
                self.save(directory, integer_encoding="hex")
            self.assertEqual({p.name: p.read_bytes() for p in Path(directory).iterdir()}, original)
        for name in ("public.json", "private_truth.json", "manifest.json"):
            with self.subTest(preexisting=name), TemporaryDirectory() as directory:
                path = Path(directory) / name
                path.write_text("preserve me")
                with self.assertRaises(FileExistsError):
                    self.save(directory)
                self.assertEqual(list(Path(directory).iterdir()), [path])
                self.assertEqual(path.read_text(), "preserve me")

    def test_all_validation_and_serialization_happen_before_writes(self):
        public_bad = deepcopy(self.public)
        public_bad[0]["p"] = 11
        truth_bad = deepcopy(self.truth)
        truth_bad["A"]["expected_message"] = "not bytes"
        attempts = (
            (public_bad, self.truth, self.expected_ids, {}),
            (self.public, truth_bad, self.expected_ids, {}),
            (self.public, self.truth, ["missing"], {}),
            (self.public, self.truth, self.expected_ids, {"integer_encoding": "float"}),
            (self.public, self.truth, self.expected_ids, {"metadata": {"bad": object()}}),
            (self.public, self.truth, self.expected_ids, {"metadata": {"bad": float("nan")}}),
        )
        for index, (public, truth, expected, kwargs) in enumerate(attempts):
            with self.subTest(attempt=index), TemporaryDirectory() as parent:
                directory = Path(parent) / "new-set"
                with self.assertRaises((ValueError, TypeError)):
                    save_fixtures(directory, public, truth, expected, **kwargs)
                self.assertFalse(directory.exists())

    def test_optional_ciphertext_and_expected_message_remain_optional(self):
        public = [{"key_id": "A", "n": 187, "e": 17}]
        truth = {"A": {"p": 11, "q": 17, "case_type": "arithmetic"}}
        with TemporaryDirectory() as directory:
            save_fixtures(directory, public, truth, [])
            loaded = load_fixtures(directory)
            self.assertEqual(loaded["public_keys"], public)
            self.assertEqual(loaded["private_truth"], truth)

    def test_rejects_malformed_json_containers_and_public_records(self):
        base = {"format": "weak-rsa-public-v1", "encryption": "RSA-OAEP-SHA256",
                "public_keys": [{"key_id": "A", "n": "187", "e": "17"}]}
        documents = [[], {}, {"format": []}, dict(base, public_keys={}),
                     dict(base, public_keys=[None]), dict(base, public_keys=[{}]),
                     dict(base, public_keys=[{"key_id": "A", "n": "187", "e": "17", "p": "11"}])]
        for document in documents:
            with self.subTest(document=document), TemporaryDirectory() as directory:
                path = Path(directory) / "public.json"
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    load_public_keys(path)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"
            path.write_text("{broken JSON")
            with self.assertRaises(ValueError):
                load_public_keys(path)

    def test_rejects_lossy_integer_encodings_without_manifest(self):
        invalid = {
            "v1": (187.9, 187, True, "1e200", "-1", "0", "1.5", "0xbb", " 187", "١٨٧"),
            "v2": (187.9, 187, True, "187", "bb", "0x", "-0xbb", "0x0", "0xgg", "0x_b"),
        }
        for version, values in invalid.items():
            for value in values:
                with self.subTest(version=version, value=value), TemporaryDirectory() as directory:
                    path = Path(directory) / "public.json"
                    path.write_text(json.dumps({
                        "format": "weak-rsa-public-" + version, "encryption": "RSA-OAEP-SHA256",
                        "public_keys": [{"key_id": "A", "n": value,
                                         "e": "17" if version == "v1" else "0x11"}],
                    }))
                    with self.assertRaises(ValueError):
                        load_public_keys(path)

    def test_rejects_invalid_private_records_without_manifest(self):
        for field, bad in (("p", 11.9), ("q", True), ("case_type", None),
                           ("observable_shared_factor", 1), ("expected_message_hex", [1])):
            with self.subTest(field=field), TemporaryDirectory() as directory:
                self.save(directory)
                (Path(directory) / "manifest.json").unlink()
                path = Path(directory) / "private_truth.json"
                private = json.loads(path.read_text())
                private["private_truth"]["A"][field] = bad
                path.write_text(json.dumps(private))
                with self.assertRaises(ValueError):
                    load_fixtures(directory)


if __name__ == "__main__":
    unittest.main()
