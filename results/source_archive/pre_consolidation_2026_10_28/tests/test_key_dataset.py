"""Public-input normalization tests."""

import copy
import unittest

from key_dataset import normalize_public_keys, validate_public_records


class PublicKeyNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "B", "n": 253, "e": 17},
            {"key_id": "C", "n": 1147, "e": 17},
            {"key_id": "D", "n": 187, "e": 3},
        ]

    def test_four_records_have_three_unique_moduli_and_preserve_exponents(self):
        result = normalize_public_keys(self.records)
        self.assertEqual(result["num_records"], 4)
        self.assertEqual(result["num_unique_moduli"], 3)
        self.assertEqual(result["duplicate_extra_records"], 1)
        self.assertEqual(result["unique_moduli"], [187, 253, 1147])
        self.assertEqual(result["public_records"], self.records)
        self.assertEqual(result["records_by_modulus"], {
            187: [self.records[0], self.records[3]],
            253: [self.records[1]],
            1147: [self.records[2]],
        })
        self.assertEqual(result["duplicate_groups"], {
            187: [self.records[0], self.records[3]],
        })
        self.assertEqual([r["e"] for r in result["records_by_modulus"][187]], [17, 3])

    def test_empty_and_single_records(self):
        empty = normalize_public_keys([])
        self.assertEqual(empty, {
            "public_records": [], "unique_moduli": [],
            "records_by_modulus": {}, "duplicate_groups": {},
            "num_records": 0, "num_unique_moduli": 0,
            "duplicate_extra_records": 0,
        })
        single = normalize_public_keys(self.records[:1])
        self.assertEqual(single["unique_moduli"], [187])
        self.assertEqual(single["records_by_modulus"], {187: [self.records[0]]})
        self.assertEqual(single["duplicate_groups"], {})
        self.assertEqual(single["num_records"], 1)
        self.assertEqual(single["num_unique_moduli"], 1)
        self.assertEqual(single["duplicate_extra_records"], 0)

    def test_duplicate_only_set_groups_all_records_without_factors(self):
        records = [
            {"key_id": "A", "n": 187, "e": 17},
            {"key_id": "B", "n": 187, "e": 17},
            {"key_id": "C", "n": 187, "e": 3},
        ]
        result = normalize_public_keys(records)
        self.assertEqual(result["unique_moduli"], [187])
        self.assertEqual(result["duplicate_groups"], {187: records})
        self.assertEqual(result["duplicate_extra_records"], 2)
        self.assertTrue(all(set(record) == {"key_id", "n", "e"}
                            for record in result["public_records"]))

    def test_does_not_mutate_or_reuse_callers_dictionaries(self):
        original = copy.deepcopy(self.records)
        result = normalize_public_keys(self.records)
        self.assertEqual(self.records, original)
        for actual, source in zip(result["public_records"], self.records):
            self.assertIsNot(actual, source)
        result["records_by_modulus"][187][0]["e"] = 3
        self.assertEqual(self.records, original)
        self.assertEqual(result["public_records"][0]["e"], 3)

    def test_ciphertext_bytes_are_preserved_exactly_in_validated_copies(self):
        ciphertext = bytes(range(256)) + b"\x00\xff"
        source = {"key_id": "A", "n": 187, "e": 17, "ciphertext": ciphertext}
        result = validate_public_records([source])
        self.assertEqual(result, [source])
        self.assertIsNot(result[0], source)
        self.assertEqual(result[0]["ciphertext"], ciphertext)
        self.assertIsInstance(result[0]["ciphertext"], bytes)
        self.assertEqual(normalize_public_keys(result)["public_records"], [source])
        self.assertEqual(validate_public_records([
            {"key_id": "empty", "n": 187, "e": 17, "ciphertext": b""}
        ])[0]["ciphertext"], b"")

    def test_consumes_input_iterable_once(self):
        class OnePassRecords:
            def __init__(self, records):
                self.records = records
                self.iterations = 0

            def __iter__(self):
                self.iterations += 1
                if self.iterations != 1:
                    raise AssertionError("input iterable was consumed twice")
                return iter(self.records)

        source = OnePassRecords(self.records)
        result = normalize_public_keys(source)
        self.assertEqual(source.iterations, 1)
        self.assertEqual(result["public_records"], self.records)
        generated = normalize_public_keys(record for record in self.records)
        self.assertEqual(generated, result)

    def test_permutation_preserves_groups_but_uses_first_seen_order(self):
        reordered = [self.records[2], self.records[3], self.records[1], self.records[0]]
        before = normalize_public_keys(self.records)
        after = normalize_public_keys(reordered)
        self.assertEqual(after["unique_moduli"], [1147, 187, 253])
        for n in before["unique_moduli"]:
            self.assertEqual(
                {r["key_id"] for r in before["records_by_modulus"][n]},
                {r["key_id"] for r in after["records_by_modulus"][n]},
            )
        self.assertEqual(after["num_records"], before["num_records"])
        self.assertEqual(after["num_unique_moduli"], before["num_unique_moduli"])
        self.assertEqual(after["duplicate_extra_records"], before["duplicate_extra_records"])

    def test_rejects_duplicate_and_blank_ids(self):
        for bad_id, error in (("", ValueError), (" \t\n", ValueError),
                              (None, TypeError), (123, TypeError), (True, TypeError)):
            with self.subTest(key_id=bad_id):
                with self.assertRaises(error):
                    normalize_public_keys([{"key_id": bad_id, "n": 187, "e": 17}])
        for n in (187, 253):
            with self.subTest(second_modulus=n):
                with self.assertRaises(ValueError):
                    normalize_public_keys([
                        {"key_id": "A", "n": 187, "e": 17},
                        {"key_id": "A", "n": n, "e": 3},
                    ])

    def test_rejects_invalid_integer_parameters_and_missing_fields(self):
        for field in ("n", "e"):
            for value in (True, False, 187.0, "187", None):
                record = dict(self.records[0], **{field: value})
                with self.subTest(field=field, value=value):
                    with self.assertRaises(TypeError):
                        normalize_public_keys([record])
            for value in (-187, -1, 0, 1, 2, 188):
                record = dict(self.records[0], **{field: value})
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        normalize_public_keys([record])
        for field in ("key_id", "n", "e"):
            record = dict(self.records[0])
            del record[field]
            with self.subTest(missing=field):
                with self.assertRaises(ValueError):
                    normalize_public_keys([record])

    def test_rejects_secret_labels_and_unknown_fields(self):
        for field in ("p", "q", "d", "case_type", "truth", "private_truth",
                      "group_id", "prime_gap", "vulnerable", "owner", "unknown"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    normalize_public_keys([dict(self.records[0], **{field: None})])

    def test_rejects_nonrecords_noniterables_and_nonbytes_ciphertext(self):
        for records in (None, 123, [None], [187], ["record"], "text", {"key_id": "A"}):
            with self.subTest(records=records):
                with self.assertRaises(TypeError):
                    normalize_public_keys(records)
        for ciphertext in (None, "00ff", bytearray(b"cipher"), [1, 2], 123):
            with self.subTest(ciphertext=ciphertext):
                with self.assertRaises(TypeError):
                    normalize_public_keys([dict(self.records[0], ciphertext=ciphertext)])

    def test_public_validation_does_not_claim_semiprimality_or_invertibility(self):
        # Public validation deliberately cannot infer the unknown factors.
        records = [
            {"key_id": "prime", "n": 101, "e": 3},
            {"key_id": "many_factors", "n": 105, "e": 5},
            {"key_id": "noninvertible", "n": 187, "e": 5},
        ]
        self.assertEqual(validate_public_records(records), records)


if __name__ == "__main__":
    unittest.main()
