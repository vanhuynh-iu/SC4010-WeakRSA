"""Validate and deduplicate Van's public RSA records without reading truth."""


from contracts import NormalizedKeySet, PublicKeyRecord


_REQUIRED_FIELDS = {"key_id", "n", "e"}
_PUBLIC_FIELDS = _REQUIRED_FIELDS | {"ciphertext"}


def validate_public_records(records) -> list[PublicKeyRecord]:
    """Copy validated public records, consuming the input once.

    Require unique nonblank IDs, built-in odd n/e > 1, and optional bytes
    ciphertext. Reject unknown/private fields and booleans; inputs are unchanged.
    Public validation does not prove semiprimality or exponent invertibility.
    """
    public_records = []
    seen_ids = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise TypeError("public record {} must be a dictionary".format(index))
        if not _REQUIRED_FIELDS.issubset(record):
            raise ValueError("each public record needs key_id, n, and e")
        if set(record) - _PUBLIC_FIELDS:
            raise ValueError("public records cannot contain unknown or private fields")

        key_id = record["key_id"]
        if not isinstance(key_id, str):
            raise TypeError("key_id must be a string")
        if not key_id.strip():
            raise ValueError("key_id must not be empty or whitespace-only")
        if key_id in seen_ids:
            raise ValueError("key_id values must be unique")

        for field in ("n", "e"):
            value = record[field]
            if type(value) is not int:
                raise TypeError("{} must be a built-in Python integer".format(field))
            if value <= 1 or value % 2 == 0:
                raise ValueError("{} must be odd and greater than one".format(field))
        if "ciphertext" in record and not isinstance(record["ciphertext"], bytes):
            raise TypeError("ciphertext must be bytes")

        copied = {"key_id": key_id, "n": record["n"], "e": record["e"]}
        if "ciphertext" in record:
            copied["ciphertext"] = record["ciphertext"]
        public_records.append(copied)
        seen_ids.add(key_id)

    return public_records


def normalize_public_keys(records) -> NormalizedKeySet:
    """Group validated copies by n, retaining first-seen order and each e.

    records_by_modulus/duplicate_groups reference public_records copies, not
    caller dictionaries. Duplicates alone are not factoring evidence.
    """
    public_records = validate_public_records(records)
    records_by_modulus = {}
    for record in public_records:
        records_by_modulus.setdefault(record["n"], []).append(record)

    unique_moduli = list(records_by_modulus)
    return {
        "public_records": public_records,
        "unique_moduli": unique_moduli,
        "records_by_modulus": records_by_modulus,
        "duplicate_groups": {
            n: group for n, group in records_by_modulus.items() if len(group) > 1
        },
        "num_records": len(public_records),
        "num_unique_moduli": len(unique_moduli),
        "duplicate_extra_records": len(public_records) - len(unique_moduli),
    }
