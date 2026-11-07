"""Lossless RSA fixture I/O with separate public inputs and private answers.

Dataset generation and assembly live in builder.py. Public-only loading never
opens the private-truth file.
"""

from datetime import datetime
from datetime import timezone
import hashlib
import json
from pathlib import Path
import platform

import Crypto

from rsa_auditor.public_inputs import normalize_public_keys
from rsa_auditor.public_inputs import validate_public_records

PUBLIC_FORMAT = "weak-rsa-public"
PRIVATE_FORMAT = "weak-rsa-private"
MANIFEST_FORMAT = "weak-rsa-manifest"
TRUTH_FLAGS = ("intended_weak_generation", "observable_shared_factor")
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def dataset_paths(public_directory, private_directory=None):
    """Return public, private-truth and manifest paths.

    Map public/name to private/name; custom folders default to _private.
    """
    public_directory = Path(public_directory)
    if private_directory is None:
        parts = public_directory.parts
        positions = [
            index for index, part in enumerate(parts) if part == "public"
        ]
        if positions:
            index = positions[-1]
            private_directory = Path(*parts[:index], "private",
                                     *parts[index + 1:])
        else:
            private_directory = public_directory / "_private"
    private_directory = Path(private_directory)
    if private_directory.resolve() == public_directory.resolve():
        raise ValueError(
            "private truth must be stored separately from the public directory")
    return (public_directory / "public.json",
            private_directory / "private_truth.json",
            public_directory / "manifest.json")


def _read_document(path, expected_format):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document,
                      dict) or document.get("format") != expected_format:
        raise ValueError("unsupported fixture format")
    return document


def _positive_integer(value):
    # Never convert arbitrary JSON numbers: int(187.9) silently loses data.
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("fixture integers must be encoded as strings")
    valid_prefix = value.startswith("0x") and len(value) > 2
    valid_digits = set(value[2:]) <= HEX_DIGITS
    if not valid_prefix or not valid_digits:
        raise ValueError("fixture integers must be 0x-prefixed hex strings")
    decoded = int(value[2:], 16)
    if decoded <= 0:
        raise ValueError("fixture integers must be positive")
    return decoded


def _decode_bytes(value):
    if not isinstance(value, str):
        raise ValueError(
            "byte fields must be hex strings with an even number of digits")
    if len(value) % 2 or not set(value) <= HEX_DIGITS:
        raise ValueError(
            "byte fields must be hex strings with an even number of digits")
    return bytes.fromhex(value)


def _json_bytes(document):
    return (json.dumps(document, indent=2, allow_nan=False) +
            "\n").encode("utf-8")


def _validate_expected_ids(expected_ids, public_ids):
    if isinstance(expected_ids, (str, bytes)):
        raise ValueError(
            "expected vulnerable IDs must be an iterable of ID strings")
    expected_ids = list(expected_ids)
    if not all(
            isinstance(key_id, str) and key_id.strip()
            for key_id in expected_ids):
        raise ValueError("expected vulnerable IDs must be nonblank strings")
    if len(expected_ids) != len(set(expected_ids)):
        raise ValueError("expected vulnerable IDs must be unique")
    if not set(expected_ids).issubset(public_ids):
        raise ValueError(
            "expected vulnerable IDs must occur in the public records")
    return expected_ids


def validate_private_truth(private_truth, public_records):
    """Check private answers against public IDs, moduli and field types."""
    if not isinstance(private_truth, dict):
        raise ValueError("private_truth must map key IDs to truth records")
    public_by_id = {record["key_id"]: record for record in public_records}
    if set(private_truth) != set(public_by_id):
        raise ValueError("public and private fixture IDs must match")
    for key_id, truth in private_truth.items():
        if not isinstance(truth, dict) or not {"p", "q", "case_type"
                                              }.issubset(truth):
            raise ValueError("truth records must contain p, q, and case_type")
        if any(
                type(truth[field]) is not int or truth[field] <= 1
                for field in ("p", "q")):
            raise ValueError(
                "truth factors must be Python integers greater than one")
        if truth["p"] * truth["q"] != public_by_id[key_id]["n"]:
            raise ValueError("truth factors do not match the public modulus")
        if not isinstance(truth["case_type"],
                          str) or not truth["case_type"].strip():
            raise ValueError("case_type must be a nonblank string")
        if "expected_message" in truth and not isinstance(
                truth["expected_message"], bytes):
            raise ValueError("expected_message must be bytes")
        if "actual_gap" in truth:
            gap = truth["actual_gap"]
            if type(gap) is not int or gap <= 0 or gap != abs(truth["p"] -
                                                              truth["q"]):
                raise ValueError(
                    "actual_gap must be a positive integer equal to abs(p-q)")
        for flag in TRUTH_FLAGS:
            if flag in truth and type(truth[flag]) is not bool:
                raise ValueError("{} must be a boolean".format(flag))


def _read_manifest(directory):
    path = Path(directory) / "manifest.json"
    if not path.exists():
        return None
    return _read_document(path, MANIFEST_FORMAT)


def _verify_checksum(path, expected, label):
    if not isinstance(expected, str) or len(
            expected) != 64 or not set(expected) <= HEX_DIGITS:
        raise ValueError("invalid {} checksum in manifest".format(label))
    actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if actual != expected.lower():
        raise ValueError("{} checksum does not match manifest".format(label))


def _verify_public_manifest(path, document, public_records, manifest):
    if manifest is None:
        return
    _verify_checksum(path, manifest.get("public_sha256"), "public")
    if manifest.get("public_format") != document["format"]:
        raise ValueError("public schema does not match manifest")
    normalized = normalize_public_keys(public_records)
    for field in ("num_records", "num_unique_moduli",
                  "duplicate_extra_records"):
        if type(manifest.get(
                field)) is not int or manifest[field] != normalized[field]:
            raise ValueError("{} does not match manifest".format(field))
    bits = sorted({n.bit_length() for n in normalized["unique_moduli"]})
    if manifest.get("modulus_bit_lengths") != bits:
        raise ValueError("modulus bit lengths do not match manifest")


def save_dataset(directory,
                 public_keys,
                 private_truth,
                 expected_ids,
                 *,
                 private_directory=None,
                 metadata=None):
    """Validate and save hex JSON and checksums without overwriting files."""
    if metadata is not None and not isinstance(metadata, dict):
        raise TypeError("metadata must be a dictionary when provided")
    directory = Path(directory)
    paths = dataset_paths(directory, private_directory)
    if any(path.exists() or path.is_symlink() for path in paths):
        raise FileExistsError(
            "fixture files already exist; load them or use a new directory")

    normalized = normalize_public_keys(public_keys)
    public_records = normalized["public_records"]
    validate_private_truth(private_truth, public_records)
    expected_ids = _validate_expected_ids(expected_ids, set(private_truth))
    encoded_public = []
    for key in public_records:
        encoded = {
            "key_id": key["key_id"],
            "n": hex(key["n"]),
            "e": hex(key["e"])
        }
        if "ciphertext" in key:
            encoded["ciphertext_hex"] = key["ciphertext"].hex()
        encoded_public.append(encoded)
    encoded_truth = {}
    for key_id, truth in private_truth.items():
        encoded = {
            "p": hex(truth["p"]),
            "q": hex(truth["q"]),
            "case_type": truth["case_type"]
        }
        if "expected_message" in truth:
            encoded["expected_message_hex"] = truth["expected_message"].hex()
        if "actual_gap" in truth:
            encoded["actual_gap"] = hex(truth["actual_gap"])
        for flag in TRUTH_FLAGS:
            if flag in truth:
                encoded[flag] = truth[flag]
        encoded_truth[key_id] = encoded
    public_document = {
        "format": PUBLIC_FORMAT,
        "description": "Educational test keys; deliberately weak RSA scenario",
        "encryption": "RSA-OAEP-SHA256",
        "public_keys": encoded_public,
    }
    private_document = {
        "format": PRIVATE_FORMAT,
        "description": "Educational evaluator truth; never an attack input",
        "expected_vulnerable_ids": expected_ids,
        "private_truth": encoded_truth,
    }
    public_bytes = _json_bytes(public_document)
    private_bytes = _json_bytes(private_document)
    manifest = {
        "format": MANIFEST_FORMAT,
        "public_format": public_document["format"],
        "private_format": private_document["format"],
        "public_sha256": hashlib.sha256(public_bytes).hexdigest(),
        "private_sha256": hashlib.sha256(private_bytes).hexdigest(),
        "num_records": normalized["num_records"],
        "num_unique_moduli": normalized["num_unique_moduli"],
        "duplicate_extra_records": normalized["duplicate_extra_records"],
        "modulus_bit_lengths": sorted(
            {n.bit_length() for n in normalized["unique_moduli"]}),
        "python_version": platform.python_version(),
        "pycryptodome_version": Crypto.__version__,
        "platform": platform.platform(),
        "created_at_utc": datetime.now(timezone.utc
                                      ).isoformat(timespec="seconds"),
    }
    if metadata is not None:
        manifest["construction_metadata"] = metadata
    manifest_bytes = _json_bytes(manifest)

    for parent in {path.parent for path in paths}:
        parent.mkdir(parents=True, exist_ok=True)
    for path, content in zip(paths,
                             (public_bytes, private_bytes, manifest_bytes)):
        with path.open("xb") as destination:
            destination.write(content)


def load_public_keys(path) -> list[dict]:
    """Load and verify public records without reading private truth."""
    path = Path(path)
    document = _read_document(path, PUBLIC_FORMAT)
    if document.get("encryption") != "RSA-OAEP-SHA256":
        raise ValueError("unsupported fixture encryption")
    if not isinstance(document.get("public_keys"), list):
        raise ValueError("public_keys must be a list of key records")
    decoded = []
    for key in document["public_keys"]:
        if not isinstance(key, dict) or not {"key_id", "n", "e"}.issubset(key):
            raise ValueError("public fixture records need key_id, n, and e")
        if set(key) - {"key_id", "n", "e", "ciphertext_hex"}:
            raise ValueError(
                "public fixture records contain unsupported fields")
        record = {
            "key_id": key["key_id"],
            "n": _positive_integer(key["n"]),
            "e": _positive_integer(key["e"])
        }
        if "ciphertext_hex" in key:
            record["ciphertext"] = _decode_bytes(key["ciphertext_hex"])
        decoded.append(record)
    public_records = validate_public_records(decoded)
    _verify_public_manifest(path, document, public_records,
                            _read_manifest(path.parent))
    return public_records


def load_dataset(directory, private_directory=None) -> dict:
    """Load public records and private truth for assembly or evaluation."""
    directory = Path(directory)
    public_path, private_path, _ = dataset_paths(directory, private_directory)
    public_keys = load_public_keys(public_path)
    document = _read_document(private_path, PRIVATE_FORMAT)
    manifest = _read_manifest(directory)
    if manifest is not None:
        if manifest.get("private_format") != document["format"]:
            raise ValueError("private schema does not match manifest")
        if "private_sha256" in manifest:
            _verify_checksum(private_path, manifest["private_sha256"],
                             "private")
    if not isinstance(document.get("private_truth"), dict):
        raise ValueError("private_truth must map key IDs to truth records")
    expected_ids = document.get("expected_vulnerable_ids")
    if not isinstance(expected_ids, list):
        raise ValueError("expected_vulnerable_ids must be a list of strings")
    private_truth = {}
    for key_id, truth in document["private_truth"].items():
        if not isinstance(truth, dict) or not {"p", "q", "case_type"
                                              }.issubset(truth):
            raise ValueError("truth records must contain p, q, and case_type")
        decoded = {
            "p": _positive_integer(truth["p"]),
            "q": _positive_integer(truth["q"]),
            "case_type": truth["case_type"]
        }
        if "expected_message_hex" in truth:
            decoded["expected_message"] = _decode_bytes(
                truth["expected_message_hex"])
        if "actual_gap" in truth:
            decoded["actual_gap"] = _positive_integer(truth["actual_gap"])
        for flag in TRUTH_FLAGS:
            if flag in truth:
                decoded[flag] = truth[flag]
        private_truth[key_id] = decoded
    validate_private_truth(private_truth, public_keys)
    expected_ids = _validate_expected_ids(
        expected_ids, {key["key_id"] for key in public_keys})
    return {
        "public_keys": public_keys,
        "private_truth": private_truth,
        "expected_vulnerable_ids": expected_ids
    }
