"""Save educational public inputs separately from evaluator truth.

Existing v1 fixtures use
decimal integer strings; opt-in v2 fixtures use 0x-prefixed hex integers.
Ciphertexts and expected messages use hex in either version.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform

import Crypto

from key_dataset import normalize_public_keys, validate_public_records


_PUBLIC_FORMATS = {"weak-rsa-public-v1": "decimal", "weak-rsa-public-v2": "hex"}
_PRIVATE_FORMATS = {"weak-rsa-private-v1": "decimal", "weak-rsa-private-v2": "hex"}
_TRUTH_FLAGS = ("intended_weak_generation", "observable_shared_factor")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _read_document(path, expected_formats):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(expected_formats, str):
        expected_formats = (expected_formats,)
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("format"), str)
        or document["format"] not in expected_formats
    ):
        raise ValueError("unsupported fixture format")
    return document


def _positive_integer(value, encoding="decimal"):
    # Never convert arbitrary JSON numbers: int(187.9) silently loses data.
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("fixture integers must be encoded as strings")
    if encoding == "decimal":
        if not value.isdecimal():
            raise ValueError("fixture integers must be positive decimal strings")
        decoded = int(value, 10)
    elif encoding == "hex":
        if not value.startswith("0x") or len(value) <= 2 or not set(value[2:]) <= _HEX_DIGITS:
            raise ValueError("fixture integers must be 0x-prefixed hex strings")
        decoded = int(value[2:], 16)
    else:
        raise ValueError("unsupported integer encoding")
    if decoded <= 0:
        raise ValueError("fixture integers must be positive")
    return decoded


def _decode_bytes(value):
    if not isinstance(value, str) or len(value) % 2 or not set(value) <= _HEX_DIGITS:
        raise ValueError("byte fields must be hex strings with an even number of digits")
    return bytes.fromhex(value)


def _json_bytes(document):
    return (json.dumps(document, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _validate_expected_ids(expected_ids, public_ids):
    if isinstance(expected_ids, (str, bytes)):
        raise ValueError("expected vulnerable IDs must be an iterable of ID strings")
    expected_ids = list(expected_ids)
    if not all(isinstance(key_id, str) and key_id.strip() for key_id in expected_ids):
        raise ValueError("expected vulnerable IDs must be nonblank strings")
    if len(expected_ids) != len(set(expected_ids)):
        raise ValueError("expected vulnerable IDs must be unique")
    if not set(expected_ids).issubset(public_ids):
        raise ValueError("expected vulnerable IDs must occur in the public records")
    return expected_ids


def _validate_truth(private_truth, public_records):
    if not isinstance(private_truth, dict):
        raise ValueError("private_truth must map key IDs to truth records")
    public_by_id = {record["key_id"]: record for record in public_records}
    if set(private_truth) != set(public_by_id):
        raise ValueError("public and private fixture IDs must match")
    for key_id, truth in private_truth.items():
        if not isinstance(truth, dict) or not {"p", "q", "case_type"}.issubset(truth):
            raise ValueError("truth records must contain p, q, and case_type")
        if any(type(truth[field]) is not int or truth[field] <= 1 for field in ("p", "q")):
            raise ValueError("truth factors must be Python integers greater than one")
        if truth["p"] * truth["q"] != public_by_id[key_id]["n"]:
            raise ValueError("truth factors do not match the public modulus")
        if not isinstance(truth["case_type"], str) or not truth["case_type"].strip():
            raise ValueError("case_type must be a nonblank string")
        if "expected_message" in truth and not isinstance(truth["expected_message"], bytes):
            raise ValueError("expected_message must be bytes")
        for flag in _TRUTH_FLAGS:
            if flag in truth and type(truth[flag]) is not bool:
                raise ValueError("{} must be a boolean".format(flag))


def _read_manifest(directory):
    path = Path(directory) / "manifest.json"
    if not path.exists():
        return None
    return _read_document(path, "weak-rsa-manifest-v1")


def _verify_checksum(path, expected, label):
    if not isinstance(expected, str) or len(expected) != 64 or not set(expected) <= _HEX_DIGITS:
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
    if manifest.get("integer_encoding") != _PUBLIC_FORMATS[document["format"]]:
        raise ValueError("integer encoding does not match manifest")
    normalized = normalize_public_keys(public_records)
    for field in ("num_records", "num_unique_moduli", "duplicate_extra_records"):
        if type(manifest.get(field)) is not int or manifest[field] != normalized[field]:
            raise ValueError("{} does not match manifest".format(field))
    bits = sorted({n.bit_length() for n in normalized["unique_moduli"]})
    if manifest.get("modulus_bit_lengths") != bits:
        raise ValueError("modulus bit lengths do not match manifest")


def save_fixtures(directory, public_keys, private_truth, expected_ids, *,
                  integer_encoding="decimal", metadata=None):
    """Save validated fixtures and a checksum manifest without overwriting.

    The default retains the existing v1 decimal schema. integer_encoding='hex'
    selects v2 with 0x-prefixed n/e/p/q strings. Serialization and validation
    finish before any directories or files are created. New files use
    exclusive creation; old fixtures are never rewritten or upgraded in place.
    """
    if integer_encoding not in ("decimal", "hex"):
        raise ValueError("integer_encoding must be 'decimal' or 'hex'")
    if metadata is not None and not isinstance(metadata, dict):
        raise TypeError("metadata must be a dictionary when provided")
    directory = Path(directory)
    paths = [directory / name for name in ("public.json", "private_truth.json", "manifest.json")]
    if any(path.exists() or path.is_symlink() for path in paths):
        raise FileExistsError("fixture files already exist; load them or use a new directory")

    normalized = normalize_public_keys(public_keys)
    public_records = normalized["public_records"]
    _validate_truth(private_truth, public_records)
    expected_ids = _validate_expected_ids(expected_ids, set(private_truth))
    encode = str if integer_encoding == "decimal" else hex
    version = "v1" if integer_encoding == "decimal" else "v2"
    encoded_public = []
    for key in public_records:
        encoded = {"key_id": key["key_id"], "n": encode(key["n"]), "e": encode(key["e"])}
        if "ciphertext" in key:
            encoded["ciphertext_hex"] = key["ciphertext"].hex()
        encoded_public.append(encoded)
    encoded_truth = {}
    for key_id, truth in private_truth.items():
        encoded = {"p": encode(truth["p"]), "q": encode(truth["q"]),
                   "case_type": truth["case_type"]}
        if "expected_message" in truth:
            encoded["expected_message_hex"] = truth["expected_message"].hex()
        for flag in _TRUTH_FLAGS:
            if flag in truth:
                encoded[flag] = truth[flag]
        encoded_truth[key_id] = encoded
    public_document = {
        "format": "weak-rsa-public-" + version,
        "description": "Educational test keys; deliberately weak RSA scenario",
        "encryption": "RSA-OAEP-SHA256", "public_keys": encoded_public,
    }
    private_document = {
        "format": "weak-rsa-private-" + version,
        "description": "Educational evaluator truth; never an attack input",
        "expected_vulnerable_ids": expected_ids, "private_truth": encoded_truth,
    }
    public_bytes = _json_bytes(public_document)
    private_bytes = _json_bytes(private_document)
    manifest = {
        "format": "weak-rsa-manifest-v1",
        "public_format": public_document["format"], "private_format": private_document["format"],
        "integer_encoding": integer_encoding,
        "public_sha256": hashlib.sha256(public_bytes).hexdigest(),
        "private_sha256": hashlib.sha256(private_bytes).hexdigest(),
        "num_records": normalized["num_records"],
        "num_unique_moduli": normalized["num_unique_moduli"],
        "duplicate_extra_records": normalized["duplicate_extra_records"],
        "modulus_bit_lengths": sorted({n.bit_length() for n in normalized["unique_moduli"]}),
        "python_version": platform.python_version(), "pycryptodome_version": Crypto.__version__,
        "platform": platform.platform(),
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if metadata is not None:
        manifest["construction_metadata"] = metadata
    manifest_bytes = _json_bytes(manifest)

    directory.mkdir(parents=True, exist_ok=True)
    for path, content in zip(paths, (public_bytes, private_bytes, manifest_bytes)):
        with path.open("xb") as destination:
            destination.write(content)


def load_public_keys(path):
    """Load/verify public inputs without opening or requiring any truth file."""
    path = Path(path)
    document = _read_document(path, _PUBLIC_FORMATS)
    if document.get("encryption") != "RSA-OAEP-SHA256":
        raise ValueError("unsupported fixture encryption")
    if not isinstance(document.get("public_keys"), list):
        raise ValueError("public_keys must be a list of key records")
    encoding = _PUBLIC_FORMATS[document["format"]]
    decoded = []
    for key in document["public_keys"]:
        if not isinstance(key, dict) or not {"key_id", "n", "e"}.issubset(key):
            raise ValueError("public fixture records need key_id, n, and e")
        if set(key) - {"key_id", "n", "e", "ciphertext_hex"}:
            raise ValueError("public fixture records contain unsupported fields")
        record = {"key_id": key["key_id"], "n": _positive_integer(key["n"], encoding),
                  "e": _positive_integer(key["e"], encoding)}
        if "ciphertext_hex" in key:
            record["ciphertext"] = _decode_bytes(key["ciphertext_hex"])
        decoded.append(record)
    public_records = validate_public_records(decoded)
    _verify_public_manifest(path, document, public_records, _read_manifest(path.parent))
    return public_records


def load_fixtures(directory):
    """Load v1/v2 public fixtures and separate truth used only by evaluation."""
    directory = Path(directory)
    public_keys = load_public_keys(directory / "public.json")
    document = _read_document(directory / "private_truth.json", _PRIVATE_FORMATS)
    manifest = _read_manifest(directory)
    if manifest is not None:
        if manifest.get("private_format") != document["format"]:
            raise ValueError("private schema does not match manifest")
        if manifest.get("integer_encoding") != _PRIVATE_FORMATS[document["format"]]:
            raise ValueError("private integer encoding does not match manifest")
        if "private_sha256" in manifest:
            _verify_checksum(directory / "private_truth.json", manifest["private_sha256"], "private")
    if not isinstance(document.get("private_truth"), dict):
        raise ValueError("private_truth must map key IDs to truth records")
    expected_ids = document.get("expected_vulnerable_ids")
    if not isinstance(expected_ids, list):
        raise ValueError("expected_vulnerable_ids must be a list of strings")
    encoding = _PRIVATE_FORMATS[document["format"]]
    private_truth = {}
    for key_id, truth in document["private_truth"].items():
        if not isinstance(truth, dict) or not {"p", "q", "case_type"}.issubset(truth):
            raise ValueError("truth records must contain p, q, and case_type")
        decoded = {"p": _positive_integer(truth["p"], encoding),
                   "q": _positive_integer(truth["q"], encoding), "case_type": truth["case_type"]}
        if "expected_message_hex" in truth:
            decoded["expected_message"] = _decode_bytes(truth["expected_message_hex"])
        for flag in _TRUTH_FLAGS:
            if flag in truth:
                decoded[flag] = truth[flag]
        private_truth[key_id] = decoded
    _validate_truth(private_truth, public_keys)
    expected_ids = _validate_expected_ids(expected_ids, {key["key_id"] for key in public_keys})
    return {"public_keys": public_keys, "private_truth": private_truth,
            "expected_vulnerable_ids": expected_ids}
