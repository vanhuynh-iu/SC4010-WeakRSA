"""Build, combine and store synthetic RSA datasets with separate public/private files."""

from copy import deepcopy
from datetime import datetime, timezone
import argparse
import hashlib
import json
from math import gcd
from pathlib import Path
import platform
import random
from typing import Iterable

import Crypto
from Crypto.Util.number import isPrime

from contracts import DatasetCase, GeneratorCase, PublicKeyRecord
from normalization import normalize_public_keys, validate_public_records


_PUBLIC_FORMAT = "weak-rsa-public"
_PRIVATE_FORMAT = "weak-rsa-private"
_MANIFEST_FORMAT = "weak-rsa-manifest"
_TRUTH_FLAGS = ("intended_weak_generation", "observable_shared_factor")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def dataset_paths(public_directory, private_directory=None):
    """Return public, private-truth and manifest paths.

    Map public/name to private/name; custom folders use _private unless supplied.
    """
    public_directory = Path(public_directory)
    if private_directory is None:
        parts = public_directory.parts
        positions = [index for index, part in enumerate(parts) if part == "public"]
        if positions:
            index = positions[-1]
            private_directory = Path(*parts[:index], "private", *parts[index + 1:])
        else:
            private_directory = public_directory / "_private"
    private_directory = Path(private_directory)
    if private_directory.resolve() == public_directory.resolve():
        raise ValueError("private truth must be stored separately from the public directory")
    return (public_directory / "public.json", private_directory / "private_truth.json",
            public_directory / "manifest.json")


def _read_document(path, expected_format):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("format"), str)
        or document["format"] != expected_format
    ):
        raise ValueError("unsupported fixture format")
    return document


def _positive_integer(value):
    # Never convert arbitrary JSON numbers: int(187.9) silently loses data.
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("fixture integers must be encoded as strings")
    if not value.startswith("0x") or len(value) <= 2 or not set(value[2:]) <= _HEX_DIGITS:
        raise ValueError("fixture integers must be 0x-prefixed hex strings")
    decoded = int(value[2:], 16)
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
        if "actual_gap" in truth:
            gap = truth["actual_gap"]
            if type(gap) is not int or gap <= 0 or gap != abs(truth["p"] - truth["q"]):
                raise ValueError("actual_gap must be a positive integer equal to abs(p-q)")
        for flag in _TRUTH_FLAGS:
            if flag in truth and type(truth[flag]) is not bool:
                raise ValueError("{} must be a boolean".format(flag))


def assemble_dataset(cases: Iterable[GeneratorCase], *,
                     duplicate_indices=(), shuffle_seed=None) -> DatasetCase:
    """Combine cases, assign neutral IDs, and recompute shared-prime expectations.

    Inputs are copied. duplicate_indices uses the original flattened record order;
    shuffle_seed controls ordering. Expected IDs describe GCD recovery only.
    """
    if shuffle_seed is not None and type(shuffle_seed) is not int:
        raise TypeError("shuffle_seed must be an integer or None")
    if isinstance(cases, (str, bytes, dict)):
        raise TypeError("cases must be an iterable of generator case dictionaries")
    flattened = []
    factors_by_modulus = {}
    prime_cache = {}
    for case in cases:
        if not isinstance(case, dict):
            raise TypeError("each case must be a dictionary")
        if "private_truth" not in case or ("public_keys" in case) == ("public_key" in case):
            raise ValueError("each case needs private_truth and exactly one public input shape")
        if "public_keys" in case:
            public_records = validate_public_records(case["public_keys"])
            private_truth = case["private_truth"]
        else:
            public_records = validate_public_records([case["public_key"]])
            private_truth = {public_records[0]["key_id"]: case["private_truth"]}
        _validate_truth(private_truth, public_records)
        for record in public_records:
            truth = private_truth[record["key_id"]]
            factors = tuple(sorted((truth["p"], truth["q"])))
            p, q = factors
            if p == q or p <= 2 or p % 2 == 0 or q % 2 == 0:
                raise ValueError("assembly requires two distinct odd prime factors")
            for prime in factors:
                if prime not in prime_cache:
                    prime_cache[prime] = bool(isPrime(prime))
                if not prime_cache[prime]:
                    raise ValueError("assembly factors must be prime")
            phi = (p - 1) * (q - 1)
            if record["e"] >= phi or gcd(record["e"], phi) != 1:
                raise ValueError("assembly exponent must be below phi(n) and coprime to it")
            if record["n"] in factors_by_modulus and factors_by_modulus[record["n"]] != factors:
                raise ValueError("duplicate modulus has conflicting private factors")
            factors_by_modulus[record["n"]] = factors
            flattened.append((deepcopy(record), deepcopy(truth)))
    if not flattened:
        raise ValueError("at least one public record is required to assemble a dataset")

    if isinstance(duplicate_indices, (str, bytes)):
        raise TypeError("duplicate_indices must be an iterable of integer indices")
    indices = list(duplicate_indices)
    for index in indices:
        if type(index) is not int:
            raise TypeError("duplicate indices must be built-in integers")
        if not 0 <= index < len(flattened):
            raise ValueError("duplicate index is outside the original flattened records")
    assembled = flattened + [deepcopy(flattened[index]) for index in indices]
    if shuffle_seed is not None:
        random.Random(shuffle_seed).shuffle(assembled)

    public_keys = []
    private_truth = {}
    moduli_by_prime = {}
    for index, (record, truth) in enumerate(assembled, 1):
        key_id = "key_{:03d}".format(index)
        record["key_id"] = key_id
        public_keys.append(record)
        private_truth[key_id] = truth
        for prime in (truth["p"], truth["q"]):
            moduli_by_prime.setdefault(prime, set()).add(record["n"])

    expected_ids = []
    for record in public_keys:
        key_id = record["key_id"]
        truth = private_truth[key_id]
        observable = any(len(moduli_by_prime[prime]) > 1 for prime in (truth["p"], truth["q"]))
        truth["observable_shared_factor"] = observable
        if observable:
            expected_ids.append(key_id)
    return {"public_keys": public_keys, "private_truth": private_truth,
            "expected_vulnerable_ids": expected_ids}


def _read_manifest(directory):
    path = Path(directory) / "manifest.json"
    if not path.exists():
        return None
    return _read_document(path, _MANIFEST_FORMAT)


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
    normalized = normalize_public_keys(public_records)
    for field in ("num_records", "num_unique_moduli", "duplicate_extra_records"):
        if type(manifest.get(field)) is not int or manifest[field] != normalized[field]:
            raise ValueError("{} does not match manifest".format(field))
    bits = sorted({n.bit_length() for n in normalized["unique_moduli"]})
    if manifest.get("modulus_bit_lengths") != bits:
        raise ValueError("modulus bit lengths do not match manifest")


def save_dataset(directory, public_keys, private_truth, expected_ids, *,
                 private_directory=None, metadata=None):
    """Validate and save hex JSON plus checksums without overwriting existing files."""
    if metadata is not None and not isinstance(metadata, dict):
        raise TypeError("metadata must be a dictionary when provided")
    directory = Path(directory)
    paths = dataset_paths(directory, private_directory)
    if any(path.exists() or path.is_symlink() for path in paths):
        raise FileExistsError("fixture files already exist; load them or use a new directory")

    normalized = normalize_public_keys(public_keys)
    public_records = normalized["public_records"]
    _validate_truth(private_truth, public_records)
    expected_ids = _validate_expected_ids(expected_ids, set(private_truth))
    encoded_public = []
    for key in public_records:
        encoded = {"key_id": key["key_id"], "n": hex(key["n"]), "e": hex(key["e"])}
        if "ciphertext" in key:
            encoded["ciphertext_hex"] = key["ciphertext"].hex()
        encoded_public.append(encoded)
    encoded_truth = {}
    for key_id, truth in private_truth.items():
        encoded = {"p": hex(truth["p"]), "q": hex(truth["q"]),
                   "case_type": truth["case_type"]}
        if "expected_message" in truth:
            encoded["expected_message_hex"] = truth["expected_message"].hex()
        if "actual_gap" in truth:
            encoded["actual_gap"] = hex(truth["actual_gap"])
        for flag in _TRUTH_FLAGS:
            if flag in truth:
                encoded[flag] = truth[flag]
        encoded_truth[key_id] = encoded
    public_document = {
        "format": _PUBLIC_FORMAT,
        "description": "Educational test keys; deliberately weak RSA scenario",
        "encryption": "RSA-OAEP-SHA256", "public_keys": encoded_public,
    }
    private_document = {
        "format": _PRIVATE_FORMAT,
        "description": "Educational evaluator truth; never an attack input",
        "expected_vulnerable_ids": expected_ids, "private_truth": encoded_truth,
    }
    public_bytes = _json_bytes(public_document)
    private_bytes = _json_bytes(private_document)
    manifest = {
        "format": _MANIFEST_FORMAT,
        "public_format": public_document["format"], "private_format": private_document["format"],
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

    for parent in {path.parent for path in paths}:
        parent.mkdir(parents=True, exist_ok=True)
    for path, content in zip(paths, (public_bytes, private_bytes, manifest_bytes)):
        with path.open("xb") as destination:
            destination.write(content)


def load_public_keys(path) -> list[PublicKeyRecord]:
    """Load and verify public records without reading private truth."""
    path = Path(path)
    document = _read_document(path, _PUBLIC_FORMAT)
    if document.get("encryption") != "RSA-OAEP-SHA256":
        raise ValueError("unsupported fixture encryption")
    if not isinstance(document.get("public_keys"), list):
        raise ValueError("public_keys must be a list of key records")
    decoded = []
    for key in document["public_keys"]:
        if not isinstance(key, dict) or not {"key_id", "n", "e"}.issubset(key):
            raise ValueError("public fixture records need key_id, n, and e")
        if set(key) - {"key_id", "n", "e", "ciphertext_hex"}:
            raise ValueError("public fixture records contain unsupported fields")
        record = {"key_id": key["key_id"], "n": _positive_integer(key["n"]),
                  "e": _positive_integer(key["e"])}
        if "ciphertext_hex" in key:
            record["ciphertext"] = _decode_bytes(key["ciphertext_hex"])
        decoded.append(record)
    public_records = validate_public_records(decoded)
    _verify_public_manifest(path, document, public_records, _read_manifest(path.parent))
    return public_records


def load_dataset(directory, private_directory=None) -> DatasetCase:
    """Load public records and private truth for assembly or evaluation."""
    directory = Path(directory)
    public_path, private_path, _ = dataset_paths(directory, private_directory)
    public_keys = load_public_keys(public_path)
    document = _read_document(private_path, _PRIVATE_FORMAT)
    manifest = _read_manifest(directory)
    if manifest is not None:
        if manifest.get("private_format") != document["format"]:
            raise ValueError("private schema does not match manifest")
        if "private_sha256" in manifest:
            _verify_checksum(private_path, manifest["private_sha256"], "private")
    if not isinstance(document.get("private_truth"), dict):
        raise ValueError("private_truth must map key IDs to truth records")
    expected_ids = document.get("expected_vulnerable_ids")
    if not isinstance(expected_ids, list):
        raise ValueError("expected_vulnerable_ids must be a list of strings")
    private_truth = {}
    for key_id, truth in document["private_truth"].items():
        if not isinstance(truth, dict) or not {"p", "q", "case_type"}.issubset(truth):
            raise ValueError("truth records must contain p, q, and case_type")
        decoded = {"p": _positive_integer(truth["p"]),
                   "q": _positive_integer(truth["q"]), "case_type": truth["case_type"]}
        if "expected_message_hex" in truth:
            decoded["expected_message"] = _decode_bytes(truth["expected_message_hex"])
        if "actual_gap" in truth:
            decoded["actual_gap"] = _positive_integer(truth["actual_gap"])
        for flag in _TRUTH_FLAGS:
            if flag in truth:
                decoded[flag] = truth[flag]
        private_truth[key_id] = decoded
    _validate_truth(private_truth, public_keys)
    expected_ids = _validate_expected_ids(expected_ids, {key["key_id"] for key in public_keys})
    return {"public_keys": public_keys, "private_truth": private_truth,
            "expected_vulnerable_ids": expected_ids}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--case", choices=("shared", "mixed", "scalability", "control"))
    source.add_argument("--merge", nargs="+", metavar="PUBLIC_DIR",
                        help="combine saved datasets into a new dataset name")
    parser.add_argument("--name", required=True, help="dataset name under data/public and data/private")
    parser.add_argument("--data-root", default="data")
    parser.add_argument("--bits", type=int, default=2048)
    parser.add_argument("--num-keys", type=int, help="default: 6 shared keys, or 20 for scalability")
    parser.add_argument("--shared-keys", type=int, default=2)
    parser.add_argument("--message", help="optional UTF-8 message to encrypt with every public key")
    parser.add_argument("--duplicate-index", type=int, action="append", default=[],
                        help="copy an original flattened record by zero-based index; repeatable")
    parser.add_argument("--shuffle-seed", type=int, help="shuffle assembled record order with a local seed")
    args = parser.parse_args(argv)
    if args.case is None:
        args.case = "shared"
    num_keys = args.num_keys if args.num_keys is not None else (20 if args.case == "scalability" else 6)
    name = Path(args.name)
    if name.is_absolute() or not name.parts or any(part in (".", "..") for part in name.parts):
        parser.error("--name must be a relative dataset name without parent traversal")
    from generators.shared_prime_cases import (
        generate_shared_prime_keys, generate_mixed_key_dataset, generate_scalability_dataset,
    )
    try:
        if args.message is not None:
            from key_recovery import encrypt_message
            message = args.message.encode("utf-8")
            if not args.merge and len(message) > (args.bits + 7) // 8 - 66:
                raise ValueError("message is too long for this modulus and OAEP SHA-256")
        if args.merge:
            case = assemble_dataset((load_dataset(directory) for directory in args.merge),
                                    duplicate_indices=args.duplicate_index,
                                    shuffle_seed=args.shuffle_seed)
        elif args.case == "mixed":
            case = generate_mixed_key_dataset(args.bits)
        elif args.case == "scalability":
            case = generate_scalability_dataset(num_keys, args.bits)
        elif args.case == "control":
            from generators.control_cases import generate_control_key
            control = generate_control_key(args.bits)
            key = control["public_key"]
            case = {"public_keys": [key], "private_truth": {key["key_id"]: control["private_truth"]},
                    "expected_vulnerable_ids": []}
        else:
            case = generate_shared_prime_keys(num_keys, args.shared_keys, args.bits)
        if not args.merge and (args.duplicate_index or args.shuffle_seed is not None):
            case = assemble_dataset([case], duplicate_indices=args.duplicate_index,
                                    shuffle_seed=args.shuffle_seed)
        if args.message is not None:
            for key in case["public_keys"]:
                key["ciphertext"] = encrypt_message(message, key["n"], key["e"])
                case["private_truth"][key["key_id"]]["expected_message"] = message
        public_directory = Path(args.data_root) / "public" / name
        metadata = {"profile": "merge" if args.merge else args.case}
        if args.merge:
            metadata["source_datasets"] = list(args.merge)
        if args.duplicate_index:
            metadata["duplicate_indices"] = list(args.duplicate_index)
        if args.shuffle_seed is not None:
            metadata["shuffle_seed"] = args.shuffle_seed
        save_dataset(public_directory, case["public_keys"], case["private_truth"],
                     case["expected_vulnerable_ids"],
                     metadata=metadata)
        public_path, private_path, manifest_path = dataset_paths(public_directory)
    except (TypeError, ValueError, OSError, RuntimeError) as error:
        parser.exit(1, "Error: {}\n".format(error))
    print("Public inputs: {}".format(public_path))
    print("Evaluator truth: {}".format(private_path))
    print("Manifest: {}".format(manifest_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
