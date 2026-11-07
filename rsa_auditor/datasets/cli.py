"""Build and combine synthetic RSA datasets with separate public/private files."""

import argparse
from pathlib import Path

from .builder import assemble_dataset, generate_auditor_dataset
from .storage import dataset_paths, load_dataset, save_dataset


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--case", choices=("shared", "mixed", "scalability", "control", "auditor"))
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
    parser.add_argument("--shuffle-seed", type=int,
                        help="shuffle assembled record order with a local seed (auditor default: 4010)")
    args = parser.parse_args(argv)
    if args.case is None:
        args.case = "shared"
    if args.case == "auditor":
        if args.num_keys is not None or args.shared_keys != 2:
            parser.error("--case auditor has a fixed composition: two shared, two controls, three close-prime keys")
        if not args.duplicate_index:
            args.duplicate_index = [0]
        if args.shuffle_seed is None:
            args.shuffle_seed = 4010
    num_keys = args.num_keys if args.num_keys is not None else (20 if args.case == "scalability" else 6)
    name = Path(args.name)
    if name.is_absolute() or not name.parts or any(part in (".", "..") for part in name.parts):
        parser.error("--name must be a relative dataset name without parent traversal")
    from .generators.shared_primes import (
        generate_shared_prime_keys, generate_mixed_key_dataset, generate_scalability_dataset,
    )
    try:
        if args.message is not None:
            from ..key_recovery import encrypt_message
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
            from .generators.controls import generate_control_key
            control = generate_control_key(args.bits)
            key = control["public_key"]
            case = {"public_keys": [key], "private_truth": {key["key_id"]: control["private_truth"]},
                    "expected_vulnerable_ids": []}
        elif args.case == "auditor":
            case = generate_auditor_dataset(args.bits, duplicate_indices=args.duplicate_index,
                                            shuffle_seed=args.shuffle_seed)
        else:
            case = generate_shared_prime_keys(num_keys, args.shared_keys, args.bits)
        if not args.merge and args.case != "auditor" and (args.duplicate_index or args.shuffle_seed is not None):
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
