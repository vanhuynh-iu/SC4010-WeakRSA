"""Build synthetic RSA collections with separate public and private files."""

from copy import deepcopy
from math import gcd
import random
from typing import Iterable

from rsa_auditor.datasets.generators import close_primes
from rsa_auditor.datasets.generators import shared_primes
from rsa_auditor.datasets.storage import validate_private_truth
from rsa_auditor.key_recovery import validate_factors
from rsa_auditor.public_inputs import validate_public_records

MAX_AUDITOR_CASE_ATTEMPTS = 100


def assemble_dataset(cases: Iterable[dict],
                     *,
                     duplicate_indices=(),
                     shuffle_seed=None) -> dict:
    """Combine cases, assign neutral IDs, and derive GCD expectations.

    Inputs are copied. duplicate_indices uses the original flattened record
    order; shuffle_seed controls ordering. Expected IDs describe GCD recovery.

    Args:
        cases: Generated cases, each with public records and private answers.
        duplicate_indices: Original record positions to copy before shuffling.
        shuffle_seed: Optional seed for record order, not prime generation.

    Returns:
        A collection with neutral IDs and its separate private answer sheet.
    """
    if shuffle_seed is not None and type(shuffle_seed) is not int:
        raise TypeError("shuffle_seed must be an integer or None")
    if isinstance(cases, (str, bytes, dict)):
        raise TypeError(
            "cases must be an iterable of generator case dictionaries")
    flattened = []
    factors_by_modulus = {}
    for case in cases:
        if not isinstance(case, dict):
            raise TypeError("each case must be a dictionary")
        has_collection = "public_keys" in case
        has_single_key = "public_key" in case
        if "private_truth" not in case or has_collection == has_single_key:
            raise ValueError(
                "each case needs private_truth and exactly one public "
                "input shape")
        if "public_keys" in case:
            public_records = validate_public_records(case["public_keys"])
            private_truth = case["private_truth"]
        else:
            public_records = validate_public_records([case["public_key"]])
            private_truth = {public_records[0]["key_id"]: case["private_truth"]}
        validate_private_truth(private_truth, public_records)
        for record in public_records:
            truth = private_truth[record["key_id"]]
            n = record["n"]
            factors = tuple(sorted((truth["p"], truth["q"])))
            if n in factors_by_modulus:
                if factors != factors_by_modulus[n]:
                    raise ValueError(
                        "duplicate modulus has conflicting private factors")
            else:
                factors = validate_factors(n, *factors)
                factors_by_modulus[n] = factors
            p, q = factors
            phi = (p - 1) * (q - 1)
            if record["e"] >= phi or gcd(record["e"], phi) != 1:
                raise ValueError(
                    "assembly exponent must be below phi(n) and coprime to it")
            flattened.append((deepcopy(record), deepcopy(truth)))
    if not flattened:
        raise ValueError(
            "at least one public record is required to assemble a dataset")

    if isinstance(duplicate_indices, (str, bytes)):
        raise TypeError(
            "duplicate_indices must be an iterable of integer indices")
    indices = list(duplicate_indices)
    for index in indices:
        if type(index) is not int:
            raise TypeError("duplicate indices must be built-in integers")
        if not 0 <= index < len(flattened):
            raise ValueError(
                "duplicate index is outside the original flattened records")
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
        observable = any(
            len(moduli_by_prime[prime]) > 1
            for prime in (truth["p"], truth["q"]))
        truth["observable_shared_factor"] = observable
        if observable:
            expected_ids.append(key_id)
    return {
        "public_keys": public_keys,
        "private_truth": private_truth,
        "expected_vulnerable_ids": expected_ids
    }


def generate_auditor_dataset(modulus_bits: int = 2048,
                             e: int = 65537,
                             *,
                             duplicate_indices=(0,),
                             shuffle_seed=4010) -> dict:
    """Build one small mixed collection for the three auditor modes.

    Start with a shared-prime pair and two independent controls, then add three
    close-prime cases at increasing gaps. The default copy of the first shared
    record tests deduplication. The seed fixes ordering, not generated primes;
    save the fixture once to compare modes on identical inputs.
    """
    if type(modulus_bits) is not int or type(e) is not int:
        raise TypeError("modulus_bits and e must be integers")
    if modulus_bits < 64 or modulus_bits % 2:
        raise ValueError(
            "auditor datasets require an even modulus_bits of at least 64")
    if shuffle_seed is not None and type(shuffle_seed) is not int:
        raise TypeError("shuffle_seed must be an integer or None")
    if isinstance(duplicate_indices, (str, bytes)):
        raise TypeError(
            "duplicate_indices must be an iterable of integer indices")
    indices = tuple(duplicate_indices)
    if any(type(index) is not int for index in indices):
        raise TypeError("duplicate indices must be built-in integers")
    if any(not 0 <= index < 7 for index in indices):
        raise ValueError(
            "auditor duplicate index must refer to one of the seven "
            "base records")

    base = shared_primes.generate_shared_prime_keys(4, 2, modulus_bits, e)
    used_primes = set()
    for record in base["public_keys"]:
        truth = base["private_truth"][record["key_id"]]
        if record["n"].bit_length() != modulus_bits:
            raise ValueError(
                "base generator returned the wrong modulus bit length")
        used_primes.update((truth["p"], truth["q"]))
        truth["actual_gap"] = abs(truth["p"] - truth["q"])
        truth["intended_weak_generation"] = truth["case_type"] == "shared_prime"

    cases = [base]
    for offset in (3, 5, 8):
        for _ in range(MAX_AUDITOR_CASE_ATTEMPTS):
            candidate = close_primes.generate_close_prime_key(
                modulus_bits, e, gap_bits=modulus_bits // 4 + offset)
            public = validate_public_records([candidate["public_key"]])
            truth = candidate["private_truth"]
            validate_private_truth({public[0]["key_id"]: truth}, public)
            if public[0]["n"].bit_length(
            ) != modulus_bits or public[0]["e"] != e:
                raise ValueError(
                    "close-prime generator returned incompatible RSA parameters"
                )
            primes = {truth["p"], truth["q"]}
            if primes & used_primes:
                continue
            used_primes.update(primes)
            cases.append(candidate)
            break
        else:
            raise RuntimeError(
                "could not generate an independent close-prime case "
                "within {} attempts".format(MAX_AUDITOR_CASE_ATTEMPTS))

    case = assemble_dataset(cases,
                            duplicate_indices=indices,
                            shuffle_seed=shuffle_seed)
    case["modulus_bits"] = modulus_bits
    case["topology_profile"] = "shared_pair_close_primes_controls"
    return case
