"""Build and combine synthetic RSA datasets with separate public/private files."""

from copy import deepcopy
from math import gcd
import random
from typing import Iterable

from Crypto.Util.number import isPrime

from ..records import DatasetCase, GeneratorCase
from ..public_inputs import validate_public_records
from .storage import (
    dataset_paths, save_dataset, load_dataset, load_public_keys, _validate_truth,
)


_MAX_AUDITOR_CASE_ATTEMPTS = 100


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


def generate_auditor_dataset(modulus_bits: int = 2048, e: int = 65537, *,
                             duplicate_indices=(0,), shuffle_seed=4010) -> DatasetCase:
    """Build one small mixed collection for the three auditor modes.

    Start with a shared-prime pair and two independent controls, then add three
    close-prime cases at increasing gaps. The default copy of the first shared
    record tests deduplication. The seed fixes ordering, not generated primes;
    save the fixture once to compare modes on identical inputs.
    """
    from .generators.shared_primes import generate_shared_prime_keys
    from .generators.close_primes import generate_close_prime_key

    if type(modulus_bits) is not int or type(e) is not int:
        raise TypeError("modulus_bits and e must be integers")
    if modulus_bits < 64 or modulus_bits % 2:
        raise ValueError("auditor datasets require an even modulus_bits of at least 64")
    if shuffle_seed is not None and type(shuffle_seed) is not int:
        raise TypeError("shuffle_seed must be an integer or None")
    if isinstance(duplicate_indices, (str, bytes)):
        raise TypeError("duplicate_indices must be an iterable of integer indices")
    indices = tuple(duplicate_indices)
    if any(type(index) is not int for index in indices):
        raise TypeError("duplicate indices must be built-in integers")
    if any(not 0 <= index < 7 for index in indices):
        raise ValueError("auditor duplicate index must refer to one of the seven base records")

    base = generate_shared_prime_keys(4, 2, modulus_bits, e)
    used_primes = set()
    for record in base["public_keys"]:
        truth = base["private_truth"][record["key_id"]]
        if record["n"].bit_length() != modulus_bits:
            raise ValueError("base generator returned the wrong modulus bit length")
        used_primes.update((truth["p"], truth["q"]))
        truth["actual_gap"] = abs(truth["p"] - truth["q"])
        truth["intended_weak_generation"] = truth["case_type"] == "shared_prime"

    cases = [base]
    for offset in (3, 5, 8):
        for _ in range(_MAX_AUDITOR_CASE_ATTEMPTS):
            candidate = generate_close_prime_key(modulus_bits, e,
                                                  gap_bits=modulus_bits // 4 + offset)
            public = validate_public_records([candidate["public_key"]])
            truth = candidate["private_truth"]
            _validate_truth({public[0]["key_id"]: truth}, public)
            if public[0]["n"].bit_length() != modulus_bits or public[0]["e"] != e:
                raise ValueError("close-prime generator returned incompatible RSA parameters")
            primes = {truth["p"], truth["q"]}
            if primes & used_primes:
                continue
            used_primes.update(primes)
            cases.append(candidate)
            break
        else:
            raise RuntimeError("could not generate an independent close-prime case within {} attempts".format(
                _MAX_AUDITOR_CASE_ATTEMPTS
            ))

    case = assemble_dataset(cases, duplicate_indices=indices, shuffle_seed=shuffle_seed)
    case["modulus_bits"] = modulus_bits
    case["topology_profile"] = "shared_pair_close_primes_controls"
    return case
