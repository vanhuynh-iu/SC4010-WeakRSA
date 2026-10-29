"""Controlled shared-prime RSA scenarios owned by Van."""

from collections import Counter, defaultdict
from copy import deepcopy
from math import gcd
from typing import Optional, Set

from Crypto.Util.number import getPrime

from contracts import DatasetCase

_MAX_PRIME_ATTEMPTS = 10_000


def _validate_rsa_parameters(modulus_bits: int, e: int) -> None:
    if type(modulus_bits) is not int or type(e) is not int:
        raise TypeError("modulus_bits and e must be integers")
    if modulus_bits < 32:
        raise ValueError("modulus_bits must be at least 32")
    if e <= 1 or e % 2 == 0:
        raise ValueError("e must be an odd integer greater than 1")
    if e >= 1 << (modulus_bits - 2):
        raise ValueError("e must be smaller than 2**(modulus_bits - 2)")


def _new_prime(
    prime_bits: int,
    e: int,
    excluded: Set[int],
    *,
    minimum: int = 0,
    maximum: Optional[int] = None,
    partner: Optional[int] = None,
    modulus_bits: Optional[int] = None,
) -> int:
    """Draw a fresh prime compatible with e within a bounded retry count.

    minimum is inclusive; maximum is exclusive. A supplied partner also enforces
    the target modulus length. Reject primes incompatible with RSA recovery.
    """
    for _ in range(_MAX_PRIME_ATTEMPTS):
        candidate = getPrime(prime_bits)
        if candidate < minimum or candidate in excluded:
            continue
        if maximum is not None and candidate >= maximum:
            continue
        if gcd(e, candidate - 1) != 1 or gcd(e, candidate) != 1:
            continue
        if partner is not None and (partner * candidate).bit_length() != modulus_bits:
            continue
        return candidate
    raise RuntimeError(
        "Could not generate a fresh RSA-compatible prime within "
        f"{_MAX_PRIME_ATTEMPTS} attempts; reduce the collection size or retry"
    )


def _fresh_factor_pair(modulus_bits: int, e: int, used: Set[int]):
    p_bits = (modulus_bits + 1) // 2
    q_bits = modulus_bits // 2

    # Keeping p in the upper quarter of its full numerical range avoids
    # selecting a p so small that almost no q can make the target bit length.
    p = _new_prime(p_bits, e, used, minimum=3 * (1 << (p_bits - 2)))
    used.add(p)
    q = _new_prime(q_bits, e, used, partner=p, modulus_bits=modulus_bits)
    used.add(q)
    return p, q


def generate_shared_prime_keys(
    num_keys: int = 4,
    num_shared: int = 2,
    modulus_bits: int = 2048,
    e: int = 65537,
) -> DatasetCase:
    """Generate keys whose first num_shared records reuse one prime.

    All other primes are unique. Return public records and separate private truth.
    The default modulus size is 2048 bits; small sizes support unit tests.
    """
    _validate_rsa_parameters(modulus_bits, e)
    if type(num_keys) is not int or type(num_shared) is not int:
        raise TypeError("num_keys and num_shared must be integers")
    if num_keys < 2:
        raise ValueError("num_keys must be at least 2")
    if not 2 <= num_shared <= num_keys:
        raise ValueError("num_shared must be between 2 and num_keys")

    public_keys = []
    private_truth = {}
    expected_vulnerable_ids = []
    used = set()

    shared_p, first_q = _fresh_factor_pair(modulus_bits, e, used)
    q_bits = modulus_bits // 2
    for index in range(num_keys):
        key_id = f"key_{index + 1:03d}"
        if index < num_shared:
            p = shared_p
            q = first_q if index == 0 else _new_prime(
                q_bits, e, used, partner=p, modulus_bits=modulus_bits
            )
            used.add(q)
            case_type = "shared_prime"
            expected_vulnerable_ids.append(key_id)
        else:
            p, q = _fresh_factor_pair(modulus_bits, e, used)
            case_type = "control"

        public_keys.append({"key_id": key_id, "n": p * q, "e": e})
        private_truth[key_id] = {"p": p, "q": q, "case_type": case_type}

    return {
        "public_keys": public_keys,
        "private_truth": private_truth,
        "expected_vulnerable_ids": expected_vulnerable_ids,
        "modulus_bits": modulus_bits,
    }


def _observable_shared_factors(public_keys, private_truth):
    """Derive expected recoveries from prime membership across distinct moduli."""
    prime_moduli = defaultdict(set)
    for key in public_keys:
        truth = private_truth[key["key_id"]]
        for prime in (truth["p"], truth["q"]):
            prime_moduli[prime].add(key["n"])

    expected_ids = []
    expected_moduli = []
    seen_moduli = set()
    for key in public_keys:
        truth = private_truth[key["key_id"]]
        observable = any(
            len(prime_moduli[prime]) > 1 for prime in (truth["p"], truth["q"])
        )
        truth["observable_shared_factor"] = observable
        if observable:
            expected_ids.append(key["key_id"])
            if key["n"] not in seen_moduli:
                expected_moduli.append(key["n"])
                seen_moduli.add(key["n"])
    return expected_ids, expected_moduli


def _prime_in_graph_range(modulus_bits: int, e: int, used: Set[int]) -> int:
    """Draw a fresh prime so any two graph primes give the target bit length."""
    prime_bits = (modulus_bits + 1) // 2
    if modulus_bits % 2 == 0:
        minimum = 3 * (1 << (prime_bits - 2))
        maximum = None
    else:
        # For B=2*k-1, all factors lie in [2**(k-1), 5*2**(k-3)).
        # Products lie in [2**(B-1), (25/32)*2**B), hence have B bits.
        minimum = 1 << (prime_bits - 1)
        maximum = 5 * (1 << (prime_bits - 3))
    prime = _new_prime(prime_bits, e, used, minimum=minimum, maximum=maximum)
    used.add(prime)
    return prime


def generate_mixed_key_dataset(modulus_bits: int = 2048, e: int = 65537) -> DatasetCase:
    """Build 18 records covering groups, controls, duplicates, chains and a triangle.

    One duplicate uses e=3 (or 5 if the base e is 3). Every modulus has the requested
    bit length; expected recoveries come from private prime membership.
    """
    _validate_rsa_parameters(modulus_bits, e)
    alternate_e = 5 if e == 3 else 3
    # gcd(e*alternate_e, p-1)==1 checks both exponent conditions at once.
    compatible_exponents = e * alternate_e

    edges = (
        ("shared_pair", "pair_a", "pair_b", e),
        ("shared_pair", "pair_a", "pair_c", e),
        ("shared_group", "group_a", "group_b", e),
        ("shared_group", "group_a", "group_c", e),
        ("shared_group", "group_a", "group_d", e),
        ("control", "control_a", "control_b", e),
        ("control", "control_c", "control_d", e),
        ("duplicate_only", "duplicate_a", "duplicate_b", e),
        ("duplicate_only", "duplicate_a", "duplicate_b", e),
        ("duplicate_with_companion", "companion_a", "companion_b", e),
        ("duplicate_with_companion", "companion_a", "companion_b", alternate_e),
        ("duplicate_with_companion", "companion_a", "companion_c", e),
        ("split_factor_chain", "chain_a", "chain_b", e),
        ("split_factor_chain", "chain_a", "chain_c", e),
        ("split_factor_chain", "chain_b", "chain_d", e),
        ("triangle", "triangle_a", "triangle_b", e),
        ("triangle", "triangle_a", "triangle_c", e),
        ("triangle", "triangle_b", "triangle_c", e),
    )
    primes = {}
    used = set()
    public_keys = []
    private_truth = {}
    for index, (case_type, left_label, right_label, exponent) in enumerate(edges, 1):
        for label in (left_label, right_label):
            if label not in primes:
                primes[label] = _prime_in_graph_range(modulus_bits, compatible_exponents, used)
        p, q = primes[left_label], primes[right_label]
        key_id = f"key_{index:03d}"
        if (p * q).bit_length() != modulus_bits:
            raise RuntimeError("mixed factor range did not produce the target bit length")
        public_keys.append({"key_id": key_id, "n": p * q, "e": exponent})
        private_truth[key_id] = {
            "p": p, "q": q, "case_type": case_type,
            "intended_weak_generation": case_type != "control",
        }

    expected_ids, expected_moduli = _observable_shared_factors(public_keys, private_truth)
    return {
        "public_keys": public_keys,
        "private_truth": private_truth,
        "expected_vulnerable_ids": expected_ids,
        "expected_factored_moduli": expected_moduli,
        "modulus_bits": modulus_bits,
    }


def generate_scalability_dataset(
    num_unique_moduli: int, modulus_bits: int = 2048, e: int = 65537
) -> DatasetCase:
    """Build a collection with 20% shared-prime pairs and 80% independent controls.

    The unique-modulus count must be a positive multiple of 10. Each factor appears
    only in its intended pair; there are no duplicate moduli.
    """
    if type(num_unique_moduli) is not int:
        raise TypeError("num_unique_moduli must be an integer")
    if num_unique_moduli < 10 or num_unique_moduli % 10 != 0:
        raise ValueError("num_unique_moduli must be at least 10 and a multiple of 10")
    _validate_rsa_parameters(modulus_bits, e)

    used = set()
    public_keys = []
    private_truth = {}

    def append_record(p, q, case_type):
        key_id = f"key_{len(public_keys) + 1:03d}"
        if (p * q).bit_length() != modulus_bits:
            raise RuntimeError("scalability factor range did not produce the target bit length")
        public_keys.append({"key_id": key_id, "n": p * q, "e": e})
        private_truth[key_id] = {
            "p": p, "q": q, "case_type": case_type,
            "intended_weak_generation": case_type == "shared_pair",
        }

    for _ in range(num_unique_moduli // 10):
        shared = _prime_in_graph_range(modulus_bits, e, used)
        for _ in range(2):
            other = _prime_in_graph_range(modulus_bits, e, used)
            append_record(shared, other, "shared_pair")
    while len(public_keys) < num_unique_moduli:
        p = _prime_in_graph_range(modulus_bits, e, used)
        q = _prime_in_graph_range(modulus_bits, e, used)
        append_record(p, q, "control")

    expected_ids, expected_moduli = _observable_shared_factors(public_keys, private_truth)
    return {
        "public_keys": public_keys,
        "private_truth": private_truth,
        "expected_vulnerable_ids": expected_ids,
        "expected_factored_moduli": expected_moduli,
        "modulus_bits": modulus_bits,
        "topology_profile": "disjoint_shared_pairs_20pct",
    }


def make_observed_subset(dataset: dict, key_ids) -> dict:
    """Copy selected records and recompute observable shared-prime recovery.

    Preserve requested ID order and original generation labels. Unknown or repeated
    IDs are rejected; removing a companion can remove an expected recovery.
    """
    if not isinstance(dataset, dict):
        raise TypeError("dataset must be a dictionary")
    if not isinstance(dataset.get("public_keys"), list):
        raise TypeError("dataset public_keys must be a list")
    if not isinstance(dataset.get("private_truth"), dict):
        raise TypeError("dataset private_truth must be a dictionary")
    if isinstance(key_ids, (str, bytes)):
        raise TypeError("key_ids must be an iterable of key ID strings")
    selected_ids = list(key_ids)
    if any(not isinstance(key_id, str) or not key_id for key_id in selected_ids):
        raise TypeError("each requested key ID must be a nonempty string")
    if len(selected_ids) != len(set(selected_ids)):
        raise ValueError("requested key IDs must be unique")

    public_by_id = {}
    for key in dataset["public_keys"]:
        if not isinstance(key, dict) or not isinstance(key.get("key_id"), str):
            raise ValueError("each public record needs a string key_id")
        key_id = key["key_id"]
        if not key_id or key_id in public_by_id:
            raise ValueError("population key IDs must be nonempty and unique")
        if type(key.get("n")) is not int or type(key.get("e")) is not int:
            raise TypeError("public n and e must be integers")
        if key_id not in dataset["private_truth"]:
            raise ValueError("private truth is missing a public key ID")
        truth = dataset["private_truth"][key_id]
        if not isinstance(truth, dict):
            raise TypeError("each private truth record must be a dictionary")
        if type(truth.get("p")) is not int or type(truth.get("q")) is not int:
            raise TypeError("private p and q must be integers")
        if truth["p"] <= 1 or truth["q"] <= 1 or truth["p"] * truth["q"] != key["n"]:
            raise ValueError("private factors must multiply to their public modulus")
        public_by_id[key_id] = key
    if set(dataset["private_truth"]) != set(public_by_id):
        raise ValueError("public and private population IDs must match")
    missing_ids = set(selected_ids) - set(public_by_id)
    if missing_ids:
        raise ValueError("unknown requested key IDs: " + ", ".join(sorted(missing_ids)))
    if type(dataset.get("modulus_bits")) is not int:
        raise TypeError("dataset modulus_bits must be an integer")

    # Annotate a copy of the full population before removing companions. The
    # original records and any original evaluation fields remain unchanged.
    population_truth = deepcopy(dataset["private_truth"])
    population_ids, _ = _observable_shared_factors(dataset["public_keys"], population_truth)
    population_observable = set(population_ids)
    modulus_counts = Counter(key["n"] for key in dataset["public_keys"])
    weak_case_types = {
        "shared_prime", "shared_pair", "shared_group", "duplicate_only",
        "duplicate_with_companion", "split_factor_chain", "triangle",
    }
    for key_id, truth in population_truth.items():
        truth.setdefault(
            "intended_weak_generation",
            truth.get("case_type") in weak_case_types
            or key_id in population_observable
            or modulus_counts[public_by_id[key_id]["n"]] > 1,
        )

    selected_public = [deepcopy(public_by_id[key_id]) for key_id in selected_ids]
    selected_truth = {key_id: population_truth[key_id] for key_id in selected_ids}
    expected_ids, expected_moduli = _observable_shared_factors(selected_public, selected_truth)
    return {
        "public_keys": selected_public,
        "private_truth": selected_truth,
        "expected_vulnerable_ids": expected_ids,
        "expected_factored_moduli": expected_moduli,
        "modulus_bits": dataset["modulus_bits"],
    }
