"""Shared dictionary contracts for Van and Krystal.

TypedDict supplies static hints; runtime validation stays in normalization,
dataset, and attack/recovery modules. Python ints/bytes are saved as hex.
Only public records enter attacks; truth is for generation and evaluation.
"""

from typing import Callable, Dict, List, Literal, Optional, Protocol, Tuple, TypedDict, Union


CompleteGCDAlgorithm = Literal["pairwise", "batch_with_fallback"]
ScanAlgorithm = Literal["pairwise", "batch_with_fallback", "batch_raw"]
GCDAlgorithmInput = Literal["pairwise", "batch", "batch_with_fallback", "batch_raw"]
ResolutionMethod = Literal["pairwise", "batch_direct", "batch_fallback"]
GCDBackend = Callable[[int, int], int]
FactorPair = Tuple[int, int]

# batch_raw is diagnostic; it is excluded from completed-algorithm benchmarks.
COMPLETE_ALGORITHMS: Tuple[CompleteGCDAlgorithm, ...] = ("pairwise", "batch_with_fallback")
SCAN_COUNTERS = (
    "gcd_calls", "pairwise_gcd_calls", "batch_leaf_gcd_calls",
    "fallback_gcd_calls", "full_gcd_before_fallback", "unresolved_after_fallback",
)
FindingStatus = Literal["factored", "no_shared_factor_in_dataset", "unresolved_full_gcd"]
FermatStatus = Literal["factored", "budget_exhausted"]


class _PublicKeyRequired(TypedDict):
    key_id: str
    n: int
    e: int


class PublicKeyRecord(_PublicKeyRequired, total=False):
    """Public n/e, a neutral unique ID, and optional OAEP ciphertext bytes.

    n/e are odd integers > 1; factors, gaps and scenario labels are forbidden.
    """

    ciphertext: bytes


class _PrivateTruthRequired(TypedDict):
    p: int
    q: int
    case_type: str


class PrivateTruthRecord(_PrivateTruthRequired, total=False):
    """Private factors and labels; never passed to an attack.

    actual_gap equals abs(p-q); expected_message is bytes. observable_shared_factor
    is dataset-dependent; intended_weak_generation describes construction.
    Neither flag predicts budgeted Fermat success.
    """

    expected_message: bytes
    actual_gap: int
    intended_weak_generation: bool
    observable_shared_factor: bool


class GeneratedKeyCase(TypedDict):
    """Single-key generator output accepted by dataset assembly."""

    public_key: PublicKeyRecord
    private_truth: PrivateTruthRecord


class CollectionCase(TypedDict):
    """Generator collection before assembly computes expected GCD IDs."""

    public_keys: List[PublicKeyRecord]
    private_truth: Dict[str, PrivateTruthRecord]


class _DatasetRequired(CollectionCase):
    expected_vulnerable_ids: List[str]


class DatasetCase(_DatasetRequired, total=False):
    """Collection with matching public/private IDs and GCD-only expected IDs.

    Expected IDs describe observable GCD recovery, not Fermat predictions.
    Optional metadata is generator-specific; loaded/assembled datasets may
    contain multiple modulus bit lengths.
    """

    modulus_bits: int
    expected_factored_moduli: List[int]
    topology_profile: str


GeneratorCase = Union[GeneratedKeyCase, CollectionCase, DatasetCase]


class NormalizedKeySet(TypedDict):
    """Records grouped by n, preserving each ID/exponent.

    Duplicates add no unique n and reveal no factors alone.
    """

    public_records: List[PublicKeyRecord]
    unique_moduli: List[int]
    records_by_modulus: Dict[int, List[PublicKeyRecord]]
    duplicate_groups: Dict[int, List[PublicKeyRecord]]
    num_records: int
    num_unique_moduli: int
    duplicate_extra_records: int


class _FindingRequired(TypedDict):
    n: int
    status: FindingStatus
    p: Optional[int]
    q: Optional[int]
    resolution_method: Optional[ResolutionMethod]


class ModulusFinding(_FindingRequired, total=False):
    """One finding per unique n; raw_batch_gcd is batch-only.

    factored requires primes p < q, p*q == n, and a resolution method;
    otherwise p/q/method are None. Other statuses do not assert security.
    """

    raw_batch_gcd: int


class DebugEvidence(TypedDict, total=False):
    """Optional bounded witnesses; neither backend must build a full graph."""

    matching_modulus_pairs: List[Tuple[int, int]]
    matching_pairs_truncated: bool
    fallback_witnesses: List[Tuple[int, int]]
    fallback_witnesses_truncated: bool


class ScanResult(TypedDict):
    """Scanner output for unique n with actual GCD-call counts.

    matching_pair_count is None for batch; pairwise_gcd_calls includes fallback.
    """

    algorithm: ScanAlgorithm
    findings: Dict[int, ModulusFinding]
    gcd_calls: int
    pairwise_gcd_calls: int
    batch_leaf_gcd_calls: int
    fallback_gcd_calls: int
    full_gcd_before_fallback: int
    unresolved_after_fallback: int
    matching_pair_count: Optional[int]
    optional_debug_evidence: DebugEvidence


class RecordFinding(_FindingRequired):
    """A modulus finding mapped back to one original public record."""

    key_id: str
    e: int


class RecoveredRecord(TypedDict):
    """Factors and the record's own e for recover_private_key(p, q, e) -> d.

    Check p*q against original n; private truth is not used.
    """

    key_id: str
    n: int
    e: int
    status: Literal["factored"]
    p: int
    q: int
    resolution_method: ResolutionMethod


class AuditReport(ScanResult):
    """GCD-only report with public records, factors and separate timings.

    recovered_keys aliases recovered_records; gcd_comparisons aliases gcd_calls.
    scan_seconds excludes preprocessing, propagation, generation, I/O, recovery
    and OAEP. Fermat/combined reports are a later integration step.
    """

    normalized: NormalizedKeySet
    record_findings: List[RecordFinding]
    recovered_records: List[RecoveredRecord]
    recovered_keys: List[RecoveredRecord]
    num_records: int
    num_unique_moduli: int
    duplicate_extra_records: int
    preprocessing_seconds: float
    scan_seconds: float
    gcd_comparisons: int


# Krystal's part.
class FermatResult(TypedDict):
    status: FermatStatus
    factors: Optional[FactorPair]
    candidate_tests: int


class FermatFactorizer(Protocol):
    def __call__(self, n: int, max_candidates: int) -> FermatResult:
        ...
