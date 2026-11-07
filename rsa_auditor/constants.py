"""Algorithm names and measured operation counters shared by experiments."""

COMPLETE_ALGORITHMS = (
    "pairwise",
    "batch_with_fallback",
)

SCAN_COUNTERS = (
    "gcd_calls",
    "pairwise_gcd_calls",
    "batch_leaf_gcd_calls",
    "fallback_gcd_calls",
    "full_gcd_before_fallback",
    "unresolved_after_fallback",
)
