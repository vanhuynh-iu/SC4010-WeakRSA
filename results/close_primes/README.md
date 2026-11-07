# Historical close-prime findings

These 16 CSV/graph files are unchanged outputs from Krystal's original project.
They moved from the standalone copy into the shared results directory. The full
original experiment and plotting source remains on `close-primes` at `bd60ccb`;
that branch was not edited by the cleanup. The current integrated command runs
the shared comparison, not the original standalone gap/sieving studies.

The paired `sieve_comparison_2048.csv` applies seven algorithms to the same key
within each trial. Its summary is the appropriate direct algorithm comparison.
The original-only detailed 2048-bit file contains uneven gap sampling, including
two groups at gap 515 and none at 511. The runtime extrapolation image contains
predictions; measured results and predictions must be distinguished.

Original raw CSVs do not save every generated modulus. Re-running the original
random generators therefore gives another experiment, not exact replay of the
historical keys. Saved files remain the record of those measurements.
