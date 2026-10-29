> Historical run: measurements and their original hashes are unchanged. Working inputs now use simpler paths and one canonical format; see results/layout_migration.json for old/current path and checksum mappings. Use the root README for current setup.

# Measured fallback stress check

The saved `data/public/van_mixed` input was reused unchanged for five timing
runs per algorithm on 2026-10-28, with one warm-up and separate memory passes.
Both algorithms recovered the same 13 distinct moduli/14 affected records.

Pairwise made 120 GCD calls. Batch made 16 leaf plus 53 fallback calls and
resolved all four raw whole-modulus cases. The output profile is labelled
`custom`; the input manifest and metadata identify the mixed fixture.

Median scan time was 0.450177 seconds pairwise and 0.443840 seconds batch.
Observed batch minimum/maximum was 0.443429/0.670946 seconds. All ten timing
rows and two memory rows passed reference checks. This small, variable timing
difference is not a claim of statistically established or universal speedup.

Raw CSVs, exact summary, source/input hashes and timing boundaries are retained
alongside this file. E1 separately checked actual OAEP decryption in
`results/van_batch_correctness`; it is outside the E3 scan-only timer.
