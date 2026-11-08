# Datasets

These are generated inputs, separate from the measured outputs in `results/`.

| Public dataset | Purpose |
| --- | --- |
| `auditor_demo` | Integrated three-mode demo: 8 records / 7 unique RSA-2048 moduli, shared/close/control cases and a duplicate |
| `fermat_pilot` | Nine new RSA-2048 keys: three per gap setting, reused across four Fermat methods and two position budgets |
| `gcd_mixed` | Active correctness/stress input: 18 records / 16 moduli; groups, controls, duplicates, chains and triangles |
| `gcd_coverage/before` and `after` | Active coverage input: the same target with its companion absent/present |
| `scalability/m20_bits2048`, `m50_bits2048`, `m100_bits2048` | Timing inputs: 20% shared pairs, 80% controls |

Each public folder contains `public.json` and a checksum `manifest.json`.
Matching `private/<name>/private_truth.json` stores p, q, labels and optional
expected messages or actual prime gaps. Assembly and evaluation use truth;
attacks receive public records only.

These are five input groups, each with a public question paper and a matching
private answer sheet. `auditor_demo` is sufficient for the main demonstration;
the other groups exercise separate experiment questions.

The old names `van_mixed` and `van_coverage` were renamed to `gcd_mixed` and
`gcd_coverage`. Their JSON contents and checksums are unchanged: earlier inputs
are intentionally reused for repeatable comparisons. Historical result files
retain the dataset names and paths that were used when those runs happened.
The unused `van_demo` collection was removed; it remains in Git history.

Use `python -m rsa_auditor.datasets.cli` to build and save collections. Integers are saved as hexadecimal strings
and bytes as hex; the loader returns Python integers and bytes. All keys are
synthetic. The mixed case deliberately includes one record with e=3 to test
recovery for the same modulus with different exponents.

`expected_vulnerable_ids` means observable GCD recovery in the collection.
Fresh run metadata hashes these canonical stored inputs directly. Earlier
input/layout maps are retained in Git history at `481dbaa`. Saved inputs are
reused intentionally; a new execution does not require new keys.

The separate private file is the synthetic experiment's **answer sheet**. It
lets the evaluator compare attack-returned factors and plaintext with the
originals. It is not supplied to an attack. The demo loads it only with
`--evaluate`, after scanning/decryption; without that flag, public-only auditing
still works. See [the code guide](../docs/CODE_GUIDE.md) for the two data paths.

The stored `expected_vulnerable_ids` field describes GCD observability only.
The shared evaluator computes budget-dependent Fermat and combined expectations
independently from the private factors; close-prime labels do not route attacks.
