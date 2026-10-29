# Datasets

These are generated inputs, separate from the measured outputs in `results/`.

| Public dataset | Purpose |
| --- | --- |
| `van_demo` | Six 2048-bit keys; two recoverable through shared primes |
| `van_mixed` | 18 records / 16 moduli; groups, controls, duplicates, chains and triangles |
| `van_coverage/before` and `after` | Same target with its companion absent/present |
| `scalability/m20_bits2048`, `m50_bits2048`, `m100_bits2048` | Timing inputs: 20% shared pairs, 80% controls |

Each public folder contains `public.json` and a checksum `manifest.json`.
Matching `private/<name>/private_truth.json` stores p, q, labels and optional
expected messages or actual prime gaps. Assembly and evaluation use truth;
attacks receive public records only.

Use `build_dataset.py` for storage. Integers are saved as hexadecimal strings
and bytes as hex; the loader returns Python integers and bytes. All keys are
synthetic. The mixed case deliberately includes one record with e=3 to test
recovery for the same modulus with different exponents.

`expected_vulnerable_ids` means observable GCD recovery in the collection.
Historical input names/checksums are mapped in `results/layout_migration.json`.
