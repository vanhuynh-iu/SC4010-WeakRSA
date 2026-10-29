> Historical run: measurements and their original hashes are unchanged. Working inputs now use simpler paths and one canonical format; see results/layout_migration.json for old/current path and checksum mappings. Use the root README for current setup.

# Measured shared-prime scalability pilot

Executed on 2026-10-28 with Python 3.9.6, PyCryptodome 3.24.1 and macOS arm64.
The exact environment, source hashes, dirty Git state and public-input hashes
are in [run_metadata.json](run_metadata.json). Git revision alone does not
identify the uncommitted/untracked source; use the recorded file hashes.

Each of three saved 2048-bit datasets contains 20% moduli in disjoint shared
pairs and 80% independent controls. There are no duplicates. One fixture was
generated per size; both algorithms used the same normalized inputs. Five
timing repetitions per algorithm/fixture follow one unmeasured warm-up. Trial
order alternates. This measures within-fixture timing variability, not
between-generated-dataset variability.

| Unique moduli | Pairwise median (s) | Batch median (s) | Pairwise GCD calls | Batch GCD calls |
| ---: | ---: | ---: | ---: | ---: |
| 20 | 0.182842 | 0.160684 | 190 | 20 |
| 50 | 0.574475 | 0.416815 | 1,225 | 50 |
| 100 | 1.540518 | 0.888476 | 4,950 | 100 |

All 30 timing rows agree with independent prime-membership truth and with
each other. Batch rebuilt its product/remainder trees inside every measured
call. The same counted Python Euclidean backend was used throughout. Scan
timing includes candidate validation/output and complete fallback (zero calls
in this disjoint-pair profile); generation, I/O, normalization, recovery,
OAEP, truth checks and plotting are excluded.

Memory was measured in six separate runs. The metric is peak traced Python
allocations with inputs preloaded, including scanner output/trees, not RSS or
total RAM. At 100 moduli: 34,256 bytes pairwise, 365,640 bytes batch. There was
one memory measurement per algorithm/fixture; no memory variability estimate
is claimed.

- [Raw timing rows](scalability_results.csv)
- [Raw memory rows](memory_results.csv)
- [Exact summaries](summary.json)
- [Runtime figure](figures/runtime_by_unique_moduli.svg)
- [GCD-call figure](figures/gcd_calls_by_unique_moduli.svg)
- [Traced-memory figure](figures/peak_traced_allocations.svg)
- [Figure source checksums and aggregation](figures/figure_metadata.json)

Figures use median runtime with observed min/max whiskers, not confidence
intervals. All measured samples are retained. The tested sizes are a pilot;
500/1000-modulus runs and multiple independently generated fixtures per size
have not been measured. No universal speedup or security claim follows.

To repeat without overwriting these results:

```bash
python experiments.py --mode scalability --sizes 20 50 100 --bits 2048 --trials 5 --warmups 1 --backend euclidean --dataset-root data/public/scalability --output results/my_new_pilot
python experiments.py --mode plot --input results/my_new_pilot
```
