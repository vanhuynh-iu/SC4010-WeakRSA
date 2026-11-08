# Fresh pairwise/batch GCD scaling — 8 November 2026

Three saved RSA-2048 fixtures contain 20% moduli in independent shared-prime
pairs and 80% controls, with no duplicate moduli. Each algorithm uses the same
counted Python Euclidean GCD backend and identical preloaded public inputs.
Five repeats follow one warm-up per algorithm/fixture, with alternating order.
All 30 timing rows, six warm-ups and six separate memory passes pass reference
checks. These are new executions on existing fixtures.

| Unique moduli | Pairwise median s | Batch median s | Speedup | Pairwise calls | Batch calls |
| --- | --- | --- | --- | --- | --- |
| 20 | 0.183563 | 0.161505 | 1.14x | 190 | 20 |
| 50 | 0.576241 | 0.418002 | 1.38x | 1225 | 50 |
| 100 | 1.554279 | 0.892413 | 1.74x | 4950 | 100 |

At 100 moduli, peak traced allocations are 34,252 bytes pairwise
and 365,640 bytes batch. These are Python allocations
with preloaded inputs, not RSS or total RAM. Each algorithm/fixture has one
memory pass; no memory variability estimate is established.

Full scanner calls include batch trees, candidate checks and fallback. Timing
excludes generation, I/O, normalization, recovery/OAEP and evaluation. Figures
in `figures/` use medians with observed minimum/maximum whiskers, not confidence
intervals. One saved fixture per size limits generalization; batch does not
universally outperform pairwise.

```bash
python -m rsa_auditor.experiments.cli --mode scalability --sizes 20 50 100 --bits 2048 --trials 5 --warmups 1 --backend euclidean --dataset-root data/public/scalability --output results/new_scalability
python -m rsa_auditor.experiments.cli --mode plot --input results/new_scalability
```
