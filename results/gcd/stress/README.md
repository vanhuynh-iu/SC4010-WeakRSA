# Fresh full-GCD fallback stress — 8 November 2026

The saved mixed fixture contains 18 records / 16 unique RSA-2048 moduli.
Both complete algorithms recover 13 unique moduli / 14 records. Five repeats,
one warm-up per algorithm and separate memory passes all agree with private
reference truth. All 10 timing and two memory rows pass.

Pairwise uses 120 GCD calls. Batch uses
16 leaf plus
53 fallback calls and resolves
all 4 whole-modulus ambiguities.
Median scan times are 0.453322 s pairwise and
0.445313 s batch. Similar timings on this small workload
do not establish a universal or statistically significant speedup.

The same scanner timing/memory scope as the scaling study applies. Raw rows,
source/input hashes, observed ranges and newly drawn figures are retained.
OAEP plaintext checks are in the separate correctness study.

```bash
python -m rsa_auditor.experiments.cli --mode stress --dataset-dirs data/public/gcd_mixed --trials 5 --warmups 1 --backend euclidean --output results/new_stress
python -m rsa_auditor.experiments.cli --mode plot --input results/new_stress
```
