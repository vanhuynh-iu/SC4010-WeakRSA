# Fresh GCD correctness and OAEP check — 8 November 2026

Both pairwise and batch recover 13 unique moduli / 14 records from the saved
mixed RSA-2048 fixture. There are zero false-positive or false-negative moduli;
all 14 expected OAEP plaintexts are checked and match for each algorithm.
The two rows are single correctness checks, not repeated benchmarks.

`shared_prime_correctness.csv` contains actual checks; `correctness_metadata.json`
records configuration and input/source hashes.

```bash
python -m rsa_auditor.experiments.cli --mode correctness --dataset-dirs data/public/gcd_mixed --output results/new_correctness
```
