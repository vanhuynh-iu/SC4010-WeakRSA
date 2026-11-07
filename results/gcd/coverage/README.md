# Fresh companion-coverage check — 8 November 2026

Both algorithms inspect the same target before and after adding a distinct
modulus sharing its prime. Every pre-existing public record, including target
n/e/ciphertext, remains identical. Before: no shared factor is observed and the
target is not decrypted. After: its factors and plaintext are recovered and
verified. All four single correctness checks pass; these are not benchmarks.

`coverage_results.csv` contains actual statuses/checks; `coverage_metadata.json`
records the source/input identities and verifies the unchanged-before-records
condition. The result demonstrates a collection-observation limit, not security
of the unobserved target.

```bash
python -m rsa_auditor.experiments.cli --mode coverage --before data/public/gcd_coverage/before --after data/public/gcd_coverage/after --target-key-id key_001 --output results/new_coverage
```
