# Educational shared-prime fixtures

`van_demo/` was actually generated and exercised on 2026-10-24 with Python
3.9.6, PyCryptodome 3.24.1, and macOS arm64.

- `public.json`: six public RSA moduli, each exactly 2048 bits, exponent 65537,
  neutral key IDs, and RSA-OAEP/SHA-256 ciphertexts. Integers are decimal
  strings and ciphertexts are hexadecimal.
- `private_truth.json`: separate original factors, scenario labels, expected
  vulnerable IDs, and expected plaintext bytes. This is evaluator data, not
  input to the attack.

These are deliberately generated educational keys, not operational credentials.
The verified outcome was two recovered vulnerable records, four unaffected
controls, one useful matching pair, 15 GCD comparisons, zero false positives,
and two correct plaintext recoveries. Timing varies and is not claimed as a
repeated benchmark result.

Rerun without generating new primes:

```bash
.venv/bin/python -m rsa_auditor --load-fixtures fixtures/van_demo
```

Run the attacker without loading evaluator truth:

```bash
.venv/bin/python -m rsa_auditor --public-only fixtures/van_demo/public.json
```

## V2 mixed and coverage fixtures

The original `van_demo/` files were retained unchanged. New fixtures were
actually generated/executed on 2026-10-28; these are correctness checks, not
repeated benchmarks:

- `van_mixed_v2/`: 18 records/16 distinct 2048-bit moduli, two duplicate extra
  records, shared pair/group, controls, duplicate-only, duplicate+companion,
  split-factor chain and triangle. The checked run recovered 13 moduli/14
  records with 120 GCD calls and 14 successful OAEP checks. A duplicate record
  uses a different public exponent and still decrypts correctly.
- `van_coverage_v2/before/`: target plus two controls, no companion; target is
  not factored, and decryption is unperformed/null.
- `van_coverage_v2/after/`: identical target n/e/ciphertext, companion added;
  target and companion are factored and decrypted. `coverage_result.json`
  contains the actual before/after run and verification flags.

These new sets use explicit v2 hexadecimal integer strings and manifests with
file hashes/counts/environment. Original v1 decimal fixtures still load. No
private data is required by the public-only loader, including with a manifest.

```bash
.venv/bin/python -m rsa_auditor --load-fixtures fixtures/van_mixed_v2
.venv/bin/python -m rsa_auditor --public-only fixtures/van_mixed_v2/public.json
.venv/bin/python -m rsa_auditor --load-fixtures fixtures/van_coverage_v2/before
.venv/bin/python -m rsa_auditor --load-fixtures fixtures/van_coverage_v2/after
```

## Scalability inputs

`scalability_v2/m20_bits2048`, `m50_bits2048` and `m100_bits2048` are actual
saved factor-only inputs used by the repeated benchmark. Every n has exactly
2048 bits; 20% of unique moduli belong to disjoint shared-prime pairs and 80%
are independent controls. These profiles have no duplicate n. Each set has
public/private files and a manifest with exact checksums and configuration.
Ciphertexts are omitted because E3 measures factor recovery, not OAEP.

Fixtures were saved before timing, reused unchanged for both algorithms and
all trials, and were not regenerated from a deterministic seed. Results and
machine/code metadata are in `results/van_batch_pilot_v2`. The mixed fixture
above is reused separately in `results/van_batch_stress_v2` to measure fallback.
