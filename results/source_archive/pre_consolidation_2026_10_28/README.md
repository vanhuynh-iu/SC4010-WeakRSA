# SC4010-WeakRSA

Local educational demonstrations of deliberately weak RSA key generation.
Van's shared-prime path is runnable: generate keys, encrypt a message, scan
public moduli, recover factors and the private exponent, decrypt, and verify.

The pairwise and batch auditors follow the v2 normalization/result contracts.
The three stages are `key_dataset.py` (records -> unique moduli),
`shared_prime_attack.py` (unique moduli -> factors), and
`shared_prime_auditor.py` (factors -> affected records). The original Euclidean
GCD and recovery interfaces are retained.

## Run now

Run commands from the repository root. A `.venv` with the required dependency
has already been prepared in this workspace.

```bash
# Start with readable numbers: 187 and 253 share the prime 11.
.venv/bin/python -m rsa_auditor --small

# Run the saved, tested 2048-bit scenario without generating primes again.
.venv/bin/python -m rsa_auditor --load-fixtures fixtures/van_demo

# Run all unit and integration tests.
.venv/bin/python -m unittest discover -s tests -v

# Saved mixed v2 dataset: duplicates, different exponents, chains and triangles.
.venv/bin/python -m rsa_auditor --load-fixtures fixtures/van_mixed_v2

# Same inputs and recovery path, now using batch GCD with complete fallback.
.venv/bin/python -m rsa_auditor --load-fixtures fixtures/van_mixed_v2 --algorithm batch

# Coverage: target stays identical; remove then add its companion.
.venv/bin/python -m rsa_auditor --load-fixtures fixtures/van_coverage_v2/before
.venv/bin/python -m rsa_auditor --load-fixtures fixtures/van_coverage_v2/after
```

For a fresh checkout, prepare the environment first:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Charts are optional; this workspace also has the tested plotting dependency:

```bash
.venv/bin/python -m pip install -r requirements-plots.txt
```

Python 3.9 or later is supported. Validation in this workspace used Python
3.9.6 and PyCryptodome 3.24.1 on macOS arm64.

## Generate and attack your own fixtures

```bash
# Default: six 2048-bit moduli, two sharing one prime, four unrelated controls.
.venv/bin/python -m rsa_auditor

# Save a new scenario. Choose a new directory for each fixture set.
.venv/bin/python -m rsa_auditor --num-keys 8 --shared-keys 3 --save-fixtures fixtures/my_run

# The attacker needs no private fixture file to recover/decrypt vulnerable keys.
.venv/bin/python -m rsa_auditor --public-only fixtures/van_demo/public.json

# Change the test message (OAEP SHA-256 allows at most 190 bytes at 2048 bits).
.venv/bin/python -m rsa_auditor --message "Hello Van"

# Generate all mixed topologies and save hex v2 data plus checksums/metadata.
.venv/bin/python -m rsa_auditor --mixed --save-fixtures fixtures/my_mixed_run --fixture-encoding hex

# Run a new before/after coverage check, preserving the target ciphertext.
.venv/bin/python -m rsa_auditor --coverage
```

Prime generation happens before attack timing and can take time. Generation
uses a finite outer retry budget and reports an error if it cannot meet the
constraints. Existing saved fixture files are never overwritten. Use
`--load-fixtures DIR` to reuse them, or a new directory to save another case.

## What to read

| File | Responsibility |
| --- | --- |
| `key_generation.py` | Van: reuse one prime deliberately; ensure other factors are unique, exponent-compatible, and produce exact-size moduli |
| `key_dataset.py` | Van: validate public records, deduplicate by n, preserve per-record exponents |
| `shared_prime_attack.py` | Van: Euclidean GCD and public-only pairwise scanning |
| `batch_gcd_attack.py` | Van: product/remainder trees, raw classification and whole-GCD fallback |
| `shared_prime_auditor.py` | Van: separate preprocessing/scan timing and propagate modulus findings to records |
| `key_recovery.py` | Van: extended GCD, inverse, private exponent, and OAEP wrappers |
| `demo.py` | Shared-prime integration and a reusable scan-timing helper |
| `shared_prime_fixtures.py` | Lossless public/private fixture storage |
| `experiments.py` | Shared-prime support runner; Krystal remains framework lead |
| `experiment_checks.py` | E1 correctness and E2 observed-dataset coverage CSVs |
| `plot_results.py` | Reproduce PNG/SVG runtime, GCD-count and traced-memory figures from CSVs |
| `tests/` | Arithmetic, generator, scanner, recovery, and integration checks |

`--small` uses textbook integer RSA so intermediate values are readable. The
large-key path uses library RSA-OAEP with SHA-256. See PyCryptodome's official
[RSA](https://www.pycryptodome.org/src/public_key/rsa),
[OAEP](https://www.pycryptodome.org/src/cipher/oaep), and
[number utilities](https://www.pycryptodome.org/src/util/util) documentation.
The installed API was inspected and tested; `requirements.txt` pins that version.

## Interfaces for integration

```python
generate_shared_prime_keys(num_keys=4, num_shared=2, modulus_bits=2048, e=65537)
# -> {public_keys, private_truth, expected_vulnerable_ids, modulus_bits}

normalize_public_keys(public_records)
# -> public_records, unique_moduli, records_by_modulus, duplicate_groups, counts

scan_moduli(unique_moduli, gcd_fn=None)
# -> algorithm, findings[n], gcd_calls and the other v2 scan counters

audit_public_keys(public_records, gcd_fn=None, algorithm="pairwise")
# -> scan result + record_findings, recovered_records, counts and timings

scan_moduli_batch(unique_moduli, gcd_fn=None, resolve_full_gcd=True)
# -> same v2 result contract, including raw_batch_gcd and fallback counters

recover_private_key(p, q, e)
# -> integer private exponent d, not a library key object

decrypt_with_recovered_key(ciphertext, n, e, p, q)
# -> plaintext bytes; checks p*q == the original public n
```

Public records contain `key_id`, `n`, and `e`, plus optional ciphertext bytes.
Unknown/private fields are rejected, as are invalid IDs, integer types, and
even/nonpositive public parameters. This validation does not prove that n is a
two-prime semiprime. The core scanner receives only distinct integers; passing
raw records or duplicate moduli directly is an error.

Deduplication is by n, including when two records have different e. Each
record keeps its own e for recovery. A finding is `factored` or
`no_shared_factor_in_dataset`; factor order is p<q. Duplicate membership is
independent of factorization status. Krystal can pass her recovered p/q into
the unchanged `recover_private_key(p,q,e)->d` interface later.

Select `algorithm="batch"` or `"batch_with_fallback"` in the auditor. Each
batch run builds a new product tree and computes remainders modulo n squared.
Whole-modulus raw GCDs stay unresolved until fallback compares against other
unique moduli throughout the dataset, including already resolved companions.
`batch_raw` disables fallback for diagnostics only; its unresolved results are
not a complete auditor benchmark and may cause the expected-set check to fail.
Batch does not compute a full pair graph: `matching_pair_count` and the legacy
summary `matching_pairs` are null. Use its leaf/fallback counters instead.

Every unordered pair of m unique moduli is scanned once, even after a factor
is known: `pairwise_gcd_calls = m*(m-1)//2`. Debug witnesses are capped at 20;
the scalar `matching_pair_count` stays exact. There is no required full
record-pair graph. The auditor propagates each factorization to every matching
record, preserving its exponent and original order.

For compatibility, audit reports retain `recovered_keys` as an alias for
`recovered_records` and `gcd_comparisons` as an alias for `gcd_calls`. Summary
`recovered_unique_keys` is an old alias for recovered record count. Prefer
`num_records`, `num_unique_moduli`, `duplicate_extra_records`,
`recovered_records`, and `recovered_unique_moduli` in new consumers. This is a
deliberate scanner API migration: callers of the old raw-record scan should
use `audit_public_keys` instead.

## Timing and interpretation

`demo.measure_shared_prime_scan(public_keys)` still returns `(result, seconds)`.
In v2, seconds is scan-only. `preprocessing_seconds` separately measures public
record validation/deduplication. `scan_seconds` measures the core unique-modulus
scan and its validation/output using `perf_counter_ns`; propagation, generation,
I/O, OAEP, evaluator truth, and printing are excluded. This boundary differs
from the earlier per-record timer, so old/new timings should not be pooled.
The printed `end_to_end_seconds` starts with in-memory records and ends after
normalization, scan, recovery/decryption and evaluation; it excludes generation,
loading/saving and printing. `attack_seconds` is a legacy scan-seconds alias.

The saved fixture has six distinct 2048-bit moduli. Its verified outcome is
two recovered vulnerable records, 15 comparisons, no false positives, and
successful message decryption. Unit tests also cover unrelated/duplicate
moduli, noninvertible values, invalid factors, damaged ciphertext, and running
with the private fixture file absent. Tests use smaller moduli for speed;
the saved 2048-bit cases were separately executed end to end.

The mixed v2 fixture was actually generated and run: 18 records, 16 unique
moduli, 2 duplicate extras, 120 GCD calls, 13 recovered moduli/14 affected records,
and 14 checked/passed OAEP decryptions, including duplicate n with a different e.
Independent controls and duplicate-only keys were not factored. Coverage was
also run on 2048-bit keys: before adding the companion the target has status
`no_shared_factor_in_dataset`; after adding it the same target/ciphertext is
factored and decrypted. `fixtures/van_coverage_v2/coverage_result.json` records
that actual run, not a theoretical output.

`decryption_cases_attempted`, `decryption_cases_checked`, and
`decryption_cases_passed` distinguish decryptions from factorization counts.
Fixtures may omit ciphertext/expected plaintext. Unperformed verification is
null, and `all_decryptions_verified` is true only when every recovered record
was actually checked successfully. Summary success covers factorization and
available plaintext checks; inspect the explicit counts for OAEP coverage.

New fixture saves include manifest.json with actual public/private checksums,
record/unique counts, bit lengths, environment, UTC creation time and construction
metadata. Default v1 decimal files remain supported unchanged; opt into v2 hex
with `--fixture-encoding hex`. The public-only loader verifies public metadata
without reading or requiring private truth. Checksums detect mismatches; they
are not signatures or proof of authenticity.

Those demo timings are single correctness checks, not repeated benchmarks.
The experiment runner below now writes actual E1/E2 CSVs and E3 repeated runs.

## Experiment commands

Run these from the root with the virtual environment active (or replace
`python` by `.venv/bin/python`). Existing result files are never overwritten;
use a new output directory to repeat a run. Importing the modules starts no job.

```bash
# E1: both algorithms, independent ground truth, all available OAEP checks.
python -m rsa_auditor.experiments --mode correctness --dataset-dirs fixtures/van_mixed_v2 --output results/my_correctness_run

# E2: preserve the target/ciphertext and add its companion; both algorithms.
python -m rsa_auditor.experiments --mode coverage --before fixtures/van_coverage_v2/before --after fixtures/van_coverage_v2/after --target-key-id key_001 --output results/my_coverage_run

# E3: save/reuse datasets first; five measured trials per algorithm and size.
python -m rsa_auditor.experiments --mode scalability --sizes 20 50 100 --bits 2048 --trials 5 --warmups 1 --backend euclidean --dataset-root fixtures/scalability_v2 --output results/my_scalability_run

# Render measured runtime, GCD-call and memory charts without rerunning scans.
python plot_results.py results/my_scalability_run
```

Scalability sizes must be multiples of ten, at least ten. The main construction
puts exactly 20% of distinct moduli into disjoint shared pairs, with 80%
independent controls and no duplicate records. Larger sizes such as 500/1000
are supported but have not been measured in the saved pilot. Generation can
take time and finishes before measurements. The CSPRNG is not seeded to fake
reproducible keys; saved fixture files and their hashes define each dataset.

Each trial uses the same preloaded normalized tuple and counted Euclidean
backend for both scanners. Their order alternates; each gets one separate
warm-up by default. Trees and candidate caches are fresh on every scan.
Tree construction and fallback are inside batch timing. Post-scan validation
checks factors against independent truth, agreement between algorithms and
actual backend call counters. `--backend math` is a separate labelled series,
not an unlabelled substitute for one side of the comparison.

Memory is a separate pass, not part of the runtime samples. The metric is
`tracemalloc_peak_python_allocations`: peak traced Python allocations during
the scanner with input already loaded, including trees/output; it is not total
process RAM/RSS. `--skip-memory` omits this pass. Failed, mismatched or
incomplete comparisons remain in raw CSVs and are excluded from successful
timing statistics. Standard deviation is null with fewer than two samples.

Outputs include `scalability_results.csv`, `memory_results.csv`, `summary.json`
and `run_metadata.json` (source hashes, dirty Git state/revision, machine,
versions, dataset hashes, boundaries and execution order). Charts use only
successful reference-verified rows, median runtime and observed min/max
whiskers. These whiskers are not confidence intervals.

## Results actually executed

On 2026-10-28, the saved pilot used one independently generated 2048-bit
fixture per size, five timing repetitions per algorithm/fixture, one warm-up
per algorithm/fixture and one separate memory pass. All 30 timing rows and
six memory rows passed validation. These are repeated timings of the same
fixture, not five independent generated datasets.

| Unique moduli | Pairwise median seconds | Batch median seconds | Pairwise GCD calls | Batch GCD calls |
| ---: | ---: | ---: | ---: | ---: |
| 20 | 0.182842 | 0.160684 | 190 | 20 |
| 50 | 0.574475 | 0.416815 | 1,225 | 50 |
| 100 | 1.540518 | 0.888476 | 4,950 | 100 |

See [the saved pilot](results/van_batch_pilot_v2/README.md), including raw CSVs
and SVG/PNG figures. Batch used more traced allocations in this pilot; at
100 moduli the separate peaks were 34,256 bytes pairwise and 365,640 bytes
batch. This tradeoff and the measured speedups apply to these inputs/backend.

The mixed chain/triangle stress fixture was also measured five times per
algorithm: median 0.450177 seconds pairwise and 0.443840 seconds batch. Batch
made 16 leaf plus 53 fallback calls; all four raw full-GCD cases were resolved.
Its observed batch range was wider (0.443429–0.670946 seconds), so this is not
evidence of a universal speedup. Raw runs are in `results/van_batch_stress_v2`.
E1 and E2 outputs are in `results/van_batch_correctness_v2` and
`results/van_batch_coverage_v2`; their timings are labelled single correctness
checks and are not pooled with E3 benchmark samples.

The batch construction follows [FactHacks batch GCD](https://facthacks.cr.yp.to/batchgcd.html)
and its [remainder-tree description](https://facthacks.cr.yp.to/remainder.html).
Memory terminology follows Python's [tracemalloc documentation](https://docs.python.org/3.9/library/tracemalloc.html).

## Scope and team boundaries

Krystal's close-prime generator and Fermat search remain to be integrated.
Krystal remains lead owner of the experiment framework. No Fermat algorithm
was created or replaced. Final group integration,
slides and presentation rehearsal remain unfinished.

All fixtures are educational test data generated by the project. Successful
attacks demonstrate the deliberately inserted shared-prime weakness. A control
surviving this scanner does not establish security against other attacks.

