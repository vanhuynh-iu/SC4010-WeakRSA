# SC4010 — RSA public-key auditor

One local auditor for two deliberate weaknesses in synthetic RSA-2048 keys:
shared primes across different keys, and unusually close primes within one key.
It implements known attacks; it does not break arbitrary RSA-2048.

## Run the integrated demo

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python demo.py --mode combined --fermat-budget 256
```

The saved default dataset is `data/public/auditor_demo`. The command reads only
public records, runs the attacks, reconstructs recovered keys, and decrypts the
available synthetic OAEP ciphertexts. Private factors and expected messages are
not attack inputs. To check the results afterward against separate evaluator
truth, add `--evaluate`:

```bash
python demo.py --mode combined --fermat-budget 256 --evaluate
```

All three modes use the same saved public file:

```bash
python demo.py --mode gcd
python demo.py --mode fermat --fermat-budget 256
python demo.py --mode combined --fermat-budget 256
```

| Mode | What runs |
| --- | --- |
| `gcd` | One selected complete GCD scanner on every unique modulus |
| `fermat` | Independent Fermat search on each unique modulus, up to B candidates each |
| `combined` | GCD first; Fermat with the same B on the unfactored moduli |

Select `--gcd-backend pairwise` or `--gcd-backend batch` (default). The CLI defaults
to GCD mode; the integrated demonstration above explicitly selects combined.
The first Fermat candidate counts as one. A zero budget performs no candidate
tests. `budget_exhausted`, `no_shared_factor_in_dataset`, and `not_run` have
different meanings; none says a key is secure. Combined records the first
successful method, so a GCD success skips Fermat even if both could recover it.

For an explicit public-only path and a saved JSON report:

```bash
python demo.py --public-only data/public/auditor_demo/public.json --mode combined --fermat-budget 256 --output results/my_audit/report.json
```

The report distinguishes unique moduli from original records, preserves each
record's exponent, shows each stage's status and work counters, and includes
recovered plaintext bytes as hex. Reports refuse to overwrite existing files.

## Simple code map

```text
public records -> normalize/deduplicate -> GCD -> Fermat on remaining moduli
               -> validate factors -> map original records -> recover/decrypt
```

| File | Responsibility |
| --- | --- |
| `demo.py` | One command for the integrated audit and report |
| `audit_pipeline.py` | Three modes, stage outcomes, timing and record mapping |
| `normalization.py`, `contracts.py` | Public records, validation and shared result formats |
| `shared_prime_attack.py`, `batch_gcd_attack.py` | Van's pairwise/batch GCD algorithms |
| `fermat_attack.py` | Krystal's original Fermat implementations, unchanged |
| `fermat_adapter.py` | Bounded common interface to her original Fermat baseline |
| `key_recovery.py` | Common factor validation, extended Euclid and OAEP-SHA256 recovery |
| `generators/` | Shared-prime/control cases and an adapter to her original generator |
| `dataset_io.py` | Lossless public/private fixture files and checksums |
| `build_dataset.py` | Assemble, deduplicate-copy, shuffle and save cases |
| `evaluation.py` | Independent private checks, used after the attack |
| `compare_modes.py`, `experiments.py` | Shared mode comparison and original GCD experiments |
| `data/`, `results/`, `tests/` | Saved inputs, actual measurements, correctness checks |

The original GCD demo remains `gcd_demo.py`; her original demo remains
`demo_close_primes.py`. Her generation, Fermat variants, prime-gap/sieving
experiments and saved results are preserved. The integrated budget uses the
baseline's consecutive candidate tests, so it has one clear meaning across
standalone and combined mode. Her optimized variants remain available for her
separate comparisons.

## Saved mixed dataset

`auditor_demo` has **8 records / 7 unique 2048-bit moduli**: a shared-prime pair,
two independent controls, three close-prime cases with different search costs,
and a copy of one shared-prime record. IDs are neutral and order is shuffled.
Only the private evaluator file contains labels, factors, actual gaps and
expected plaintext. Unrelated cases are checked for accidental prime reuse.

To generate another fixture without overwriting the saved demonstration:

```bash
python build_dataset.py --case auditor --name my_auditor --bits 2048 --message "SC4010 combined auditor demo"
```

A shuffle seed fixes ordering, not cryptographic primes. Save the file once and
compare modes on those exact bytes. Public files are under `data/public/`; the
matching evaluator files are under `data/private/`.

## Experiments

Run the shared comparison with fresh state for every mode, budget and trial:

```bash
python experiments.py --mode compare --dataset data/public/auditor_demo --budgets 16 256 --trials 5 --output results/my_comparison
```

It saves raw `mode_comparison.csv`, `summary.json`, `run_metadata.json`, and an
explicitly evaluator-only `fermat_gap_budget.csv`. Results include recovery sets,
overlap, additional combined recoveries, union agreement, candidate counts,
exhaustion, scan time and actual checked decryptions. Private gaps are exported
only after the scans. Failed runs remain explicit rather than appearing as zero
runtime or successful factorisations at the budget cap.

Scan timing includes selected GCD work (trees and fallback included), Fermat
searches and factor validation. It excludes normalization, record mapping,
generation, I/O, key reconstruction/decryption, evaluation and printing. Mode
order rotates across repeats. This small fixed fixture is an integration pilot,
not evidence of a universal speedup. The joint runner does not measure memory;
the original pairwise/batch runner measures traced allocations separately.

The checked-in shared pilot is in `results/auditor_pilot/`. Earlier Van findings
are described in [results/README.md](results/README.md). Krystal's original CSVs
and graphs remain in `results/`; `prime_gap_experiments.py` and
`sieve_experiments.py` retain her separate experiments. Her runtime extrapolation
is a prediction, distinct from measured results.

## Verify and explain the work

```bash
python -m unittest discover -s tests -v
```

Tests cover budget boundaries, duplicate-only and same-n/different-e records,
full-GCD fallback, independent mode unions, public/private separation, and real
RSA-2048 recovery/decryption through both attack branches. Adding a shared-prime
companion can make an unchanged target recoverable; exhaustion only describes
the configured search budget.

See [CONTRIBUTIONS.md](CONTRIBUTIONS.md) for source provenance and the AI-assisted
integration record. Planned ownership is not proof of actual authorship.
