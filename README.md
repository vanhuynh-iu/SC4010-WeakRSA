# SC4010 — RSA public-key auditor

A local auditor for synthetic RSA-2048 keys with shared prime factors or
unusually close prime factors. It combines Van's GCD work with Krystal's
Fermat implementation in one system.

## Start here

Run commands from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python demo.py --mode combined --fermat-budget 256 --evaluate
```

The saved demonstration has 8 public records / 7 unique 2048-bit moduli.
At budget 256, the recorded combined run recovers 4 moduli / 5 records and
verifies all 5 OAEP plaintexts. Three moduli exhaust that Fermat budget.
`--evaluate` loads the separate private truth only after scanning and recovery.
Omit it for a public-only audit.

## Folder guide

```text
SC4010-WeakRSA/
├── demo.py                  # run the auditor
├── build_dataset.py         # create a saved dataset
├── experiments.py           # run experiments or plots
├── rsa_auditor/
│   ├── cli.py               # audit command and report output
│   ├── audit_pipeline.py    # public-only audit orchestration
│   ├── key_recovery.py      # validate recovered factors and decrypt
│   ├── public_inputs.py     # validate/deduplicate public records
│   ├── records.py           # shared record and result formats
│   ├── attacks/
│   │   ├── pairwise_gcd.py
│   │   ├── batch_gcd.py
│   │   └── fermat.py        # budgeted interface to the original baseline
│   ├── datasets/
│   │   ├── storage.py       # public/private JSON and checksums
│   │   ├── builder.py       # assemble cases and assign neutral IDs
│   │   ├── cli.py           # dataset-building command
│   │   └── generators/      # shared_primes.py, close_primes.py, controls.py
│   ├── evaluation/
│   │   ├── reference.py     # prepare the private answer sheet
│   │   ├── checks.py        # grade completed three-mode audits
│   │   └── gcd.py           # original GCD-only evaluation
│   └── experiments/
│       ├── cli.py           # select an experiment
│       ├── comparison.py    # three-mode/budget comparison
│       ├── gcd_scalability.py
│       ├── gcd_checks.py    # correctness and companion coverage
│       ├── plots.py         # aggregate and draw saved measurements
│       └── common.py        # shared execution, loading and provenance
├── data/public/             # attack inputs
├── data/private/            # synthetic answer sheets
├── results/                 # saved combined/GCD measurements
├── tests/                   # correctness and integration tests
├── legacy/close_primes/     # original close-prime code and results
├── legacy/gcd_demo.py       # original GCD demonstration
└── docs/                    # code guide, contributions and publishing
```

Read [the code guide](docs/CODE_GUIDE.md) for the short execution path and an
explanation of the public/private boundary. The root Python files remain small
launchers, so the same three commands work after the refactor. The original
close-prime files/results remain unchanged in content and are used by adapters.
The `close-primes`, `gcd` and `main` branch references are unchanged.

## What “private evaluation truth” means

Because we generated these synthetic keys, we know the original primes and
messages. We save those answers separately in `data/private/` so a checker can
grade the audit. The auditor receives `data/public/`: ID, n, e and ciphertext.
It must calculate the factors itself. In the demo, `--evaluate` reads the answer
sheet after the audit and decryption. Without that option, the demo never loads
it. The two paths in the design diagram describe separate responsibilities,
not two attacks running in parallel.

## Three modes, one saved input

```bash
python demo.py --mode gcd
python demo.py --mode fermat --fermat-budget 256
python demo.py --mode combined --fermat-budget 256
```

| Mode | Execution |
| --- | --- |
| `gcd` | Scan every unique modulus using the selected GCD backend |
| `fermat` | Search each unique modulus independently, up to B candidates each |
| `combined` | Run GCD first, then Fermat only on remaining unfactored moduli |

Choose `--gcd-backend pairwise` or `--gcd-backend batch` (default). The CLI
defaults to GCD mode. The first Fermat candidate counts as one; budget zero
performs no candidate tests. Combined records the first successful method.
`budget_exhausted`, `no_shared_factor_in_dataset` and `not_run` are different
outcomes; none establishes that a key is secure.

To use a public file directly and save a new lossless JSON report:

```bash
python demo.py --public-only data/public/auditor_demo/public.json --mode combined --fermat-budget 256 --output results/my_audit/report.json
```

Reports distinguish unique moduli from original records, retain each record's
exponent, and include stage statuses, counters and recovered plaintext bytes as
hex. Existing output files are protected from overwrite.

## Datasets and experiments

Create another mixed collection without replacing the saved demonstration:

```bash
python build_dataset.py --case auditor --name my_auditor --bits 2048 --message "SC4010 combined auditor demo"
```

The collection contains a shared-prime pair, two controls, three close-prime
cases at different costs and a duplicate. Neutral IDs and shuffling hide case
labels; private truth is stored separately. Unrelated sources are checked for
accidental prime reuse. Save once and compare the same public bytes across all
modes; a shuffle seed alone does not reproduce cryptographic prime generation.

Run the shared mode/budget comparison:

```bash
python experiments.py --mode compare --dataset data/public/auditor_demo --budgets 16 256 --trials 5 --output results/my_comparison
```

The runner uses fresh state and rotates mode order. It records recovery sets,
overlap, additional combined recoveries, union agreement, candidate work,
exhaustion, scan time and actual verified decryptions. The gap/budget CSV is
explicitly evaluator-only; private gaps never enter the attack.

Scan time includes selected GCD work, trees/fallback, Fermat calls and factor
validation. It excludes normalization, record mapping, generation, I/O,
recovery/OAEP, evaluation and reporting. Memory is measured separately by the
original GCD runner, not the shared comparison. These small fixed-fixture pilots
do not establish a universal speedup.

See [results/README.md](results/README.md) for saved findings and raw files.
Earlier benchmark metadata preserves its original source revision and paths;
[the initial move record](docs/layout-migration.json) and [component refactor record](docs/component-migration.json) trace those paths through the current layout.
Recorded measurements keep their original run metadata; cleanup smoke checks use temporary outputs.

## Tests, originals and history

```bash
python -m unittest discover -s tests -v
```

The suite covers budget boundaries, duplicates and different exponents for the
same modulus, full-GCD fallback, mode unions, public/private separation, and
real RSA-2048 recovery/decryption through both attack branches.

To run the original standalone projects:

```bash
python -m legacy.gcd_demo --dataset data/public/van_demo
cd legacy/close_primes
python demo.py
```

Original close-prime scripts use their sibling imports and local `results/`
folder. Their [project notes](legacy/close_primes/README.md) explain that layout.

[Contributions and AI assistance](docs/CONTRIBUTIONS.md) records actual source
provenance. [Publishing steps](docs/PUBLISHING.md) explain how to make this
version GitHub's `main` after review. Nothing was pushed automatically.
