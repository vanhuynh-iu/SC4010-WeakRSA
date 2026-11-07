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
├── build_dataset.py         # create a new saved dataset
├── experiments.py           # run repeatable comparisons
├── rsa_auditor/             # shared application code
│   ├── cli.py               # command-line input and audit reports
│   ├── audit_pipeline.py    # GCD / Fermat / combined orchestration
│   ├── shared_prime_attack.py
│   ├── batch_gcd_attack.py
│   ├── fermat_adapter.py    # calls Krystal's original Fermat code
│   ├── key_recovery.py      # factor validation, inverse and OAEP
│   ├── contracts.py         # common records and result formats
│   ├── normalization.py     # validation and duplicate handling
│   ├── dataset_io.py        # lossless public/private JSON files
│   ├── build_dataset.py     # dataset assembly
│   ├── generators/          # shared-prime, control and close-prime cases
│   ├── evaluation.py        # independent post-attack checks
│   ├── compare_modes.py     # shared three-mode comparison
│   └── experiments.py       # original GCD experiments and shared runner
├── data/
│   ├── public/              # attack inputs and checksums
│   └── private/             # evaluator factors, labels and messages
├── results/                 # combined pilot and GCD findings
├── tests/                   # shared correctness and integration tests
├── legacy/
│   ├── close_primes/        # Krystal's original project, preserved together
│   │   └── results/         # her original CSVs and graphs
│   └── gcd_demo.py          # original standalone GCD demo
└── docs/                    # contributions, history and publishing steps
```

The three top-level Python files are small entrypoints. Implementation lives in
`rsa_auditor/`; data, measured outputs and original standalone work each have a
clear home. Krystal's original algorithms are still used through the adapters.
Her original files and saved results were moved without changing their contents.
The `close-primes`, `gcd` and `main` branches are unaffected by this cleanup.

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
[the move record](docs/layout-migration.json) maps those paths to this layout.
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
