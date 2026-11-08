# SC4010 — RSA public-key auditor

One local program that checks synthetic RSA-2048 public keys for shared prime
factors and unusually close prime factors, then reconstructs recovered private
keys and verifies selected message decryptions.

## Run this first

Open a terminal in this project folder and run:

```bash
.venv/bin/python -m rsa_auditor.cli --mode combined --fermat-budget 256 --evaluate
```

Expected result for the saved demonstration: **8 records / 7 unique moduli;
4 recovered moduli / 5 records; all 5 plaintext checks pass**. Three moduli
exhaust the Fermat budget. `--evaluate` checks the results against the separate
synthetic answer sheet after scanning and recovery.

If setting up a new environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## What the outer folder means

```text
SC4010-WeakRSA/           the whole project, not a second program
├── rsa_auditor/         ALL application code
│   ├── attacks/         pairwise GCD, batch GCD and bounded Fermat
│   ├── datasets/        create, assemble and load inputs
│   ├── evaluation.py    check results against private answers
│   └── experiments/     repeated comparisons and plots
├── data/                saved public inputs and private answer sheets
├── results/             fresh measurements and figures
├── tests/               correctness and integration checks
├── docs/                code guide, contributions and publishing
├── requirements.txt     Python dependencies
└── README.md            this starting guide
```

`rsa_auditor` uses an underscore because it is a Python import/package name.
The outer folder contains the code plus everything needed to run, check and
explain the project. `.git` stores branch history and `.venv` is the local
Python environment; neither is a second copy of the application.

## Choose a mode

```bash
.venv/bin/python -m rsa_auditor.cli --mode gcd --evaluate
.venv/bin/python -m rsa_auditor.cli --mode fermat --fermat-budget 256 --evaluate
.venv/bin/python -m rsa_auditor.cli --mode combined --fermat-budget 256 --evaluate
```

All commands use `data/public/auditor_demo` by default. GCD-only checks the
collection; Fermat-only searches every unique modulus; combined runs GCD first
and searches remaining moduli. Select `--gcd-backend pairwise` or `batch`.
The default audit mode is GCD, so explicitly select combined for the full demo.
A budget is per unique modulus and the first candidate counts as one.
Exhaustion or an absent shared factor is not a claim of security.

For public-only operation, omit `--evaluate` or specify the file directly:

```bash
.venv/bin/python -m rsa_auditor.cli --public-only data/public/auditor_demo/public.json --mode combined --fermat-budget 256
```

The auditor receives ID, n, e and ciphertext. The separate `data/private/` file
contains the generator's original primes and expected messages. It is an answer
sheet for checking the attack afterward, not an attack input.

## After the demo

Run a repeatable comparison into a new output directory:

```bash
.venv/bin/python -m rsa_auditor.experiments.cli --mode compare --dataset data/public/auditor_demo --budgets 16 256 --trials 5 --output results/my_comparison
```

Run the tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Create another mixed dataset only when needed:

```bash
.venv/bin/python -m rsa_auditor.datasets.cli --case auditor --name my_auditor --bits 2048 --message "SC4010 combined auditor demo"
```

Output files refuse overwrite; use a new name for each generated dataset or
experiment. The freshly measured findings provide evidence for a presentation:
see [results/README.md](results/README.md). Scan times exclude generation, I/O,
normalization, record mapping, recovery/OAEP and private evaluation; the source
metadata states the exact boundary. Fixed-fixture pilots do not establish a
universal speedup.

## Guides and original work

- [Code guide](docs/CODE_GUIDE.md): reading order and the private-answer boundary.
- [Contributions](docs/CONTRIBUTIONS.md): original algorithms and AI-assisted integration.
- [Publishing](docs/PUBLISHING.md): how to advance main after reviewing this branch.

Your friend's Fermat methods live in `attacks/fermat.py`, alongside the bounded
audit entrypoint. Her prime-generation methods live in
`datasets/generators/close_primes.py`, alongside the shared dataset entrypoint.
The algorithms are retained without separate `_original.py` copies; their
original source remains on `close-primes`. The paired pilot measures four
Fermat methods using nine saved RSA-2048 inputs:

```bash
.venv/bin/python -m rsa_auditor.experiments.cli --mode fermat-pilot --fermat-dataset data/public/fermat_pilot --gap-bits 515 518 520 --keys-per-gap 3 --bits 2048 --budgets 16 65536 --output results/new_fermat
```

The fresh GCD fallback study can also be repeated directly:

```bash
.venv/bin/python -m rsa_auditor.experiments.cli --mode stress --dataset-dirs data/public/gcd_mixed --trials 5 --warmups 1 --backend euclidean --output results/new_stress
```

Only fresh runs are kept in the current `results/` tree: `comparison/`,
`gcd/`, `fermat/` and `audit_report.json`. The saved datasets stay because they
are inputs, not obsolete result copies. New execution times can differ from
old runs; use the current study settings and measured values for presentation.

The active code uses the [Google Python style guide](https://google.github.io/styleguide/pyguide.html)
for straightforward functions, descriptive names and explanatory docstrings.
`.style.yapf` selects Google formatting for future edits. Saved measurements
still identify producer revision `4c552fd`; this readability refactor does not
rewrite their timings or source hashes.

The old GCD findings remain on `gcd` at `2660d26`; the full original close-prime
studies remain on `close-primes` at `bd60ccb`. Before deletion, previously
uncommitted local archives were saved exactly in commit `481dbaa`. Normal
promotion to main retains the original project ancestry. The earlier auditor
development commits, including producer `4c552fd` and archive `481dbaa`, are
preserved by tag `archive/rsa-auditor-before-squash-2026-11-08` after consolidation
into three commits. Old result copies, migration maps and archive folders were
removed from the working tree after new runs passed. The original project
branches were not edited.
