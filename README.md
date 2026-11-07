# SC4010 — RSA public-key auditor

One local program that checks synthetic RSA-2048 public keys for shared prime
factors and unusually close prime factors, then reconstructs recovered private
keys and verifies selected message decryptions.

## Run this first

Open a terminal in this project folder and run:

```bash
.venv/bin/python -m rsa_auditor --mode combined --fermat-budget 256 --evaluate
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
│   ├── evaluation/      check results against private answers
│   └── experiments/     repeated comparisons and plots
├── data/                saved public inputs and private answer sheets
├── results/             actual measurements and figures, including close_primes/
├── tests/               correctness and integration checks
├── docs/                code guide, contributions, publishing and historical maps
├── requirements.txt     Python dependencies
└── README.md            this starting guide
```

`rsa_auditor` uses an underscore because it is a Python import/package name.
The outer folder contains the code plus everything needed to run, check and
explain the project. `.git` stores branch history and `.venv` is the local
Python environment; neither is a second copy of the application.

## Choose a mode

```bash
.venv/bin/python -m rsa_auditor --mode gcd --evaluate
.venv/bin/python -m rsa_auditor --mode fermat --fermat-budget 256 --evaluate
.venv/bin/python -m rsa_auditor --mode combined --fermat-budget 256 --evaluate
```

All commands use `data/public/auditor_demo` by default. GCD-only checks the
collection; Fermat-only searches every unique modulus; combined runs GCD first
and searches remaining moduli. Select `--gcd-backend pairwise` or `batch`.
The default audit mode is GCD, so explicitly select combined for the full demo.
A budget is per unique modulus and the first candidate counts as one.
Exhaustion or an absent shared factor is not a claim of security.

For public-only operation, omit `--evaluate` or specify the file directly:

```bash
.venv/bin/python -m rsa_auditor --public-only data/public/auditor_demo/public.json --mode combined --fermat-budget 256
```

The auditor receives ID, n, e and ciphertext. The separate `data/private/` file
contains the generator's original primes and expected messages. It is an answer
sheet for checking the attack afterward, not an attack input.

## After the demo

Run a repeatable comparison into a new output directory:

```bash
.venv/bin/python -m rsa_auditor.experiments --mode compare --dataset data/public/auditor_demo --budgets 16 256 --trials 5 --output results/my_comparison
```

Run the tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Create another mixed dataset only when needed:

```bash
.venv/bin/python -m rsa_auditor.datasets --case auditor --name my_auditor --bits 2048 --message "SC4010 combined auditor demo"
```

Output files refuse overwrite; use a new name for each generated dataset or
experiment. The saved findings already provide evidence for a presentation:
see [results/README.md](results/README.md). Scan times exclude generation, I/O,
normalization, record mapping, recovery/OAEP and private evaluation; the source
metadata states the exact boundary. Fixed-fixture pilots do not establish a
universal speedup.

## Guides and original work

- [Code guide](docs/CODE_GUIDE.md): reading order and the private-answer boundary.
- [Contributions](docs/CONTRIBUTIONS.md): original algorithms and AI-assisted integration.
- [Publishing](docs/PUBLISHING.md): how to advance main after reviewing this branch.

Only the original close-prime files used by the program are kept in the active
package, unchanged in content: `attacks/fermat_original.py` and
`datasets/generators/close_primes_original.py`. All historical close-prime CSVs
and graphs are in [results/close_primes/](results/close_primes/README.md).
The full original standalone studies remain on `close-primes` at `bd60ccb`;
the old GCD demonstration remains in `gcd` at `2660d26`. Current commands run
the integrated auditor studies; use those original revisions to reproduce
standalone historical studies. Historical run metadata is preserved unchanged.

No branch was published automatically, and the original branches were not edited.
