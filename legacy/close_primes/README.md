# Original close-prime project

This folder preserves Krystal's project from `close-primes` at `bd60ccb`.
Its original Python files, Docker files, CSVs and graphs are unchanged in
content. The original demo is named `demo.py` here again.

The shared auditor imports the original `fermat_attack` baseline and
`generate_close_prime_key` through adapters. It does not import the experiment
or plotting scripts, some of which execute work immediately when run/imported.

Activate the repository's environment, then use this directory as the working
folder for the original scripts:

```bash
source .venv/bin/activate
cd legacy/close_primes
python demo.py
```

Sibling imports such as `from key_generation import ...` and paths such as
`results/sieve_comparison_2048.csv` therefore keep their original meaning.
`prime_gap_experiments.py`, `sieve_experiments.py` and the plotting/control
scripts remain available with their original arguments and behavior.

Saved results here are the original measurements, not new cleanup runs.
The integrated auditor's dataset and combined measurements are at the
repository's `data/` and `results/auditor_pilot/` paths.
