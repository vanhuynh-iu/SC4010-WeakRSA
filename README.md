# SC4010 — Weak RSA

A shared RSA project for Van and Krystal. Van's pairwise/batch GCD path works.
Defaults: a 2048-bit modulus, e = 65537, and RSA-OAEP with SHA-256.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Local environments and historical copies are excluded from Git.

## Run

```bash
python -m unittest discover -s tests -v
python demo.py --dataset data/public/van_demo
python demo.py --dataset data/public/van_mixed --algorithm batch
```

To scan without loading private truth:

```bash
python demo.py --public-only data/public/van_mixed/public.json --algorithm batch
```

`demo.py` prints results. `experiments.py` saves reports and graphs.

## File map

| File or folder | Purpose |
| --- | --- |
| `contracts.py` | Shared records and return formats |
| `generators/` | Van's shared-prime/controls and Krystal's close-prime slot |
| `build_dataset.py` | Combine, save and load both generators' cases |
| `normalization.py` | Validate public records and deduplicate by n |
| `shared_prime_attack.py` | Pairwise GCD baseline |
| `batch_gcd_attack.py` | Batch GCD with fallback |
| `key_recovery.py` | Recover d and decrypt OAEP |
| `audit_pipeline.py` | Connect scanning, record mapping, recovery and evaluation |
| `fermat_attack.py` | Krystal's Fermat slot |
| `demo.py` / `experiments.py` | Run demonstrations / save measurements |
| `data/` / `results/` | Generated inputs / measured outputs |
| `tests/` | Arithmetic, dataset and integration checks |

## Data

Public records contain ID, n, e and optional ciphertext. Private truth contains
original factors and expected messages for evaluation. These saved keys are
synthetic educational fixtures. See [data/README.md](data/README.md) for cases.
`expected_vulnerable_ids` and `evaluate_scan` describe observable GCD recovery.

Create a new collection:

```bash
python build_dataset.py --case shared --name my_shared --num-keys 6 --shared-keys 2 --bits 2048 --message "Hello Van"
```

It writes matching `data/public/my_shared` and `data/private/my_shared` folders.
Existing files are protected. Other cases: `mixed`, `scalability`, `control`.

## Experiments

Use a new output folder for each run:

```bash
python experiments.py --mode correctness --dataset-dirs data/public/van_mixed --output results/my_correctness
python experiments.py --mode coverage --before data/public/van_coverage/before --after data/public/van_coverage/after --target-key-id key_001 --output results/my_coverage
python experiments.py --mode scalability --sizes 20 50 100 --trials 5 --bits 2048 --dataset-root data/public/scalability --output results/my_scalability
python experiments.py --mode plot --input results/my_scalability
```

Scan timing includes validation, batch trees and fallback, excluding generation,
I/O, normalization, recovery and OAEP. Memory is measured separately with
tracemalloc. Saved findings and graphs are explained in [results/README.md](results/README.md).

## Krystal's part

Close-prime generation and the Fermat attack.
