# Fresh paired Fermat pilot — 8 November 2026

Nine new saved independent RSA-2048 keys: three for each starting-gap exponent
515, 518 and 520, with e=65537. Public inputs and private truth were saved before
any measurement at `data/public/fermat_pilot` and `data/private/fermat_pilot`.
Each same key is tested by original Fermat, mod-64 filtering, wheel-960 and
wheel-6720 at position budgets 16 and 65,536. Order rotates by key/budget index.

All 72 kernel calls and 18 same-key/budget agreement checks pass independent
validation. There are 48 successful factorisations and
24 budget-exhausted calls. At B=16 every method
factors the three easy keys and exhausts the other six; at B=65,536 every method
factors all nine. Exhaustion is recorded as a search limit, never success at the
cap. No warm-ups or memory/decryption measurements are included.

High-budget successful results:

| Gap setting | Method | Factored | Median kernel ms | Median paired speedup |
| --- | --- | --- | --- | --- |
| 515 | original | 3/3 | 0.024 | 1.00x |
| 515 | mod64 | 3/3 | 0.012 | 1.78x |
| 515 | wheel_960 | 3/3 | 0.526 | 0.04x |
| 515 | wheel_6720 | 3/3 | 3.780 | 0.01x |
| 518 | original | 3/3 | 0.955 | 1.00x |
| 518 | mod64 | 3/3 | 0.525 | 2.13x |
| 518 | wheel_960 | 3/3 | 0.604 | 1.69x |
| 518 | wheel_6720 | 3/3 | 3.851 | 0.25x |
| 520 | original | 3/3 | 17.938 | 1.00x |
| 520 | mod64 | 3/3 | 8.445 | 2.12x |
| 520 | wheel_960 | 3/3 | 1.070 | 16.13x |
| 520 | wheel_6720 | 3/3 | 4.087 | 4.22x |

A budget counts consecutive a positions from ceil(sqrt(n)), not the number of
square roots taken by a filtered method. Actual square checks are separately
validated using residue counts. Kernel timing includes per-call wheel setup;
private reference/factor validation, generation and I/O are outside the timer.
These component times have a different boundary from integrated-auditor times.

Very short searches are dominated by wheel preparation; on the larger tested
gap, filtering reduces work. The smaller wheel is faster than the larger wheel
in this pilot. Speedups are computed per successful same-key pair, then their
median is reported; they need not equal a ratio of displayed aggregate medians.
Three independent keys per gap and one call per combination form a small pilot,
not a population-wide claim or a reproduction of the older 17-gap study.

`fermat_results.csv` records every attempt, status, key identity, evaluator gap,
reference distance, position/square counts and measured time. `summary.json`
separates successful-factorisation times from all accepted attempts;
`run_metadata.json` fingerprints the actual source and saved inputs.

```bash
python -m rsa_auditor.experiments.cli --mode fermat-pilot --fermat-dataset data/public/fermat_pilot --gap-bits 515 518 520 --keys-per-gap 3 --bits 2048 --budgets 16 65536 --output results/new_fermat
```
