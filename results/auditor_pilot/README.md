# Integrated RSA-2048 auditor pilot

Actual local measurements on the saved `data/public/auditor_demo` fixture: 8 records, 7 unique 2048-bit moduli, including one duplicate. The same public bytes were used for every run. The GCD backend was batch with full-GCD fallback; Fermat used the unchanged original baseline through its budget adapter.

There are five independent calls per mode at each budget, with rotated mode order and no factor cache. All 30 measured runs passed independent evaluation. The combined set equalled the standalone union in all 10 comparisons.

| Budget B | Mode | Recovered moduli | Checked plaintexts | Fermat tests | Median scan seconds |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16 | gcd | 2 | 3 | 0 | 0.177710 |
| 16 | fermat | 1 | 1 | 107 | 0.099143 |
| 16 | combined | 3 | 4 | 75 | 0.276508 |
| 256 | gcd | 2 | 3 | 0 | 0.178256 |
| 256 | fermat | 2 | 2 | 1469 | 0.201047 |
| 256 | combined | 4 | 5 | 957 | 0.378592 |

At B=16 the combined auditor adds one recovered modulus beyond GCD-only; at B=256 it adds two. At B=256 those four recovered moduli map to five records, and all five OAEP plaintexts are verified. The remaining three moduli exhausted this Fermat budget; that result is not a security claim.

Combined mode saves Fermat work on the two moduli already recovered by GCD (32 candidate tests at B=16 and 512 at B=256), while also paying for the GCD scan. Its scan therefore costs more than stopping after GCD; the added recovery is the benefit being measured. This tiny fixed fixture does not establish a universal speedup.

Scan timing includes GCD trees/fallback, bounded Fermat and common factor validation. It excludes generation, input loading, normalization, record mapping, reconstruction/OAEP, evaluation, output and plotting. There were no warm-ups in this pilot. Repeated measurements reuse one saved fixture; they do not sample independent key populations. Memory is not measured here.

Files:

- `mode_comparison.csv`: raw mode measurements and independent correctness checks.
- `fermat_gap_budget.csv`: evaluator-only actual gaps, reference search costs, outcomes and measured Fermat work; no gaps were passed to attacks.
- `summary.json`: medians and observed ranges plus per-trial union comparisons.
- `run_metadata.json`: input/source fingerprints, clean implementation revision, environment and timing scope.
- `audit_report.json`: one combined B=256 audit with per-modulus/per-record outcomes and actual checked decryptions.

To repeat with new output files:

```bash
python experiments.py --mode compare --dataset data/public/auditor_demo --budgets 16 256 --trials 5 --output results/my_comparison
```

Existing results are protected from overwrite. Original GCD and close-prime results elsewhere in `results/` are unchanged.
