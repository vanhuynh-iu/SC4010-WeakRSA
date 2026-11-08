# Fresh shared-auditor comparison — 8 November 2026

Five fresh calls per mode at budgets 16 and 256 on the same saved RSA-2048
fixture. There are 8 records / 7 unique moduli. All 30 calls pass independent
evaluation and all 10 combined-recovery union checks agree. No factor cache
is reused between modes. The input keys were reused, not newly sampled.

| Budget | Mode | Recovered moduli | Verified plaintexts | Fermat tests | Median scan seconds |
| --- | --- | --- | --- | --- | --- |
| 16 | gcd | 2 | 3 | 0 | 0.179025 |
| 16 | fermat | 1 | 1 | 107 | 0.100023 |
| 16 | combined | 3 | 4 | 75 | 0.278143 |
| 256 | gcd | 2 | 3 | 0 | 0.178634 |
| 256 | fermat | 2 | 2 | 1469 | 0.201730 |
| 256 | combined | 4 | 5 | 957 | 0.379269 |

At B=256 combined recovery maps four moduli to five records. All five OAEP
plaintexts match their expected messages. Three moduli exhaust the Fermat
budget. Combined saves 512 Fermat candidate tests versus Fermat-only, while
paying for the GCD scan and obtaining the union of standalone recoveries.

Scan time includes selected GCD trees/fallback, Fermat calls and factor
validation. It excludes normalization, record mapping, generation, I/O,
recovery/OAEP, private evaluation and reporting. Order rotates; no warm-ups
were used. Medians/ranges describe five repeats on one fixed fixture, not
population variation or confidence intervals. Memory is not measured here.

`mode_comparison.csv` contains raw runs; `fermat_gap_budget.csv` is evaluator-only
and includes private gaps/reference costs. `summary.json` aggregates accepted
runs. `run_metadata.json` records input/source hashes and the clean code revision.
The full saved combined report is [../audit_report.json](../audit_report.json).

```bash
python -m rsa_auditor.experiments.cli --mode compare --dataset data/public/auditor_demo --budgets 16 256 --trials 5 --output results/new_comparison
```
