# Saved findings

| Location | Purpose | Recorded finding |
| --- | --- | --- |
| [auditor_pilot/](auditor_pilot/README.md) | Shared GCD/Fermat/combined RSA-2048 comparison | All 30 runs and 10 union checks passed; B=256 recovered 4 moduli / 5 records and verified 5 plaintexts |
| [van_batch_correctness/](van_batch_correctness/) | GCD correctness and OAEP | 13 unique moduli / 14 records recovered; 14 decryptions passed |
| [van_batch_coverage/](van_batch_coverage/) | Remove/add a shared-prime companion | The unchanged target becomes recoverable when its companion is present |
| [van_batch_pilot/](van_batch_pilot/README.md) | Pairwise versus batch at 20/50/100 moduli | Recorded median speedups: 1.14x, 1.38x, 1.73x |
| [van_batch_stress/](van_batch_stress/README.md) | Complex sharing and full-GCD fallback | Four ambiguous batch results resolved; runtime close to pairwise |
| [Original close-prime results](close_primes/README.md) | Krystal's Fermat gap/sieving studies | Original CSVs and graphs preserved; full standalone source remains on close-primes at bd60ccb |

Raw CSVs contain actual measurements; JSON files describe summaries, inputs,
environment and source fingerprints. Each experiment's README states its limits.
The GCD pilot repeats one saved dataset per size, and its memory figures are
traced Python allocations rather than total RAM. Runtime extrapolation in the
original close-prime project is prediction rather than measured output.

Existing benchmark data and metadata were kept unchanged during file cleanup.
Source paths in old metadata describe the source tree at the recorded commit.
Historical move records in `docs/` refer to their recorded commit layouts.
The current location of original close-prime outputs is `results/close_primes/`;
new experiment runs fingerprint the active package source paths.

Use a new output directory when repeating experiments. For example:

```bash
python -m rsa_auditor.experiments --mode compare --dataset data/public/auditor_demo --budgets 16 256 --trials 5 --output results/my_comparison
python -m rsa_auditor.experiments --mode plot --input results/van_batch_pilot --output results/my_redrawn_figures
```
