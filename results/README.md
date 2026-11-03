# Results

Saved measurements from Van's GCD experiments. Both pairwise and batch are
included; Fermat/combined results are still pending.

| Folder | Experiment | Main finding |
| --- | --- | --- |
| `van_batch_correctness` | Mixed-case correctness and OAEP | 13 moduli / 14 records recovered; 14 decryptions passed |
| `van_batch_coverage` | Remove/add a shared-prime companion | The unchanged target becomes recoverable when its companion is present |
| `van_batch_pilot` | Five timing repeats at 20/50/100 moduli | Batch median speedups: 1.14x, 1.38x, 1.73x |
| `van_batch_stress` | Five repeats with complex sharing/fallback | All four ambiguous batch results resolved; runtime close to pairwise |

## Files

- `*.csv`: raw measurements or correctness checks.
- `summary.json`: calculated medians, ranges and variation.
- `*_metadata.json`: settings, environment and source/input fingerprints.
- `figures/*.png`: graphs for viewing/slides; SVG files are scalable copies.
- `README.md`: experiment-specific explanation.

Start with correctness, then coverage, then the pilot README and graphs.
The pilot uses one saved fixture per size, not five independent datasets.
Memory is a separate measurement of traced Python allocations, not total RAM.

Main raw measurements and graphs are preserved. `layout_migration.json` maps
historical paths/checksums to current files and records removed duplicate checks.
Older names inside recorded metadata describe those original runs.

To redraw saved data into a new folder:

```bash
python experiments.py --mode plot --input results/van_batch_pilot --output results/my_redrawn_figures
```
