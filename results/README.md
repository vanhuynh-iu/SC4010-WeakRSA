# Current measured results — 8 November 2026

Only fresh runs are kept in this working results tree. All studies used the
committed implementation `4c552fd` with a clean source tree; metadata
contains its full revision, environment and source/input fingerprints. Runs
were performed sequentially. Older findings remain in Git history and the
unchanged original branches; they were not relabelled as new measurements.

The active source has since been simplified and the separate `_original.py`
modules consolidated. These measurements still describe their recorded
producer revision; their timings and source fingerprints are preserved.

| Location | Fresh evidence |
| --- | --- |
| [comparison/](comparison/README.md) | 30 three-mode scans, 10 union checks; B=256 recovers 4 moduli / 5 records and verifies 5 plaintexts |
| [audit_report.json](audit_report.json) | One fully evaluated combined audit at B=256 |
| [gcd/correctness/](gcd/correctness/README.md) | Two correctness/OAEP checks; 13 moduli / 14 records; 14 matching plaintexts per algorithm |
| [gcd/coverage/](gcd/coverage/README.md) | Four checks of unchanged target without/with a companion |
| [gcd/scalability/](gcd/scalability/README.md) | 30 timing rows, six warm-ups and six separate memory passes at 20/50/100 moduli, plus fresh figures |
| [gcd/stress/](gcd/stress/README.md) | 10 timing rows, two warm-ups and two memory passes; all four batch ambiguities resolved, plus fresh figures |
| [fermat/](fermat/README.md) | 72 paired calls on nine newly saved keys; all methods/budgets independently checked |

The auditor/GCD studies reuse saved inputs to make the new executions
reproducible; that is different from sampling new datasets. The separate Fermat
pilot saves its new keys and uses identical inputs across all four methods.
Successful runs, exhausted searches and errors have distinct meanings.

Raw CSVs, exact summaries and run metadata accompany the findings. GCD memory
means traced Python allocations, not total RAM; figures show observed min/max
whiskers rather than confidence intervals. The study READMEs specify timing
boundaries. These selected pilots do not show universal speedups or security
of keys unbroken within a budget.

Old Van results are available on `gcd` (`2660d26`); old Krystal results are on
`close-primes` (`bd60ccb`). Commit `481dbaa` preserves the exact prior project
snapshot and the previously uncommitted source archive. Updating main normally
retains the original project ancestry. Pre-squash auditor commits, including
producer `4c552fd` and archive `481dbaa`, remain reachable through tag
`archive/rsa-auditor-before-squash-2026-11-08`; the consolidated branch has a new
three-commit sequence. No measured values or fingerprints were changed by the
history cleanup. See [publishing/history instructions](../docs/PUBLISHING.md).
