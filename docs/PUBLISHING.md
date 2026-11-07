# Make the integrated auditor the main version

The working integrated project is on `rsa-auditor`. Its cleanup was performed
there; `close-primes`, `gcd`, local `main` and GitHub's `main` were left alone.

Local `main` is the original starter commit. `origin/main` is the original
GCD implementation. That GCD commit is already an ancestor of `rsa-auditor`,
so the integrated branch can advance main while retaining the existing history.
A force push is not needed.

After reviewing the cleaned layout and tests, publish the development branch:

```bash
git switch rsa-auditor
git push -u origin rsa-auditor
```

Then make it main with a normal fast-forward merge and push:

```bash
git switch main
git merge --ff-only rsa-auditor
git push origin main
```

This makes local and GitHub main contain the integrated project. The two
original project branches stay available. A normal push refuses to overwrite
new remote history if GitHub changed in the meantime; inspect that difference
before continuing. If the repository requires a pull request, use rsa-auditor
as the source branch and main as the destination.

These are publishing instructions only. The cleanup task did not execute them.

## Old work is retained in history

Advancing main with the commands above keeps earlier commits. Removing an old
file from the current snapshot does not remove its earlier versions. Van's
original GCD findings remain on gcd at 2660d26, and Krystal's standalone work
remains on close-primes at bd60ccb. Before the results refresh, previously
uncommitted archive files were captured byte-for-byte in commit 481dbaa. That
commit is also in rsa-auditor's ancestry, so a normal main push preserves it.

For example, view an old result without changing branches:

```bash
git show gcd:results/van_batch_pilot/summary.json
git show close-primes:results/sieve_comparison_summary_2048.csv
git show 481dbaa:results/source_archive/pre_consolidation_2026_10_28/README.md
```
