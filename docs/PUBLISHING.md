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

The auditor's eight development commits were consolidated into three commits
after the unchanged gcd base at 2660d26. Advancing main keeps the original GCD
and close-prime ancestry. Van's original GCD findings remain on gcd, and
Krystal's standalone work remains on close-primes at bd60ccb.

The complete pre-squash auditor history is preserved under the published tag
`archive/rsa-auditor-before-squash-2026-11-08`, pointing to 88fce7c. This retains
the measurement producer 4c552fd and the byte-for-byte source archive captured
in 481dbaa. Those development commits are retained through the tag rather than
as ancestors of the new three-commit auditor sequence. Measurements continue
to identify their actual producer; they were not rerun or relabelled.

Fetch the archive explicitly if the old objects are not present locally:

```bash
git fetch origin tag archive/rsa-auditor-before-squash-2026-11-08
```

For example, view an old result without changing branches:

```bash
git show gcd:results/van_batch_pilot/summary.json
git show close-primes:results/sieve_comparison_summary_2048.csv
git show 481dbaa:results/source_archive/pre_consolidation_2026_10_28/README.md
```

The consolidation rewrote the published rsa-auditor branch using a pinned
force-with-lease guard. Normal future commits use a normal push. The commands
for promoting the resulting branch to main still use a fast-forward merge;
no force push to main is required.
