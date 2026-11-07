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
