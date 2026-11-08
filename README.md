# SC4010 RSA public-key auditor

Audit synthetic RSA-2048 public keys for shared prime factors and close prime
factors using GCD, Fermat or their combination. Recovered factors support
private-key reconstruction and OAEP-SHA256 message verification.

Run from the project root after installing requirements.txt in .venv:

```bash
.venv/bin/python -m rsa_auditor.cli --mode combined --fermat-budget 256 --evaluate
.venv/bin/python -m rsa_auditor.datasets.cli --help
.venv/bin/python -m rsa_auditor.experiments.cli --help
.venv/bin/python -m unittest discover -s tests -v
```

The saved demo has 8 records / 7 unique moduli. Combined mode at budget 256
recovers 4 moduli / 5 records and verifies 5 plaintexts. Attacks receive public
records only; optional evaluation checks separate synthetic private answers.

The implementation reuses existing GCD/Fermat algorithms and includes
AI-assisted integration, refactoring and tests.
