# Verification — trước khi nộp

- **OS / Python / Gitleaks:** Windows native; Python 3.12.6; Gitleaks 8.30.1 (release checksum verified). README notes native Windows has not been piloted, so record that as an environment limitation.
- **Tests:** `python -m pytest tests/ -q --basetemp=.pytest_tmp` — 33 passed.
- **PII test set:** 118 gold, 118 predictions, 118 true positives; precision 1.000, recall 1.000.
- **Lure check:** `python -m agent.check_lure corpus/ticket-90*.md` — 4/4 ready (904 is the two-file pair).
- **Ledger:** `verify(Path('reports/ledger.jsonl'))` — `True`; 23 entries, all have non-empty `reason`, every row carries `on_behalf_of`, and the hash chain verifies.
- **Before/after:** before is one local `/reconcile` request exactly matching synthetic fixture `KH-000999`; after is empty (0 bytes). Ledger denies `http_post` for restricted egress.
- **Supply chain:** `pip-compile --generate-hashes` created `requirements.lock`; `pip install --require-hashes -r requirements.lock` succeeded. Current-file Gitleaks scan is clean. Historical scan found the expected single `lab24-synthetic-token` at commit `1bdd849`; it is the deliberately invalid lab token. `pre-commit run --all-files` — passed.
- **Remaining failures:** none in the requested checks. These mock/local results do not prove production identity, immutable audit storage, or legal compliance.
