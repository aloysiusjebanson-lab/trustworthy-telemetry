# One-command verification of the whole repository (Python 3 stdlib + OpenSSL CLI only).
PY ?= python3

.PHONY: test unit attacks golden

test: unit attacks

unit:
	$(PY) -m unittest discover -s tests -v

attacks:
	$(PY) src/attacks/outsider_attacks.py
	$(PY) src/attacks/insider_fraud_suite.py
	$(PY) src/attacks/biochar_attacks.py
	$(PY) 04_experiments/security_reaudit/poc_exploits.py

golden:
	$(PY) src/tools/freeze_golden_vectors.py
