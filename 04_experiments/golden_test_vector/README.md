# Golden Test Vector (v1.3)

**Frozen Date:** October 11, 2026  
**Profile:** `energy_submetering` (v1.3)  
**Security Level:** Zero private keys contained (`git ls-files | grep -i private` is empty; device private key stored strictly outside bundle)

This directory contains a frozen, deterministic reference claim bundle designed for cross-language conformance testing.

Any secondary verifier implementation (e.g., the Milestone 3 zero-dependency Rust CLI `telemetry-verify` or C/WASM runtimes) must execute against `claim_bundle/` using `company_root_public_key.pem` and reproduce the exact audit results in `expected_audit_verdict.json`.

---

## Contents

- `claim_bundle/`: Complete immutable evidence bundle adhering to `02_protocol/evidence_bundle_spec.md` (v1.3).
  - 5 signed observations in unbroken cryptographic hash-chain (`prev_hash`).
  - MID 2014/32/EU legal metrology verified (`Class_B_EN50470`, unexpired calibration).
  - Hardware attestation stub (`SIMULATED_STUB` bound to device public key hash; production Microchip ATECC608 certificate chain verification is Milestone 2 scope).
  - Dual registers (`cumulative_wh` = 15,432,500 Wh, `interval_wh` = 2,500 Wh).
  - Total aggregated energy = `12,500 Wh` (12.5 kWh).
  - Pinned ISPRA 2026 emission factor (`0.2750 kg CO2e/kWh`).
  - Total Scope 2 emissions = `3.4375 kg CO2e`.
  - Manifest cryptographically sealed with ECDSA P-256 (`bundle_seal`).
  - **No private keys included:** Device private key is generated and stored externally.
- `company_root_public_key.pem`: P-256 public key of the certifying Company Root Authority.
- `expected_audit_verdict.json`: Expected JSON audit output asserting that all 10 checks PASS.

---

## Conformance Command

```bash
python3 src/verifier/verify_bundle.py 04_experiments/golden_test_vector/claim_bundle \
  --company-key 04_experiments/golden_test_vector/company_root_public_key.pem \
  --json
```
