# Biochar Golden Test Vector (v1.3)

**Frozen Date:** October 11, 2026  
**Profile:** `biochar_pyrolysis` (v1.3)  
**Security Level:** Zero private keys contained (`git ls-files | grep -i private` is empty; device private key stored strictly outside bundle)

This directory contains a frozen, deterministic reference evidence bundle for High-Durability Carbon Dioxide Removal (Biochar Pyrolysis dMRV) under EU CRCF Delegated Regulation (EU) 2026/285, Puro.earth, and European Biochar Certificate (EBC) standards.

It is designed for cross-language conformance testing. Any secondary verifier implementation (e.g., the Milestone 3 zero-dependency Rust CLI `telemetry-verify` or C/WASM embedded runtimes) must execute against `biochar_bundle/` using `producer_root_public_key.pem` and reproduce the exact audit results in `expected_audit_verdict.json`.

---

## Contents

- `biochar_bundle/`: Complete immutable evidence bundle adhering to `02_protocol/evidence_bundle_spec.md` (v1.3, `biochar_pyrolysis` profile).
  - 5 signed batch telemetry records in an unbroken cryptographic hash-chain (`prev_hash`).
  - Pyrolysis temperatures verified ($T \ge 500^\circ\text{C}$ across all batches) confirming thermal permanence.
  - Legal-for-trade scale indicators compliant with EU Directive 2014/31/EU NAWI (Class III) with dynamic calibration validity verification.
  - Silicon hardware attestation stub (`SIMULATED_STUB` bound to device public key hash; production Microchip ATECC608 certificate chain verification is Milestone 2 scope).
  - Accredited ISO 17025 laboratory test report ($C_{\text{org}} = 82.00\%$, moisture $= 15.00\%$, permanence factor $= 85.00\%$, bound to batch range).
  - Certified biomass feedstock manifest (FSC Forestry Residues, 40 metric tonne quota).
  - Physical mass-balance conservation ($M_{\text{dry}} = 8,500,000\text{ g} \le 31,250,000\text{ g}$ input feedstock; per-batch dry yield $\le 40\%$).
  - Recomputed net carbon removal: `20,523,166 g` (`20.523166 metric tonnes CO2`).
  - Manifest cryptographically sealed with Producer Root Key ECDSA P-256 (`bundle_seal`).
  - **No private keys included:** Device private key is generated and stored externally.
- `producer_root_public_key.pem`: P-256 public key of the certifying Producer Authority / Trust Anchor.
- `expected_audit_verdict.json`: Expected JSON audit report asserting that all 10 checks PASS.

---

## Conformance Verification Command

```bash
python3 src/verifier/verify_bundle.py 04_experiments/golden_test_vector_biochar/biochar_bundle \
  --company-key 04_experiments/golden_test_vector_biochar/producer_root_public_key.pem \
  --json
```
