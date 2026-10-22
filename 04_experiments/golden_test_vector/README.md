# Golden Conformance Vector — `energy_submetering` (bundle format v1.3)

Frozen, self-contained reference bundle for cross-implementation conformance (the Milestone 3
Rust verifier must reproduce `expected_audit_verdict.json` exactly). EU MID energy submeter, 5 × 15-minute interval records, integer Wh dual registers, pinned grid factor (integer mg CO2e/kWh).

Regenerate with `python3 src/tools/freeze_golden_vectors.py`; checked by `tests/test_golden_vectors.py`.

## Layout

- `bundle/` — sealed evidence bundle (see `02_protocol/evidence_bundle_spec.md`).
- `trust/` — auditor-side inputs, supplied out-of-band and never read from the bundle:
  - `producer_root_public_key.pem` — producer root (device certificate + manifest seal).
  - `manufacturer_root_ca.pem` — **SIMULATED** secure-element manufacturer root CA (TEST ONLY).
    The device key's X.509 chain in `bundle/device/attestation/` must validate against it.
  - `registry.json` — pinned reference datasets and methodology parameters.
- `expected_audit_verdict.json` — expected verdict, per-check results and recomputed integer metrics.

No private keys are included; they are generated in a temporary directory and destroyed.

## Honest scope

The manufacturer CA is a simulation, so the verdict reports `hardware_attestation:
SIMULATED_MANUFACTURER_CA` and warns that hardware key origin is not established for production.
With a real ATECC608B, the auditor pins the vendor's root CA instead; the verification code path
is identical.

## Conformance command

```bash
python3 src/verifier/verify_bundle.py 04_experiments/golden_test_vector/bundle \
  --profile energy_submetering \
  --producer-key 04_experiments/golden_test_vector/trust/producer_root_public_key.pem \
  --manufacturer-ca 04_experiments/golden_test_vector/trust/manufacturer_root_ca.pem \
  --trusted-registry 04_experiments/golden_test_vector/trust/registry.json \
  --json
```
