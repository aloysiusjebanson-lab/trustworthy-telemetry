# Experiment Plan (bundle format v1.3)

**Status:** Detection experiments implemented and automated (`make test`). Performance and
hardware measurements are planned (Milestones 2–4).

The authoritative list of attack vectors, with adversary type and expected failing check, is
[`attack_registry.csv`](attack_registry.csv) (40 vectors + 6 re-audit regressions). Threat
model: [`03_system/threat_model.md`](../03_system/threat_model.md).

## 1. Detection experiments (implemented)

| Family | Vectors | Suite |
|---|---|---|
| Outsider tampering (no keys) | O1–O13, B5 | `src/attacks/outsider_attacks.py`, `biochar_attacks.py` |
| Insider fraud (producer key + control of the gateway's signing) | I1–I8, B1–B4, B6–B9, B11–B19 | `src/attacks/insider_fraud_suite.py`, `biochar_attacks.py` |
| Revoked / decommissioned device | O10, B10 | both suites |
| Re-audit regressions | P1–P6 | `04_experiments/security_reaudit/poc_exploits.py` |

**Adversary knowledge.** Insider vectors re-sign records through the device key and re-seal with
the producer key, modelling an operator who controls the gateway. They test only the controls the
operator does not hold (manufacturer attestation, pinned references, physical invariants, lineage,
auditor mandates).

**Detection criterion (machine-readable).** A vector counts as caught only if the verifier exits
with `verdict == FAILED` **and** the specific `expected_failed_check` in the JSON report is
`FAILED`. A verifier crash is a test failure, not a catch (`src/attacks/harness.py`).

**False-positive control.** Every suite first asserts that its clean fixture verifies as
`PASSED`; the golden vectors (`tests/test_golden_vectors.py`) must reproduce their expected
verdict exactly.

**Determinism.** Each run builds fresh fixtures (new simulated manufacturer PKI, producer and
device keys) in a temporary directory; vectors are deterministic given those keys.

**Encoding conformance.** `04_experiments/conformance/jcs_vectors.json` (transcribed from RFC
8785) and the golden bundles are the shared targets for the Python and planned Rust verifiers.

## 2. Out of scope for digital detection

Documented in the threat model, not claimed as detected: fabricated readings signed by a genuine
gateway, spoofed devices on the RS-485 bus, rescaled meter configuration, manipulation of
physical inputs or lab sampling, and clock manipulation (until trusted time lands in M3).

## 3. Planned measurements (not yet run)

- Signing and verification latency; end-to-end verification time per bundle.
- Bytes per record and per bundle.
- Sustainable records per second on the reference gateway (CM4 + ATECC608B).
- The same detection suite run against bundles produced by real hardware (M4).

## 4. Reproducibility

Every result is reproducible from a commit hash: `make test` regenerates all fixtures; CI
(`.github/workflows/ci.yml`) runs it on Python 3.9 and 3.12 for every push and pull request.
