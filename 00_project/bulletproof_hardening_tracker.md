# Bulletproof Hardening & Zero-Trust Roadmap

This tracker outlines the end-to-end plan to elevate the Verifiable Telemetry pipeline from a prototype to a cryptographically bulletproof, insider-resilient industrial standard.

---

## Phase Overview

| Phase | Focus Area | Impact | Status |
|---|---|---|:---:|
| **Phase 1: Protocol & Data Spec Freeze** | Spec update, hash-chaining, integer Wh, trust boundaries | Spec integrity | ✅ Completed |
| **Phase 2: Verifier Fail-Closed & Pinned Trust** | Pinned reference factors, path traversal, algorithm whitelist, fail-closed guards | Attack surface elimination | ✅ Completed |
| **Phase 3: Pipeline & Edge Simulator Upgrade** | Hash-chain generator, running register check, hardware attestation stub | Data origin & continuity | ✅ Completed |
| **Phase 4: Adversarial & Insider Attack Benchmark** | Outsider vs. Insider attack suites, programmatic test assertions | Rigorous verification | ✅ Completed |
| **Phase 5: Grant Application & Threat Model Sync** | Formal Threat Model doc, Milestone 1 update, employment IP check | NLnet review readiness | ✅ Completed |

---

## Detailed Task Breakdown

### Phase 1: Protocol & Data Spec Freeze (The Foundation)
- [x] **Task 1.1: Spec Update (`02_protocol/evidence_bundle_spec.md`)**
  - Documented the **3-Layer Security Hierarchy** (Hardware Attestation -> Bundle Seal -> did:web/eIDAS).
  - Formalized **Hash-Chained Observations** (`prev_hash`).
  - Formalized **Integer Watt-Hour (Wh) Standard** to eliminate float rounding across systems.
  - Formalized **Meter Register Consistency** (`Δ cumulative_wh == interval_wh`).
  - Formalized **Auditor-Pinned Reference Data** (`trusted_references.json`).
  - Formalized **Metrological Pedigree Binding** (EU MID Directive 2014/32/EU Class B, calibration hash, validity window).
  - Defined the **10-Check Verifier Standard**.

---

### Phase 2: Verifier Zero-Trust & Fail-Closed Hardening
- [x] **Task 2.1: Authoritative Reference Registry (`src/verifier/trusted_references.json`)**
  - Pinned ISPRA 2026 dataset SHA-256 hash (`8e6cc7a7359fb935c5bdf236bd193fa996dfb990a40873f719f99ae5d5f69442`) and factor `0.2750`.
- [x] **Task 2.2: Hardened Verifier Engine (`src/verifier/verify_bundle.py`)**
  - **S1 (Hash-Chain Continuity):** Verifies `prev_hash` sequential links.
  - **S2 (Register Difference Validation):** Asserts `cumulative_wh[t] - cumulative_wh[t-1] == interval_wh[t]`.
  - **S3 (Pinned Factor Enforcement):** Rejects unpinned factor hashes even with valid company root signatures.
  - **S4 (Path Traversal & Unmanifested Files):** Rejects path traversal and unexpected unmanifested files.
  - **S5 (Algorithm Whitelisting):** Enforces `ECDSA_P256_SHA256` only.
  - **S6 (Device ID Re-Derivation):** Re-derives `device_id` from public key bytes.
  - **S7 (Metrological Pedigree Check):** Validates MID accuracy class and calibration expiration date (implemented & verified Oct 11, 2026 via [`00_project/security_fix_tracker.md`](security_fix_tracker.md), Task C2).
  - **S8 (Fail-Closed Architecture):** Zero-crash policy across all malformed inputs.
  - **S9 (Integer Wh Math):** Zero-tolerance match on integer Watt-hours.
  - **S10 (Machine-Readable JSON Output):** Emits `--json` reports with strict exit codes.

---

### Phase 3: Pipeline & Simulator Upgrade
- [x] **Task 3.1: Upgrade Edge Simulator (`src/device_simulator/mock_edge.py`)**
  - Implemented sequential hash-chain calculation (`prev_hash`).
  - Tracked physical meter registers (`cumulative_wh`, `interval_wh`).
  - Bound metrological pedigree (MID 2014/32/EU Class B, EN 50470-3 calibration) into `device_certificate.json`.
  - Added Microchip ATECC608 factory CA attestation certificate stub.
  - Enforced `0o600` file permissions on generated private keys.
- [x] **Task 3.2: Upgrade Claim Generator (`src/pipeline/claim_generator.py`)**
  - Handled integer Wh and hash-chained streams.
  - Declared period boundaries (`first_sequence`, `last_sequence`, `record_count`, `terminal_hash`) in `claim.json`.
  - Sealed manifest with Company Root Key (`bundle_seal`).

---

### Phase 4: Adversarial & Insider Attack Benchmark & Test Vectors
- [x] **Task 4.1: Separate Attack Suites (`src/attacks/`)**
  - **`outsider_attacks.py`**: 10/10 attack vectors detected and rejected (including key revocation and path traversal).
  - **`insider_fraud_suite.py`**: 5/5 insider fraud vectors detected and rejected.
- [x] **Task 4.2: Programmatic Test Assertions**
  - All 15 tests assert via exit codes and JSON verdict.
- [x] **Task 4.3: Conformance Golden Test Vector (`04_experiments/golden_test_vector/`)**
  - Frozen canonical bundle, root key, and expected audit JSON for Milestone 3 cross-language (Rust) verifier conformance testing.

---

### Phase 5: Grant Application & Threat Model Sync
- [x] **Task 5.1: Threat Model Document (`03_system/threat_model.md`)**
  - Completed formal threat model and security boundaries document (NLnet Task 3.4).
- [x] **Task 5.2: Update NLnet Application Draft (`00_project/nlnet_restack_application_draft.md`)**
  - Added hardware attestation (ATECC608), metrological probe quality (MID 2014/32/EU Class B), hash-chains, integer Wh, and pinned reference registry to Field 8.
  - Neutralized pilot site and client references in Field 10 to protect employment IP and NDAs.
- [x] **Task 5.3: Sync Tracker (`00_project/nlnet_application_tracker.md`)**
  - Marked technical milestones, Task 1.4, Task 1.5, Task 3.1, Task 3.2, Task 3.3, and Task 3.4 as complete.
