# System Threat Model & Security Boundaries (v1.1)

This document formalizes the threat model, adversary capabilities, cryptographic guarantees, and security boundaries for the Verifiable Telemetry architecture in accordance with NLnet Milestone requirements.

---

## 1. Adversary Model & Trust Assumptions

We define two distinct threat actors with asymmetric capabilities:

### Adversary A: Outsider Intermediary (Man-in-the-Middle, Rogue Cloud, Malicious Carrier)
* **Capabilities:** Can intercept network packets, read telemetry, alter CSVs or JSON files in transit, inject replay packets, drop arbitrary rows, or manipulate unauthenticated metadata.
* **Limitations:** Does NOT hold the enterprise's private Company Root Key and cannot extract private keys from the hardware Secure Element (ATECC608A).

### Adversary B: Dishonest Reporting Enterprise (Insider Greenwashing)
* **Capabilities:** Holds the Company Root Private Key, operates the cloud data ingestion pipeline, can run the claim generator, can manipulate local databases, and can issue and seal claim bundles with cryptographically valid signatures.
* **Motivations:** Under-report Scope 2 emissions for CSRD compliance, avoid carbon border taxes (CBAM), achieve green building certifications (LEED/WELL) fraudulently, or peak-shave industrial load curves.
* **Limitations:** Does NOT hold the chip manufacturer's private CA keys and cannot forge hardware attestation certificates; cannot alter physical meter registers without physical access; cannot alter independent external emission factor registries pinned by auditors.

---

## 2. Attack Vectors & Defensive Guarantees

| Vector | Adversary | Attack Description | Cryptographic Defense | Verifier Check |
|---|:---:|---|---|:---:|
| **A1** | Outsider | Altering observation kWh value | Fails ECDSA P-256 signature verification over canonical payload | Check 3 |
| **A2** | Outsider | Replaying historical readings | Fails sequence monotonicity and duplicate detection | Check 5 |
| **A3** | Outsider | Dropping peak-hour rows in transit | Breaks sequential sequence numbers and cryptographic hash-chain (`prev_hash`) | Check 4 & 5 |
| **A4** | Outsider | Impersonating an edge gateway | Device certificate fails Company Root signature check | Check 2 |
| **A5** | Outsider | Swapping observation device_id | Re-derivation of `device_id` from public key fails; cert meter binding fails | Check 2 & 3 |
| **A6** | Outsider | Backdating/Forward-dating records | Observation timestamp outside certificate validity window (`valid_from` / `valid_until`) | Check 3 |
| **A7** | Outsider | Tampering file + updating manifest | Fails Cryptographic Bundle Seal (Company Root Key signs manifest `files` dictionary) | Check 1 |
| **A8** | Outsider | Path traversal injection (`../../`) | Verifier path sanitization rejects non-canonical or directory-traversing paths | Check 1 |
| **A9** | Outsider | Dropping extra backdoor files in bundle | Verifier detects unmanifested files and fails closed | Check 1 |
| **B1** | **Insider** | **Emission Factor Greenwashing** (swapping grid factor to 0.05 and resealing bundle) | Fails Auditor's Pinned Reference Registry (`trusted_references.json`); unpinned factor hash rejected | Check 8 |
| **B2** | **Insider** | **Dual-Register Shaving** (lowering interval Wh while meter totalizer advances) | Fails register difference assertion: $\text{cumulative\_wh}[t] - \text{cumulative\_wh}[t-1] == \text{interval\_wh}[t]$ | Check 5 |
| **B3** | **Insider** | **Head/Tail Truncation** (omitting peak production hours at shift ends and resealing) | Fails Claim Period Boundary Bounding (declared timestamps, `first_seq`, `last_seq`, and `--expected-count`) | Check 6 |
| **B4** | **Insider** | **Software Simulator Impersonation** (generating software keys to fabricate data) | Fails Hardware Attestation: requires Microchip factory CA certificate proving key is hardware-locked | Check 2 |
| **B5** | **Insider** | **Telemetry Splicing** (stitching non-consecutive days together) | Breaks cryptographic hash-chain link (`prev_hash` mismatch across splice boundary) | Check 4 |
| **B6** | **Insider** | **Uncalibrated / Cheap Probe Substitution** (attaching inaccurate or drifting sensor) | Fails Metrological Pedigree: requires valid EU MID (2014/32/EU) accuracy class & active calibration certificate | Check 2 |

---

## 3. Explicit Security Boundaries (What is Out of Scope)

Honest cryptographic engineering requires explicitly defining what cannot be solved with math alone:

1. **Physical Current Transformer (CT) Tampering:**
   * If an attacker physically detaches a CT clamp from an electrical busbar, the meter will physically measure zero current.
   * **Mitigation:** Cryptography proves *data origin and transit integrity*, not physical wire placement. Hardware anti-tamper switches and physical seal auditing are complementary physical controls.
2. **Facility Upstream Collusion / Bypassing the Switchgear:**
   * If a facility routes an unmetered power line around the primary switchgear, the sensor cannot detect power it never encounters.
   * **Mitigation:** Single-line electrical diagrams (SLDs) and commissioning audit certificates cross-checked during LEED/ISO 50001 audits.
3. **Legal Identity Jurisdiction (Company Name vs Legal Entity):**
   * A cryptographic key proves possession of an algorithm, not legal liability.
   * **Mitigation:** Tier 3 PKI bridge: binding the Company Root Key to legal identity via `did:web` (domain control) and eIDAS Qualified Electronic Seals (EU statutory commercial registry presumption).

---

## 4. Benchmark Verification Summary

The architecture is validated against 14 automated adversarial test vectors across two dedicated test runners:
* `src/attacks/outsider_attacks.py`: 9/9 outsider attack vectors detected and rejected.
* `src/attacks/insider_fraud_suite.py`: 5/5 insider fraud vectors detected and rejected.
