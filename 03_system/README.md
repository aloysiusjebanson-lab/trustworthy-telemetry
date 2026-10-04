# System Architecture & Implementation (v1.1)

This directory documents the technical architecture, cryptographic data flow, and components of the **Verifiable Telemetry** pipeline.

---

## 1. System Architecture & Data Flow

```mermaid
flowchart TD
    subgraph EDGE["1. Edge Gateway & Physical Ingestion"]
        METER["Physical Energy Meter\n(Carlo Gavazzi EM24, MID Class B)"]
        MODBUS["RS-485 Modbus RTU\n(Registers: cumulative_wh, interval_wh)"]
        SIM["Hardened Gateway Ingestion\n(mock_edge.py)"]
        ATECC["Secure Element (ATECC608)\n(Hardware Private Key Slot 0)"]
        FACTORY["Microchip Factory CA\n(hardware_attestation.json)"]
        CHAIN["Sequential Hash-Chain\n(prev_hash link)"]
        OBS_OUT["Signed Telemetry Records\n(observations.ndjson)"]

        METER --> MODBUS
        MODBUS --> SIM
        FACTORY -.->|Silicon cert chain| SIM
        SIM --> ATECC
        ATECC -->|ECDSA P-256 Sign| CHAIN
        CHAIN --> OBS_OUT
    end

    subgraph PIPELINE["2. Evidence Pipeline & Claim Packaging"]
        INGEST["Pipeline Aggregator\n(claim_generator.py)"]
        ROOT_KEY["Company Root Key\n(company_root_private_key.pem)"]
        DEV_CERT["Signed Device Certificate\n(device_certificate.json + MID Class B)"]
        RECIPES["Lineage Transformations\n(energy_aggregation.json\ncarbon_calculation.json)"]
        PROV["W3C PROV-O Graph\n(provenance.json)"]
        CLAIM["Claim Declaration\n(claim.json)"]
        SEAL["Bundle Seal\n(Root Signature over Manifest)"]
        MANIFEST["manifest.json\n(Canonical SHA-256 file catalog)"]
        BUNDLE["claim_bundle/"]

        OBS_OUT --> INGEST
        ROOT_KEY -->|Issues & signs| DEV_CERT
        INGEST --> RECIPES
        INGEST --> PROV
        INGEST --> CLAIM
        DEV_CERT --> BUNDLE
        RECIPES --> BUNDLE
        PROV --> BUNDLE
        CLAIM --> BUNDLE
        OBS_OUT --> BUNDLE
        BUNDLE --> MANIFEST
        ROOT_KEY -->|Signs manifest| SEAL
        SEAL --> MANIFEST
    end

    subgraph AUDIT["3. Independent Offline Verifier"]
        CLI["Verifier CLI Engine\n(verify_bundle.py / OpenSSL)"]
        TRUST_ANCHOR["Company Root Public Key\n(company_root_public_key.pem)"]
        REGISTRY["Auditor Pinned Registry\n(trusted_references.json / ISPRA digests)"]
        
        subgraph CHECKS["10 Fail-Closed Verification Checks"]
            C1["Check 1: Manifest Integrity & Bundle Seal"]
            C2["Check 2: Device Cert, Attestation & MID Pedigree"]
            C3["Check 3: Observation Signatures & Timestamp Bounds"]
            C4["Check 4: Cryptographic Hash-Chain Continuity"]
            C5["Check 5: Sequence Monotonicity & Dual Registers"]
            C6["Check 6: Claim Period Boundary Bounds Enforcement"]
            C7["Check 7: W3C PROV-O Lineage & Recipe Digests"]
            C8["Check 8: Pinned Registry Emission Factor Match"]
            C9["Check 9: Independent Integer Wh Recomputation"]
            C10["Check 10: Zero-Tolerance Numeric Reconciliation"]
        end

        VERDICT{"Formal Audit Verdict:\nPASSED or FAILED"}

        BUNDLE --> CLI
        TRUST_ANCHOR -->|Verification key| CLI
        REGISTRY -->|Authoritative factor digests| CLI
        CLI --> CHECKS
        CHECKS --> VERDICT
    end
```

---

## 2. Directory & Component Mapping

| Directory / File | Role | Description |
|---|---|---|
| [`src/device_simulator/mock_edge.py`](../src/device_simulator/mock_edge.py) | Edge Simulator | Simulates physical Modbus RTU registers, Microchip ATECC608 silicon attestation, sequential hash-chain calculation (`prev_hash`), and NIST P-256 observation signing. |
| [`src/pipeline/claim_generator.py`](../src/pipeline/claim_generator.py) | Claim Pipeline | Ingests observation streams, applies deterministic integer Wh summation and GHG Scope 2 calculations, builds W3C PROV-O provenance, generates `manifest.json`, and cryptographically seals the bundle. |
| [`src/verifier/verify_bundle.py`](../src/verifier/verify_bundle.py) | Offline Verifier | Independent zero-trust verification CLI executing 10 fail-closed checks using native OpenSSL. Zero pip dependencies. |
| [`src/verifier/trusted_references.json`](../src/verifier/trusted_references.json) | Pinned Registry | Pinned authoritative emission factor database hashes (ISPRA 2026, EEA) maintained independently by the auditor. |
| [`src/attacks/outsider_attacks.py`](../src/attacks/outsider_attacks.py) | Outsider Benchmark | Programmatic test harness verifying rejection of 10 outsider adversarial attack vectors. |
| [`src/attacks/insider_fraud_suite.py`](../src/attacks/insider_fraud_suite.py) | Insider Benchmark | Programmatic test harness verifying rejection of 5 insider fraud vectors (greenwashing, dual-register shaving, truncation, software keys, broken chains). |
| [`04_experiments/golden_test_vector/`](../04_experiments/golden_test_vector/) | Conformance Vector | Canonical frozen bundle, root key, and expected audit JSON for Milestone 3 cross-language (Rust) conformance testing. |
| [`03_system/threat_model.md`](threat_model.md) | Formal Threat Model | NLnet Task 3.4 threat model and security boundary document. |

---

## 3. Cryptographic Lifecycle Sequence

```mermaid
sequenceDiagram
    autonumber
    participant M as Physical Meter (MID Class B)
    participant E as Edge Gateway (ATECC608)
    participant C as Company Pipeline
    participant A as Auditor Verifier (Zero-Trust)
    participant R as Pinned Authority Registry

    Note over M,E: Tier 1: Hardware Telemetry Ingestion
    M->>E: Stream register readings (cumulative_wh, interval_wh)
    E->>E: Calculate prev_hash chain: H_n = SHA256(H_{n-1} || reading_n)
    E->>E: Sign observation envelope with Silicon Private Key (NIST P-256)
    E-->>C: Stream signed observations.ndjson

    Note over C: Tier 2: Transformation & Sealing
    C->>C: Execute energy aggregation & Scope 2 GHG calculation
    C->>C: Generate W3C PROV-O graph & claim.json with period boundaries
    C->>C: Hash all bundle files into canonical manifest.json
    C->>C: Sign manifest.json with Company Root Key (Bundle Seal)

    Note over A,R: Tier 3: Independent Offline Audit
    C-->>A: Submit sealed claim_bundle/ & Company Root Public Key
    A->>A: Check 1: Verify Company Root Signature over manifest.json (Bundle Seal)
    A->>A: Check 2: Verify Microchip Factory Attestation & MID Metrology Pedigree
    A->>A: Check 3-5: Verify Observation Signatures, Hash-Chain & Dual Registers
    A->>A: Check 6: Enforce period boundaries (record_count, terminal_hash)
    A->>R: Check 8: Match bundled emission factor against Pinned ISPRA/EEA Registry
    A->>A: Check 9-10: Independently sum integer Wh & reconcile carbon claim
    A-->>A: Emit Audit Verdict: PASSED (Zero-Knowledge, Air-Gapped)
```
