# System Architecture & Implementation (v1.2)

This directory documents the technical architecture, cryptographic data flow, pluggable profile dispatcher, and repository components of the **Universal Verifiable Telemetry Engine**.

---

## 1. Universal Engine Architecture & Data Flow

The system separates the **Core Cryptographic Verification Engine** (7 domain-agnostic checks) from **Pluggable Domain Profile Drivers** (3 invariant hooks dispatched via `SUPPORTED_PROFILE_DRIVERS`).

```mermaid
flowchart TD
    subgraph EDGE["1. Physical Sensor Bus & Hardened Edge Boundary"]
        SENSORS["Legal-for-Trade Field Instruments\n- Driver 1: EU MID 2014/32/EU Submeter\n- Driver 2: EU NAWI 2014/31/EU Scale & Thermocouple"]
        MODBUS["2.5 kV Isolated RS-485 Tap\n(Direct Modbus RTU Read)"]
        GATEWAY["Hardened Edge Gateway\n(mock_edge.py / biochar_edge.py)"]
        ATECC["Secure Element Silicon\n(ATECC608B / TPM 2.0 Key Slot)"]
        ATTEST["Silicon Attestation Descriptor\n(hardware_attestation.json)"]
        CHAIN["Sequential Hash-Chain Engine\n(prev_hash = SHA-256 of prior record)"]
        OBS_OUT["Signed Telemetry Stream\n(observations/observations.ndjson)"]

        SENSORS --> MODBUS
        MODBUS --> GATEWAY
        ATTEST -.->|Public key SHA-256 binding| GATEWAY
        GATEWAY --> ATECC
        ATECC -->|ECDSA P-256 Sign| CHAIN
        CHAIN --> OBS_OUT
    end

    subgraph PIPELINE["2. Evidence Packaging & Provenance Pipeline"]
        INGEST["Deterministic Claim Packager\n(claim_generator.py / biochar_claim_generator.py)"]
        ROOT_KEY["Producer Root Key\n(NIST P-256 Private Key)"]
        DEV_CERT["Signed Device Certificate\n(device_certificate.json + Metrology Window)"]
        RECIPES["Integer Transformation Recipes\n(transformations/*.json)"]
        PROV["W3C PROV-O Lineage Graph\n(provenance/provenance.json)"]
        CLAIM["Declared Claim Metrics\n(claim.json)"]
        MANIFEST["Canonical File Catalog\n(manifest.json + bundle_seal)"]
        BUNDLE["Self-Contained Evidence Container\n(claim_bundle/)"]

        OBS_OUT --> INGEST
        ROOT_KEY -->|Signs cert & metrology| DEV_CERT
        INGEST --> RECIPES
        INGEST --> PROV
        INGEST --> CLAIM
        DEV_CERT --> BUNDLE
        RECIPES --> BUNDLE
        PROV --> BUNDLE
        CLAIM --> BUNDLE
        OBS_OUT --> BUNDLE
        BUNDLE --> MANIFEST
        ROOT_KEY -->|Signs RFC 8785 manifest| MANIFEST
    end

    subgraph AUDIT["3. Independent Offline Verifier Engine (verify_bundle.py)"]
        CLI["Universal Verifier State Machine\n(Python 3 Stdlib + OpenSSL CLI)"]
        TRUST_ANCHOR["Producer Root Public Key"]
        REGISTRY["Auditor Pinned Authority Registry\n(trusted_references.json)"]
        LEDGER["Cross-Claim Deduplication Ledger\n(--claim-ledger)"]

        subgraph CORE_CHECKS["7 Universal Core Engine Checks"]
            C1["Check 1: Manifest Seal, Path Jail & Key Hygiene"]
            C2["Check 2: Device Cert, Key Binding, Silicon & Metrology"]
            C3["Check 3: Observation ECDSA Signatures & Calibration Window"]
            C4["Check 4: Genesis & Sequential prev_hash Continuity"]
            C6["Check 6: Claim Boundaries & Cross-Claim Replay Ledger"]
            C7["Check 7: W3C PROV-O Entity & Recipe Digest Lineage"]
            C10["Check 10: Zero-Tolerance Integer Claim Reconciliation"]
        end

        subgraph PROFILE_HOOKS["3 Pluggable Domain Profile Hooks (SUPPORTED_PROFILE_DRIVERS)"]
            C5["Check 5 Hook: Process Continuity Invariant"]
            C8["Check 8 Hook: Pinned Authority Reference Verification"]
            C9["Check 9 Hook: Physical Conservation & Recomputation"]
        end

        VERDICT{"Formal Audit Verdict:\nPASSED or FAILED (Fail-Closed)"}

        BUNDLE --> CLI
        TRUST_ANCHOR --> CLI
        REGISTRY --> CLI
        LEDGER --> CLI
        CLI --> CORE_CHECKS
        CLI --> PROFILE_HOOKS
        CORE_CHECKS --> VERDICT
        PROFILE_HOOKS --> VERDICT
    end
```

---

## 2. Directory & Component Mapping

| Directory / File | Architectural Layer | Description |
|---|---|---|
| [`src/verifier/verify_bundle.py`](../src/verifier/verify_bundle.py) | **Core Verifier Engine** | Universal zero-trust verification CLI executing the 7 core cryptographic/structural checks and dispatching the 3 pluggable domain hooks via `SUPPORTED_PROFILE_DRIVERS`. Supports `--list-profiles`, `--claim-ledger`, and `--require-hardware-attestation`. Zero pip dependencies. |
| [`src/verifier/trusted_references.json`](../src/verifier/trusted_references.json) | **Core Authority Registry** | Out-of-band auditor-pinned SHA-256 digests for authoritative reference datasets (ISPRA/EEA grid factors, ISO 17025 lab certificates, certified delivery manifests) and pinned `methodology_parameters`. |
| [`src/device_simulator/mock_edge.py`](../src/device_simulator/mock_edge.py) | **Reference Driver 1 (`energy_submetering`)** | Simulates EU MID 2014/32/EU Class B Modbus RTU dual registers (`cumulative_wh`, `interval_wh`), hardware attestation descriptor, sequential `prev_hash` chaining, and P-256 signing. |
| [`src/pipeline/claim_generator.py`](../src/pipeline/claim_generator.py) | **Reference Driver 1 (`energy_submetering`)** | Packages signed energy observations, integer Wh summation, Scope 2 GHG recipes, W3C PROV-O lineage, and root-sealed `manifest.json`. |
| [`src/device_simulator/biochar_edge.py`](../src/device_simulator/biochar_edge.py) | **Reference Driver 2 (`biochar_pyrolysis`)** | Simulates EU NAWI 2014/31/EU Class III weighing indicators and Type-K pyrolysis thermocouple buses, silicon attestation binding, and batch `prev_hash` signing. |
| [`src/pipeline/biochar_claim_generator.py`](../src/pipeline/biochar_claim_generator.py) | **Reference Driver 2 (`biochar_pyrolysis`)** | Packages multi-sensor pyrolysis batches, ISO 17025 lab assays, feedstock manifests, 6-part mass-balance conservation recipes, and W3C PROV-O lineage. |
| [`src/attacks/outsider_attacks.py`](../src/attacks/outsider_attacks.py) | **Core Engine Benchmark (`O1–O11`)** | Automated adversarial test suite verifying fail-closed rejection of 11 outsider tampering, spoofing, path traversal, and key-hygiene vectors. |
| [`src/attacks/insider_fraud_suite.py`](../src/attacks/insider_fraud_suite.py) | **Insider Benchmark (`I1–I5`)** | Automated test suite verifying rejection of 5 operator fraud vectors (reference factor greenwashing, dual-register shaving, period truncation, simulator key injection, stream splicing). |
| [`src/attacks/biochar_attacks.py`](../src/attacks/biochar_attacks.py) | **Domain Driver Stress Suite (`B1–B17`)** | Automated test suite verifying rejection of 17 multi-sensor physical & metrological fraud vectors (moisture inflation, thermal undercooking, unpinned lab reports, expired calibration, cross-claim replay, yield-cap violations). |
| [`04_experiments/security_reaudit/poc_exploits.py`](../04_experiments/security_reaudit/poc_exploits.py) | **Security Regression Harness (`P1–P6`)** | Automated regression harness validating all 6 security re-audit hardening fixes (`P1–P6`). |
| [`04_experiments/golden_test_vector/`](../04_experiments/golden_test_vector/) | **Golden Vector 1 (`energy_submetering`)** | Frozen reference bundle, public key, and expected JSON verdict for cross-language (Rust) conformance testing of linear cumulative flows. |
| [`04_experiments/golden_test_vector_biochar/`](../04_experiments/golden_test_vector_biochar/) | **Golden Vector 2 (`biochar_pyrolysis`)** | Frozen reference bundle, public key, and expected JSON verdict for cross-language conformance testing of non-linear mass transformations. |
| [`03_system/threat_model.md`](threat_model.md) | **Formal Threat Model** | Formal threat taxonomy, adversary capabilities, physical-to-digital security boundaries, and 33-vector benchmark mapping. |

---

## 3. Universal Cryptographic Lifecycle Sequence

```mermaid
sequenceDiagram
    autonumber
    participant S as Legal-for-Trade Sensors (MID / NAWI)
    participant E as Edge Gateway (ATECC608 / TPM 2.0)
    participant P as Packaging Pipeline
    participant V as Offline Verifier Engine (verify_bundle.py)
    participant R as Pinned Authority Registry & Claim Ledger

    Note over S,E: Tier 1: Hardware Edge Boundary
    S->>E: Read physical registers over 2.5 kV isolated RS-485
    E->>E: Chain record: prev_hash = SHA-256(canonical_json(record_{n-1}))
    E->>E: Sign canonical integer payload in Secure Element (ECDSA P-256)
    E-->>P: Emit observations/observations.ndjson

    Note over P: Tier 2: Deterministic Packaging & Sealing
    P->>P: Generate integer transformation recipes & W3C PROV-O graph
    P->>P: Bind sequence bounds & terminal_hash into claim.json
    P->>P: Compute SHA-256 catalog in manifest.json & sign with Producer Root Key

    Note over V,R: Tier 3: Independent Zero-Trust Verification
    P-->>V: Deliver self-contained claim_bundle/
    V->>V: Core Checks 1-4: Verify Manifest Seal, Key Hygiene, Silicon Attestation, Metrology & Hash-Chain
    V->>V: Profile Hook Check 5: Verify Process Continuity Invariant (via SUPPORTED_PROFILE_DRIVERS)
    V->>R: Core Check 6 & 7: Verify Claim Boundaries, Cross-Claim Replay Ledger & PROV-O Lineage
    V->>R: Profile Hook Check 8: Verify External Reference SHA-256 Digests against Pinned Registry
    V->>V: Profile Hook Check 9 & Core Check 10: Enforce Physical Conservation & Zero-Tolerance Reconciliation
    V-->>V: Emit Deterministic Audit Verdict: PASSED or FAILED (Air-Gapped)
```
