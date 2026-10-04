# NLnet Restack (Open Internet Stack) — Grant Guidelines & Application Strategy

**Call:** Restack Open Call 1 (Horizon Europe Grant Agreement No. 101299072)  
**Opening Date:** September 3, 2026  
**Closing Deadline:** November 3, 2026 at 12:00 PM CET (noon)  
**Programme Lifespan:** June 1, 2026 – May 30, 2030 (Total Budget: €7,000,000)  
**Target Grant Request:** €35,000 – €38,000 (First-time maximum cap: €50,000)

---

## 1. Key Eligibility Rules

* **Individual Applicants Welcome:** Open to individual citizens/natural persons. You do **not** need an incorporated company, a consortium, university affiliation, or a physical laboratory.
* **Geographical Priority:** Inhabitants of the EU and Horizon Europe associated countries are explicitly prioritized (the applicant in Italy qualifies).
* **Open Source Mandate:** All software and hardware designs must be published under a recognized Free/Open Source Software (FOSS) license (e.g., Apache 2.0, MIT, or CERN-OHL). All research results must be Open Access.
* **Funding Mechanism:** Paid in milestone installments against verified deliverables directly to the applicant. Treated under beneficial tax rules as a non-dilutive charitable donation/gift.
* **Growth Pathway:** After successfully completing a first grant ($\le €50,000$), grantees can re-apply for up to **€150,000** per proposal, up to a lifetime ceiling of **€500,000**.

---

## 2. Evaluation Process & Scoring Matrix

Proposals are evaluated in two stages and scored out of **7.0 points** (must achieve $> 5.0$ to pass Stage 1).

| Weight | Criterion | How Reviewers Evaluate | How Our Project Wins |
| :--- | :--- | :--- | :--- |
| **40%** | **Relevance / Impact / Strategic Potential** | Does it break vendor lock-in? Does it contribute to an open, decentralized internet stack rather than proprietary "dark stack" silos? | We provide a local-first, vendor-neutral telemetry provenance layer that prevents greenwashing and cloud lock-in for industrial ESG claims. |
| **30%** | **Technical Excellence / Feasibility** | Is the technical approach sound? Can the applicant realistically build it? | We already have a functioning deterministic edge simulator, threat model, and cryptographic spec in our repository. |
| **30%** | **Cost-Effectiveness / Value for Money** | Is the budget frugal and justified? | We ask for a lean €38,000 across 4 concrete software/hardware milestones, well below the €50k ceiling. |

### Stage 2 Clarification Focus:
Reviewers may ask clarifying questions before awarding the grant:
* Differences from existing projects (e.g., why not just use generic cloud IoT?).
* Practical approach to complicating factors (e.g., clock drift, legacy Modbus meters).
* Long-term sustainability and open standards alignment.

---

## 3. Eligible Activities & Costs

* Design and development of free and open-source software and open hardware.
* Validation and security proofs for novel technical architectures.
* Software quality improvements, test harnesses, and CI/CD pipelines.
* Documentation, educational tutorials, and standardisation efforts.
* Essential out-of-pocket hardware/infrastructure costs (e.g., development boards, secure element breakout chips, RS-485 dongles).
* Project management and developer time.

---

## 4. Why You Do NOT Need a Laboratory

1. **NLnet was created for independent hackers and solo builders:** Unlike traditional Horizon Europe research consortia that require university cleanrooms and academic hierarchies, NLnet's statutory mission is to fund independent developers and small open-source teams working remotely.
2. **Our scope is embedded software and open hardware specs:** Our hardware scope is an edge gateway running on low-cost microcontrollers (€15–€70, e.g., ESP32 or Raspberry Pi with an ATECC608 crypto chip over I2C). This is built on an ordinary home desk with a USB cable and a laptop.
3. **Frugality is a scoring advantage:** Evaluators actively penalize bloated lab overheads. A solo developer asking for modest milestone compensation to deliver clean, functional code is seen as having maximum "Value for Money."

---

## 5. Strategic Project Positioning for Restack

* **Project Title:** *Verifiable Telemetry Engine: Open-Source Hardware Root-of-Trust and Local-First Provenance for Industrial Energy & Carbon Claims*
* **The Problem:** Modern sustainability accounting (CSRD, EU Battery Passport) relies on closed, proprietary cloud databases where raw sensor data can be silently altered or falsified before audit. Current systems require blind trust in cloud vendors and lack physical origin integrity.
* **The Solution:** A vendor-neutral, local-first telemetry engine that cryptographically signs industrial energy observations at the hardware boundary and packages them into deterministic, verifiable claim bundles that any third party can verify offline without specialized infrastructure.

---

## 6. Proposed Milestone Breakdown (€38,000)

```
[ M1: Specification & Schema Freeze ] (€8,000 - Month 1)
   └── Canonical JSON schema, deterministic serialization spec, threat model freeze.

[ M2: Hardware Root-of-Trust & Simulator ] (€11,000 - Months 2-3)
   └── Driver interface for hardware secure elements (ATECC608/TPM), Modbus reader, and fixture simulator.

[ M3: Independent Offline Verifier Engine ] (€11,000 - Month 4)
   └── Zero-dependency CLI verifier that checks cryptographic signatures, sequences, and calculation lineage.

[ M4: End-to-End Test Suite & Public Release ] (€8,000 - Month 5)
   └── Reproducible test harness, adversarial corruption tests, open-access docs, and GitHub release under Apache 2.0.
```

---

## 7. Submission Action Checklist (Target: Before Nov 3, 2026)

- [ ] Draft concise answers to the standard NLnet application questions (~2 pages total).
- [ ] Refine the short problem statement focusing on the "dark stack" / proprietary cloud lock-in of current industrial telemetry.
- [ ] Link to public GitHub repository demonstrating existing progress (simulator and specs).
- [ ] Submit final proposal before **November 3, 2026, 12:00 CET**.

---

## 8. The End-to-End Architecture (Hardware to Software)

Our core technical differentiator is spanning the entire physical-to-computational chain:

```
[ Physical World ]          [ Hardware Trust Boundary ]          [ Software & Audit ]
Existing Modbus Meter ──> Hardened Edge Gateway (ATECC608) ──> Canonical Transformation ──> Offline Verifier CLI
(Unencrypted RS-485)       (ECDSA P-256 Hardware Signature)     (Versioned Lineage Manifest)  (Zero-Trust Audit)
```

1. **Physical Fieldbus (Hardware):** Reads legacy, unencrypted RS-485 / Modbus RTU or M-Bus meters inside the electrical cabinet.
2. **Hardware Root-of-Trust (Hardware):** Locks private keys inside a physical Secure Element (ATECC608 / TPM) to stamp a 64-byte ECDSA signature on raw readings at the ingestion boundary.
3. **Reproducible Pipeline (Software):** Applies deterministic transformations, tracking emission factor versions and calculation hashes in an immutable manifest.
4. **Verifiable Claim Bundle (Software):** Emits a self-contained, portable folder containing observations, signatures, manifests, and checksums.

---

## 9. The "Offline Verification Engine" Concept

### What is it? (The Biometric Passport Analogy)
When airport border control inspects a traveler’s biometric e-passport, the scanner does not need to connect to a foreign government server or call the issuing authority. The cryptographic signature on the chip is mathematically verified **locally and offline**. 

Our **Offline Verifier CLI** works the exact same way for industrial sustainability:
* **Zero Cloud Dependency:** An auditor can copy a `claim_bundle/` to an air-gapped laptop with Wi-Fi disabled and run `verify-claim ./claim_bundle`.
* **Zero Vendor Lock-In:** Even if the cloud provider, SaaS platform, or gateway vendor goes out of business, the proof remains mathematically verifiable 10 years later.
* **Instant Tamper Detection:** If a single character or decimal place in the energy reading or calculation formula was modified in a database, the cryptographic hash verification fails immediately.

---

## 10. The High Stakes: Real-World Fraud & Regulatory Exposure

To make a compelling impact case for NLnet (and enterprise buyers), we highlight four high-stakes scenarios where falsified telemetry leads to massive financial and environmental fraud:

1. **Carbon Border Tax Evasion (CBAM & EU Battery Passport):**
   * *Stakes:* Under EU CBAM, imported goods (steel, aluminium, batteries) face carbon border tariffs of **€60–€85 per ton of CO2e**.
   * *Fraud Risk:* An industrial manufacturer falsifying factory telemetry by 20% can evade **€2,000,000 to €10,000,000** in statutory EU border taxes. Today, customs authorities have no way to verify whether reported values came from physical meters or a manipulated spreadsheet.
2. **Sustainability-Linked Loans (Covenant & Interest Fraud):**
   * *Stakes:* European banks (BNP Paribas, Intesa Sanpaolo, Deutsche Bank) issue billions in green financing where loan interest rates drop by 0.25% to 0.5% if the company meets energy reduction targets.
   * *Fraud Risk:* On a €200M loan, hitting the target by altering unverified sensor scripts saves **€500,000 to €1,000,000 per year** in pure interest payments, directly defrauding lenders.
3. **Energy Efficiency Subsidy Theft (White Certificates / TEE):**
   * *Stakes:* In countries like Italy (Titoli di Efficienza Energetica / TEE) and France, national grid operators pay direct cash subsidies for certified energy savings.
   * *Fraud Risk:* Ingestion scripts can artificially fabricate phantom energy savings, siphoning millions in public green transition funds.
4. **Colocation Data Centre Tenant Overbilling:**
   * *Stakes:* Cloud and colocation tenants pay millions based on allocated server rack power consumption.
   * *Fraud Risk:* Without signed physical meter provenance, operators can misallocate power consumption to high-margin tenants or disguise cooling inefficiencies.

---

## 11. Market Validation, Commercial Tailwinds & Regulatory Drivers

### A. The $26.35 Billion Market Boom (17.4% CAGR to 2035)
* Independent industry reports project the **Blockchain IoT Hardware** market to grow from early stages to **$26.35B by 2035 at a 17.4% CAGR**.
* **Key Industry Insight:** *"IoT sensors are becoming trust infrastructure. The answer to data tampering increasingly involves hardware that doesn't just sense and transmit, but records in ways that are difficult to tamper with."*
* **Our Advantage over Blockchain:** Enterprises want tamper-evident verification but reject public blockchains due to volatile gas fees, corporate trade secret leaks, and cryptocurrency stigma. We deliver the cryptographic proof and Merkle auditability **without the blockchain overhead**.

### B. The EU Cyber Resilience Act (CRA) Tailwinds
* The EU CRA legally mandates that connected IoT devices sold in the EU implement **hardware-backed roots of trust, secure boot, and cryptographic data integrity mechanisms**.
* Hardware security is no longer an optional enterprise feature—it is becoming a mandatory European compliance requirement.

### C. Technology Stack Clarity (Where We Sit)
* **Layer 0 (Silicon IP Cores — e.g., Xiphera):** Design Verilog/VHDL cryptographic acceleration for chipmakers. (We do NOT do this).
* **Layer 1 (Physical Crypto Chips — e.g., Microchip ATECC608, NXP EdgeLock, TPM 2.0):** Off-the-shelf, mass-produced €2–€5 Secure Elements. (We USE these).
* **Layer 2 (Hardware Trust Boundary — OUR ENGINE):** Connects to unencrypted industrial Modbus/M-Bus meters, reads serial telemetry, and signs it at the physical cabinet boundary using Layer 1 chips.
* **Layer 3 (Reproducible Lineage & Verification — OUR ENGINE):** Manifest tracking, canonical serialization, and zero-dependency offline CLI verification for auditors.

---

## 12. Competitive Comparison: IoT Device Identity vs. Telemetry Provenance

A critical comparison point for **Field 7 of the NLnet proposal** is contrasting our engine with commercial IoT device security platforms (e.g., **Crypto Quantique**, Keyfactor, AWS IoT Device Defender):

| Feature / Dimension | IoT Device Security (e.g., Crypto Quantique QuarkLink) | Our Project: Verifiable Telemetry Engine |
| :--- | :--- | :--- |
| **Core Objective** | **Device Identity & Pipe Security:** Proves that an authorized smart device is connecting to a cloud broker. | **Data Provenance & Claim Assurance:** Proves that a carbon/energy claim is mathematically verified from physical sensors. |
| **Analogy** | **An Employee ID Badge:** It unlocks the door and proves the device is genuine. | **A Notarized Legal Contract:** It binds raw readings, calculation manifests, and emission factors into an unforgeable record. |
| **Business / Trust Model** | **Proprietary "Dark Stack" SaaS:** Devices are locked into a recurring cloud subscription. If the vendor shuts down, security fails. | **Open-Source Commons:** Local-first, zero-cloud dependency, zero subscriptions. Any auditor can verify bundles 10 years later. |
| **Brownfield Feasibility** | **Greenfield only:** Requires manufacturing custom chips with specialized silicon PUF IP. | **Retrofit-ready:** Bridges existing, unencrypted Modbus RTU / M-Bus meters already installed in European factories. |
| **Calculation Lineage** | **None:** Blind to data transformations, ETL scripts, and emission calculation math. | **Full Lineage:** Binds raw observations, transformation manifests, and factor versions in an immutable evidence bundle. |

**The Strategic Pitch to NLnet:**
> *"Existing commercial solutions treat IoT trust as a proprietary, closed-source cloud subscription, locking enterprises into 'dark stack' SaaS portals for basic device onboarding. Our project breaks this vendor lock-in by providing a local-first, open-source standard for verifiable data provenance that runs on off-the-shelf hardware and verifies completely offline."*

---

## 13. Competitive Comparison: Web3 / Tokenized IoT (IOTA, Helium, IoTeX) vs. Zero-Token Telemetry

A common misconception is that verifiable IoT requires public blockchains or crypto tokens. Our engine explicitly rejects the "tokenized machine economy" model in favor of lightweight, token-free cryptographic provenance:

| Dimension | Web3 / Tokenized IoT (e.g., IOTA Tangle, Helium) | Our Project: Zero-Token Verifiable Telemetry |
| :--- | :--- | :--- |
| **Token Dependency** | **Requires Crypto Tokens:** Devices hold wallets, execute micro-payments, or pay network gas fees. | **Zero Tokens:** Uses pure asymmetric cryptography (ECDSA P-256 / SHA-256). No financial layer. |
| **Security Risk** | **Honeypot for Financial Theft:** Embedded wallets holding currency make IoT devices targets for theft and balance draining. | **Zero Financial Surface:** Private keys can only sign measurement statements; they have no ability to spend or transfer funds. |
| **Data Privacy** | **Public Ledger Leakage:** Publishing sensor streams to distributed ledgers leaks proprietary factory operating schedules and yields. | **Strict Confidentiality:** Raw telemetry remains on-premise; only selective mathematical claim bundles are exported to auditors. |
| **Scalability & Cost** | **Network Bottlenecks:** Billions of high-frequency sensor events overwhelm distributed ledgers or incur prohibitive gas costs. | **Infinite Local Scalability:** Signing is performed locally in 40ms; claim bundles are verified offline with zero network load. |
| **Regulatory & Enterprise Fit** | **High Resistance:** Conservative European manufacturers and auditors refuse to manage crypto wallets for CSRD/DPP compliance. | **High Acceptance:** Directly aligns with standard audit practices (ISO 27001, eIDAS, deterministic evidence packages). |

**The Strategic Pitch to NLnet:**
> *"While speculative Web3 projects attempt to force cryptocurrency wallets and volatile tokens onto connected devices, our project extracts the genuine cryptographic benefits of distributed ledgers—tamper-evident hash trees and hardware signatures—into a lean, token-free, local-first engine designed for real-world industrial compliance."*

---

## 14. Cryptographic Key Hierarchy & Trust Chain Architecture

### The Core Trust Problem

A claim bundle includes signed observations and a device public key. But an auditor receiving both from the same company faces a fundamental question: *"How do I know you didn't fabricate a throwaway keypair, sign fake data, and hand me both?"* Without an external trust anchor, self-contained signatures prove internal consistency but not authentic origin.

### Solution: Two-Level Key Hierarchy

The system uses two cryptographic levels — a **Company Root Key** (identity authority) and per-device **Sensor Keys** (data signers) — linked by device certificates.

```
                     ┌──────────────────────────────┐
                     │      COMPANY ROOT KEY         │
                     │  (ECDSA P-256 or Ed25519)     │
                     │                               │
                     │  Private: kept in HSM / safe  │
                     │  Public:  shared with auditors │
                     │           once, out-of-band    │
                     └───────────────┬────────────────┘
                                     │
                  Company signs a DEVICE CERTIFICATE
                  for each sensor at provisioning time
                                     │
            ┌────────────────────────┼────────────────────────┐
            ▼                        ▼                        ▼
   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
   │  SENSOR KEY A    │    │  SENSOR KEY B    │    │  SENSOR KEY C    │
   │  (ATECC608 chip) │    │  (ATECC608 chip) │    │  (ATECC608 chip) │
   │                  │    │                  │    │                  │
   │  Private: locked │    │  Private: locked │    │  Private: locked │
   │  in silicon,     │    │  in silicon,     │    │  in silicon,     │
   │  never leaves    │    │  never leaves    │    │  never leaves    │
   │  the chip        │    │  the chip        │    │  the chip        │
   └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
            │                       │                       │
     Signs each              Signs each              Signs each
     observation             observation             observation
     payload                 payload                 payload
```

### What Each Party Holds and Shares

```
┌─────────────────────────────────────────────────────────────────────┐
│  COMPANY (Sensor Deployer)                                         │
│                                                                     │
│  HOLDS (secret):                                                    │
│    • Company Root Private Key (in HSM or secure offline storage)    │
│                                                                     │
│  SHARES (once, out-of-band):                                        │
│    • Company Root Public Key → to auditor                           │
│      (published on website / exchanged in person /                   │
│       registered with certification body like eIDAS)                │
│                                                                     │
│  SHARES (with each claim):                                          │
│    • claim_bundle/ containing:                                      │
│      - device_certificate.json (signed by Company Root Key)         │
│      - device_public_key.pem                                        │
│      - observations.ndjson (each row signed by Device Key)          │
│      - manifest, transformations, checksums                         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  EACH SENSOR / EDGE GATEWAY                                        │
│                                                                     │
│  HOLDS (secret, hardware-locked):                                   │
│    • Device Private Key (burned into ATECC608 at provisioning,      │
│      physically cannot be read or exported)                         │
│                                                                     │
│  PRODUCES:                                                          │
│    • Signed observation payloads (timestamp + device_id + value     │
│      + sequence number → deterministic JSON → ECDSA signature)      │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  AUDITOR                                                            │
│                                                                     │
│  HOLDS (trusted, received once):                                    │
│    • Company Root Public Key                                        │
│                                                                     │
│  RECEIVES (with each audit):                                        │
│    • claim_bundle/ folder                                           │
│                                                                     │
│  VERIFIES (using our open-source Offline Verifier CLI):             │
│    • Everything — zero trust in the company's database or cloud     │
└─────────────────────────────────────────────────────────────────────┘
```

### Auditor Verification Flow (3-Step Chain)

```
STEP 1 — DEVICE AUTHENTICITY
"Does this sensor belong to this company?"

  device_certificate.json
  ┌──────────────────────────────────┐
  │ device_id:     "sensor_A"        │
  │ device_pubkey: "04 3A F7 ..."    │     Verify       🔑 Company
  │ valid_from:    "2026-01-15"      │ ──────────────→       Root
  │ company_sig:   "30 45 02 ..."    │   signature         Public Key
  └──────────────────────────────────┘                  (auditor has this)
                                            │
                                     ✅ "Yes, Company Y
                                        certified this device"
                                            │
                                            ▼
STEP 2 — DATA AUTHENTICITY
"Did this reading come from that physical sensor?"

  observation row #47
  ┌──────────────────────────────────┐
  │ timestamp:   1727647200          │
  │ device_id:   "sensor_A"          │     Verify       🔑 Device A
  │ reading_kwh: 15421.25            │ ──────────────→      Public Key
  │ sequence:    47                  │   signature      (trusted from
  │ signature:   "30 44 02 ..."      │                   Step 1 above)
  └──────────────────────────────────┘
                                            │
                                     ✅ "Yes, this kWh reading
                                        came from sensor_A"
                                            │
                                            ▼
STEP 3 — COMPLETENESS
"Is any data missing or deleted?"

  Sequence check:
  ┌──────────────────────────────────┐
  │ row 45  → sequence: 45          │
  │ row 46  → sequence: 46          │     Check for
  │ row 47  → sequence: 47          │ ──────────────→  Gaps?
  │ row 48  → sequence: 48          │                  Duplicates?
  │ row 49  → sequence: 49          │
  └──────────────────────────────────┘
                                            │
                                     ✅ "No gaps, no duplicates,
                                        no deletions detected"
```

### What Happens When Someone Tampers

```
ATTACK 1: Modify a reading (e.g., change 15421.25 → 12000.00)
  → Step 2 FAILS: signature does not match altered payload
  → Verdict: ❌ TAMPERED — observation integrity violated

ATTACK 2: Delete rows to hide high-consumption periods
  → Step 3 FAILS: sequence 45, 46, [GAP], 49
  → Verdict: ❌ TAMPERED — 2 observations missing (seq 47, 48)

ATTACK 3: Fabricate a fake device and sign fake data
  → Step 1 FAILS: device certificate not signed by Company Root Key
  → Verdict: ❌ UNTRUSTED — device not certified by known authority

ATTACK 4: Replay old data with correct signatures
  → Step 3 FAILS: duplicate sequence numbers or timestamps out of range
  → Verdict: ❌ TAMPERED — replay attack detected

ATTACK 5: Tamper data and recompute file hashes to bypass manifest integrity
  → Step 1 FAILS: Bundle Seal signature invalid (Company Root Key sealed original file hashes)
  → Verdict: ❌ TAMPERED — bundle seal cryptographic commitment broken
```

### Three-Layer Cryptographic Architecture

```
Layer 1: Telemetry Data Layer (Observations)
  └─ Hardware Secure Element signs individual Modbus readings (ECDSA P-256)
     Bound to physical device_id, sequence counter, and monotonic timestamps.

Layer 2: Claim Evidence Bundle Layer (Integrity & Lineage)
  └─ Company Root Key seals the bundle manifest (`bundle_seal`)
     Binds file hashes, transformation recipes, PROV-O lineage, and reference emission factors.

Layer 3: Enterprise Identity Layer (Trust Anchor)
  └─ Company Root Public Key anchored via multi-tier legal trust models:
     • Tier 1 (€0 / Instant): `did:web` domain-bound key (`https://company.com/.well-known/did.json`)
     • Tier 2 (~€150/yr): GLEIF vLEI (Verifiable Legal Entity Identifier)
     • Tier 3 (~€280/yr): eIDAS Qualified Electronic Seal (EU Trusted List statutory presumption)
```

### Device Certificate Structure (Implemented)

```json
{
  "certificate_body": {
    "device_id": "device_6b5aa5626e38",
    "device_type": "edge_gateway_modbus_p256",
    "meter_binding": "meter_main_switchgear_01",
    "device_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "valid_from": 1767225600,
    "valid_until": 1830297600,
    "issued_by": "company_authority_milan"
  },
  "company_signature": "3045022100df0270811c45c3ba1040e4...",
  "algorithm": "ECDSA_P256_SHA256"
}
```

### Implementation Status & Milestone Mapping

| Component | Status | Location | Target Milestone |
|:----------|:------:|:---------|:----------------:|
| Device keypair generation (ECDSA P-256) | ✅ Implemented | `src/device_simulator/mock_edge.py` | Complete (Local Prototype) |
| Observation payload signing (P-256) | ✅ Implemented | `src/device_simulator/mock_edge.py` | Complete (Local Prototype) |
| Deterministic JSON canonicalization | ✅ Implemented | `mock_edge.py`, `claim_generator.py` | Complete (Local Prototype) |
| Company Root Key authority | ✅ Implemented | `CompanyAuthority` in `mock_edge.py` | Complete (Local Prototype) |
| Device certificate issuance | ✅ Implemented | `mock_edge.py` | Complete (Local Prototype) |
| Full 10-check offline verifier CLI | ✅ Implemented | `src/verifier/verify_bundle.py` | Complete (Local Prototype) |
| Sequence gap & duplicate detection | ✅ Implemented | `verify_bundle.py` (Check 5) | Complete (Local Prototype) |
| Cryptographic hash-chain continuity (`prev_hash`) | ✅ Implemented | `verify_bundle.py` (Check 4) | Complete (Local Prototype) |
| Auditor-pinned reference registry (`trusted_references.json`) | ✅ Implemented | `verify_bundle.py` (Check 8) | Complete (Local Prototype) |
| Transformation & provenance lineage checks | ✅ Implemented | `verify_bundle.py` (Check 7) | Complete (Local Prototype) |
| Machine-readable audit output (`--json`) | ✅ Implemented | `verify_bundle.py` (Check 10) | Complete (Local Prototype) |
| Adversarial attack suite (14 distinct vectors) | ✅ Implemented | `outsider_attacks.py` (9/9) & `insider_fraud_suite.py` (5/5) | Complete (Local Prototype) |
| Hardware Secure Element integration (ATECC608 I2C) | ⬜ Planned | Physical prototype bench | Milestone 2 (€11,000) |
| Enterprise Identity did:web / eIDAS PKI bridge | ⬜ Planned | Enterprise gateway module | Milestone 2 (€11,000) |
| Rust-based zero-dependency verifier binary | ⬜ Planned | `target/release/telemetry-verify` | Milestone 3 (€11,000) |
| Operational field pilot in commercial facility | ⬜ Planned | Commercial building / testbench deployment | Milestone 4 (€8,000) |

### Analogy for NLnet Reviewers

> **The Biometric Passport Chain:** When an airport border officer scans your e-passport, they don't call your home country's government. Instead: (1) they trust the ICAO Root Certificate (received once); (2) the root certificate signed your country's signing certificate; (3) your country's certificate signed the chip in your passport. Three links, zero network calls, full verification. Our system applies the same chain to industrial energy data: Company Root → Device Certificate → Signed Observation → Verified Claim.
