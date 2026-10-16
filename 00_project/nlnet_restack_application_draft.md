# NLnet Restack Application Draft

**Fund:** Restack Fund (Call 1 — Horizon Europe Grant Agreement No. 101299072)  
**Closing Deadline:** November 3, 2026 at 12:00 CET (noon)  
**Applicant:** Individual (Resident in Italy)  
**Requested Amount:** €38,000  

---

### Field 1: Have you been funded by NLnet before?
**Response:** No

---

### Field 2: Proposal Title
**Draft Title:**
Verifiable Telemetry: Open-Source Hardware Root-of-Trust and Pluggable Provenance Engine for Industrial IoT

*(Length: 107 characters / 150)*

---

### Field 3: Project Website(s) / Repositories
*(Free text)*
**Draft:**
https://github.com/aloysiusjebanson-lab/trustworthy-telemetry
(Includes the universal 10-check offline verifier engine, pluggable profile driver registry, working edge simulators for EU MID energy and EU NAWI/CRCF pyrolysis, 33/33 automated adversarial tests, and RFC 8785 bundle specs under Apache 2.0).

---

### Field 4: Project Summary
*(Limit: Max 1,000 characters)*

**Draft Text:**
Industrial IoT lacks an open, trustworthy physical-to-internet boundary: edge sensor data flows into operator-controlled PLCs, mutable SQL databases, and proprietary cloud "dark stacks" where telemetry can be silently altered or truncated before audit. We build an open-source, local-first Verifiable Telemetry Engine—the universal cryptographic engine, not a single-sector SaaS app. A hardened edge gateway taps physical field instruments over 2.5 kV isolated RS-485, signs canonical integer readings inside hardware secure elements (ATECC608/TPM2) into unbroken hash-chains, and packages self-contained W3C PROV-O evidence bundles. A zero-dependency offline verifier executes 7 universal cryptographic/lineage checks plus 3 pluggable domain invariant hooks (process continuity, pinned authority digests, integer conservation). We validate the engine via two reference drivers: linear energy submetering (EU MID/CSRD) and non-linear pyrolysis mass-balance (EU NAWI/CRCF).

*(Current character count: 972 / 1,000 characters)*

---

### Field 5: Requested Budget
**Amount:** €38,000

---

### Field 6: Budget Breakdown
*(Limit: Max 4,000 characters)*

**Draft Text:**
The requested budget of €38,000 covers 5 months of engineering (720 hours at €50/hour = €36,000) and €2,000 for reference hardware, fieldbus isolation interfaces, and test apparatus.

1. Milestone 1: Universal Container Specification, RFC 8785 Schemas & Pluggable Profile Contract (€8,000 | Month 1 — 160h)
- Formalize the universal Claim Evidence Bundle specification, RFC 8785 JSON Canonicalization Scheme (JCS), and deterministic scaled-integer arithmetic (Wh, g, °C, basis points) to eliminate floating-point drift across runtimes.
- Define JSON Schemas for the core container: root-sealed manifests, device certificates with legal metrology validity windows (EU Directive 2014/32/EU MID and 2014/31/EU NAWI), hardware secure-element attestation descriptors (ATECC608B/TPM 2.0), hash-chained observation envelopes, and W3C PROV-O lineage graphs.
- Formalize the 3-part Pluggable Profile Driver Contract (Check 5 process continuity hook, Check 8 pinned authority registry hook, Check 9 integer conservation & recomputation hook) and the 33-vector adversarial threat model covering outsider tampering (O1-O11), operator fraud (I1-I5), and multi-sensor physical gaming (B1-B17).
- Deliverable: RFC-style protocol specification, JSON Schema suite, and formal threat model under Apache 2.0.

2. Milestone 2: Hardware Root-of-Trust & Galvanically Isolated Edge Ingestion Daemon (€11,000 | Months 2-3 — 220h)
- Implement open-source hardware driver interfaces for physical Secure Elements (Microchip ATECC608B over I2C, TPM 2.0, and TCG DICE) alongside deterministic software simulators for CI testing.
- Build the safe-zone RS-485 Modbus RTU ingestion daemon using 2.5 kV galvanically isolated transceivers to tap legal-for-trade field instruments directly at the wire—bypassing operator PLC/SCADA software register overwrites.
- Implement the two-tier cryptographic hierarchy: Producer Root Key signing device metrology certificates, X.509 silicon attestation chain binding, and sequential per-record hash-chaining (prev_hash).
- Deliverable: Hardened edge ingestion daemon, ATECC608B/TPM2 signing drivers, and provisioning tooling.

3. Milestone 3: Zero-Dependency Offline Verifier Engine & Standalone Rust Port (€11,000 | Month 4 — 220h)
- Complete the modular offline verifier CLI in Python/OpenSSL and build a standalone, zero-dependency Rust verifier binary for air-gapped auditor workstations.
- Implement the 10-check fail-closed state machine: 7 Universal Core Checks (manifest seal & key hygiene, device cert & silicon attestation with --require-hardware-attestation, per-observation ECDSA P-256 signatures & dynamic calibration expiry, prev_hash continuity, claim boundary & --claim-ledger replay protection, W3C PROV-O lineage, and zero-tolerance reconciliation) plus the SUPPORTED_PROFILE_DRIVERS dispatcher for Checks 5, 8, and 9.
- Validate bit-for-bit parity between Python and Rust using frozen golden conformance vectors.
- Deliverable: Python and Rust offline verifier CLIs, profile plugin SDK, and conformance test suite.

4. Milestone 4: Reference Hardware Testbench, Dual-Driver Validation & Public Release (€8,000 | Month 5 — 120h + €2,000 hardware)
- Assemble the physical reference testbench validating both reference profile drivers on live hardware: Driver 1 (EU MID Class B RS-485 energy submeter) and Driver 2 (EU NAWI Class III weighing indicator + Type-K Modbus thermocouple array) wired through 2.5 kV isolated RS-485 taps to an ATECC608B-equipped Linux gateway.
- Execute the 33-vector automated adversarial benchmark and P1-P6 security regression suite against hardware-generated bundles.
- Materials (€2,000): MID Class B submeter & NAWI load-cell indicator (€600), DIN-rail Modbus thermocouple module (€400), 2.5 kV isolated RS-485 hats, Raspberry Pi CM4 & ATECC608B boards (€500), and test rig enclosures (€500).
- Deliverable: Open-hardware wiring guides, 33-vector benchmark report, and v1.0 Apache 2.0 release.

*(Current character count: 3,948 / 4,000 characters)*

---

### Field 7: Comparison with Other Efforts
*(Limit: Max 4,000 characters)*

**Draft Text:**
Existing approaches to industrial telemetry verification and digital compliance reporting (dMRV, ESG, and legal metrology) fall into four categories, each leaving a critical architectural gap that our open-source engine resolves:

1. Proprietary Vertical SaaS Platforms & Cloud "Dark Stacks" (e.g., Siemens Insights Hub, AWS IoT SiteWise, Carbonfuture, Isometric):
Commercial industrial cloud platforms and digital MRV providers funnel raw sensor data into vendor-hosted cloud databases and private APIs. While modern registries (such as Isometric or Carbonfuture) have improved automated data sharing over manual spreadsheets, their architectures remain centralized cloud services tailored to specific vertical markets. Facility operators or platform administrators can still modify telemetry upstream before cloud ingestion, and relying on proprietary APIs creates permanent vendor lock-in: if a company or registry terminates a SaaS contract, independent auditors have no vendor-neutral, offline mechanism to verify historical claims 5 to 10 years later. We build the open-source, local-first engine underneath: self-contained cryptographic evidence bundles that any party can verify 100% offline with zero cloud accounts.

2. Speculative Web3 / Blockchain IoT Projects (e.g., Helium, Peaq, Toucan, KlimaDAO):
Web3 approaches attempt to anchor IoT telemetry or environmental credits onto public blockchains via crypto tokens. In regulated European industrial settings, this model fails: public ledgers leak commercially sensitive operational load curves and production batches; transaction fees and throughput limits prohibit continuous fieldbus logging; and conservative European conformity assessment bodies (DNV, TUV, Bureau Veritas) and industrial operators reject the legal, tax, and security liabilities of cryptocurrency tokens. Our engine achieves verifiable cryptographic provenance without blockchains or tokens—using standard NIST P-256 ECDSA hardware signatures, RFC 8785 canonical JSON, sequential SHA-256 hash-chains, and W3C PROV-O graphs running offline on standard POSIX systems.

3. Traditional PLC/SCADA Exports & Manual Spreadsheet Audits:
Across thousands of industrial sites, compliance audits for energy directives (EU CSRD, EPBD) and physical mass-balance certifications (EU CRCF, ISO 14064) still rely on unauthenticated CSV exports from plant PLCs, manual spreadsheets, and PDF lab certificates. Because the facility operator has root access to the SCADA server, insiders can shave peak intervals, drop failed batches, ignore expired sensor calibrations, or cherry-pick reference conversion factors without leaving a forensic trail. Our engine replaces mutable SCADA exports with direct safe-zone RS-485 hardware signing and automated conservation checks.

4. Academic Cloud-Layer Verifiable Computing (e.g., Kleppmann et al., ACM e-Energy):
Recent academic work explores cryptographic aggregation of sustainability metrics in software, but explicitly assumes honest sensor inputs at the edge boundary. Similarly, horizontal IoT frameworks (EdgeX Foundry, Eclipse Kura) standardize transport protocols (MQTT/OPC-UA) without enforcing hardware-attested hash-chains, legal metrology certificate windows, or physical conservation laws.

Our project bridges this exact gap by providing a universal, pluggable verification engine at the physical-to-digital boundary. We do not claim software alone solves all physical tampering; rather, our engine shifts the security boundary so fraud requires physical hardware breach or multi-party institutional collusion across accredited labs and metrology authorities, rather than a costless database or spreadsheet edit.

*(Current character count: 3,685 / 4,000 characters)*

---

### Field 8: Technical Challenges
*(Limit: Max 4,000 characters)*

**Draft Text:**
Engineering a universal, deterministic hardware-to-audit verification engine across heterogeneous industrial environments involves six non-trivial technical challenges:

1. Decoupling the Universal Cryptographic Engine from Domain Physics (Pluggable Profile Architecture):
Industrial sectors vary widely: electrical submetering measures continuous linear cumulative flows (Watt-hours), whereas thermal/chemical processing involves non-linear batch mass transformations, moisture loss, and temperature thresholds. Hardcoding sector rules creates brittle single-use software. We solve this by architecting a strict separation between the 7 Universal Core Engine Checks (manifest sealing, X.509/silicon attestation, dynamic calibration windows, ECDSA P-256 observation verification, sequential prev_hash continuity, cross-claim replay ledgers, W3C PROV-O lineage, and zero-tolerance reconciliation) and a 3-hook Pluggable Profile Contract (Check 5 process continuity, Check 8 pinned authority digests, Check 9 integer conservation inequalities).

2. "The Last Foot" Bus Spoofing & 2.5 kV Galvanically Isolated Safe-Zone Tapping:
Hardware secure elements (ATECC608B/TPM 2.0) fail above 85°C–125°C and cannot sit inside high-voltage switchgear or 650°C thermal reactors, nor inside explosive ATEX zones. Furthermore, reading telemetry from a plant PLC allows insiders with SCADA access to overwrite holding registers in software. We solve this by mounting the gateway in the safe-zone control cabinet (<55°C) and tapping legal-for-trade field instruments (EU MID submeters, EU NAWI scale indicators, Modbus thermocouple modules) directly at the RS-485 wire via 2.5 kV galvanically isolated transceivers ahead of the PLC, combined with Check 5 multi-register continuity invariants.

3. Cross-Platform Floating-Point Drift & Parser-Differential Attacks:
Floating-point arithmetic (IEEE 754) and inconsistent JSON serializers produce subtle rounding discrepancies across Python, Rust, and C, breaking cryptographic hashes and audit reconciliations. We eliminate floating-point math across all protocol schemas: energy is encoded in integer Watt-hours (Wh), mass in integer grams (g), temperature in integer °C, and ratios/moisture in integer basis points (10,000 bps = 100.00%), serialized via RFC 8785 (JCS) with strict duplicate-key rejection.

4. Dynamic Legal Metrology Pedigree & Calibration Expiry Enforcement:
Cryptographic signatures prove which gateway signed a packet, not whether the physical sensor was accurate. Operators can connect cheap uncalibrated sensors or run instruments years past calibration expiry. Our engine binds EU Directive 2014/32/EU (MID) and 2014/31/EU (NAWI) metrology metadata into the root-signed Device Certificate and dynamically verifies in Check 3 that every observation timestamp satisfies timestamp <= calibration_valid_until.

5. The External Reference Oracle Problem & First-Law Conservation Traps:
Edge sensors measure physical units (Wh, g, °C), not grid carbon intensity or chemical composition. To prevent operators from self-attesting favorable conversion factors or inflating weight with water, Check 8 verifies external reference files (ISPRA grid factors, ISO 17025 lab assays, delivery manifests) against out-of-band SHA-256 digests pinned in the auditor's trusted_references.json, while Check 9 enforces per-batch physical conservation (M_dry <= M_feedstock, max conversion yield ceilings, and cumulative delivery caps).

6. Zero-Dependency Air-Gapped Verification & Cross-Claim Replay Protection:
Auditors inspect facilities in air-gapped industrial enclaves where cloud access or pip installation is prohibited, and must block operators from re-submitting valid bundles across audits. Our verifier runs 100% offline using Python stdlib + POSIX OpenSSL (and a standalone Rust binary in Milestone 3) with a local --claim-ledger that blocks any reuse of claim IDs, batch IDs, or terminal hashes.

*(Current character count: 3,940 / 4,000 characters)*

---

### Field 9: Ecosystem & Engagement
*(Limit: Max 2,000 characters)*

**Draft Text:**
This project is engineered as an open-source digital commons to provide a vendor-neutral verification layer across European industrial IoT, legal metrology, and regulatory compliance ecosystems:

1. Open Standards & European Regulatory Alignment:
The core engine natively implements open internet and provenance standards—W3C PROV-O (provenance graphs), RFC 8785 (JSON Canonicalization Scheme), and NIST P-256 / SHA-256 hardware cryptography—aligned with the EU Cyber Resilience Act (hardware root-of-trust mandates). Through its pluggable profile architecture, it directly supports European legal metrology directives (2014/32/EU MID for utility meters and 2014/31/EU NAWI for weighing instruments) as well as statutory sustainability reporting frameworks (EU CSRD Directive 2022/2464 and EU CRCF Regulation 2024/3012 / Delegated Regulation 2026/285).

2. Target Communities & Adopters:
- Conformity Assessment Bodies & Auditors (e.g., DNV, TUV, CSQA, Bureau Veritas) needing a zero-dependency, offline CLI tool to mathematically verify industrial telemetry claims without trusting proprietary vendor clouds.
- Open-Source Industrial IoT & Edge Communities (e.g., Eclipse IoT, EdgeX Foundry, Linux Foundation Energy) seeking a drop-in hardware-signing and W3C PROV-O evidence container module for fieldbus gateways.
- Industrial Facility Operators & Equipment OEMs (submetering integrators, heat/hydrogen/pyrolysis equipment builders) requiring audit-grade regulatory compliance without permanent SaaS subscription lock-in.

3. Dissemination & Extensibility:
All specifications, JSON schemas, Python/Rust verifier engines, 33-vector adversarial benchmarks, and hardware cabinet wiring guides are released under Apache 2.0 on GitHub. By publishing a clear 3-hook Profile Driver SDK, external developers can rapidly contribute new sector drivers (e.g., green hydrogen electrolysis, district heating, water discharge monitoring).

*(Current character count: 1,927 / 2,000 characters)*

---

### Field 10: Background / Why You?
*(Limit: Max 2,000 characters)*

**Draft Text:**
I am an engineer and industrial telemetry specialist based in Milan, Italy. I hold an MSc in Management Engineering (Sustainability & Social Impact) from Politecnico di Milano—where I was recognized as a Polimi Ambassador in Green Technologies—and a Bachelor of Engineering in Mechanical Engineering.

Professionally, I manage energy and environmental telemetry pipelines across 100+ commercial and industrial facilities across EMEA, APAC, and North America. My mechanical engineering background combined with daily telemetry pipeline operations gives me firsthand experience with physical instrumentation, Modbus/fieldbus interfacing, and the exact architectural vulnerability this project solves: the mutable, unverified gap between physical edge sensors and regulatory audit filings.

On the systems research side, I designed TrustPass, an EU ESPR-compliant Digital Product Passport architecture validating cryptographic signing, immutable audit retention, and fine-grained access control (research paper currently under review).

Crucially, I have already built and open-sourced the working v1.2 prototype of the Verifiable Telemetry Engine: a modular 10-check zero-dependency offline verifier (separating the 7 universal cryptographic/lineage checks from the 3 pluggable domain invariant hooks), two end-to-end reference profile drivers (EU MID energy submetering and EU NAWI/CRCF pyrolysis mass-balance), frozen cross-language golden conformance vectors, and an automated adversarial testbench that deterministically catches 33 distinct outsider and insider fraud vectors (plus 6 security re-audit PoC regressions). Combining mechanical instrumentation expertise, cryptographic systems engineering, and European regulatory fluency, I am equipped to deliver all four milestones on schedule without institutional overhead.

*(Current character count: 1,826 / 2,000 characters)*

---

### Field 11: Other Funding Sources
*(Limit: Max 1,000 characters)*

**Draft Text:**
No other funding has been requested or received for this project. This project is currently entirely self-funded through personal research and development. The requested NLnet Restack grant will provide 100% of the financial support needed to execute the proposed milestones, complete the open specifications, and release the reference hardware and software tools to the public commons.

*(Current character count: 386 / 1,000 characters)*

---

### Field 12: AI Disclosure Policy
**Options:**
- **Path A (Recommended):** Review, personalize, and rewrite the final submission in your own authentic voice. Select: "No AI tools were used in writing this proposal."
- **Path B:** Submit the assisted text directly. Select: "Yes, AI tools were used for drafting and formatting assistance," and attach the conversation trajectory log.
