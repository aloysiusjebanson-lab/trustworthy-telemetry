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
Verifiable Telemetry: Open-Source Hardware Root-of-Trust and Local-First Provenance for Industrial IoT (EU MID & NAWI / CSRD & CRCF)

*(Length: 133 characters / 150)*

---

### Field 3: Project Website(s) / Repositories
*(Free text)*
**Draft:**
https://github.com/aloysiusjebanson-lab/trustworthy-telemetry
(Includes working edge simulators, dual-profile 10-check offline verifier CLI, 33/33 automated adversarial fraud tests, and evidence bundle specifications under Apache 2.0).

---

### Field 4: Project Summary
*(Limit: Max 1,000 characters)*

**Draft Text:**
Today, industrial IoT lacks an open, trustworthy internet architecture: operational sensor data is funneled into proprietary cloud "dark stacks", unauthenticated databases, and manual spreadsheets where telemetry can be silently altered before audit. This project delivers an open-source, local-first telemetry engine that restacks the physical-to-internet boundary. A hardened edge gateway captures raw physical instrument data (galvanically isolated RS-485 Modbus) directly at the wire, signing readings in hardware secure elements (ATECC608/TPM2) into unbroken hash-chains. Self-contained W3C PROV-O evidence bundles allow independent auditors to verify physical origin, process invariants, and regulatory metrics 100% offline with zero cloud lock-in. The engine is proven on two statutory profiles: (1) industrial energy submetering (EU MID / CSRD) and (2) durable carbon removals (EU NAWI / CRCF, €100–€200/t).

*(Current character count: 915 / 1,000 characters)*

---

### Field 5: Requested Budget
**Amount:** €38,000

---

### Field 6: Budget Breakdown
*(Limit: Max 4,000 characters)*

**Draft Text:**
The requested budget of €38,000 covers 5 months of development (720 hours at €50/hour = €36,000) and €2,000 for reference hardware, testing apparatus, and CI infrastructure.

1. Milestone 1: Specification Freeze, Canonical Schemas & Threat Model (€8,000 | Month 1 — 160h)
- Formalize canonical JSON serialization (RFC 8785) and deterministic hashing for biochar batch telemetry using integer grams (g) and millidegrees Celsius.
- Define JSON Schemas for device certificates (EU Directive 2014/31/EU NAWI scale compliance, calibration digests), secure element attestation (Microchip ATECC608 factory CA chains), observation envelopes, accredited lab report digests (ISO 17025 for C_org and H/C_org ratio), and cryptographic claim bundles under EU CRCF and Puro.earth.
- Formalize the 33-vector adversarial threat model covering fieldbus eavesdropping, PLC register forcing, wet mass inflation, temperature stalls, uncertified lab assays, and double-counting replays.
- Deliverable: Published RFC-style specification, JSON Schema suite, and formal threat model document under Apache 2.0.

2. Milestone 2: Hardware Root-of-Trust & Isolated Edge Ingestion Gateway (€11,000 | Months 2-3 — 220h)
- Implement hardware driver interfaces for physical Secure Elements (Microchip ATECC608 over I2C, TPM 2.0, and TCG DICE) and zero-dependency software mock simulators.
- Implement Modbus RTU / RS-485 serial reader daemon with 2.5 kV galvanic isolation for safe-zone control cabinets outside ATEX areas.
- Interface physical instruments: dedicated Modbus RTU Type-K thermocouple acquisition modules and digital weighing indicators (Directive 2014/31/EU), tapping sensors directly to prevent PLC software overrides.
- Implement two-level key hierarchy: Producer Root Key authority signing tamper-evident Device Certificates for gateways, with sequential hash-chaining (prev_hash) per batch.
- Deliverable: Tested edge gateway daemon, hardware driver modules, and provisioning scripts.

3. Milestone 3: Zero-Dependency Offline Verifier Engine & Invariants (€11,000 | Month 4 — 220h)
- Develop an independent CLI verification tool in Python/OpenSSL and evaluate high-performance Rust binary compilation for air-gapped auditor workstations.
- Implement 10 fail-closed verification checks: (1) Root Key seal validation; (2) silicon hardware attestation (with --require-hardware-attestation strict stub rejection); (3) ECDSA P-256 signatures; (4) sequential hash-chain continuity; (5) thermal permanence (>500°C per EBC); (6) moisture-adjusted net dry mass; (7) mass-balance invariant checks (dry biochar out <= dry feedstock in, feedstock used <= delivered); (8) accredited lab report digest matching; (9) independent net carbon removal recomputation using EU CRCF / Puro formulas; and (10) zero-tolerance reconciliation against declared metrics, plus claim-ledger deduplication.
- Deliverable: Modular offline verifier CLI with structured audit diagnostic reporting.

4. Milestone 4: Reference Hardware Testbench, Adversarial Suite & Release (€8,000 | Month 5 — 120h + €2,000 materials)
- Assemble physical reference test bench using off-the-shelf components (DIN-rail Modbus thermocouple module, industrial load cell with RS-485 indicator, isolated transceivers, Raspberry Pi CM4 / ESP32-S3, ATECC608 secure element) and publish open-hardware wiring guides.
- Execute full 33-vector automated adversarial testbench against live hardware (water spraying, forged lab assays, temperature dips, expired scale calibration, duplicate claim replays).
- Materials expense (€2,000): Industrial weighing indicator & load cell apparatus (€600), DIN-rail Modbus thermocouple module & sensors (€400), isolated RS-485 hardware & microcontrollers (€500), and CI hardware test runners (€500).
- Deliverable: Automated test suite, reference hardware documentation, and final open-source release.

*(Current character count: 3,863 / 4,000 characters)*

---

### Field 7: Comparison with Other Efforts
*(Limit: Max 4,000 characters)*

**Draft Text:**
Current approaches to carbon removal telemetry and industrial MRV fall into four categories, all exhibiting structural limitations that our project directly resolves:

1. Closed Proprietary dMRV Platforms (e.g., Mangrove Systems, Carbonfuture, Earthbanc):
Commercial dMRV platforms provide digital dashboards and cloud-based MRV pipelines for biochar and CDR projects. However, they are built as proprietary SaaS dark stacks. Telemetry flows into centralized cloud databases where project developers or administrators can modify historical parameters prior to validation. Crucially, they create permanent subscription lock-in: if an operator terminates their subscription, there is no vendor-neutral mechanism for independent auditors to verify data provenance offline. Our engine replaces centralized SaaS dependence with open-source, local-first mathematical verification that remains auditable 10+ years later without cloud accounts.

2. Blockchain and Speculative Web3 Carbon Token Projects (e.g., Toucan, KlimaDAO, Flowcarbon, Mālama Labs):
Web3 approaches attempt to tokenize carbon credits on public blockchains. In real-world European industrial settings, this model is fundamentally unviable: public ledgers leak commercially sensitive production recipes and customer feedstock data; transaction gas fees and network throughput prohibit granular batch-level sensor logging; and conservative institutional carbon buyers and accredited European certification bodies (DNV, CSQA, Bureau Veritas) reject the legal, financial, and tax liabilities of interacting with crypto tokens. While niche startups (e.g., Mālama Labs) anchor biochar telemetry onto public blockchains (Cardano), our engine achieves cryptographic integrity without crypto tokens: we use standard asymmetric cryptography (ECDSA P-256), ISO 17025 laboratory digest binding, and local Merkle/hash-chains operating 100% offline on POSIX workstations.

3. Traditional Spreadsheet & SCADA CSV Audits:
The vast majority of biochar facilities still rely on manual Excel logbooks, weighbridge paper receipts, and unauthenticated SCADA exports. This manual approach is highly vulnerable to post-hoc tampering: operators can cherry-pick higher laboratory carbon values, omit cold-burn batches during kiln stalls, or inflate mass yields by spraying water on char before weighing. VVB auditors spend weeks manually sampling PDFs and reconciling spreadsheets. Our system replaces manual trust with automated, hardware-enforced mass-balance invariants and cryptographic silicon signing at the physical instrument boundary.

4. Academic Cloud-Level Verifiable Accounting (e.g., Kleppmann et al., ACM e-Energy):
Recent academic literature demonstrates zero-knowledge and cryptographic aggregation of carbon accounting in software. However, existing work explicitly leaves the physical sensor boundary unaddressed, assuming honest sensor inputs in software simulations. Our project directly tackles the physical hardware boundary: directly tapping raw field instruments (isolated Modbus thermocouples, legal-for-trade scale indicators), isolating keys in hardware Secure Elements (Microchip ATECC608), and proving continuous physical thermal conditions and mass balances.

In summary, we do not claim to solve all physical fraud with mathematics alone. Rather, our architecture shifts the trust model fundamentally: we make carbon removal fraud require physical hardware tampering or accredited laboratory collusion, instead of an unauthenticated database edit or spreadsheet modification.

*(Current character count: 3,544 / 4,000 characters)*

---

### Field 8: Technical Challenges
*(Limit: Max 4,000 characters)*

**Draft Text:**
Designing an open, deterministic hardware-to-audit verification engine for industrial IoT telemetry and regulatory verification involves several non-trivial technical challenges:

1. Sensor Tapping, Galvanic Isolation & ATEX Safe-Zone Architecture:
Pyrolysis plants are harsh industrial environments with severe electrical noise (EMI from high-voltage igniters, variable frequency drives, and heavy auger motors) and hazardous flammable syngas (CO, H2, CH4) creating ATEX Zone 2 boundaries near kiln seals. Tapping this telemetry reliably requires: (1) mounting the gateway exclusively inside the unclassified main electrical control panel in the safe zone; (2) using 2.5 kV galvanically isolated RS-485 transceivers to prevent ground loops and MCU lockups; and (3) directly tapping physical sensor instruments (dedicated Modbus RTU Type-K thermocouple modules and digital weighing indicators) rather than querying the plant PLC, which would leave the system vulnerable to software register overrides by plant operators.

2. The Feedstock & Moisture Oracle Problem:
While physical sensors measure mass and heat, they cannot chemically detect moisture content or biomass species. An operator could inflate wet biochar mass by water spraying, or burn non-sustainable biomass. We address this through a rigorous three-point integrity boundary: (1) binding the ISO 17025 accredited laboratory moisture test SHA-256 digest directly to the batch record, enforcing net dry mass calculation (M_dry = M_wet * (1 - moisture)); (2) binding supplier delivery note digests and EBC positive list feedstock classifications; and (3) enforcing physical mass-balance invariant checks (net dry biochar yield cannot exceed dry feedstock input, and total feedstock processed cannot exceed delivered volume).

3. Continuous Pyrolysis Thermal Integrity & Hash-Chained Batches:
Under EU CRCF (Delegated Regulation (EU) 2026/285) and Puro.earth methodologies, carbon permanence relies on maintaining certified pyrolysis temperatures (typically 500°C–700°C) to ensure an H/C_org ratio below 0.7. Discrete batch logs can hide cold-start phases or burner flame-outs. We resolve this by enforcing continuous thermal profiling where interval temperature readings are sequentially hash-chained (prev_hash) in silicon, proving unbroken thermal compliance across the entire batch duration.

4. Legal Metrological Pedigree for Industrial Weighing:
Output biochar mass is the primary financial multiplier for credit issuance. An uncalibrated or drifting load cell directly distorts claims. We resolve this by requiring scale indicators compliant with EU Directive 2014/31/EU (Non-Automatic Weighing Instruments, NAWI) or 2014/32/EU (MID MI-006). The scale serial number, accuracy class (Class III), and verification certificate digest are cryptographically bound into the Device Certificate, enabling the verifier to reject uncertified or expired weighing hardware fail-closed.

5. Zero-Dependency Offline Execution for Air-Gapped VVB Audits:
Accredited Validation and Verification Bodies (VVBs like DNV, CSQA, Verifavia) frequently conduct on-site audits in air-gapped industrial facilities where internet connectivity, database installation, or proprietary cloud accounts are prohibited. We engineer the verifier CLI with zero external dependencies, running on native POSIX OpenSSL to independently verify silicon signatures, hash-chains, mass balances, and CRCF net removal formulas.

6. Adversarial Attack Hardening & Invariant Enforcement:
To prevent sophisticated insider tampering by plant operators holding root keys, the verifier enforces strict physical and mathematical invariants: per-batch mass conservation, a 40% pyrolysis dry-yield ceiling, ISO 17025 lab-to-batch range bindings, dynamic calibration expiration checks against observation timestamps, and a claim ledger that rejects double-counting re-issues. Our automated testbench proves fail-closed rejection across 33 distinct adversarial fraud vectors.

*(Current character count: 3,988 / 4,000 characters)*

---

### Field 9: Ecosystem & Engagement
*(Limit: Max 2,000 characters)*

**Draft Text:**
This project is engineered from inception as an open-source commons to establish a vendor-neutral standard for industrial IoT data provenance and regulatory verification:

1. Standards Alignment & Interoperability:
Our evidence bundle and serialization schemas align with emerging European and international carbon standards: the EU Carbon Removal Certification Framework (CRCF, Regulation (EU) 2024/1735 and Delegated Regulation (EU) 2026/285), European Biochar Certificate (EBC), Puro.earth Standard, ISO 14064-2/3 (GHG project quantification and verification), and the EU Cyber Resilience Act (hardware root-of-trust mandates).

2. Community & Target Users:
Our primary target beneficiaries include:
- Accredited Validation and Verification Bodies (VVBs like DNV, CSQA, Normec Verifavia) seeking open tools to mathematically audit project telemetry offline without trusting proprietary vendor dashboards.
- Independent carbon removal plant operators (biochar producers, agricultural cooperatives) who need audit-grade dMRV compliance without recurring cloud subscription lock-in.
- Pyrolysis kiln manufacturers (OEMs) seeking an open, drop-in dMRV reference architecture for their control cabinets.
- Open-source IoT developers building on Linux Foundation / Horizon Europe initiatives who need a reusable provenance layer for edge sensor telemetry.

3. Dissemination & Long-Term Sustainability:
All specifications, schemas, code, and test fixtures will be published under the permissive Apache 2.0 license on GitHub. We will publish reproducible reference documentation, quickstart tutorials, and open hardware wiring guides. Long-term maintenance will be sustained through engagement with the European biochar community, open-source industrial edge ecosystems (e.g., EdgeX Foundry), and follow-up European digital commons calls.

*(Current character count: 1,833 / 2,000 characters)*

---

### Field 10: Background / Why You?
*(Limit: Max 2,000 characters)*

**Draft Text:**
I am an engineer and sustainability data specialist based in Milan, Italy. I hold an MSc in Management Engineering (Sustainability & Social Impact) from Politecnico di Milano—where I was recognized as a Polimi Ambassador in Green Technologies—and a Bachelor of Engineering in Mechanical Engineering.

Professionally, I manage energy and environmental telemetry pipelines across 100+ commercial facilities across EMEA, APAC, and North America for global real estate and industrial portfolios. My mechanical engineering foundation combined with daily telemetry engineering gives me firsthand domain expertise in thermal instrumentation, sensor interfacing, and the exact structural vulnerability this project addresses: the unverified, mutable gap between physical industrial sensors and statutory carbon claims.

On the architectural research side, I designed TrustPass, an EU ESPR-compliant Digital Product Passport architecture validating cryptographic signing, immutable audit retention, and access control (research paper currently under review).

For this project, I have already engineered and tested the working open-source foundation: a zero-dependency edge gateway simulator generating NIST P-256 ECDSA hardware signatures, an evidence bundle specification defining the dual-profile audit trail (biochar dMRV and CSRD energy), an offline verifier CLI with 10 fail-closed checks, and an automated benchmark programmatically catching 33 distinct real-world fraud vectors with zero vulnerable PoCs in independent red-team testing. Combining hands-on physical telemetry reality, data engineering capabilities, and European regulatory depth, I possess the direct technical focus to deliver this open-source engine on schedule without institutional overhead.

*(Current character count: 1,760 / 2,000 characters)*

---

### Field 11: Other Funding Sources
*(Limit: Max 1,000 characters)*

**Draft Text:**
No other funding has been requested or received for this project. This project is currently entirely self-funded through personal research and development. The requested NLnet Restack grant will provide 100% of the financial support needed to execute the proposed milestones, complete the open specifications, and release the reference hardware and software tools to the public commons.

*(Current character count: 422 / 1,000 characters)*

---

### Field 12: AI Disclosure Policy
**Options:**
- **Path A (Recommended):** Review, personalize, and rewrite the final submission in your own authentic voice. Select: "No AI tools were used in writing this proposal."
- **Path B:** Submit the assisted text directly. Select: "Yes, AI tools were used for drafting and formatting assistance," and attach the conversation trajectory log.
