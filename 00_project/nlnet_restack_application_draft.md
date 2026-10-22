# NLnet Restack Application Draft (rev. Oct 22 — post-review)

**Fund:** Restack Fund (Call 1 — Horizon Europe Grant Agreement No. 101299072)  
**Closing Deadline:** November 3, 2026 at 12:00 CET (noon)  
**Applicant:** Individual (Resident in Italy)  
**Requested Amount:** €38,000 (720 h × €50 + €2,000 hardware, 8 months)

> **Revision note (Oct 22):** Rewritten after the external review
> (`nlnet_reviewer_feedback_claude.md`, tracker `review_remediation_tracker.md`): 8-month
> timeline, ATECC608B only, transparency log in scope, RATS/EAT/SCITT/Eichrecht framing, claims
> aligned with the v1.3 code, and limits stated openly. Character counts are computed by script.
> Field 10 must still be rewritten in your own voice (application tracker 4.3). The previous
> draft is in git history.

---

### Field 1: Have you been funded by NLnet before?
**Response:** No

---

### Field 2: Proposal Title

**Draft Title:**

Open Evidence Format and Hardware Root-of-Trust for Verifiable Sensor Telemetry

*(Character count: 79 / 150)*

---

### Field 3: Project Website(s) / Repositories

https://github.com/aloysiusjebanson-lab/trustworthy-telemetry
Working Python prototype under Apache 2.0: evidence bundle specification v1.3, offline verifier with a shared core and two pluggable domain profiles, simulated secure-element PKI, RFC 8785 and golden conformance vectors, and a 40-vector adversarial regression suite (make test).

---

### Field 4: Project Summary

**Draft Text:**

Compliance data from industrial sensors (energy, emissions, mass balances) crosses an untrusted boundary: readings pass through operator-controlled PLCs, databases and vendor clouds, where they can be altered, truncated or cherry-picked before audit without trace. We build an open, local-first evidence format and toolchain for that boundary. An edge gateway reads legal-for-trade instruments over RS-485, signs integer readings with a secure-element key whose manufacturer attestation auditors verify independently, and hash-chains them. Chain heads are anchored in an append-only transparency log, so backdating, truncation and double-claiming become detectable. Evidence ships as self-contained bundles with W3C PROV lineage; independent Python and Rust verifiers check them fully offline through a shared core plus pluggable domain profiles. Two reference profiles (MID energy submetering, NAWI/CRCF pyrolysis mass balance) demonstrate generality.

*(Character count: 952 / 1,000)*

---

### Field 5: Requested Budget
**Amount:** €38,000

---

### Field 6: Budget Breakdown

**Draft Text:**

€38,000 = 720 hours at €50/hour (€36,000) over 8 months (about 22 h/week alongside my employment) + €2,000 reference hardware. Starting point: a working Python prototype (spec v1.3, shared verifier core, two profiles, simulated secure-element PKI, 40-vector regression suite, golden vectors), so the grant funds hardware, standards alignment, a second implementation and release.

M1 – Specification v1.0, standards alignment, conformance suite (Months 1–2, 140 h, €7,000)
- Publish the bundle format as an RFC-style specification with JSON Schemas; integer-only RFC 8785 encoding.
- Map device evidence to IETF RATS roles (RFC 9334) and EAT claims; define how chain heads are expressed as SCITT-compatible signed statements (COSE).
- Extend the conformance suite (JCS vectors, golden bundles, negative vectors) and the threat model.
Deliverables: tagged spec v1.0 + schemas; conformance suite running in public CI; threat model document.

M2 – Secure-element provisioning and RS-485 ingestion daemon (Months 2–4, 200 h, €10,000)
- ATECC608B driver (I2C) and provisioning tool; verifier accepts the vendor's TrustFLEX/TNG root as pinned manufacturer CA (same code path as today's simulated CA). TPM 2.0/DICE kept as a documented interface, not implemented.
- Modbus RTU ingestion daemon: interval/batch records, meter configuration and event-log registers captured into signed records, signed idle heartbeats.
- Gateway firmware digest recorded in the device evidence; measured-boot options documented.
Deliverables: daemon + driver + provisioning tooling; bundles from real hardware verifying against the vendor root.

M3 – Rust verifier and transparency anchoring (Months 4–6, 220 h, €11,000)
- Standalone zero-dependency Rust verifier implementing the same checks; must pass every golden and negative vector in CI.
- Trusted time: RFC 3161 timestamp verification on chain heads.
- Chain-head anchoring in a witnessed append-only log (C2SP tlog format); offline inclusion-proof verification in both verifiers; cross-auditor double-claim detection.
Deliverables: Rust crate and binary; log client; both verifiers passing 100% of the conformance suite.

M4 – Hardware testbench, validation and release (Months 7–8, 160 h, €8,000 + €2,000 hardware)
- Testbench: MID Class B submeter, NAWI weighing indicator, Modbus thermocouple module, gateway with ATECC608B.
- Run the regression suite against hardware-generated bundles; publish results and known limitations.
- Wiring and deployment guides, packaging, v1.0 release; present the work to the IETF SCITT WG and LF Energy / Eclipse IoT communities.
- Materials: submeter + weighing indicator €600, thermocouple module €400, CM4 gateway + ATECC608B + isolated RS-485 interface €500, enclosures and cabling €500.
Deliverables: hardware validation report, guides, v1.0 release.

*(Character count: 2,823 / 4,000)*

---

### Field 7: Comparison with Other Efforts

**Draft Text:**

1. Signed metering and attestation prior art. German Eichrecht already requires signed meter readings for EV charging (OCMF, verified offline by the open-source S.A.F.E. Transparenzsoftware), and smart-meter gateways sign readings under their own national framework. IETF RATS (RFC 9334) and EAT standardise device attestation; IETF SCITT standardises transparency-logged signed statements; Sigstore, in-toto and C2PA apply the same ideas to software and media. These prove the building blocks are sound, but each covers one meter type or one layer. We reuse them rather than reinvent: attestation follows RATS roles, chain heads become SCITT-compatible statements, and our contribution is the missing open layer joining fieldbus capture, legal-metrology pedigree, lineage and domain conservation checks into one verifiable bundle.

2. Industrial cloud and dMRV platforms. Industrial IoT clouds and digital MRV services move data into vendor-hosted databases and private APIs. Data can still be changed before ingestion, and verification depends on the vendor remaining available. Our bundles are self-contained and verifiable offline by anyone, years later, without an account; platforms could adopt the format instead of competing with it.

3. Blockchain approaches. Public ledgers expose commercially sensitive load and production data and add token, fee and legal questions that regulated operators avoid. We obtain append-only guarantees from transparency logs with witnesses, without tokens or consensus.

4. PLC/SCADA exports and spreadsheets. Most audits still rely on unauthenticated CSV exports and PDF certificates from systems the operator administers, so intervals and batches can be dropped and factors cherry-picked without trace.

5. Edge frameworks (EdgeX Foundry, Eclipse Kura). They standardise transport (MQTT, OPC UA) but do not provide hardware-attested records, metrology binding or audit verification. Our gateway component is designed to plug into them.

What we do not claim: cryptography cannot prove what was put on a scale, and a genuine secure element signs whatever its gateway sends. The engine removes costless, traceless edits: falsifying a verified claim requires intervention at the instruments or gateway hardware, or the cooperation of parties the operator does not control (chip manufacturer, accredited lab, auditor, log witnesses).

*(Character count: 2,372 / 4,000)*

---

### Field 8: Technical Challenges

**Draft Text:**

1. Attestation the operator cannot forge. The operator holds the producer key, so a device certificate signed by the producer proves nothing about hardware. The verifier therefore requires an X.509 chain from the device key to a manufacturer root pinned by the auditor (implemented with a clearly labelled simulated CA; M2 replaces it with the real ATECC608B vendor root). Remaining gap: a genuine chip signs whatever the gateway firmware sends, so M2 adds firmware evidence and documents measured boot; our tests already model the insider who re-signs data through the device.

2. An unauthenticated fieldbus. RS-485/Modbus has no authentication: a device on the bus can impersonate a meter, and many meters expose writable scaling registers. Reading instruments directly removes PLC/SCADA software from the path but does not authenticate them. We capture configuration and event-log registers into signed records, rely on metrology seals, and state these limits in the threat model rather than claim to solve them.

3. Time and withheld data. Timestamps come from an operator-controlled clock, and a gateway can be switched off for a bad period. The verifier already enforces a maximum gap between records and auditor-mandated reporting periods; M3 adds RFC 3161 timestamps and chain heads in a witnessed transparency log, which also detects the same evidence being claimed with two auditors.

4. Deterministic encoding across languages. Hashes and signatures must match bit for bit in Python and Rust. We use RFC 8785 restricted to integers (Wh, g, °C, basis points, mg CO2e/kWh), reject floats and duplicate keys (parser-differential attacks), and gate both implementations on shared conformance vectors transcribed from the RFC plus golden bundles.

5. A generic core with domain plug-ins. Energy is linear and cumulative; pyrolysis is batch-based with moisture loss and thermal thresholds. The shared core runs every domain-agnostic check once; a profile declares required instruments and implements three hooks (process continuity, pinned references, integer recomputation) that receive verified records and return errors or integer metrics. Profiles cannot override core checks, and the core reconciles their metrics against the claim exactly.

6. Reference data and physics. Sensors measure Wh and grams, not grid intensity or carbon content. Reference datasets are accepted only if their hash and dataset type are pinned by the auditor, and conservation inequalities (per-batch yield caps, delivered-feedstock caps) bound crude inflation; they cannot prove honest sampling, which remains an institutional control.

*(Character count: 2,623 / 4,000)*

---

### Field 9: Ecosystem & Engagement

**Draft Text:**

Standards. The project builds on and feeds back into open standards: RFC 8785 (canonical JSON), IETF RATS/EAT (attestation roles and claims), IETF SCITT and C2SP transparency logs (append-only signed statements), W3C PROV (lineage) and X.509. It supports secure-by-design obligations under the EU Cyber Resilience Act, and its profiles encode EU legal metrology (MID 2014/32/EU, NAWI 2014/31/EU) and reporting frameworks (CSRD, CRCF) as data rather than vendor logic. We will share the use case and conformance vectors with the IETF SCITT working group.

Who uses it.
- Auditors and conformity assessment bodies: an offline verifier they can run without trusting a vendor platform or installing packages.
- Open edge communities (Eclipse IoT, EdgeX Foundry, LF Energy): a gateway signing component and evidence format for fieldbus devices.
- Operators and equipment makers (submetering integrators, heat, hydrogen or pyrolysis plant builders): audit-grade evidence without SaaS lock-in.

Dissemination. Specification, schemas, both verifiers, simulators, conformance vectors, regression suite and hardware guides are published under Apache 2.0. A profile is a small module with three documented hooks, so others can add sectors (district heating, electrolysis, water discharge) without touching the core. We would welcome NLnet partner support (security review, packaging) where available.

*(Character count: 1,389 / 2,000)*

---

### Field 10: Background / Why You? (rewrite in your own voice before submitting)

**Draft Text:**

I am an engineer based in Milan, Italy, with an MSc in Management Engineering (Sustainability & Social Impact) from Politecnico di Milano, where I was a Polimi Ambassador in Green Technologies, and a Bachelor's in Mechanical Engineering.

Professionally I run energy and environmental telemetry pipelines for 100+ commercial and industrial sites across EMEA, APAC and North America. That work puts me daily at the gap this project addresses: meter and fieldbus data that changes hands several times before it reaches an audit, with no way for the auditor to check it.

On the research side I designed TrustPass, a Digital Product Passport architecture for the EU ESPR covering signed records, audit retention and access control (paper under review).

I have already built the working prototype: the evidence bundle specification (v1.3), an offline verifier with a shared core and two domain profiles, X.509 attestation against a pinned manufacturer CA (simulated for now), RFC 8785 conformance vectors, golden bundles for a second implementation, and a 40-vector regression suite modelling both outsiders and a dishonest operator. Writing that suite is also how I found the limits stated in this proposal.

The work is done independently, in my own time and on my own equipment; my employer has no IP claim on it. I plan about 22 hours per week over the 8 months.

*(Character count: 1,363 / 2,000)*

---

### Field 11: Other Funding Sources

**Draft Text:**

No other funding has been requested or received for this project. It has been self-funded so far. The NLnet Restack grant would be the sole funding for the milestones described, and all results will be released under Apache 2.0.

*(Character count: 228 / 1,000)*

---

### Field 12: AI Disclosure Policy
**Open decision (application tracker 2.8):**
- **Path A:** Rewrite the final submission in your own words and answer accordingly.
- **Path B:** Disclose that AI tools assisted drafting.
Answer truthfully for whichever text you actually submit.
