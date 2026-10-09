# Project Master Roadmap

This document outlines the dual-track roadmap for **Verifiable Telemetry**:
1. **Track 1: Pre-Grant Application Sprint** (Sept 27 – Nov 3, 2026) — Finalizing and submitting the NLnet Restack Open Call 1 proposal.
2. **Track 2: Post-Award Project Execution Roadmap** (Months 1–5, €38,000) — Executing the 4 grant deliverables upon award.

---

## Track 1: Pre-Grant Application Sprint (Sept 27 – Nov 3, 2026)

**Submission Target:** November 1, 2026 (23 days remaining / 2-day buffer)  
**Hard Portal Deadline:** November 3, 2026 at 12:00 CET (25 days remaining)  

```
Sep 27         Oct 4          Oct 10         Oct 19         Oct 27    Nov 1   Nov 3
  │              │              │              │              │         │       │
  ├─ Phase 1 ────┤              │              │              │         │       │
  │  Foundation  │              │              │              │         │       │
  │  (Complete)  ├─ Phase 2 ────┤              │              │         │       │
  │              │  Drafting    │              │              │         │       │
  │              │  (90% Done)  ├─ Phase 3 ────┤              │         │       │
  │              │              │  Tech Demo   │              │         │       │
  │              │              │  (80% Done)  ├─ Phase 4 ────┤         │       │
  │              │              │              │  Polish &    │         │       │
  │              │              │              │  Self-Score  ├─ P5 ────┤       │
  │              │              │              │              │  Submit │       │
  ▼              ▼              ▼              ▼              ▼         ▼       ▼
                                                                     TARGET  HARD
                                                                    (2d buf) DEADLINE
```

### Phase Breakdown & Key Dates

| Phase | Window | Focus | Key Deliverables | Status |
|---|---|---|---|:---:|
| **Phase 1: Foundation** | Sept 27 – Oct 3 | Repository & Core Proving | GitHub repository initialized, Apache 2.0 license, initial OpenSSL simulator and verifier | ✅ Complete |
| **Phase 2: Drafting** | Oct 4 – Oct 12 | NLnet Restack Proposal | All 8 fields drafted within character limits; Restack framing aligned; Title selected | 🔵 90% (Task 2.8 due Oct 10) |
| **Phase 3: Proving** | Oct 11 – Oct 19 | Dual-Profile Benchmark | 10-check verifier, 25/25 attack suite, golden vectors frozen; Terminal demo recording (Task 3.5 due Oct 19) | 🔵 80% (Demo pending) |
| **Phase 4: Polish** | Oct 20 – Oct 27 | Review & Optimization | Self-score against NLnet 7.0 rubric; finalize Field 10 personal voice; peer review | ⬜ Scheduled |
| **Phase 5: Submission** | Oct 28 – Nov 1 | Portal Upload & Buffer | Form input, final character audit, submission on portal 48h before deadline | ⬜ Scheduled |

---

## Track 2: NLnet Restack Execution Roadmap (Months 1–5, €38,000)

Upon award from the NLnet Restack Fund (GA No. 101299072), the project will execute across four structured milestones over 5 months (720 engineering hours + €2,000 hardware budget):

### Milestone 1: Specification Freeze, Canonical Schemas & Threat Model
* **Allocation:** €8,000 | Month 1 (160h)
* **Scope:**
  - Formalize RFC 8785 canonical JSON serialization schemas for industrial biochar batch telemetry (integer grams, millidegrees Celsius).
  - Specify JSON Schemas for device certificates (EU Directive 2014/31/EU NAWI legal scale compliance, calibration records), ATECC608 factory CA attestation chains, observation envelopes, and ISO 17025 accredited laboratory assays ($^{14}\text{C}$ radiocarbon and ICP-MS).
  - Formalize the 25-vector adversarial threat model document under Apache 2.0.
* **Deliverable:** Published RFC-style specification, complete JSON Schema suite, and formal Threat Model document.

### Milestone 2: Hardware Root-of-Trust & Isolated Edge Ingestion Gateway
* **Allocation:** €11,000 | Months 2–3 (220h)
* **Scope:**
  - Implement production hardware driver interfaces for physical Secure Elements (Microchip ATECC608 over I2C, TPM 2.0, and TCG DICE for MCUs).
  - Implement Modbus RTU / RS-485 serial reader daemon with 2.5 kV galvanic isolation for safe-zone control cabinets.
  - Interface physical instruments directly (DIN-rail thermocouple acquisition modules, digital legal-for-trade weighing indicators), bypassing plant PLC software registers.
  - Implement dual-key hierarchy with sequential hash-chaining (`prev_hash`) per batch.
* **Deliverable:** Production edge gateway daemon, hardware drivers, and cryptographic provisioning scripts.

### Milestone 3: Zero-Dependency Offline Verifier Engine & Cross-Language Determinism
* **Allocation:** €11,000 | Month 4 (220h)
* **Scope:**
  - Implement a high-performance, standalone verifier in **Rust** as a zero-dependency statically compiled binary (`cargo build --release`), complementing the Python/OpenSSL prototype.
  - Implement 10 fail-closed checks: (1) Root seal validation; (2) Silicon hardware attestation; (3) ECDSA P-256 signatures; (4) Hash-chain continuity; (5) Thermal permanence ($T_{\min} \ge 500^\circ\text{C}$); (6) Net dry mass calculation; (7) Mass-balance conservation ($M_{\text{dry}} \le M_{\text{feedstock}}$); (8) Accredited lab report digest matching; (9) Independent net carbon removal recomputation; (10) Zero-tolerance claim reconciliation.
  - Verify 100% byte-for-byte and mathematical parity between Python and Rust engines using frozen golden test vectors.
* **Deliverable:** Cross-platform Rust verifier binary, Python CLI, and structured JSON audit reporting engine.

### Milestone 4: Reference Hardware Testbench, Adversarial Benchmark & Public Release
* **Allocation:** €8,000 (€6,000 labor / 120h + €2,000 materials) | Month 5
* **Scope:**
  - Build physical reference desk testbench (~€150–€250 component cost): DIN-rail Modbus thermocouple module, industrial load cell with RS-485 indicator, 2.5 kV isolated transceivers, Raspberry Pi CM4 / ESP32-S3 boards, Microchip ATECC608 secure element.
  - Publish open-hardware wiring diagrams, bill of materials (BOM), and enclosure blueprints.
  - Run the full 25-vector adversarial testbench against live hardware.
  - Complete end-to-end documentation, quickstart tutorials, and open-source release under Apache 2.0.
* **Deliverable:** Automated adversarial benchmark suite, open-hardware reference guide, and final public release.

---

## Definition of Done (Submission Readiness)

The grant application is ready for final portal submission when:
1. All 8 proposal fields are drafted, formatted, and strictly within character limits.
2. Field 10 is reviewed and finalized in the applicant's authentic personal voice.
3. The AI disclosure strategy (Path A or B) is formally selected.
4. The proposal self-scores $\ge 5.0 / 7.0$ against the NLnet evaluation rubric.
5. All 25 adversarial attack test vectors pass fail-closed validation.
6. The repository is clean, well-documented, and ready to be made public.
