# Project Roadmap

Two tracks:
1. **Pre-grant sprint** (Sept 27 – Nov 3, 2026): finish and submit the NLnet Restack proposal.
2. **Grant execution** (8 months, €38,000): the four milestones in Field 6 of the application.

---

## Track 1: Pre-Grant Sprint

**Submission target:** November 1, 2026 · **Hard deadline:** November 3, 2026, 12:00 CET

| Phase | Window | Focus | Status |
|---|---|---|:---:|
| 1 — Foundation | Sept 27 – Oct 3 | Repository, licence, first simulator and verifier | ✅ |
| 2 — Drafting | Oct 4 – Oct 12 | First full application draft | ✅ |
| 3 — Proving | Oct 11 – Oct 19 | Hardened verifier, attack suites, golden vectors | ✅ |
| 4b — Review remediation | Oct 22 – Oct 23 | Shared core, bundle v1.3, attestation chain, JCS, docs and draft rewrite, CI | ✅ |
| 4 — Polish | Oct 23 – Oct 30 | Field 10 in own voice, AI disclosure, self-score, outside read, repo public, external contact | 🔵 |
| 5 — Submission | Oct 31 – Nov 1 | Portal entry and submission | ⬜ |

---

## Track 2: Grant Execution (8 months, ~22 h/week)

Starting point: working Python prototype (spec v1.3, shared verifier core, two profiles,
simulated secure-element PKI, 40-vector regression suite, golden vectors, CI).

### M1 — Specification v1.0, standards alignment, conformance suite
**Months 1–2 · 140 h · €7,000**
- RFC-style specification with JSON Schemas; integer-only RFC 8785 encoding.
- Map device evidence to IETF RATS roles (RFC 9334) and EAT claims; define chain heads as
  SCITT-compatible signed statements (COSE).
- Extend conformance suite (JCS, golden and negative vectors) and the threat model.
- **Deliverables:** tagged spec v1.0 + schemas; conformance suite in public CI; threat model.

### M2 — Secure-element provisioning and RS-485 ingestion daemon
**Months 2–4 · 200 h · €10,000**
- ATECC608B driver (I2C) and provisioning; verifier pins the vendor TrustFLEX/TNG root (same
  code path as the simulated CA). TPM 2.0 / DICE as a documented interface only.
- Modbus RTU daemon: interval/batch records, meter configuration and event-log registers in
  signed records, signed idle heartbeats.
- Gateway firmware digest in the device evidence; measured-boot options documented.
- **Deliverables:** daemon, driver, provisioning tooling; hardware bundles verifying against
  the vendor root.

### M3 — Rust verifier and transparency anchoring
**Months 4–6 · 220 h · €11,000**
- Standalone Rust verifier passing every golden and negative vector in CI.
- RFC 3161 timestamp verification on chain heads.
- Chain-head anchoring in a witnessed append-only log (C2SP tlog); offline inclusion proofs in
  both verifiers; cross-auditor double-claim detection.
- Independent security audit through NLnet's partner (Radically Open Security), if offered.
- **Deliverables:** Rust crate and binary; log client; 100% conformance; audit findings resolved.

### M4 — Hardware testbench, validation and release
**Months 7–8 · 160 h + €2,000 hardware · €10,000**
- Testbench: MID Class B submeter, NAWI weighing indicator, Modbus thermocouple module, gateway
  with ATECC608B.
- Regression suite against hardware-generated bundles; published results and known limits.
- Packaging / reproducible-build review with NLnet's partners where offered; wiring and
  deployment guides; v1.0 release; presentation to IETF SCITT WG and LF Energy / Eclipse IoT.
- **Materials:** submeter + indicator €600, thermocouple module €400, CM4 + ATECC608B + isolated
  RS-485 interface €500, enclosures and cabling €500.
- **Deliverables:** hardware validation report, guides, v1.0 release.

---

## Definition of Done (submission readiness)

1. All fields final and within limits (counted by script).
2. Field 10 rewritten in the applicant's own voice; Field 12 answered truthfully.
3. `make test` green locally and in CI; branch merged into `main`.
4. Repository public; README quickstart works on a fresh clone.
5. Self-score done; at least one outside read-through.
