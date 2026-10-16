# Project Status

**Current Phase:** Phase 3 Complete / Entering Phase 4 — Pre-Submission Review & Polish  
**Target Program:** NLnet Restack Open Call 1 (Horizon Europe GA No. 101299072)  
**Submission Target:** November 1, 2026 (16 days remaining / 2-day buffer)  
**Hard Portal Deadline:** November 3, 2026 — 12:00 CET (18 days remaining)  
**Protocol Frozen:** Yes (Specification v1.2 — Dual-Profile: Biochar dMRV primary, Energy submetering secondary)  
**Hardware Root-of-Trust:** Architected (Microchip ATECC608 / TPM 2.0 / TCG DICE; `--require-hardware-attestation` flag active; physical CA chain scheduled for M2/M4)  
**Grant Target:** €38,000 across 4 milestones over 5 months  
**Current Date:** October 16, 2026  

---

## Executive Summary of Technical State

1. **Dual-Profile Verifier Engine (`src/verifier/verify_bundle.py`):**
   - 10 zero-trust fail-closed verification checks fully implemented and hardened against insider/outsider PoCs (`poc_exploits.py` 0/6 vulnerable).
   - Zero external pip dependencies; native POSIX OpenSSL 3.x and Python standard library only.
   - Evaluates both Biochar dMRV (`biochar_bundle/`) and Energy Submetering (`claim_bundle/`).
   - Enforces public-key-to-certificate binding, derived `device_id`, dynamic scale/meter calibration validity vs. observation timestamps, per-batch mass conservation, 40% max dry yield ceiling, auditor claim ledger double-counting rejection (`--claim-ledger`), and strict hardware attestation enforcement (`--require-hardware-attestation`).

2. **Adversarial Benchmark Suite (`src/attacks/`):**
   - **33 / 33 fraud vectors detected and rejected fail-closed** (via strict `harness.py` & self-contained `fixtures.py` with baseline-PASS assertions):
     - Biochar dMRV suite (`biochar_attacks.py`): **17/17 caught** (water spraying, cold-kiln undercooking, forged lab assays, quota exhaustion, dropped batches, non-certified scales, software key forgery, uncertified feedstock, claim inflation, revoked gateways, private key leakage, cert-key binding break, expired scale calibration, claim replay double-counting, per-batch mass violation, 95% dry yield violation, and strict attestation stub rejection).
     - Outsider suite (`outsider_attacks.py`): **11/11 caught** (falsified readings, rogue keys, dropped records, replay attacks, device ID swap, timestamp breach, re-hashed manifest bypass, path traversal, unmanifested files, revoked gateways, private key injection).
     - Insider corporate suite (`insider_fraud_suite.py`): **5/5 caught** (factor greenwashing, dual-register shaving, period truncation, unattested software keys, telemetry splicing).

3. **Conformance Golden Test Vectors (`04_experiments/`):**
   - Refrozen immutable test vectors for Biochar (`golden_test_vector_biochar/`) and Energy (`golden_test_vector/`) with zero private keys on disk or in git.
   - Serves as the cross-language benchmark for Milestone 3 (Rust verifier engine).

4. **Grant Application Draft (`00_project/nlnet_restack_application_draft.md`):**
   - All 8 application fields drafted and audited within character limits.
   - Reframed under the NLnet "Restack the Internet" mandate: eliminating proprietary cloud dark stacks, replacing them with open-source, local-first hardware roots-of-trust and air-gapped cryptographic verification.
   - Primary proving ground: high-durability carbon removals under EU CRCF (€110–€180/t).

---

## Active Milestone Progress

| Item | Target | Status | Notes |
|---|---|:---:|---|
| Phase 1: Foundation & Git | Oct 4 | ✅ Done | Private GitHub repo synchronized; Apache 2.0 license; README v1.2 |
| Phase 2: Application Drafting | Oct 12 | 🔵 90% | 8/8 fields drafted within character limits; Task 2.8 (AI disclosure decision) pending |
| Phase 3: Technical Proving | Oct 19 | 🔵 95% | Hardened verifier, self-contained fixtures, and 33/33 attack suites done; Task 3.5 (terminal demo) pending |
| Phase 4: Polish & Self-Score | Oct 20–27 | ⬜ Pending | Self-score against NLnet 7.0 rubric; finalize Field 10 personal voice; make repo public before submission |
| Phase 5: Portal Submission | Nov 1 | ⬜ Pending | Submit on NLnet portal with 2-day buffer before Nov 3 12:00 CET |

---

## Risk Register & Mitigations

| Risk | Probability | Severity | Mitigation Strategy |
|---|:---:|:---:|---|
| **NLnet Scope Framing Disconnect** | Low | High | Proposal reframed to lead with Open Internet Stack / local-first architecture (eliminating cloud SaaS dark stacks) with biochar and CSRD as high-stakes proving grounds. |
| **Physical Sensor Spoofing (Analog Boundary)** | Medium | High | Addressed via safe-zone RS-485 tapping, multi-sensor thermal fusion, ISO 17025 accredited laboratory binding, and mass-conservation thermodynamic invariants ($M_{\text{dry}} \le M_{\text{feedstock}}$). |
| **Portal Submission Glitches / Server Overload** | Medium | Critical | Target submission set to November 1, 2026 (48 hours ahead of the November 3, 12:00 CET hard deadline). |
| **Dependency / Bitrot Risk** | Zero | High | Architecture enforces zero external pip dependencies; native OpenSSL 3.x ensures 10+ year forward auditability. |

---

## Next Immediate Actions

1. **Task 2.8:** Decide AI disclosure strategy (Path A vs Path B).
2. **Task 3.5:** Record 90-second terminal demo screencast (or clean terminal output capture) by October 19.
3. **Phase 4 (Oct 20–27):** Self-score proposal against NLnet 7.0 evaluation rubric, polish Field 10 in authentic personal voice, and switch GitHub repo visibility from Private to Public prior to portal submission.
