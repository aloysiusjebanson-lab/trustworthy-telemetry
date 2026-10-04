# NLnet Restack Application — Task Tracker & Timeline

**Created:** September 27, 2026  
**Deadline:** November 3, 2026 — 12:00 CET (noon)  
**Days Remaining:** 37  
**Target Submission:** November 1, 2026 (2-day buffer)

---

## Status Legend

| Symbol | Meaning |
|:------:|---------|
| ⬜ | Not started |
| 🔵 | In progress |
| ✅ | Done |
| ⏭️ | Skipped / Deprioritized |

**Priority:** 🔴 Must-do (blocks submission) · 🟡 Should-do (strengthens application) · 🟢 Nice-to-have (bonus credibility)

---

## Phase 1: Foundation & Go Decision
**Sept 27 – Oct 3 (Week 1)**

| # | Task | Priority | Owner | Status | Due | Notes |
|---|------|----------|-------|--------|-----|-------|
| 1.1 | Make go/no-go decision on applying | 🔴 | User | ✅ | Sept 29 | GO decision confirmed — committed to apply |
| 1.2 | Create public GitHub repo (name, description, LICENSE) | 🔴 | Together | 🔵 | Sept 30 | Apache 2.0 license created locally; ready for remote repo |
| 1.3 | Write repo README.md (problem, architecture diagram, vision) | 🔴 | Together | ✅ | Oct 1 | Comprehensive technical README with 3-layer architecture & quickstart |
| 1.4 | Move `evidence_bundle_spec.md` into repo | 🟡 | User | ✅ | Sept 30 | Implemented in pipeline and verified by verifier CLI |
| 1.5 | Test & commit `mock_edge.py` (run it, fix issues) | 🟡 | Together | ✅ | Sept 29 | Zero-dependency OpenSSL NIST P-256 implemented & tested |
| 1.6 | Add `03_system/` architecture docs to repo | 🟢 | Together | ✅ | Oct 3 | System docs and formal threat model (Task 3.4) completed |

**Phase 1 Exit Criteria:** Public repo exists with README, spec, and working simulator. (Local repository fully staged & verified).

---

## Phase 2: Application Drafting
**Oct 4 – Oct 12 (Week 2)**

| # | Task | Priority | Owner | Status | Due | Notes |
|---|------|----------|-------|--------|-----|-------|
| 2.1 | Draft Field 3: Project Summary (≤1000 chars) | 🔴 | Together | ✅ | Oct 5 | Complete (969/1000 chars) focused on EU CRCF biochar dMRV |
| 2.2 | Draft Field 5: Budget Breakdown (≤4000 chars) | 🔴 | Together | ✅ | Oct 6 | Complete (3,960/4000 chars) across 4 milestones (€38,000) |
| 2.3 | Draft Field 7: Comparison with Other Efforts (≤4000 chars) | 🔴 | Together | ✅ | Oct 7 | Complete (3,410/4000 chars) vs SaaS dMRV/Web3/Spreadsheets |
| 2.4 | Draft Field 8: Technical Challenges (≤4000 chars) | 🔴 | Together | ✅ | Oct 8 | Complete (3,718/4000 chars) covering isolation, oracle bounds, scales |
| 2.5 | Draft Field 9: Ecosystem & Engagement (≤2000 chars) | 🔴 | Together | ✅ | Oct 9 | Complete (1,820/2000 chars) on CRCF, EBC, Puro standards & VVBs |
| 2.6 | Draft Field 10: Background / Why You (≤2000 chars) | 🔴 | **User** | ✅ | Oct 10 | Complete (1,587/2000 chars) with Polimi MSc & mechanical telemetry depth |
| 2.7 | Draft Field 11: Other Funding Sources (≤1000 chars) | 🟡 | Together | ✅ | Oct 10 | Complete (422/1000 chars) self-funded |
| 2.8 | Decide AI disclosure strategy (Path A or B) | 🔴 | User | ⬜ | Oct 10 | Path A (rewrite in own voice) vs Path B (disclose) |
| 2.9 | Choose project title (final) | 🟡 | Together | ✅ | Oct 8 | Final title selected (109 chars) |

**Phase 2 Exit Criteria:** All 8 application fields have first drafts with character counts.

---

## Phase 3: Technical Credibility Build
**Oct 11 – Oct 19 (Week 3)**

| # | Task | Priority | Owner | Status | Due | Notes |
|---|------|----------|-------|--------|-----|-------|
| 3.1 | Build basic `verify_bundle.py` CLI (signature check) | 🟡 | Together | ✅ | Sept 29 | Zero-dependency OpenSSL offline verifier built & working |
| 3.2 | End-to-end demo: mock_edge signs → verifier validates | 🟡 | Together | ✅ | Sept 29 | Verified local pipeline (sign -> audit pass) |
| 3.3 | Add adversarial test (corrupt 1 byte → verification fails) | 🟢 | Together | ✅ | Sept 30 | 7/7 attack vectors benchmarked & rejected by verifier |
| 3.4 | Add threat model doc to repo | 🟢 | Together | ✅ | Oct 4 | Formal threat model & security boundaries written in 03_system/threat_model.md |
| 3.5 | Record terminal demo (asciinema or screenshot) | 🟢 | User | ⬜ | Oct 19 | Visual proof for repo README |

**Phase 3 Exit Criteria:** Repo has working sign + verify flow. Reviewers can clone and run it.

---

## Phase 4: Review & Polish
**Oct 20 – Oct 27 (Week 4)**

| # | Task | Priority | Owner | Status | Due | Notes |
|---|------|----------|-------|--------|-----|-------|
| 4.1 | Self-score application against NLnet rubric (7.0 scale) | 🔴 | Together | ⬜ | Oct 21 | 40% relevance, 30% technical, 30% cost |
| 4.2 | Trim all fields to exact character limits | 🔴 | Together | ⬜ | Oct 22 | NLnet form enforces hard limits |
| 4.3 | Rewrite Field 10 (Background) — final personal version | 🔴 | **User** | ⬜ | Oct 23 | Must sound like you, not AI |
| 4.4 | External review — have someone else read it | 🟡 | User | ⬜ | Oct 25 | Even a non-technical friend catches jargon |
| 4.5 | Finalize repo README with architecture diagram | 🟡 | Together | ⬜ | Oct 26 | Clean, professional first impression |
| 4.6 | Add roadmap / post-grant plans to repo | 🟢 | Together | ⬜ | Oct 27 | Shows long-term thinking |

**Phase 4 Exit Criteria:** Application is submission-ready. All fields polished, within limits, and self-scored ≥5.0.

---

## Phase 5: Submission
**Oct 28 – Nov 1 (Final Week)**

| # | Task | Priority | Owner | Status | Due | Notes |
|---|------|----------|-------|--------|-----|-------|
| 5.1 | Final read-through of entire application | 🔴 | User | ⬜ | Oct 29 | Fresh eyes after a day away |
| 5.2 | Fill out NLnet web form with final text | 🔴 | User | ⬜ | Oct 31 | Copy-paste from our draft doc |
| 5.3 | Submit application on NLnet portal | 🔴 | User | ⬜ | **Nov 1** | 2-day buffer before deadline |
| 5.4 | Verify confirmation email received | 🔴 | User | ⬜ | Nov 1 | Screenshot / save confirmation |
| 5.5 | 🚨 HARD DEADLINE — Nov 3, 12:00 CET | — | — | — | **Nov 3** | Absolute last chance if something went wrong |

---

## Timeline Overview

```
Sep 27                    Oct 3      Oct 12     Oct 19     Oct 27  Nov 1  Nov 3
  │                         │          │          │          │       │      │
  ├─── Phase 1: Foundation ─┤          │          │          │       │      │
  │    Repo + Simulator     │          │          │          │       │      │
  │                         ├─ Phase 2 ┤          │          │       │      │
  │                         │  Drafts  │          │          │       │      │
  │                         │          ├─ Phase 3 ┤          │       │      │
  │                         │          │  Code    │          │       │      │
  │                         │          │          ├─ Phase 4 ┤       │      │
  │                         │          │          │  Polish  │       │      │
  │                         │          │          │          ├─ P5 ──┤      │
  │                         │          │          │          │Submit │      │
  ▼                         ▼          ▼          ▼          ▼       ▼      ▼
 TODAY                                                            TARGET  HARD
                                                                         DEADLINE
```

---

## Progress Summary

| Phase | Tasks | Done | Remaining |
|-------|:-----:|:----:|:---------:|
| 1. Foundation | 6 | 5 | 1 |
| 2. Drafting | 9 | 8 | 1 |
| 3. Code | 5 | 4 | 1 |
| 4. Polish | 6 | 0 | 6 |
| 5. Submit | 4 | 0 | 4 |
| **Total** | **30** | **17** | **13** |

---

## Notes & Decisions Log

| Date | Decision / Note |
|------|-----------------|
| Sept 27 | Tracker created. Awaiting go/no-go decision. |
| Sept 29 | **GO decision confirmed.** Committed to applying for NLnet Restack Open Call 1 (€38k target). |
| Sept 29 | **Local Technical Milestones Achieved:** Upgraded `mock_edge.py` and built `src/verifier/verify_bundle.py` using native OpenSSL (NIST P-256 ECDSA). Tested full local pipeline: 3 records generated, signed, verified offline, and tamper attacks (byte alteration + row deletion) verified caught. |
| Sept 30 | **Full Evidence Bundle & 8-Check Verifier Complete:** Built `src/pipeline/claim_generator.py` and upgraded `src/verifier/verify_bundle.py` to execute all 8 checks from `evidence_bundle_spec.md`. Created `src/attacks/tamper_bundle.py` covering all 4 attack vectors (all caught). Verified end-to-end execution. |
| Sept 30 | **5 Critical Security & Audit Hardening Fixes Applied:** (1) Hardened `.gitignore` to strictly ignore all private keys (`*_private_key.pem`, `src/device_simulator/keys/`) and build outputs (verified via `git check-ignore`); (2) Implemented `device_id` & `meter_id` consistency checks in verifier; (3) Added duplicate sequence / replay attack detection; (4) Added certificate validity window validation; (5) Enforced observation timestamp bounds (`valid_from <= ts <= valid_until`). Expanded attack test suite to 7/7 vectors (100% caught). |
| Sept 30 | **Three-Layer Security & Cryptographic Bundle Seal Complete:** (1) Added Company Root Key `bundle_seal` signing the manifest files dictionary in `claim_generator.py`; (2) Upgraded `verify_bundle.py` Check 1 to verify the bundle seal; (3) Upgraded Check 4 to verify W3C PROV-O entity hashes; (4) Generalized Check 5 to load country/activity from transformation metadata and cross-validate emission factor; (5) Upgraded Check 6 to cross-validate recomputed metrics against transformation declarations; (6) Added `--json` and `--json-out` machine-readable output; (7) Expanded attack suite to 8/8 vectors (Attack H: Re-hash seal bypass caught); (8) Updated Section 14 of strategy doc with 3-layer architecture. |
| Oct 4 | **Bulletproof v1.1 Architecture & Insider Fraud Immunity:** (1) Created `00_project/bulletproof_hardening_tracker.md`; (2) Updated `02_protocol/evidence_bundle_spec.md` to v1.1 (hash-chains, integer Wh, dual registers, 10-check standard); (3) Upgraded `mock_edge.py` with sequential hash-chaining, integer Wh, and Microchip ATECC608 attestation stub; (4) Created `src/verifier/trusted_references.json` with pinned authoritative dataset registry; (5) Upgraded `verify_bundle.py` to 10 zero-trust checks with fail-closed architecture, path traversal guards, and dual-register checks; (6) Built two dedicated attack runners: `outsider_attacks.py` (10/10 caught) and `insider_fraud_suite.py` (5/5 caught); (7) Completed formal Threat Model document in `03_system/threat_model.md` (Task 3.4). |
| Oct 4 | **Biochar Pyrolysis dMRV (v1.2) Multi-Profile Pivot & Test Suite Complete:** (1) Formally adopted Decision D010 pivoting NLnet proposal to high-durability carbon removals (EU CRCF / Puro.earth / EBC) while preserving energy submetering as secondary profile (Option A); (2) Rewrote all 8 fields of `00_project/nlnet_restack_application_draft.md` within character limits; (3) Upgraded protocol spec to v1.2 with integer gram stoichiometry, EU 2014/31/EU NAWI scale metrology, and physical mass-balance invariants; (4) Implemented `mock_biochar_edge.py` and `biochar_claim_generator.py`; (5) Unified `verify_bundle.py` into a dual-profile verifier passing 10/10 checks on both biochar and energy; (6) Built `src/attacks/biochar_attacks.py` testing 10 biochar fraud vectors (10/10 caught); (7) Froze Biochar Golden Test Vector (`04_experiments/golden_test_vector_biochar/`). |

