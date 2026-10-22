# Review Remediation Tracker — Oct 22 External Review

**Source:** `00_project/nlnet_reviewer_feedback_claude.md`  
**Created:** October 22, 2026  
**Goal:** Close every gap the review raised before the target submission on **Nov 1, 2026**. Either fix the code or reword the claim so the text matches the repo.  
**Parent tracker:** `00_project/nlnet_application_tracker.md` (Phase 4b)

---

## Status Legend

| Symbol | Meaning |
|:------:|---------|
| ⬜ | Not started |
| 🔵 | In progress |
| ✅ | Done |
| ⏭️ | Skipped / Deprioritized (reason in Notes) |
| ❓ | Waiting on a user decision |

**Priority:** 🔴 Must-do (blocks submission) · 🟡 Should-do · 🟢 Nice-to-have  
**Type:** `Code` (change in `src/`) · `Text` (application draft / docs) · `Decision` (user call) · `Repo` (hygiene)

---

## Decisions Needed First

These decisions determine how several items below are resolved.

| # | Decision | Affects | Status | Answer |
|---|----------|---------|--------|--------|
| D1 | Who holds the Producer Root Key, and is the device trust anchor the manufacturer CA, pinned by the auditor? | A1, A2, B1 | ✅ | **Manufacturer CA, pinned by the auditor**, separate from the producer key |
| D2 | Add a public transparency log (C2SP tlog / SCITT-compatible) to the proposal scope? | B2, B3, B8, C1, E1 | ✅ | **Yes, in scope** |
| D3 | Stretch the timeline from 5 months to 8–9 months (same hours and budget)? | D1, D2 | ✅ | **8 months** (~22 h/week) |
| D4 | Choose one secure element for M2 (ATECC608B recommended); TPM2 and DICE become an interface only | D3 | ✅ | **ATECC608B only**; TPM2/DICE as an interface |
| D5 | Is there any employer IP claim or conflict? (confirm, and mention it in Field 10/11 if relevant) | D2 | ✅ | **No employer IP claim or conflict**: conceived and built independently, personal time and equipment, Apache 2.0. Use in Field 10/11 |

---

## A. Code vs. Claims (Review §0) — fix first

| # | Item | Pri | Type | Status | Where | Notes / Evidence of done |
|---|------|-----|------|--------|-------|--------------------------|
| A1 | Real attestation verification: check the device key against a cert chain rooted in a **manufacturer CA pinned by the auditor** (separate from the producer key), instead of trusting plain-text `attestation_mode` / `attestation_status` strings | 🔴 | Code | ✅ | `verify_bundle.py:357-367`, `:1078-1090` | Oct 22: Check 2 validates the secure-element X.509 chain (`openssl verify -x509_strict`) against the **auditor-supplied `--manufacturer-ca`** and requires the attested key == `device/public_key.pem`; `device_id` derived from the attested key. `--require-hardware-attestation` and the JSON attestation file removed. Vectors: **B17** producer-forged CA chain, **B7** genuine chain of a different chip, **I4** chain removed |
| A2 | Remove the misleading attestation fixture: no real vendor CA named as signer; label it clearly as a simulation | 🔴 | Code | ✅ | `*/device/hardware_attestation.json`, `mock_edge.py`, `mock_biochar_edge.py` | Oct 22: simulator now has a real (simulated) PKI, `O=SIMULATED Secure Element Manufacturer (TEST ONLY)`; report says `SIMULATED_MANUFACTURER_CA` + warning. Also replaced fabricated lab/supplier records that named real organisations (Eurofins, DAkkS id) with illustrative fixtures |
| A3 | Real shared core: extract the 7 universal checks into one implementation; profiles provide only the hooks for Checks 5, 8 and 9 | 🔴 | Code | ✅ | `verify_biochar_bundle` `:147`, `verify_energy_bundle` `:890` | Oct 22: `src/verifier/core.py` implements Checks 0–4, 6, 7, 10 once; `profiles/energy_submetering.py` and `profiles/biochar_pyrolysis.py` contain only instrument requirements + hooks 5/8/9. Unified bundle format **v1.3** (one envelope, claim and manifest layout for all profiles). Check 7 is now a real PROV graph check (completeness, acyclicity, claim ancestry, `wasInformedBy`); Check 10 is generic exact-match |
| A4 | The auditor chooses the profile: require `--profile` (or match it against the auditor's config); refuse a bundle whose declared profile differs; no default to energy | 🔴 | Code | ✅ | `verify_bundle()` dispatcher | Oct 22: `--profile` is mandatory; `claim.json` (sealed) and `manifest.json` must both declare the same profile, otherwise `check0_profile_binding` FAILS. Energy generator now declares `profile`. New vector **B18 Profile Substitution** caught. Suites: outsider 11/11, insider 5/5, biochar 18/18, PoC 0 vulnerable |
| A5 | Real RFC 8785 JCS: UTF-16 key ordering, ES6 number serialisation, no ASCII escaping; reject floats in canonical payloads | 🔴 | Code | ✅ | `canonical_json_bytes` `:85-87` | Oct 22: `src/verifier/jcs.py` (UTF-16 key sort, ES6 string escaping, raw UTF-8, integer-only I-JSON) + strict parser. RFC-transcribed vectors in `04_experiments/conformance/jcs_vectors.json`; `tests/test_jcs.py`. The old `json.dumps` canonicaliser fails 2/5 RFC vectors |
| A6 | Remove floats from the verifier: integer-scaled emission factors; reject `float` types | 🟡 | Code | ✅ | `:725`, `:1442`, `:1453` | Oct 22: no floats anywhere in protocol data (parser rejects them). Emission factor = integer `factor_mg_co2e_per_kwh`; emissions = integer g (ceil); removals = integer g (floor); `h_c_org_bps`. Vector **O13** float injection |
| A7 | Run the full attack suite and the PoC regression after A1–A6; refreeze both golden vectors | 🔴 | Code | ✅ | `src/attacks/*`, `04_experiments/*` | Oct 22: outsider **13/13**, insider **8/8**, biochar **19/19** (= **40/40**, each failing for the expected check), PoC P1–P6 **0 vulnerable**, unit tests 6/6. Golden vectors refrozen with `src/tools/freeze_golden_vectors.py` (bundle + `trust/` inputs + expected verdict); `tests/test_golden_vectors.py` |
| A8 | Legacy `tamper_bundle.py` (v1.0): counts *any* failure as "caught" (doesn't check the reason), always exits 0, runs on the stale root `claim_bundle/`. Superseded by `outsider_attacks.py` | 🟡 | Code | ✅ | `src/attacks/tamper_bundle.py` | Oct 22: deleted with user OK |

## B. Threat-Model Gaps (Review §2)

| # | Item | Pri | Type | Status | Notes |
|---|------|-----|------|--------|-------|
| B1 | Producer-root-key insider forgery (§2.1): the trust anchor for the device must be the manufacturer, not the operator | 🔴 | Code + Text | ✅ | Code (A1) + text: threat model §2, Field 8 #1 |
| B2 | Operator-controlled clock (§2.2): add external time evidence (RFC 3161 TSA token on chain heads, verifiable offline with `openssl ts -verify`, and/or log anchoring) | 🔴 | Code + Text | 🔵 | Text done (threat model §5, spec §7, Field 8 #3, M3 scope). Code (RFC 3161) is M3 work |
| B3 | Withholding / truncation (§2.3): signed heartbeats + a maximum time-gap rule in the core; logged chain heads | 🔴 | Code + Text | 🔵 | Code: max gap + period mandates (I6, I7). Text: Field 8 #3, threat model §5. Heartbeats + tlog are M2/M3 deliverables |
| B4 | Unauthenticated RS-485 bus (§2.4): document meter impersonation and CT/VT ratio rewrites; capture the meter's config and event-log registers in the signed record | 🟡 | Text (+Code) | ✅ | Threat model §4, Field 8 #2; 'ahead of the PLC' removed everywhere; config/event-log registers in M2 |
| B5 | 2.5 kV isolation and temperature limits presented as security (§2.5): demote to electrical-safety notes | 🟡 | Text | ✅ | Removed as a security claim; threat model §4 calls isolation an electrical-safety measure |
| B6 | Dual-register check strength (§2.6): state whether both registers come from the meter independently | 🟡 | Text | ✅ | Spec §4, threat model §4: both registers via gateway; independent value = auditor reading the meter totaliser |
| B7 | Physical attacks on the ATECC608 (§2.7): state the cost, the evidence left, tamper seals and revocation | 🟡 | Text | ✅ | Threat model §4 (fault injection, sealing, revocation) |
| B8 | Claim ledger works only within one auditor (§2.8) | 🟡 | Text | ✅ | Threat model §5; tlog cross-auditor detection in M3 and Field 8 #3 |
| B9 | Physical inputs remain open (§2.9): moisture, lab-sample selection, what goes on the scale | 🟡 | Text | ✅ | Threat model §4, Field 8 #6 |
| B10 | Rewrite the "collusion-forcing" argument once B1–B3 are done | 🔴 | Text | ✅ | Rewritten in threat model §6, README §5, Field 7 closing paragraph, naming the two open gaps (signing oracle, clock) |
| B11 | **New (found Oct 22): the secure element is a signing oracle for the insider.** A genuine ATECC608B proves the key can't be extracted, not that the gateway firmware only signs real sensor readings. An operator with physical access can feed it fabricated readings | 🔴 | Text (+M2 scope) | ✅ | Stated in threat model §2/§5, spec §7, README §5, Field 7 + Field 8 #1; M2 adds firmware evidence |
| B12 | **New: old spec/docs claimed checks that were never implemented** (¹⁴C ≥ 95%, heavy metals, TPM 2.0 attestation, `--require-hardware-attestation`) | 🔴 | Text | 🔵 | Done: spec, README, 03_system/README, threat model, application draft. Still stale (internal logs): 00_project/status.md, roadmap.md, security_fix_tracker.md |

## C. Restack Fit & Standards (Review §1, §4)

| # | Item | Pri | Type | Status | Notes |
|---|------|-----|------|--------|-------|
| C1 | Add standards alignment: RATS (RFC 9334) roles, EAT (RFC 9711), SCITT-compatible signed statements, COSE/JOSE choice explained | 🔴 | Text | ✅ | Fields 4, 6 (M1), 7, 9 |
| C2 | Add prior art to Field 7: Eichrecht/OCMF + S.A.F.E. Transparenzsoftware, smart-meter gateway, SCITT/RATS, Sigstore/in-toto; cut Web3 to 2 sentences | 🔴 | Text | ✅ | Field 7 #1 (Eichrecht/OCMF/S.A.F.E., SMGW, RATS/EAT, SCITT, Sigstore/in-toto/C2PA); Web3 cut to 2 sentences; vendors no longer called 'dark stacks'. The IETF draft from the Oct 9 log was not cited (could not verify it) |
| C3 | Reduce regulatory detail; weight the text toward open standards and reuse | 🟡 | Text | ✅ | Regulation now a supporting sentence in Field 9; Fields 4/8 lead with mechanisms and standards |
| C4 | Get one named external party (CAB, Eclipse / LF Energy contact, OEM) | 🟡 | Decision | ⬜ | User outreach; even an email reply counts |

## D. Milestones & Budget (Review §3)

| # | Item | Pri | Type | Status | Notes |
|---|------|-----|------|--------|-------|
| D1 | Realistic schedule (hours/week vs. day job) | 🔴 | Text | ✅ | Field 6: 8 months, ~22 h/week; milestones M1 M1–2, M2 M2–4, M3 M4–6, M4 M7–8 |
| D2 | State availability and IP position | 🟡 | Text | ✅ | Field 10 last paragraph: independent work, no employer IP claim, ~22 h/week |
| D3 | Reduce M2 scope to one secure element + an interface | 🔴 | Text | ✅ | Field 6 M2: ATECC608B only, TPM 2.0/DICE as documented interface |
| D4 | Move the shared-core refactor out of M3 (done before submission via A3, or in M1) | 🟡 | Text | ✅ | Refactor no longer in M3; M3 = Rust verifier + RFC 3161 + tlog |
| D5 | Measurable deliverables per milestone (spec tag, N vectors passing in CI for Python and Rust, crates.io, audit) | 🔴 | Text | ✅ | Each milestone lists checkable deliverables (tagged spec, public CI, crate, hardware bundles verifying against vendor root, 100% conformance) |
| D6 | Check whether Restack offers NGI-style partner services (security audit, packaging); mention them if it does | 🟡 | Text | ✅ | User decision Oct 22: Field 6 M3 (security audit via Radically Open Security) and M4 (packaging/reproducibility review), Field 9. Worded 'where offered' because Restack availability is unverified |
| D7 | Present the 33 vectors as a regression suite, not as evidence of security | 🟡 | Text | ✅ | README §7, threat model §3 and Field 10 call it an author-written regression suite |

## E. Proposal Text Edits (Review §5)

| # | Field | Item | Status | Notes |
|---|-------|------|--------|-------|
| E1 | 4 Summary | Replace with the revised summary (941 chars); keep or drop the log sentence based on D2 | ✅ | Field 4 (952 chars) with tlog sentence |
| E2 | 7 Comparison | New point 4 on prior art (661 chars); shorten Web3; stop calling named vendors "dark stacks" | ✅ | Field 7 rewritten (2,372 chars) |
| E3 | 8 Challenges | Item 1: describe the hook interface instead of re-listing the checks. Item 2: replace the temperature/ATEX text with honest bus limits | ✅ | Field 8 #5 describes the hook interface; #2 states bus limits |
| E4 | 9 Ecosystem | Fix the CRA claim → "supports CRA secure-by-design obligations" | ✅ | 'supports secure-by-design obligations under the EU CRA' |
| E5 | 10 Background | Tone down "mathematically verify", "deterministically catches", "without institutional overhead" | 🔵 | User will rewrite Field 10 in own voice and choose the Field 12 AI disclosure before submitting |
| E6 | 2 Title | Consider "Open Evidence Format and Hardware Root-of-Trust for Verifiable Sensor Telemetry" | ✅ | Title: 'Open Evidence Format and Hardware Root-of-Trust for Verifiable Sensor Telemetry' (79 chars) |
| E7 | All | Verify citations: "Kleppmann et al., ACM e-Energy" and "Delegated Regulation 2026/285" | ✅ | User confirmed: unverified citations stay out |
| E8 | All | Recount every field against its character limit after the edits | ✅ | Counted by script: 79 / 952 / 3,092 / 2,372 / 2,623 / 1,511 / 1,363 / 228 |

## F. Repo Hygiene (Review §0, last row)

| # | Item | Pri | Type | Status | Notes |
|---|------|-----|------|--------|-------|
| F1 | Remove duplicated bundles at the repo root (`claim_bundle/`, `biochar_bundle/`, root `*.pem`); generate them into a git-ignored build directory | 🟡 | Repo | ✅ | Oct 22: root `claim_bundle/`, `biochar_bundle/`, root `*.pem` removed from git; simulators/generators default to git-ignored `build/` |
| F2 | Keep manuscript drafts (Medium, illuminem) out of the public repo or move them under `docs/` | 🟡 | Repo | ✅ | `07_manuscript/*_draft.*` git-ignored (illuminem drafts stay local); Medium article moved to `07_manuscript/archive/` |
| F3 | Rename `bulletproof_hardening_tracker.md` to a neutral name | 🟢 | Repo | ✅ | Renamed to `security_hardening_tracker.md`, retitled as a historical v1.1 plan; path references updated |
| F4 | One-command test entry point (`make test` or `python -m src.attacks.run_all`) and a CI workflow | 🟡 | Repo | ✅ | `make test` + `.github/workflows/ci.yml` (Python 3.9 and 3.12 on ubuntu-latest, push + PR). Verified locally on 3.9 and 3.11; first GitHub run pending push |
| F5 | Make the README match the code exactly (simulated attestation, current limitations) | 🔴 | Repo | ✅ | README rewritten for v1.3 (CLI table, simulated CA, honest limits); quickstart commands executed and PASS |

---

## Progress Summary

| Section | Items | Done | In progress | Open |
|---------|:-----:|:----:|:-----------:|:----:|
| Decisions | 5 | 5 | 0 | 0 |
| A. Code vs Claims | 8 | 8 | 0 | 0 |
| B. Threat Model | 12 | 9 | 3 | 0 |
| C. Restack Fit | 4 | 3 | 0 | 1 |
| D. Milestones | 7 | 7 | 0 | 0 |
| E. Text Edits | 8 | 7 | 1 | 0 |
| F. Repo Hygiene | 5 | 5 | 0 | 0 |
| **Total** | **49** | **44** | **4** | **1** |

## Suggested Order

1. **Decisions D1–D5**: quick user calls that unblock the rest.
2. **Code A4 → A5 → A6 → A3 → A1/A2 → B3 → B2 → A7**: start with small, independent fixes, then the refactor, then attestation on top of the clean core.
3. **Text B/C/D/E**: rewrite the application to describe the fixed code.
4. **Repo F1–F5**, then the final character count (E8).

## Change Log

| Date | Item(s) | Change |
|------|---------|--------|
| Oct 22 | — | Tracker created from the review |
| Oct 22 | D1–D4 | Decisions: manufacturer CA, tlog in scope, 8 months, ATECC608B only |
| Oct 22 | A4, A8 | Auditor-bound profile + B18 vector. Found that the legacy `tamper_bundle.py` suite is unreliable |
| Oct 22 | D6, E7, F2–F4 | Partner services in M3/M4 + Field 9; CI workflow; tracker renamed; drafts ignored/archived |
| Oct 22 | F5, B, C, D, E | Docs aligned with v1.3 (README, 03_system/README, threat model); application draft rewritten (8 months, RATS/EAT/SCITT/Eichrecht, honest limits). Open: C4 external party, D6 Restack partner services, E5 own-voice rewrite, E7 citations, F2/F3, F4 CI, B12 internal logs |
| Oct 22 | D5, A1–A3, A5–A8, F1, F4 | Shared core + bundle v1.3, RFC 8785 JCS, integer-only data, manufacturer-CA attestation, max-gap/period mandates, golden vectors refrozen, `make test`. 40/40 vectors, 0/6 PoCs. Spec rewritten to v1.3. New findings B11 (SE signing oracle), B12 (docs claimed unimplemented checks) |
