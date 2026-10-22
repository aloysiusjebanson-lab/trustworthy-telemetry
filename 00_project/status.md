# Project Status

**Current date:** October 23, 2026  
**Current phase:** Phase 4b — external-review remediation (code and docs done) → final polish and submission  
**Target program:** NLnet Restack Open Call 1 (Horizon Europe GA No. 101299072)  
**Submission target:** November 1, 2026 · **Hard deadline:** November 3, 2026, 12:00 CET  
**Protocol:** Bundle format **v1.3** (`02_protocol/evidence_bundle_spec.md`)  
**Grant plan:** €38,000 (720 h × €50 + €2,000 hardware) over **8 months**, 4 milestones  
**Work branch:** `refactor-shared-core-v1.3` (to be merged into `main`)

---

## Technical State

1. **Verifier** (`src/verifier/`): one shared core (`core.py`: Checks 0–4, 6, 7, 10) plus two
   profile drivers (`profiles/`: hooks for Checks 5, 8, 9). RFC 8785 canonicalisation restricted to
   integers; strict parser (no floats, no duplicate keys). Python stdlib + OpenSSL CLI only.
2. **Attestation:** the device key must chain (X.509) to a manufacturer root CA pinned by the
   auditor. The repo uses a **simulated** manufacturer PKI labelled `TEST ONLY`; real ATECC608B
   provisioning is Milestone 2.
3. **Tests** (`make test`, CI on Python 3.9 / 3.12): 40/40 regression vectors (13 outsider,
   8 insider, 19 biochar), P1–P6 re-audit regressions 0 vulnerable, JCS + golden-vector unit
   tests. These are author-written regression tests, not an external evaluation.
4. **Golden vectors:** `04_experiments/golden_test_vector*/` (bundle + auditor trust inputs +
   expected verdict), targets for the Rust verifier.
5. **Known limits (documented):** gateway as a signing oracle (no firmware attestation yet),
   unauthenticated RS-485 bus, operator-controlled clock, ledger local to one auditor, physical
   inputs operator-controlled.

## Application State

- Draft rewritten after the external review (`00_project/nlnet_restack_application_draft.md`):
  8-month plan, ATECC608B only, transparency log and RFC 3161 in M3, RATS/EAT/SCITT/Eichrecht
  framing, NLnet partner audit and packaging review, all fields within limits (counted by script).
- Remediation tracker: `00_project/review_remediation_tracker.md`.

## Progress

| Item | Status | Notes |
|---|:---:|---|
| Phase 1 — Foundation | ✅ | |
| Phase 2 — Drafting | ✅ | Superseded by the Oct 22 rewrite; AI disclosure (Field 12) pending with Field 10 |
| Phase 3 — Technical proving | ✅ | Terminal demo (3.5) still optional |
| Phase 4b — Review remediation | ✅ code & docs | Open: C4 external contact; E5 Field 10 rewrite |
| Phase 4 — Polish & self-score | 🔵 | Self-score, outside read-through, repo made public |
| Phase 5 — Submission | ⬜ | Nov 1 |

## Risk Register

| Risk | Probability | Severity | Mitigation |
|---|:---:|:---:|---|
| Reviewer sees a vertical tool, not infrastructure | Medium | High | Lead with the open format, shared core and standards (RATS, SCITT, RFC 8785); transparency log in scope |
| Reviewer finds claims the code does not support | Low (after v1.3) | High | Spec, README and threat model describe only implemented checks; limits listed explicitly |
| Prior art overlap (Eichrecht/OCMF, SCITT, RATS) | Medium | Medium | Field 7 positions the project as the layer joining them, reusing their roles and formats |
| Feasibility alongside employment | Medium | Medium | 8 months at ~22 h/week; working prototype already exists |
| Repository still private at submission | Medium | Critical | Make public after merging into `main` |
| Portal problems | Low | Critical | Submit Nov 1 with a 2-day buffer |

## Next Actions

1. Get CI green on GitHub, merge `refactor-shared-core-v1.3` into `main`, push.
2. Make the repository public.
3. Rewrite Field 10 in own voice; choose the Field 12 AI disclosure answer.
4. Outreach for one named external contact (C4).
5. Self-score against the NLnet criteria; outside read-through; submit Nov 1.
