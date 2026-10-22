# Threat Model & Security Boundaries (bundle format v1.3)

This document states what the verifier defends against, what it relies on, and what it does not
defend against. Every "caught" claim below corresponds to an automated vector in `src/attacks/`
or `04_experiments/security_reaudit/`; anything planned is marked as such.

---

## 1. Assets, Parties and Trust Anchors

**Asset:** the integrity of a compliance claim (energy, emissions, carbon removal) derived from
instrument readings.

| Party | Holds | Trusted by the auditor for |
|---|---|---|
| Secure-element manufacturer | Root/signer CA keys | Issuing device certificates only for keys generated inside genuine chips |
| Producer (facility operator) | Producer root key; physical control of instruments and gateway | Nothing by default — treated as a potential adversary |
| Accredited bodies (labs, metrology, grid-factor publishers) | Reference datasets | The contents of datasets whose SHA-256 the auditor pins |
| Auditor | Profile choice, registry, mandates, manufacturer CA, ledger | — |

The verifier takes every trust anchor from the auditor (`--profile`, `--manufacturer-ca`,
`--producer-key`, `--trusted-registry`, mandates). Nothing inside the bundle can act as a trust
anchor.

---

## 2. Adversaries

### A. Outsider
Can read and modify bundles in transit or at rest, inject files, replay or reorder records.
Holds no keys. **Defence:** Checks 1–4 (seal, file hashes, path safety, signatures, chain).

### B. Insider operator
Holds the producer root key; can re-package and re-seal any bundle; physically controls the
gateway and instruments. Crucially, **the gateway's secure element signs whatever its host
presents**: a genuine chip proves the key cannot be extracted, not that the data is real. The
attack suites model this by re-signing tampered records through the device key.

**Defences that remain against an insider** (the operator does not control them):
1. Manufacturer attestation (Check 2): the device key must chain to the auditor-pinned
   manufacturer root, so the operator cannot substitute a software key or mint its own CA.
2. Auditor-pinned references (Check 8): factors, lab assays and delivery manifests must match
   digests the auditor pinned, with the expected dataset type.
3. Physical invariants (Checks 5, 9): register continuity, temperature floor, per-batch yield cap,
   delivered-feedstock cap, H/C_org cap, integer recomputation.
4. Structural rules (Checks 4, 6, 7, 10): maximum record gap, period and count mandates, local
   double-counting ledger, complete lineage, exact reconciliation.

### C. Compromised gateway host
Equivalent to B for signing purposes: malware on the gateway can request signatures over
fabricated readings. Not detectable by the verifier today (see §5).

---

## 3. Attack Coverage (regression suite)

40 vectors, each required to fail the specific check listed; run with `make test`. These are
author-written regression tests, not an independent evaluation.

### 3.1 Outsider — `src/attacks/outsider_attacks.py` (energy profile)

| ID | Attack | Check |
|:-:|---|:-:|
| O1 | Falsified meter reading | 3 |
| O2 | Rogue device id in certificate | 2 |
| O3 | Dropped middle record | 4 |
| O4 | Replayed (duplicated) record | 4 |
| O5 | Foreign device id in record | 3 |
| O6 | Timestamp outside certificate window | 3 |
| O7 | File edited, manifest re-hashed without seal | 1 |
| O8 | Path traversal entry in manifest | 1 |
| O9 | Unmanifested file injected | 1 |
| O10 | Revoked gateway | 2 |
| O11 | Private key material in bundle | 1 |
| O12 | Duplicate JSON key (parser differential) | 3 |
| O13 | Float injected into signed payload | 3 |

### 3.2 Insider — `src/attacks/insider_fraud_suite.py` (energy profile; re-signed and re-sealed)

| ID | Attack | Check |
|:-:|---|:-:|
| I1 | Unpinned (greenwashed) emission factor | 8 |
| I2 | One register shaved | 5 |
| I3 | Records truncated vs `--expected-count` | 6 |
| I4 | Attestation chain removed | 2 |
| I5 | Spliced record (foreign `prev_hash`) | 4 |
| I6 | Window withheld, chain re-signed and renumbered | 4 (max gap) |
| I7 | Tail truncated vs `--period-end` | 6 |
| I8 | Undeclared adjustment recipe added | 7 |

### 3.3 Domain stress — `src/attacks/biochar_attacks.py` (biochar profile)

| ID | Attack | Check |
|:-:|---|:-:|
| B1 | Water spraying (dry yield far above cap) | 9 |
| B2 | Undercooking (T_min 420 °C) | 5 |
| B3 | Counterfeit lab assay | 8 |
| B4 | Feedstock used > delivered | 9 |
| B5 | Dropped batch (outsider) | 4 |
| B6 | Non-NAWI scale certified by producer | 2 |
| B7 | Genuine attestation chain of a different chip | 2 |
| B8 | Uncertified feedstock manifest | 8 |
| B9 | Claim metric inflated, re-sealed | 10 |
| B10 | Revoked gateway | 2 |
| B11 | Private key sealed into bundle | 1 |
| B12 | Rogue software device key | 2 |
| B13 | Calibration expired before batches | 3 |
| B14 | Same batches re-issued under a new claim id | 6 (ledger) |
| B15 | One batch yields more than its feedstock | 9 |
| B16 | 95% dry yield | 9 |
| B17 | Operator-forged manufacturer CA chain for a software key | 2 |
| B18 | Profile substitution | 0 |
| B19 | Pinned dataset of the wrong type used as lab assay | 8 |

### 3.4 Re-audit regressions — `04_experiments/security_reaudit/poc_exploits.py`
P1 private key in bundle; P2 rogue device key; P3 expired calibration; P4 double counting;
P5 per-batch mass balance; P6 implausible yield. All defended.

---

## 4. Physical Boundary: What the Edge Design Does and Does Not Give

* **RS-485 / Modbus RTU is unauthenticated.** The gateway cannot tell a genuine meter response
  from one injected by another device on the bus, and on a multidrop bus there is no "ahead of
  the PLC". Reading instruments directly removes PLC/SCADA *software* from the path; it does not
  authenticate the instrument.
* **Instrument configuration can be changed at the source.** Many meters expose writable CT/VT
  ratio or scaling registers; a gateway would faithfully sign rescaled values. Mitigations
  (planned): read configuration and event-log registers into signed records; rely on metrology
  seals and their records.
* **Dual registers** (energy profile) both pass through the gateway. An insider who rewrites both
  consistently passes Check 5 (I2 is caught only because one register was changed). Independent
  value: the auditor reading the meter's own totaliser at period start and end.
* **Galvanic isolation (2.5 kV) is an electrical-safety and noise measure, not a security
  control.**
* **Physical inputs remain operator-controlled:** what goes on the scale, feedstock moisture,
  which sample is sent to the lab. Conservation checks bound crude inflation; they do not prove
  honest sampling.
* **Secure-element physical attacks:** fault-injection key extraction has been published for
  parts of the ATECC family. A successful extraction requires lab equipment and physical access;
  mitigations are tamper-evident sealing of the gateway and revocation (`--revoked`).

---

## 5. Residual Risks and Planned Mitigations

| Risk | Current state | Planned mitigation |
|---|---|---|
| Fabricated readings signed by a genuine gateway (signing oracle) | Not detected | Measured/secure boot with firmware attestation; gateway provisioned and sealed by an independent party; physical invariants |
| Operator-controlled clock (backdating, keeping expired calibrations "valid") | Not detected | RFC 3161 timestamps on chain heads; transparency-log inclusion times |
| Withholding a whole period and never claiming it | Detected only when the auditor sets `--period-start/--period-end` or links periods with `--prev-terminal-hash` | Chain heads in a public, witnessed transparency log (C2SP tlog / SCITT-compatible) |
| Same evidence claimed with two different auditors | `--claim-ledger` is local to one auditor | Public transparency log |
| Legitimate downtime vs. withheld data | Treated as a gap above `max_record_gap_s` | Signed idle heartbeats |
| Real manufacturer PKI | Simulated CA (`SIMULATED ... (TEST ONLY)`), always warned | ATECC608B TrustFLEX/TNG root pinned by the auditor (same code path) |

---

## 6. What the Design Achieves

The engine does not make fraud impossible. It removes *costless, traceless* fraud: once readings
are signed by an attested key at the gateway and the auditor pins references and mandates,
falsifying a verified claim requires intervention at the instruments or gateway hardware, or the
cooperation of a party the operator does not control (chip manufacturer, accredited lab, auditor).
Two gaps keep this from being a complete argument today and are the priority of the next
milestones: the gateway as a signing oracle (firmware attestation) and the operator-controlled
clock (trusted time / transparency log).
