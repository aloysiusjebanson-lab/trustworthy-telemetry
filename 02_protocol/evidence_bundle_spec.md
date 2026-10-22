# Claim Evidence Bundle Specification (v1.3)

> Self-contained, offline-verifiable evidence format for industrial telemetry claims: a shared
> verification core plus pluggable domain profiles. Reference implementation:
> `src/verifier/` (Python 3 stdlib + OpenSSL CLI). Conformance vectors: `04_experiments/`.

This document describes exactly what the reference verifier enforces. Planned work is listed
separately in §7 and is not claimed as implemented.

---

## 1. Scope & Threat Model

An evidence bundle lets an independent auditor verify a compliance claim (energy, emissions,
carbon removal, ...) from signed edge telemetry without trusting the reporting operator, its
databases or any SaaS platform. Full threat model: `03_system/threat_model.md`.

**Parties and trust anchors.** All trust anchors are supplied to the verifier by the auditor
out-of-band; nothing inside the bundle can act as a trust anchor.

| Party | Key / artefact | Trusted for |
|---|---|---|
| Secure-element manufacturer | Root CA certificate (`--manufacturer-ca`) | The device key was generated in, and cannot leave, a genuine secure element |
| Producer (facility operator) | Producer root public key (`--producer-key`) | Which instruments the device is wired to; sealing the bundle |
| Auditor | Registry (`--trusted-registry`), profile choice (`--profile`), mandates | Reference datasets, methodology parameters, reporting period |

**Adversaries.** *Outsiders* hold no keys. *Insiders* (the operator) hold the producer root key
and physically control the gateway, so they can make its secure element sign arbitrary records
and can re-seal any bundle. Insider fraud must therefore be caught by controls the operator does
not hold: the manufacturer attestation chain, auditor-pinned references, physical invariants,
lineage rules and auditor mandates.

---

## 2. Container Layout & Encoding

### 2.1 Directory layout

```text
bundle/
├── manifest.json                       # file catalog + producer seal
├── claim.json                          # claim id, profile, device, period, integer metrics
├── device/
│   ├── public_key.pem                  # device P-256 public key (held in the secure element)
│   ├── device_certificate.json         # producer-signed binding of key -> profile + instruments
│   └── attestation/
│       ├── se_device_cert.pem          # X.509 certificate of the secure-element key (manufacturer-issued)
│       └── se_signer_ca.pem            # manufacturer intermediate CA
├── observations/observations.ndjson    # signed, hash-chained records (one envelope per line)
├── reference_data/*.json               # external authority datasets (pinned by the auditor)
├── transformations/*.json              # recipes with declared integer outputs
└── provenance/provenance.json          # W3C PROV lineage graph (PROV-JSON layout)
```

### 2.2 Canonical encoding (RFC 8785, integer-only profile)

* Every signed or hashed JSON object is serialised with **RFC 8785 JCS**: members sorted by
  UTF-16 code units, ECMAScript string escaping (only `"`, `\` and U+0000–U+001F escaped; other
  characters as raw UTF-8), no whitespace. Implementation: `src/verifier/jcs.py`; conformance
  vectors transcribed from the RFC: `04_experiments/conformance/jcs_vectors.json`.
* **Protocol data contains no floating-point numbers.** The strict parser rejects floats
  (including exponent notation), NaN/Infinity, integers outside ±(2^53 − 1), lone surrogates and
  duplicate object keys. For this input domain JCS output equals full RFC 8785 output.
* Integer base units: energy Wh; mass g; temperature °C; ratios basis points (10,000 bps =
  100%); emission factors mg CO2e/kWh; emissions and removals g CO2e.

### 2.3 Observation envelope & hash chain

```json
{
  "record": {
    "device_id": "dev-6aec872ee7ae6c3a",
    "sequence": 1,
    "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "timestamp_start": 1790800000,
    "timestamp_end": 1790800900,
    "payload": { "...": "profile-specific integer fields" }
  },
  "algorithm": "ECDSA_P256_SHA256",
  "signature": "<hex DER ECDSA signature over JCS(record)>"
}
```

* Envelope and record must contain exactly these members.
* `prev_hash[0]` = 64 zeros, or the auditor-supplied `--prev-terminal-hash` of the previous period.
* `prev_hash[i] = SHA-256(JCS(record[i-1]))`. The chain covers the signed record, not the
  signature, so ECDSA signature malleability cannot break or fork the chain.
* `terminal_hash = SHA-256(JCS(record[last]))`.
* `device_id = "dev-" + first 16 hex of SHA-256(DER SubjectPublicKeyInfo of the device key)`.

### 2.4 Device certificate

`device_certificate.json = {"body": {...}, "algorithm": "ECDSA_P256_SHA256", "signature": ...}`,
signed by the producer root over `JCS(body)`. The body contains `device_id`, `profile`,
`device_public_key_sha256` (DER), `secure_element`, `valid_from`/`valid_until` (unix seconds),
`issued_by` and `instruments`: one object per instrument with `role`, `instrument_id`, `model`,
`serial`, `standard`, `accuracy_class`, `calibration_cert_sha256`, `calibration_valid_until`.

### 2.5 Manifest & seal

`manifest.json = {"manifest_version": "1.3", "profile", "claim_id", "files": {path: sha256},
"seal": {"algorithm", "signature"}}`. The seal is the producer's signature over
`JCS({manifest_version, profile, claim_id, files})`, so it also binds the profile and claim id.

### 2.6 Claim

`claim.json = {"claim_id", "profile", "device_id", "period": {first_sequence, last_sequence,
record_count, start_timestamp, end_timestamp, genesis_prev_hash, terminal_hash}, "metrics":
{name: integer}}`. Every period field must equal the value derived from the evidence; unknown
period fields are rejected.

### 2.7 Lineage graph

PROV-JSON layout: `entity` (each with `tte:path`, `tte:sha256`), `activity` (each with
`tte:recipe`, an entity under `transformations/`), and the relations `used`, `wasGeneratedBy`
and `wasInformedBy` (`prov:informed` / `prov:informant`, linking steps of a multi-step
calculation without intermediate files).

---

## 3. Verification State Machine

The verifier is fail-closed: malformed input yields FAILED, never a crash or a pass. Every check
runs and reports independently so that an audit report lists all failures.

### 3.1 Core checks (shared by all profiles, `src/verifier/core.py`)

| # | Check | Enforced |
|---|---|---|
| 0 | Profile binding | `--profile` is mandatory; `claim.json` and `manifest.json` must declare exactly that profile (no default, no fallback). |
| 1 | Manifest & seal | `manifest_version` 1.3; every path relative, normalised, no `..`, not a symlink; file hashes match; no unmanifested files; no private-key material anywhere; producer seal valid. |
| 2 | Device & attestation | Device key is P-256; its X.509 certificate chains (`openssl verify -x509_strict`) through `se_signer_ca.pem` to the **auditor-pinned manufacturer root**, and certifies exactly `device/public_key.pem`; producer signature on the device certificate; certificate bound to the key, the derived `device_id` and the profile; valid window; every instrument role required by the profile present exactly once with an accepted standard, accuracy class, calibration digest and integer expiry; device not revoked. |
| 3 | Record signatures | Exact envelope/record schema; algorithm allow-list; `device_id` = certified device; signature over `JCS(record)` valid; record inside the certificate window; `timestamp_end` ≤ the earliest instrument calibration expiry. |
| 4 | Chain continuity | `prev_hash` chain from the genesis value; contiguous sequence numbers; `timestamp_start < timestamp_end`; no overlap; gap between consecutive records ≤ registry `max_record_gap_s` (detects withheld periods even when the operator re-signs and renumbers the chain). |
| 6 | Claim boundaries | Claim id = sealed manifest; claim device = certified device; period fields equal the evidence; auditor mandates `--expected-count`, `--period-start`, `--period-end` (head/tail truncation, tolerance `max_record_gap_s`); `--claim-ledger` rejects reuse of a claim id with different evidence, of a terminal hash, or of any `device_id:sequence`. |
| 7 | Lineage | Every claim, observation, reference and recipe file is exactly one entity with a matching hash; relations reference known nodes; only `claim.json` is generated; graph acyclic; every lineage file and activity is an ancestor of the claim. |
| 10 | Reconciliation | `claim.metrics` equals the profile's recomputed metrics exactly (same keys, same integers); every `outputs` value declared in a recipe equals the recomputed value. |

### 3.2 Profile contract (`src/verifier/profiles/`)

A profile supplies data and three hooks; it cannot override core checks.

* **Data:** `profile_id`; `instrument_requirements` (`role → accepted standards and accuracy
  classes`, enforced by Check 2); methodology parameters are read from the auditor registry under
  `methodology_parameters.<profile_id>` (no defaults in code).
* **Check 5 hook** `check5_process_continuity(audit) → [errors]`: payload schema and per-record
  process invariants.
* **Check 8 hook** `check8_pinned_references(audit) → refs | None`: uses the core helper
  `audit.pin_reference(path, dataset_type)`, which requires the file to be manifested, its SHA-256
  to be in the registry and the pinned dataset `type` to match; then validates content.
* **Check 9 hook** `check9_recompute(audit) → ([errors], {metric: int})`: conservation
  inequalities and deterministic integer recomputation. Metrics must be integers.

---

## 4. Reference Profile 1: `energy_submetering`

* **Instruments:** `energy_meter` — `MID_2014_32_EU`, class `Class_A/B/C_EN50470`.
* **Payload:** exactly `{meter_id, cumulative_wh, interval_wh}` (non-negative integers).
* **Check 5:** `meter_id` is the certified meter; `cumulative_wh[i] − cumulative_wh[i−1] == interval_wh[i]`.
  Limitation: both registers pass through the gateway, so an insider who rewrites both
  consistently is not caught by this check alone (see threat model).
* **Check 8:** `reference_data/emission_factor.json` pinned as type `grid_emission_factor`;
  `factor_mg_co2e_per_kwh` must equal the pinned value.
* **Check 9 metrics:** `total_energy_wh = Σ interval_wh`; `emission_factor_mg_co2e_per_kwh`;
  `total_emissions_g_co2e = ceil(total_energy_wh × factor / 10^6)` (rounded up: never under-report).
* **Registry parameters:** `max_record_gap_s` (0 for contiguous 15-minute intervals).

## 5. Reference Profile 2: `biochar_pyrolysis`

* **Instruments:** `weighing_indicator` — `NAWI_2014_31_EU`, `Class_I/II/III`;
  `thermocouple_module` — `IEC_60584_1`, `Class_1/2`.
* **Payload:** exactly `{batch_id, feedstock_delivery_ref, feedstock_input_g, scale_wet_mass_g,
  temp_min_c, temp_avg_c, temp_max_c}`.
* **Check 5:** integer temperatures with `T_min ≤ T_avg ≤ T_max`; `T_min ≥ min_pyrolysis_temp_c`;
  unique `batch_id`.
* **Check 8:** `reference_data/lab_analysis.json` pinned as `iso17025_accredited_lab_report`
  (integer `moisture_bps`, `c_org_bps`, `permanence_factor_bps`, `h_c_org_bps` in 0..10000;
  `sample_batch_ref` must equal `<first batch>_to_<last batch>`);
  `reference_data/feedstock_manifest.json` pinned as `feedstock_delivery_manifest`; every batch
  references its `delivery_ref`.
* **Check 9:** per batch `dry = ⌊wet × (10000 − moisture_bps) / 10000⌋` and
  `dry × 10000 ≤ feedstock × max_dry_yield_bps`; `Σ feedstock ≤ delivered_mass_total_g`;
  `h_c_org_bps ≤ max_h_c_org_bps`;
  `gross = ⌊Σdry × c_org_bps × permanence_factor_bps × 44 / (10^8 × 12)⌋` (rounded down: never
  over-credit); `net = gross − process_deduction_g` must be positive.
* **Metrics:** `total_feedstock_input_g, total_wet_biochar_g, total_dry_biochar_g,
  gross_co2_removed_g, process_deductions_co2_g, net_co2_removed_g`.
* **Registry parameters:** `max_record_gap_s`, `min_pyrolysis_temp_c`, `max_dry_yield_bps`,
  `max_h_c_org_bps`, `process_deduction_g`.

---

## 6. Audit Report

`--json` emits `verdict`, `bundle_format`, `profile`, per-check results, all errors, warnings,
the trust anchors used, and findings (`device_id`, `hardware_attestation` =
`MANUFACTURER_CA_VERIFIED` | `SIMULATED_MANUFACTURER_CA` | `NOT_VERIFIED`, record count, terminal
hash, recomputed metrics). A pinned manufacturer root whose subject contains `SIMULATED` always
produces a warning that hardware key origin is not established for production use.

---

## 7. Not Yet Implemented (planned, not claimed)

* **Real secure-element provisioning:** the reference fixtures use a simulated manufacturer PKI.
  Verification against the real Microchip ATECC608B TrustFLEX/TNG root is the same code path and
  is a Milestone 2 deliverable. A genuine secure element proves the key cannot be extracted; it
  does not prove the gateway firmware only signs real sensor readings (needs measured boot /
  firmware attestation or an independently sealed gateway).
* **Trusted time:** record timestamps come from the gateway clock, which the operator controls.
  External time evidence (RFC 3161 timestamps or transparency-log inclusion of chain heads) is
  planned.
* **Public transparency log:** anchoring chain heads in an append-only, witnessed log
  (C2SP tlog / IETF SCITT-compatible) to detect backdating, truncation and double use across
  auditors. The current `--claim-ledger` only protects within a single auditor's ledger.
* **Idle heartbeats:** records emitted while a process is idle, so that legitimate downtime is
  distinguishable from withheld data without loosening `max_record_gap_s`.
* **Additional lab criteria** (e.g. radiocarbon biogenic fraction, heavy-metal screening) are
  not enforced by the current biochar profile.
