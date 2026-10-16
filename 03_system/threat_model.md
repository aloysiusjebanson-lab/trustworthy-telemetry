# System Threat Model & Physical-to-Digital Security Boundaries (v1.2)

> **Formal Threat Taxonomy, Adversary Capabilities, and Physical-to-Digital Edge Boundaries for the Universal Verifiable Telemetry Engine**

---

## 1. Adversary Model & Trust Assumptions

Industrial compliance and environmental auditing differ fundamentally from standard enterprise cybersecurity: **the primary adversary is often the facility operator who owns the local network, database, and SCADA servers**. We formalize three distinct threat actors across our universal engine and its two reference profile drivers:

### Adversary A: Outsider Intermediary (Man-in-the-Middle, Rogue Cloud, Unauthenticated Injector)
* **Capabilities:** Can intercept network traffic, modify JSON/NDJSON payloads in transit, inject replay packets, drop rows, attempt relative path traversal (`../../`), or inject unmanifested files/keys into an evidence directory.
* **Limitations:** Does not possess the Producer Root Private Key and cannot extract private signing keys from the edge gateway's hardware Secure Element (`ATECC608B` / `TPM 2.0`).

### Adversary B: Dishonest Facility Operator — Linear Metering (`energy_submetering`)
* **Capabilities:** Holds the Producer Root Private Key, controls the facility's IT/SCADA network and claim packaging pipeline, and can generate validly sealed bundles.
* **Motivations:** Under-report industrial energy consumption or Scope 2 greenhouse gas emissions (EU CSRD / CBAM), shave peak-demand intervals, or substitute favorable emission factors.
* **Limitations:** Cannot forge legal metrology certificates (`EU_MID_2014_32_EU` Class B); cannot break dual-register physical counter conservation (`cumulative_wh[i] - cumulative_wh[i-1] == interval_wh[i]`) without tampering with sealed meter hardware; cannot alter national grid emission factors pinned out-of-band in the auditor's `trusted_references.json`.

### Adversary C: Dishonest Facility Operator — Non-Linear Transformation (`biochar_pyrolysis`)
* **Capabilities:** Holds the Producer Root Private Key, controls plant PLC/SCADA software, operates physical material handling, and can sign arbitrary manifests.
* **Motivations:** Inflate high-value industrial output or carbon removal claims (e.g., EU CRCF / durable CDR credits trading at €100–€200/t) by adding water weight prior to weighing, running reactors below statutory temperature thresholds ($T_{\min} < 500^\circ\text{C}$) to save fuel, substituting unaccredited lab assays, exceeding certified feedstock deliveries, or replaying prior batches under a new claim ID.
* **Limitations:** Cannot forge hardware secure-element attestation chains (`--require-hardware-attestation`); cannot violate first-law mass conservation ($M_{\text{dry}, i} \le M_{\text{feedstock}, i}$) or thermodynamic dry-yield ceilings ($\le 40.00\%$); cannot modify ISO 17025 laboratory assays or feedstock manifests pinned in the auditor's `trusted_references.json`; cannot bypass the auditor's cross-claim deduplication ledger (`--claim-ledger`).

---

## 2. Comprehensive Adversarial Attack Benchmark (33/33 Caught)

The Universal Verifiable Telemetry Engine is continuously validated against **33 automated adversarial attack vectors** across three test suites—ordered from **Core Engine Outsider Attacks (`O1–O11`)**, to **Core & Linear Insider Fraud (`I1–I5`)**, to **Multi-Sensor Non-Linear Transformation Stress Tests (`B1–B17`)**.

### 2.1 Core Engine Outsider Adversary Matrix (`src/attacks/outsider_attacks.py` — 11/11 Caught)

| ID | Attack Vector | Adversary Action | Core Engine Defense | Verifier Check | Verdict |
|:---:|---|---|---|:---:|:---:|
| **O1** | **Falsified Reading Value** | Modifies integer telemetry payload in transit | NIST P-256 ECDSA observation signature verification failure | Check 3 | ❌ CAUGHT |
| **O2** | **Rogue Uncertified Key** | Signs forged observation with attacker-generated keypair | Producer Root Certificate signature & key-binding failure | Check 2 | ❌ CAUGHT |
| **O3** | **Dropped Middle Record** | Deletes intermediate interval reading from stream | Monotonic sequence (`+1`) and `prev_hash` SHA-256 chain break | Check 4 & 5 | ❌ CAUGHT |
| **O4** | **Duplicate Replay Record** | Replays previous reading inside stream | Sequence monotonicity and duplicate identifier detection | Check 4 & 5 | ❌ CAUGHT |
| **O5** | **Envelope Device ID Swap** | Alters `device_id` field in envelope to disguise origin | Public key SHA-256 fingerprint mismatch vs certified `device_id` | Check 2 & 3 | ❌ CAUGHT |
| **O6** | **Timestamp Validity Breach** | Injects readings outside certificate validity window | Temporal window enforcement (`valid_from <= ts <= valid_until`) | Check 3 | ❌ CAUGHT |
| **O7** | **Re-Hashed Manifest Bypass** | Modifies payload and updates `manifest.json` hashes without Root Key | Producer Root ECDSA Bundle Seal verification failure | Check 1 | ❌ CAUGHT |
| **O8** | **Path Traversal Injection** | Injects `../../etc/shadow` into `manifest.json` file list | Relative path normalization and bundle root jail enforcement | Check 1 | ❌ CAUGHT |
| **O9** | **Unmanifested File Injection** | Drops extra unindexed file or script into bundle directory | Bidirectional filesystem-to-manifest inventory reconciliation | Check 1 | ❌ CAUGHT |
| **O10**| **Revoked Gateway Key** | Submits bundle signed by compromised or decommissioned gateway | Pinned `--revoked` device revocation list enforcement | Check 2 | ❌ CAUGHT |
| **O11**| **Private Key in Bundle** | Leaves `device_private_key.pem` inside bundle directory | Zero-tolerance private key scanner across disk and manifest | Check 1 | ❌ CAUGHT |

### 2.2 Core & Linear Flow Insider Fraud Matrix (`src/attacks/insider_fraud_suite.py` — 5/5 Caught)

| ID | Attack Vector | Adversary Action | Engine & Profile Hook Defense | Verifier Check | Verdict |
|:---:|---|---|---|:---:|:---:|
| **I1** | **Reference Factor Greenwashing** | Alters grid emission factor (`0.05` vs `0.254`) and re-seals with Root Key | Pinned Authority Registry SHA-256 mismatch (`trusted_references.json`) | Check 8 | ❌ CAUGHT |
| **I2** | **Dual-Register Shaving** | Lowers `interval_wh` while hardware totalizer `cumulative_wh` advances | Process Continuity Hook: `Δ cumulative_wh == interval_wh` violation | Check 5 | ❌ CAUGHT |
| **I3** | **Period Boundary Truncation** | Drops high-load shift records from end of window and re-seals | Claim Boundary Binding (`record_count`, `last_sequence`, `terminal_hash`) | Check 6 | ❌ CAUGHT |
| **I4** | **Software Simulator Key** | Uses unattested software keypair instead of secure element silicon | Hardware Attestation key-hash binding (`hardware_attestation.json`) | Check 2 | ❌ CAUGHT |
| **I5** | **Telemetry Stream Splicing** | Stitches non-consecutive observation windows across shutdowns | Sequential `prev_hash` SHA-256 chain discontinuity across splice | Check 4 | ❌ CAUGHT |

### 2.3 Multi-Sensor Non-Linear Transformation Stress Matrix (`src/attacks/biochar_attacks.py` — 17/17 Caught)

| ID | Attack Vector | Adversary Action | Engine & Profile Hook Defense | Verifier Check | Verdict |
|:---:|---|---|---|:---:|:---:|
| **B1** | **Moisture Weight Inflation** | Drenches output with water and fakes moisture to claim impossible dry mass | Conservation Hook: $M_{\text{dry}} \le M_{\text{feedstock}}$ failure | Check 9 | ❌ CAUGHT |
| **B2** | **Thermal Undercooking** | Operates reactor at $T_{\min} < 500^\circ\text{C}$ to save energy | Process Continuity Hook: continuous $T_{\min} \ge 500^\circ\text{C}$ enforced | Check 5 | ❌ CAUGHT |
| **B3** | **Counterfeit Lab Assay** | Substitutes unaccredited lab report with inflated carbon ratio ($C_{\text{org}}$) | Pinned Authority Registry: unpinned lab report SHA-256 rejected | Check 8 | ❌ CAUGHT |
| **B4** | **Feedstock Quota Exhaustion** | Processes batches exceeding certified biomass delivery manifest | Conservation Hook: $\sum M_{\text{feedstock}} \le M_{\text{delivered}}$ | Check 9 | ❌ CAUGHT |
| **B5** | **Silent Batch Omission** | Deletes failed or out-of-spec batch from middle of campaign | Core Hash-Chain Continuity: breaks sequential `prev_hash` link | Check 4 | ❌ CAUGHT |
| **B6** | **Uncertified Weighing Scale** | Uses non-metrological commercial scale outside EU NAWI standard | Core Metrology Check: requires `EU_Directive_2014_31_EU_NAWI` Class I–III | Check 2 | ❌ CAUGHT |
| **B7** | **Tampered Attestation Binding** | Modifies hardware attestation public key hash binding | Core Attestation Check: `attested_public_key_sha256` mismatch | Check 2 | ❌ CAUGHT |
| **B8** | **Uncertified Input Material** | Uses non-approved input material code outside positive list | Reference Hook: positive list & pinned manifest digest check | Check 8 | ❌ CAUGHT |
| **B9** | **Declared Claim Inflation** | Edits `claim.json` output metric (`25.0` vs `20.5` tonnes) and re-seals | Core Check 10: zero-tolerance integer recomputation mismatch | Check 10 | ❌ CAUGHT |
| **B10** | **Revoked Edge Gateway** | Submits telemetry from revoked gateway ID | Core Check 2: `--revoked` device list enforcement | Check 2 | ❌ CAUGHT |
| **B11** | **Bundled Private Key Leak** | Ships `*private*.pem` inside bundle directory | Core Check 1: zero-tolerance private key hygiene failure | Check 1 | ❌ CAUGHT |
| **B12** | **Unbound Software Device Key** | Swaps `device/public_key.pem` without matching certificate body | Core Check 2: `cert_body.device_public_key` & derived `device_id` binding | Check 2 | ❌ CAUGHT |
| **B13** | **Expired Sensor Calibration** | Records batch after scale or thermocouple `calibration_valid_until` | Core Check 3: dynamic `timestamp_end <= calibration_valid_until` check | Check 3 | ❌ CAUGHT |
| **B14** | **Cross-Claim Replay (Double Counting)** | Re-seals already-claimed batches under a new `claim_id` | Core Check 6: offline `--claim-ledger` batch & terminal hash deduplication | Check 6 | ❌ CAUGHT |
| **B15** | **Per-Batch Conservation Breach** | Single batch dry output exceeds its own input mass while aggregate passes | Conservation Hook: per-batch $M_{\text{dry}, i} \le M_{\text{feedstock}, i}$ check | Check 9 | ❌ CAUGHT |
| **B16** | **Implausible 95% Dry Yield** | Claims 95% dry conversion yield (exceeding physical 40% ceiling) | Conservation Hook: pinned `biochar_max_dry_yield_bps` ($\le 4000\text{ bps}$) | Check 9 | ❌ CAUGHT |
| **B17** | **Simulator Stub in Strict Audit** | Submits `SIMULATED_STUB` attestation when strict hardware mode is active | Core Check 2: rejected when `--require-hardware-attestation` is passed | Check 2 | ❌ CAUGHT |

---

## 3. Universal Physical-to-Digital Edge Threat Taxonomy

A verifiable telemetry engine is only as strong as its physical-to-digital boundary. Across all industrial IoT domains, edge attacks fall into **five universal classes**:

### 3.1 Class 1: Analog & Fieldbus Sensor Spoofing ("The Last Foot" Problem)
* **Universal Vulnerability:** Secure elements (`ATECC608B` / `TPM 2.0`) operate at $-40^\circ\text{C}$ to $+85^\circ\text{C}$ and cannot sit inside high-voltage busbars or $650^\circ\text{C}$ reactors. Field sensors transmit over RS-485 Modbus RTU, pulse outputs, or $4\text{–}20\text{ mA}$ loops. An insider with root access to the plant PLC/SCADA server can overwrite Modbus holding registers in software before cloud upload.
* **Engine & Architecture Defense:**
  1. **Direct Safe-Zone Wire Tapping:** The hardened edge gateway sits inside a locked cabinet (under $55^\circ\text{C}$) and taps the RS-485 fieldbus via a **2.5 kV galvanically isolated transceiver** directly at the legal-for-trade instrument, bypassing the operator's PLC/SCADA software entirely.
  2. **Check 5 Process Continuity Hooks:** Profile drivers enforce continuous multi-register or multi-sensor correlation (e.g., `Δ cumulative_wh == interval_wh` in `energy_submetering`; continuous $T_{\min} \ge 500^\circ\text{C}$ and aerodynamic-thermal correlation in `biochar_pyrolysis`).

### 3.2 Class 2: Uncertified Sensor Substitution & Calibration Drift
* **Universal Vulnerability:** An operator replaces an accurate instrument with a drifting, uncalibrated sensor—or continues operating an instrument years after its legal calibration seal has expired.
* **Engine & Architecture Defense:**
  1. **Check 2 Legal Metrology Pedigree:** `device_certificate.json` binds the specific legal metrology directive (`EU_MID_2014_32_EU` Class B for energy meters; `EU_Directive_2014_31_EU_NAWI` Class I–III for industrial scales), serial number, and calibration certificate SHA-256 digest.
  2. **Check 3 Dynamic Calibration Window Enforcement:** The core engine verifies that every individual observation timestamp satisfies `timestamp <= calibration_valid_until`, automatically rejecting readings taken after calibration expiry (`B13`).

### 3.3 Class 3: External Reference & Input Manipulation ("Garbage In" Problem)
* **Universal Vulnerability:** Edge sensors measure physical quantities (Watt-hours, grams, degrees Celsius), not external emission factors or chemical composition. An operator can self-attest favorable grid carbon intensity factors or substitute unaccredited laboratory assays.
* **Engine & Architecture Defense:**
  1. **Check 8 Out-of-Band Authority Pinning:** External reference files in `reference_data/` are verified against SHA-256 digests and statutory bounds pinned in the auditor's independent `trusted_references.json` (`I1`, `B3`, `B8`).
  2. **Check 9 Physical Conservation Inequalities:** Pluggable conservation hooks cross-check physical telemetry against pinned reference caps—enforcing per-record mass conservation ($M_{\text{dry}, i} \le M_{\text{feedstock}, i}$), thermodynamic conversion ceilings (`biochar_max_dry_yield_bps <= 4000`), and cumulative delivery quotas ($\sum M_{\text{in}} \le M_{\text{delivered}}$) (`B1`, `B4`, `B15`, `B16`).

### 3.4 Class 4: Host OS Compromise ("Confused Deputy" Gateway Attack)
* **Universal Vulnerability:** A hardware secure element prevents private key extraction, but if an attacker compromises the gateway's Linux/RTOS host OS, the host CPU could feed synthetic payloads to the secure element for signing.
* **Engine & Architecture Defense:**
  1. **Check 2 Silicon Attestation Binding:** Verifies the cryptographic binding between `hardware_attestation.json` and the certified `device/public_key.pem`, with strict rejection of software stubs under `--require-hardware-attestation` (`I4`, `B7`, `B17`).
  2. **Hardware Secure Boot & Cabinet Tamper Zeroization:** In production hardware deployments (Milestone 2), the gateway MCU enforces ROM-anchored Secure Boot and chassis-intrusion microswitches that zeroize key slots upon unauthorized enclosure opening.

### 3.5 Class 5: Selective Stream Truncation & Cross-Audit Replay
* **Universal Vulnerability:** An operator drops unfavorable intervals/batches, or submits the exact same valid evidence bundle to two different registries or across two reporting periods to double-count credits/deductions.
* **Engine & Architecture Defense:**
  1. **Check 4 & Check 6 Hash-Chain & Boundary Binding:** Every observation links `prev_hash` from the genesis zero-hash (`sequence == 1`) to the `terminal_hash` sealed in `claim.json` (`O3`, `I3`, `I5`, `B5`).
  2. **Check 6 Cross-Claim Deduplication Ledger (`--claim-ledger`):** The verifier tracks claimed `claim_id`, `terminal_hash`, `batch_id`, and `(device_id, sequence)` tuples across audits, failing closed on any replay (`B14`).

---

## 4. The "Collusion-Forcing" Security Thesis

> **Core Axiom:** A cryptographic telemetry engine does not replace the laws of physics; instead, it **eliminates costless digital fraud** and forces any prospective attacker into high-cost, high-risk physical tampering or multi-party institutional collusion.
>
> * **Without Verifiable Telemetry (Spreadsheets / Unauthenticated Cloud DBs):** Fraud leaves **zero physical trace**. An insider edits a CSV cell, runs an `UPDATE` query, or cherry-picks a conversion factor.
> * **With the Universal Verifiable Telemetry Engine:** To forge a verified claim, an adversary must simultaneously:
>   1. Physically breach a sealed, tamper-monitored industrial gateway cabinet and defeat hardware key isolation (Checks 1–3).
>   2. Forge sequential hardware-signed hash-chains without breaking continuity or triggering replay ledgers (Checks 4–6).
>   3. Satisfy first-law physical conservation inequalities and thermodynamic yield ceilings evaluated in integer arithmetic (Check 9).
>   4. Collude with an external accredited authority (e.g., an ISO 17025 laboratory or national metrology body) whose report digests are pinned out-of-band by the auditor (Check 8).

---

## 5. Universal Scope Boundary Matrix

| Threat Class | Specific Attack Vector | In-Scope Engine & Profile Defense | Complementary Physical / Institutional Control |
|---|---|---|---|
| **Class 1: Sensor Spoofing** | PLC/SCADA register overwrite or sensor bypass | **Check 5 Continuity Hook:** Dual-register delta (`Δ cumulative_wh == interval_wh`) or thermal floor ($T_{\min} \ge 500^\circ\text{C}$) | Direct 2.5 kV isolated RS-485 wire tap ahead of PLC + multi-zone sensor placement |
| **Class 2: Metrology Drift** | Uncertified sensor or expired calibration | **Check 2 & 3 Metrology Binding:** Certifies EU MID / NAWI class and enforces `timestamp <= calibration_valid_until` | Physical lead seals and periodic calibration by accredited national metrology institutes |
| **Class 3: Reference / Input Fraud** | Emission factor swap, water-weight inflation, or fossil adulteration | **Check 8 Pinned Registry & Check 9 Conservation:** Pinned SHA-256 reference digests + integer mass/yield conservation traps | ISO 17025 accredited lab assays ($^{14}\text{C}$ dating, ICP-MS heavy metals, moisture) |
| **Class 4: Gateway Compromise** | Software key injection or host OS manipulation | **Check 2 Silicon Attestation:** Key-hash binding + `--require-hardware-attestation` enforcement | ATECC608B / TPM 2.0 hardware slot isolation, Secure Boot, cabinet tamper switches |
| **Class 5: Stream / Replay Fraud** | Dropping peak records or double-counting bundles across audits | **Check 4 & 6 Continuity & Ledger:** Genesis-anchored `prev_hash` chain + `--claim-ledger` cross-claim deduplication | External RFC 3161 timestamping / public transparency log anchoring |

---

## 6. Resolved Security Re-Audit Findings (`P1–P6`) & Residual Threat Surface

Following the October 2026 security re-audit, six proof-of-concept vulnerabilities (`P1–P6`) were remediated and locked down with automated regression tests (`04_experiments/security_reaudit/poc_exploits.py`):

1. **`P1` — Key Hygiene in Bundle (`Check 1`):** Private keys are stored strictly outside bundle directories (`src/device_simulator/keys/`). Check 1 scans both manifest entries and filesystem paths, failing closed if any file matches `*private*`, `*.key`, or contains PEM private key headers.
2. **`P2` — Public Key & Identity Binding (`Check 2`):** Check 2 verifies that `device/public_key.pem` is byte-for-byte identical to `certificate_body.device_public_key` and that `device_id` matches the canonical SHA-256 fingerprint of the public key.
3. **`P3` — Dynamic Calibration Expiry (`Checks 2 & 3`):** Check 3 compares every individual observation timestamp against the instrument's `calibration_valid_until` timestamp (covering MID meters, NAWI scales, and thermocouple modules).
4. **`P4` — Cross-Claim Replay Protection (`Check 6`):** Added `--claim-ledger <path>` and `--record-ledger` to `verify_bundle.py`, preventing any `claim_id`, `terminal_hash`, `batch_id`, or `(device_id, sequence)` tuple from being verified more than once.
5. **`P5` — Per-Record Conservation Enforcement (`Check 9`):** Check 9 enforces conservation inequalities on every individual batch/record ($M_{\text{dry}, i} \le M_{\text{feedstock}, i}$) in addition to period aggregates.
6. **`P6` — Pinned Thermodynamic Yield Ceilings (`Check 9`):** Added `methodology_parameters` to `trusted_references.json` (including `biochar_max_dry_yield_bps = 4000` and `min_pyrolysis_temp_c = 500`), preventing physically implausible conversion yields.

### Residual Risks & Planned Milestone Mitigations
* **Hardware X.509 Attestation Chain (Milestone 2):** Current simulators emit `"attestation_mode": "SIMULATED_STUB"` (flagged with an audit warning by default or rejected via `--require-hardware-attestation`). Full X.509 certificate chain validation anchored to Microchip/TPM manufacturer root CAs is scheduled for Milestone 2 hardware integration.
* **External Chronological Anchoring (Milestone 1/2):** While `prev_hash` prevents internal record deletion, tail truncation prior to sealing by a root-key holder requires external sequence commitments (`--expected-count`, `--prev-terminal-hash`, or RFC 3161 / transparency log anchoring).
* **Cross-Language Rust Verifier Parity (Milestone 3):** Full RFC 8785 JCS conformance vectors (`04_experiments/golden_test_vector/` and `04_experiments/golden_test_vector_biochar/`) anchor bit-for-bit verification parity for the standalone Rust verifier.
