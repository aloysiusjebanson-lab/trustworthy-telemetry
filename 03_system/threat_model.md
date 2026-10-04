# System Threat Model & Security Boundaries (v1.2)

> **Formal Threat Model, Adversary Capabilities, and Physical-to-Digital Security Boundaries for High-Durability Carbon Removals (EU CRCF) and Industrial Telemetry**

---

## 1. Adversary Model & Trust Assumptions

We formalize three distinct threat actors with asymmetric capabilities and economic motivations:

### Adversary A: Outsider Intermediary (Man-in-the-Middle, Rogue Cloud, Malicious Carrier)
* **Capabilities:** Can intercept network packets, read telemetry streams in transit, alter JSON/NDJSON records, inject replay packets, drop arbitrary rows, or manipulate unauthenticated metadata.
* **Limitations:** Does NOT hold the enterprise's private Producer Root Key and cannot extract private keys from the hardware Secure Element (ATECC608 in Silicon Slot 0).

### Adversary B: Dishonest Biochar Carbon Removal Producer (Carbon Credit Fraud)
* **Capabilities:** Holds the Producer Root Private Key, operates the plant data ingestion pipeline, runs the claim generator, controls the kiln SCADA/PLC software, and can seal evidence bundles with valid digital signatures.
* **Economic Motivations:** Carbon credits for high-durability carbon removals trade at **\$100–\$200 per metric ton of $\text{CO}_2$**. An operator has massive financial incentives to:
  * Spray biochar with water hoses prior to weighing to inflate gross tonnage.
  * Operate the pyrolysis kiln at low temperatures ($<500^\circ\text{C}$) to save fuel, producing non-permanent charcoal.
  * Forge or substitute laboratory test certificates to inflate organic carbon ($C_{\text{org}}$) or conceal high moisture.
  * Burn cheap fossil coal dust, tire crumbs, or toxic CCA-treated demolition lumber instead of certified sustainable forestry residues.
  * Double-count certified biomass deliveries beyond delivered quotas.
  * Silently drop failed or undercooked production batches.
* **Limitations:** Does NOT hold the secure element manufacturer's private CA keys and cannot forge hardware attestation certificates; cannot alter physical mass-balance conservation laws ($M_{\text{dry}} \le M_{\text{feedstock}}$); cannot modify independent laboratory assays pinned in the auditor's immutable registry (`trusted_references.json`).

### Adversary C: Dishonest Reporting Enterprise (Corporate Scope 2 Greenwashing)
* **Capabilities:** Holds the Company Root Private Key, operates the submetering ingestion pipeline, can modify internal energy databases, and can seal claim bundles.
* **Motivations:** Under-report Scope 2 greenhouse gas emissions for CSRD compliance (Directive 2022/2464/EU), avoid carbon border taxes (CBAM), achieve green building certifications (LEED/WELL) fraudulently, or shave industrial peak-demand curves.
* **Limitations:** Cannot forge MID Class B legal metrology certificates; cannot break dual-register mathematical agreement ($\Delta \text{cumulative\_wh} == \text{interval\_wh}$) without physical meter tampering; cannot alter national grid emission factor registries pinned by auditors.

---

## 2. Comprehensive Adversarial Attack Benchmark (25/25 Caught)

The architecture is validated against 25 automated adversarial attack vectors across three dedicated benchmark suites:

### 2.1 Biochar Pyrolysis dMRV Adversary Matrix (`src/attacks/biochar_attacks.py` — 10/10 Caught)

| ID | Attack Vector | Adversary Action | Cryptographic & Physical Defense | Verifier Check | Verdict |
|:---:|---|---|---|:---:|:---:|
| **B1** | **Water Spraying Fraud** | Drenches biochar with water; fakes lab moisture to claim high dry yield | Physical Mass Conservation Invariant: $M_{\text{dry}} \le M_{\text{feedstock}}$ violates thermodynamics | Check 9 | ❌ CAUGHT |
| **B2** | **Thermal Undercooking** | Pyrolyzes kiln at $T_{\min} < 500^\circ\text{C}$ to save electrical/gas fuel | Statutory EU CRCF Permanence Invariant: continuous $T_{\min} \ge 500^\circ\text{C}$ enforced | Check 5 | ❌ CAUGHT |
| **B3** | **Counterfeit Lab Report** | Replaces accredited lab report with fabricated high $C_{\text{org}}$ assay | Auditor Pinned Reference Registry: unpinned lab assay SHA-256 digest rejected | Check 8 | ❌ CAUGHT |
| **B4** | **Feedstock Cap Exhaustion** | Ingests batches consuming biomass beyond certified delivered quota | Cumulative Feedstock Quota Tracking: $\sum M_{\text{feedstock}} \le M_{\text{delivered\_quota}}$ | Check 9 | ❌ CAUGHT |
| **B5** | **Dropped Batch / Omission** | Silently deletes cold or low-yield production batches | Sequential Hash-Chain Continuity: breaks $H_n = \text{SHA-256}(H_{n-1} \mathbin{\Vert} \text{batch}_n)$ | Check 4 | ❌ CAUGHT |
| **B6** | **Non-Certified Scale** | Replaces certified weighing indicator with uncalibrated commercial scale | EU Directive 2014/31/EU NAWI Class III legal metrology binding | Check 2 | ❌ CAUGHT |
| **B7** | **Software Key Forgery** | Simulates edge gateway using uncertified software OpenSSL key | Microchip ATECC608 Hardware Attestation certificate chain verification | Check 2 | ❌ CAUGHT |
| **B8** | **Uncertified Biomass** | Uses timber from illegal clear-cutting without EBC certification | EBC Positive List validation (`EBC-1.1-FOREST`) against pinned manifest registry | Check 8 | ❌ CAUGHT |
| **B9** | **Numeric Claim Inflation** | Hand-edits declared removal claim from 20.5 tonnes to 25.0 tonnes | Recomputed Stoichiometry: zero-tolerance match with declared `claim.json` | Check 10 | ❌ CAUGHT |
| **B10** | **Revoked Kiln Gateway** | Re-submits telemetry from compromised or decommissioned gateway | Pinned `--revoked` device list enforcement | Check 2 | ❌ CAUGHT |

### 2.2 Outsider Adversary Matrix (`src/attacks/outsider_attacks.py` — 10/10 Caught)

| ID | Attack Vector | Adversary Action | Cryptographic Defense | Verifier Check | Verdict |
|:---:|---|---|---|:---:|:---:|
| **O1** | **Falsified Reading Value** | Modifies kWh / mass payload in transit | NIST P-256 ECDSA observation signature verification failure | Check 3 | ❌ CAUGHT |
| **O2** | **Rogue Uncertified Key** | Signs forged observation with attacker-generated public key | Producer Root Certificate chain validation failure | Check 2 | ❌ CAUGHT |
| **O3** | **Dropped Middle Record** | Deletes peak interval reading to reduce declared consumption | Monotonic sequence check and sequential hash-chain break | Check 4 & 5 | ❌ CAUGHT |
| **O4** | **Duplicate Replay Record** | Replays previous low-carbon reading | Sequence monotonicity and duplicate detection | Check 5 | ❌ CAUGHT |
| **O5** | **Envelope Device ID Swap** | Changes `device_id` field in envelope to disguise origin | Public key fingerprint mismatch vs certified identity | Check 2 & 3 | ❌ CAUGHT |
| **O6** | **Timestamp Validity Breach** | Injects readings before certificate issuance or after expiration | Temporal window check vs certificate `valid_from` / `valid_until` | Check 3 | ❌ CAUGHT |
| **O7** | **Re-Hashed Manifest Bypass** | Modifies bundle payload, recalculates manifest SHA-256, but lacks root key | Producer Root Bundle Seal signature verification failure | Check 1 | ❌ CAUGHT |
| **O8** | **Path Traversal Injection** | Injects `../../etc/shadow` in manifest file paths | Strict relative path schema validation and jail enforcement | Check 1 | ❌ CAUGHT |
| **O9** | **Unmanifested File Injection**| Drops backdoor script or extra unmanifested telemetry file | Zero-tolerance directory inventory reconciliation | Check 1 | ❌ CAUGHT |
| **O10**| **Revoked Gateway Rejection** | Attempts audit verification using compromised device key | Pinned `--revoked` device blacklist enforcement | Check 2 | ❌ CAUGHT |

### 2.3 Insider Corporate Fraud Matrix (`src/attacks/insider_fraud_suite.py` — 5/5 Caught)

| ID | Attack Vector | Adversary Action | Cryptographic & Mathematical Defense | Verifier Check | Verdict |
|:---:|---|---|---|:---:|:---:|
| **I1** | **Emission Greenwashing** | Swaps grid emission factor to 0.05 and reseals bundle with valid root key | Auditor Pinned Reference Registry (`trusted_references.json`) | Check 8 | ❌ CAUGHT |
| **I2** | **Dual-Register Shaving** | Lowers interval Wh while running meter totalizer advances | Dual-Register Delta Invariant: $\Delta \text{cumulative\_wh} == \text{interval\_wh}$ | Check 5 | ❌ CAUGHT |
| **I3** | **Period Truncation** | Drops peak production shifts at shift ends and reseals | Claim Boundary Bounds: declared period timestamps & sequence bounds | Check 6 | ❌ CAUGHT |
| **I4** | **Software Simulator Key** | Generates software keys to fabricate clean data without hardware | Silicon Hardware Attestation: requires Microchip factory CA cert | Check 2 | ❌ CAUGHT |
| **I5** | **Telemetry Splicing** | Stitches non-consecutive days together across maintenance shut-downs | Sequential Hash-Chain Continuity: `prev_hash` break across splice | Check 4 | ❌ CAUGHT |

---

## 3. Physical-to-Digital Boundaries: Engineering Out Real-World Scams

Hardware-secured dMRV must protect the physical-to-digital seam where analog physics meets digital cryptography:

### 3.1 "The Last Foot" Vulnerability: Analog Sensor Spoofing
* **Vulnerability:** Silicon crypto chips (ATECC608) fail at $>125^\circ\text{C}$ and cannot survive inside a $650^\circ\text{C}$ rotary pyrolysis kiln. Thermocouples (Type-K) are analog, transmitting millivolt signals over unencrypted wires. An attacker could plug a Modbus simulator into the wire or apply a blowtorch to the probe tip while the rest of the kiln runs cold.
* **Engineering Defense:**
  1. **Direct Safe-Zone Wire Tapping:** The edge gateway resides inside the locked electrical control cabinet in the safe zone ($<55^\circ\text{C}$). It taps the RS-485 Modbus RTU loop directly from the transmitter with 2.5 kV galvanic isolation, completely bypassing the plant SCADA/PLC software to prevent register overwrites.
  2. **Multi-Zone Sensor Fusion:** Thermocouples are installed across multiple hearth zones (inlet, core pyrolysis, outlet). Temperature readings are correlated in real time with draft fan amperage (ID fan kW) and differential hearth pressure. A localized blowtorch or detached probe breaks the aerodynamic-thermal correlation, triggering an immediate anomaly flag.
  3. **Check 5 Invariant:** Continuous $T_{\min} \ge 500^\circ\text{C}$ is enforced across every single batch without exception.

### 3.2 "Garbage In" Problem: Feedstock Fraud
* **Vulnerability:** Scales measure gravitational weight, not molecular composition. An operator could blend fossil coal dust, tire crumbs, or toxic CCA-treated demolition lumber into the biomass conveyor.
* **Engineering Defense:**
  1. **Authoritative Reference Pinning (Check 8):** Lab assay SHA-256 digests are pinned in the auditor's independent registry (`trusted_references.json`).
  2. **$^{14}\text{C}$ Radiocarbon Isotopic Dating:** Biogenic plants absorb atmospheric $^{14}\text{C}$ during photosynthesis ($100\%\text{ Fraction Modern Carbon}$). Ancient fossil coal has zero $^{14}\text{C}$ due to radioactive decay (half-life 5,730 years). Any fossil blending is detected immediately by the ISO 17025 laboratory.
  3. **ICP-MS Heavy Metal & Preservative Screening:** Demolition wood treated with toxic Chromated Copper Arsenate (CCA) or creosote is caught by mandatory ISO 17025 ICP-MS screening ($<10\text{ mg/kg}$ As, $<50\text{ mg/kg}$ Cu, $<1\text{ mg/kg}$ Cd).
  4. **Feedstock Delivery Quota Capping (Check 9):** Verified batches track delivered quota manifests, preventing "ghost-truck" double billing.

### 3.3 "Confused Deputy" Attack: Gateway OS Compromise
* **Vulnerability:** An ATECC608 secure element protects private keys from extraction, but the host processor (running Linux/RTOS) tells the ATECC608 what payload to sign.
* **Engineering Defense:**
  1. **Hardware Secure Boot:** The host processor's bootloader cryptographically verifies the digital signature of the kernel and firmware against a ROM-fused manufacturer key prior to execution.
  2. **Physical Tamper Detection & Key Zeroization:** The edge gateway is housed inside a locked electrical cabinet equipped with chassis intrusion microswitches. If the cabinet door or enclosure is opened without cryptographic authorization, the secure element immediately triggers hardware zeroization, permanently erasing its private keys.

### 3.4 Downstream Leakage: The End-Use Blind Spot
* **Vulnerability:** If biochar is pyrolyzed cleanly but then sold to a third party and burned as barbecue charcoal or metallurgical fuel, all sequestered carbon is immediately re-released into the atmosphere.
* **Engineering Defense:**
  1. **W3C PROV-O Lineage Extension:** Digital chain of custody extends from factory loading dock to agricultural soil application.
  2. **Verified Soil Application Manifests:** Final carbon credit retirement requires binding cryptographically signed delivery receipts and GPS-stamped tractor spreader telemetry proving that the biochar was blended into agricultural soils or permanent construction materials (e.g. concrete).

---

## 4. The "Collusion-Forcing" Security Thesis

> **Core Axiom:** Verifiable Telemetry does not claim to replace physical reality. Instead, it fundamentally changes the economics and operational feasibility of fraud:
>
> * **Traditional System (Spreadsheets / Databases):** Fraud requires **zero physical traces**. An insider alters an Excel cell, changes an unauthenticated database row, or re-exports a CSV.
> * **Verifiable Telemetry Architecture:** Fraud is elevated to **criminal hardware tampering or multi-party institutional collusion**. To fraudulently mint a carbon credit, an adversary must:
>   1. Physically break into a locked, tamper-monitored electrical cabinet.
>   2. Defeat hardware secure boot and bypass 2.5 kV isolated RS-485 taps.
>   3. Violate first-law thermodynamic mass conservation ($M_{\text{dry}} \le M_{\text{feedstock}}$).
>   4. Bribe an independent, accredited ISO 17025 laboratory (Eurofins) to falsify radiocarbon dating and heavy metal assays.
>   5. Forge cryptographically signed biomass delivery manifests from certified forestry suppliers.

---

## 5. Scope Boundary Matrix: What dMRV Enforces vs Physical Controls

| Fraud Vector | Can Software / Math Alone Solve It? | In-Scope dMRV Cryptographic Defense | Complementary Physical / Metrological Control |
|---|:---:|---|---|
| **Water Spraying (Moisture Fraud)** | No (cannot stop physical water hoses) | **Net Dry Mass Formula** ($M_{\text{dry}} = M_{\text{wet}} \times (1 - \text{moist})$) + **Mass Conservation Trap** ($M_{\text{dry}} \le M_{\text{feedstock}}$) | Composite sampling under ISO 17025 accredited laboratory protocol |
| **Cold Kiln Undercooking ($T < 500^\circ\text{C}$)** | Yes | **Check 5 Invariant:** Continuous $T_{\min} \ge 500^\circ\text{C}$ signed at source; fails closed | Direct Modbus RS-485 tap inside safe-zone cabinet + Multi-Zone Sensor Fusion |
| **Fossil Coal Dust Adulteration** | No (scales measure mass, not chemistry) | **Check 8 Pinned Reference Match:** Lab assay digest pinned in auditor registry | ISO 17025 $^{14}\text{C}$ radiocarbon dating (detects 0% modern carbon in fossil fuels) |
| **Toxic Demolition Wood (CCA Treated)** | No (scales measure mass, not chemistry) | **Check 8 & 9 Delivery Quota:** Pinned EBC positive list supplier + usage cap | ISO 17025 ICP-MS heavy metal screening (strict limits on As, Cu, Cr) |
| **Scale Drift / Cheap Fake Scales** | Yes | **Check 2 Metrological Pedigree:** EU Directive 2014/31/EU NAWI Class III certificate binding | Annual physical calibration by national metrology bodies (stamped lead seals) |
| **Dropping Failed / Cold Batches** | Yes | **Check 4 Hash-Chain Continuity:** Sequential `prev_hash` links prevent record dropping | Monotonic hardware sequence counters locked in ATECC608 silicon |
| **Post-Hoc Spreadsheet / DB Edits** | Yes | **Check 1 Bundle Seal:** Producer Root signature over canonical SHA-256 manifest | eIDAS Qualified Electronic Seal / enterprise PKI trust anchor |
| **Sensor Cable Disconnection / Spoofing** | Partial | **Direct Cabinet Tapping:** Bypasses SCADA software registers; 2.5 kV galvanic isolation | Armored conduit, locked cabinet, chassis intrusion tamper switches |
| **End-Use Combustion (BBQ Burning)** | No (factory cannot police customer usage) | **W3C PROV-O Graph:** Lineage tracking downstream to delivery manifest | GPS-tracked tractor spreader telemetry & verified soil application receipts |
