# From Sensor to Sustainability Claim: Can We Trust the Data in Between?

### Sensors drop offline, ingestion pipelines transform readings, and downstream reports may have no way to prove the original evidence was preserved.

---

A commercial building with just fifty submeters recording a single value every fifteen minutes generates more than 1.75 million timestamped observations per year.

Electricity submeters track power quality and circuit-level consumption. Thermal Btu meters monitor hydronic heating and cooling loops. Indoor environmental sensors track CO₂, particulate matter, and humidity. These observations travel through fieldbuses, network gateways, MQTT brokers, APIs, and ingestion pipelines before eventually appearing in building management systems, certification dossiers, and corporate sustainability disclosures.

Across Europe, building-performance data is becoming central to compliance, third-party verification, and capital allocation. Frameworks such as the Corporate Sustainability Reporting Directive (CSRD) and the Energy Performance of Buildings Directive (EPBD) are elevating the scrutiny around operational efficiency, while asset owners deploy dense networks of connected instruments to measure their footprint.

Yet behind these digital systems lies a fundamental question we rarely ask:

**Can we actually prove that a number in a sustainability report is directly connected to the physical instrument that originally measured it?**

A database may have clean timestamps. A dashboard may show smooth, continuous trends. A compliance submission may contain verified formulas. 

Yet along that journey, data can be lost, estimated, adjusted, aggregated, or otherwise transformed.

This doesn't imply fraud. Most transformations are legitimate, well-intentioned, and practically necessary to keep systems running. But without a verifiable chain of evidence, it becomes almost impossible to distinguish an authentic physical measurement from a perfectly plausible reconstruction of one.

---

## 1. The Operational Reality of Missing Telemetry

To capture the true operational footprint of a facility, companies deploy sensor networks across multiple communication layers. But in large multi-site deployments, some degree of missing telemetry is an inevitable operational reality.

The scale of data loss varies significantly depending on network topology, device maintenance, and site conditions:
* Electrical submeters communicating over Modbus RTU/TCP suffer from serial bus noise, loose screw terminals, or power interruptions during switchboard maintenance.
* Thermal Btu meters on heating and cooling loops experience M-Bus polling timeouts or bus power drops.
* Indoor air quality (IAQ) monitors transmitting over LoRaWAN lose packets due to structural concrete attenuation or duty-cycle constraints.

Consider a multi-site commercial or retail portfolio across European cities. Between cellular gateway reboots, local network drops, and routine electrical servicing, intervals go missing.

Missing data isn't the surprising part. Anyone who has operated a large sensor network expects it. What matters is whether those gaps remain visible once the data reaches reporting systems.

---

## 2. The Upstream Transformation Problem

In real-world implementations, missing telemetry creates immense pressure—from monthly reporting deadlines, tenant SLA dashboards, and annual submission targets—to produce continuous, usable datasets.

Software platforms and reporting pipelines must handle messy data. But that handling introduces a major integrity challenge: it happens upstream, before the data is committed to storage.

> **A perfectly audited database cannot prove the integrity of data before it entered the database.**

Before telemetry lands in a central PostgreSQL, InfluxDB, or Timescale database, it passes through an intermediate transit stack: edge gateways, message queues, APIs, and Python ETL scripts. If you've ever built one of these pipelines, you know how much logic can quietly accumulate between the sensor and the database. A standard defensive fallback—such as repeating the last valid reading during a gateway timeout so an ingestion worker doesn't crash—can inadvertently turn a multi-day network outage into a flatline that passes as legitimate low-variability data to anyone who isn't specifically looking for gaps.

Other adjustments happen just as invisibly:
* Automated smoothing: An ETL pipeline interpolates across an extended outage, potentially masking genuine operational peaks.
* Offset adjustments: A script applies a calibration factor or multiplier without preserving the adjustment logic and supporting evidence.
* Selective filtering: A poorly designed quality-control rule classifies legitimate extreme readings as telemetry noise and removes them before database insertion.

None of these examples necessarily imply bad faith. The integrity challenge arises because a downstream reviewer cannot distinguish what the instrument originally observed from what the data pipeline subsequently reconstructed, corrected, or removed.

Because these transformations take place before the database write, the stored records look completely authentic. They carry clean timestamps, valid schemas, and plausible values—but without preserved provenance, a later reviewer has no way to reconstruct what happened upstream.

---

## 3. The Audit Visibility Gap

By the time this data travels into downstream sustainability workflows, the original operational roughness has been completely erased.

It is helpful here to separate three distinct reporting streams that are often conflated:
1. Building certifications (such as BREEAM In-Use, LEED, WELL, or RESET Air), which evaluate asset-level design, operational performance, and indoor environmental quality.
2. Building energy regulations (such as national implementations of the EPBD), which govern operational energy performance, statutory boiler/chiller inspections, and Energy Performance Certificate (EPC) registries.
3. Corporate sustainability disclosures (such as CSRD / ESRS E1), which require organization-wide accounting of environmental impacts and operational emissions.

Each of these frameworks relies on professional verification: BREEAM licensed assessors compile detailed evidence dossiers; EPBD compliance depends on accredited independent inspectors; and CSRD disclosures will be subjected to external limited assurance by statutory auditors under standards like ISAE 3000.

These professionals do rigorous work: they inspect single-line diagrams, review calibration certificates, evaluate sampling methodologies, examine utility invoices, and cross-check engineering calculations.

The blind spot is what happens inside custom or proprietary telemetry pipelines before the evidence package was compiled. Even a thorough document-based audit has limited visibility into that upstream layer.

An auditor can verify that the submitted spreadsheet matches approved calculation guidelines, that the equipment exists on site, and that the numbers appear mathematically consistent. But they rarely have cryptographic proof that every reported interval originated unchanged from the physical instrument.

The system verifies the methodology and documentation of the claim, but the digital chain of custody remains broken.

---

## 4. Closing the Gap: Device Identity and the Three Layers of Trust

If building sustainability reporting is to approach the evidentiary rigor expected of financial reporting, we need an evidence architecture that verifies origin, transformation, and lineage.

A credible technical framework should rest on three principles:

### 1. Hardware-Protected Identity at the Edge
Readings should not travel through gateways as plain, unauthenticated payloads.

In brownfield commercial buildings, existing Modbus and M-Bus meters cannot cryptographically sign their own readings. In practice, a hardened edge gateway or secure data logger must provide the initial trusted boundary, signing observations as they are acquired from fieldbuses using a hardware-protected private key stored in a secure element. 

This does not make legacy fieldbus communication cryptographically trustworthy end-to-end. A gateway can only attest to the data it received at its own serial interface; physical bus security and gateway hardening remain essential parts of the trust model. However, once an observation is signed at that gateway boundary, downstream message brokers, cloud queues, and Python ETL scripts cannot alter the payload in transit without immediately invalidating the cryptographic signature.

### 2. Version-Controlled Transformation Manifests
Data cleaning, gap-handling, and unit conversions are often legitimate engineering necessities. What must change is doing them invisibly.

Every material transformation should be reproducible, version-controlled, and attributable to a specific version of code and reference data. An auditable evidence package should cryptographically bind:
* The signed raw instrument observations,
* The exact version and cryptographic hash of the transformation code,
* The declared metadata and conversion parameters, and
* The recomputed claim.

### 3. Acknowledging the Three Layers of Trust
There is an equally important distinction to keep in mind: **digital provenance is not the same as physical truth.** 

A complete trust framework must separate three distinct questions:

* **Authenticity (Device Identity):** *Did this specific device produce this digital observation?* Addressed through hardware-protected keys and digital signatures at the edge.
* **Integrity (Data Lineage):** *Was the observation altered in transit or storage?* Addressed through cryptographic hashing, versioned transformation manifests, and tamper-evident logs.
* **Measurement Validity (Physical Reality):** *Was the physical measurement actually correct?* Addressed through physical commissioning, proper instrument placement, and periodic calibration.

A valid cryptographic signature proves that a specific trusted device or gateway produced or recorded a digital observation, and that the signed record was not altered after signing. (For instruments with native hardware-protected identities, that trust boundary moves directly to the sensor itself.)

What it cannot prove is whether the instrument was installed in the correct location, whether a current transformer was clamped onto the wrong phase, or whether an indoor air sensor has drifted out of calibration.

Digital integrity must therefore complement—not replace—calibration, commissioning, and on-site physical verification.

---

## The Next Step for Building Data

The tools to close this gap already exist in other industries: financial audit trails, supply-chain custody chains, and version-controlled software releases.

The question isn't whether the technology exists—it already does. What remains to be seen is whether the building sustainability sector is willing to hold its operational telemetry to the same standard of evidence that it applies to its financial disclosures and engineering models.

Until we build that chain of custody, our sustainability claims will remain vulnerable—not because the buildings are failing, but because our evidence cannot prove what happened to it along the way.

---

*I research data architectures, physical-to-digital telemetry integrity, and verifiable sustainability claims. If you work in building operations, IoT engineering, or ESG assurance, I welcome your thoughts and critique in the comments.*
