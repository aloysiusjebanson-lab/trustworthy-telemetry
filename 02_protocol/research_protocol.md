# Research Protocol

**Status:** Draft — freeze at the end of Week 2  
**Version:** 0.1

## Working title

From Measurement to Carbon Claim: End-to-End Verifiable Provenance for Building Sustainability Data

## Central question

To what extent can protected measurement identity and verifiable software transformations establish an independently reproducible chain of evidence from electricity measurements to operational-carbon claims?

## Research questions

- **RQ1 — Assurance coverage:** Which claim dependencies can be verified across acquisition, storage, processing, and reference-data use?
- **RQ2 — Attack detection:** Which defined attacks are detected by conventional telemetry, source authentication, and full-chain provenance?
- **RQ3 — Overhead:** What computation, latency, message-size, storage, and throughput overhead does each assurance level introduce?
- **RQ4 — Boundaries:** Which physical, firmware, contextual, and metrological properties remain outside the demonstrated trust boundary?

## Intended contribution

The system provides independently verifiable evidence of the declared origin and integrity of measurement records, preserves traceability through subsequent computational transformations and reference-data inputs, and enables independent reproduction of the resulting carbon claim while explicitly identifying physical and metrological properties outside the cryptographic trust boundary.

## Baselines

- **A — Conventional:** measurement → transport/storage → calculation → claim
- **B — Source authenticated:** measurement → signed observation → storage → calculation → claim
- **C — Full provenance:** signed observation → verified storage → versioned transformations → versioned emission factor → claim bundle → independent verifier

## Primary outcomes

- Attack detection by family and baseline
- False acceptance and false rejection
- Exact claim recomputation result
- Observation signing and verification latency
- Evidence size and storage overhead
- Pipeline throughput
- Stream completeness reporting
- Assurance-coverage table with explicit residual risks

## Scope

One low-voltage electricity measurement stream, one aggregation pipeline, one declared emission-factor input, and one operational-carbon claim.

## Explicit non-claims

- The secure element does not attest correct MCU firmware.
- Signatures do not establish sensor accuracy or calibration.
- Provenance does not establish correct physical placement or absence of bypass.
- Emission-factor provenance does not establish scientific correctness of the factor.
- This prototype does not demonstrate production-scale building integration.

## Analysis principles

- Predefine attack success and detection criteria before running final experiments.
- Preserve raw results and generate tables/figures by script.
- Report uncertainty and failed trials.
- Distinguish detected malicious manipulation from ordinary data loss or device failure.
- Avoid a weighted “trust score”; report evidence coverage property by property.

## Protocol deviations

Record any post-freeze deviation here with date, reason, and effect on interpretation.

