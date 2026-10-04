# Rapid Structured Literature Review Protocol

## Review question

Which existing systems preserve independently verifiable evidence from physical sustainability measurements through computational transformations and external reference data to a reproducible building-carbon claim, and how have they been evaluated adversarially?

## Search streams

Run searches in five streams:

1. IoT sensor-data provenance and secure sensing
2. Hardware-backed device identity and signed measurements
3. Building energy/carbon data quality and MRV
4. Scientific-workflow and transformation provenance
5. Calibration, physical context, and assurance limitations

## Core concept blocks

Combine terms from these blocks and record the exact query in `search_log.csv`.

- Domain: `building`, `built environment`, `energy`, `operational carbon`, `sustainability`, `MRV`
- Source: `IoT`, `sensor`, `meter`, `telemetry`, `physical measurement`
- Assurance: `provenance`, `attestation`, `authentication`, `integrity`, `chain of custody`, `verifiable`
- Processing: `workflow provenance`, `transformation provenance`, `reproducible`, `data lineage`
- Evaluation: `attack`, `adversarial`, `tamper`, `replay`, `substitution`, `threat model`

## Sources

Prioritize Scopus, Web of Science, IEEE Xplore, ACM Digital Library, ScienceDirect, SpringerLink, Crossref, and Google Scholar for discovery. Use official standards sources for standards, but do not count standards as peer-reviewed evidence.

## Inclusion criteria

- Peer-reviewed journal or full conference paper, plus separately tracked authoritative standards.
- Direct relevance to at least one link in the measurement-to-claim chain.
- Sufficient technical detail to classify implemented assurance properties.
- English full text available for closest-study assessment.

## Exclusion criteria

- Pure blockchain proposals with no relevant source or processing assurance.
- Generic smart-building security without measurement or claim provenance.
- Pure sustainability analytics with no data-lineage or integrity mechanism.
- Abstract-only records when full text is needed to determine equivalence.
- Nontechnical opinion pieces.

## Screening procedure

1. Deduplicate records.
2. Screen title and abstract.
3. Read full text for included and near-equivalent studies.
4. Populate every evidence column with `yes`, `partial`, `no`, or `unclear`.
5. Record page/section evidence in notes; do not infer a capability from terminology alone.
6. Backward- and forward-snowball the five closest studies.

## Stop rule

Stop the rapid phase when all conditions hold:

- At least 20 closest studies have been fully classified.
- The five closest studies have been snowballed.
- Two consecutive searches add no materially closer architecture.
- The novelty statement can be written without relying on absence-by-assumption.

## Gate G1 questions

- Does any study cover authenticated physical origin, processing provenance, external reference-data provenance, independent recomputation, and adversarial evaluation together?
- If yes, what assurance property or evaluation dimension remains genuinely missing?
- Is the remaining gap important enough for a full research article?
- Can it be tested with the available time and budget?

