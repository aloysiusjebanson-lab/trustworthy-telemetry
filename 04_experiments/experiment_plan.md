# Experiment Plan

**Status:** Draft — freeze at the end of Week 2

## Experimental factors

- Baseline: A, B, C
- Attack family: source, stream/storage, processing, sustainability input/bundle
- Attack instance: predefined mutation configuration
- Data source: deterministic synthetic, trace replay, optional physical device
- Sampling and batch configuration: to be frozen

## Attack families

### 1. Source attacks

- Modify a reading after origin
- Replay a valid reading
- Substitute device identity

### 2. Stream and storage attacks

- Delete records
- Reorder records
- Alter stored records

### 3. Processing attacks

- Change aggregation or cleaning parameters
- Substitute calculation code

### 4. Sustainability-input and bundle attacks

- Replace the emission-factor file or metadata
- Modify the final evidence bundle

Physical relocation is a residual-risk demonstration/discussion, not a digitally detectable attack target.

## Detection definition template

For each attack specify:

- files/records mutated;
- adversary knowledge;
- expected baseline behavior;
- machine-readable detection criterion;
- false-positive control;
- number of independent trials or deterministic cases;
- expected and observed result.

## Metrics

- Detection count/rate by attack and family
- False acceptance and rejection
- Signing and verification latency
- End-to-end verification time
- Bytes per observation and per claim bundle
- Storage increase relative to baseline A
- Sustainable observations per second
- Duplicate, gap, and reorder reporting
- Absolute/relative recomputation difference

## Reproducibility

Every run receives an immutable ID, configuration file, software revision, input hashes, environment description, start/end timestamps, and raw output path.

