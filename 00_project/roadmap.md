# Eight-Week Roadmap

## Definition of done

The project is submission-ready when it has:

- a defensible novelty matrix;
- a frozen research protocol and threat model;
- three implemented baselines;
- a verifier that independently recomputes a carbon claim;
- reproducible attack and overhead experiments;
- a small hardware demonstration if the Week-1 gap survives;
- a complete manuscript and archived research artifact.

Publication itself is not an eight-week deliverable because peer-review timing is outside the project team's control.

## Week 1 — Novelty gate

- Screen the 20–30 closest peer-reviewed studies.
- Search backward and forward from the closest five studies.
- Complete the evidence columns in `01_literature/literature_matrix.csv`.
- Write a one-page gap statement.
- Decide whether the hardware-to-claim plus adversarial-evaluation gap survives.

**Gate G1:** Do not purchase hardware until the gap is confirmed.

## Week 2 — Protocol freeze

- Finalize research questions and contribution claims.
- Freeze the trust boundary, adversary model, baselines, attacks, metrics, and analysis.
- Define the evidence-bundle schema and verifier acceptance rules.
- Choose the target journal based on the confirmed contribution.

**Gate G2:** No new features after the protocol is frozen.

## Week 3 — Software spine

- Implement observation generation, signing, storage, aggregation, emission-factor lookup, and carbon calculation.
- Implement conventional telemetry baseline A.
- Implement source-authenticated baseline B.
- Create deterministic test fixtures.

## Week 4 — Full evidence pipeline

- Implement baseline C with transformation and reference-data provenance.
- Implement the independent verifier.
- Create valid and deliberately corrupted claim bundles.
- Add automated verification tests.

## Week 5 — Minimal hardware

- Integrate a safe low-voltage sensor, MCU, and protected signing key if G1 passed.
- Record hardware configuration and firmware version.
- Measure signing latency, observation size, and collection reliability.
- Retain a software-only path if hardware integration becomes a schedule risk.

## Week 6 — Experiments

- Execute the four attack families across all baselines.
- Run overhead, throughput, completeness, and reproducibility experiments.
- Preserve immutable run manifests and raw results.

## Week 7 — Analysis and writing

- Generate statistical results, tables, and figures from scripts.
- Write methods and results first, followed by introduction and discussion.
- Report residual physical and metrological risks explicitly.

## Week 8 — Independent reproduction and submission

- Ask an independent person to run the verifier from the instructions.
- Freeze the code, data, environment, and manuscript versions.
- Assemble the artifact and supplementary materials.
- Submit the paper and optionally archive a policy-compliant preprint.

## Weekly operating rhythm

- Monday: update status and select no more than three outcomes.
- During the week: record every material decision and experiment run.
- Friday: assess evidence produced, risks, and the next gate.
- Never count an activity as complete without a file, result, or recorded decision.

