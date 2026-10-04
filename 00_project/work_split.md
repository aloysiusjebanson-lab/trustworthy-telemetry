# Work Split and Heavy-Lifting Map

## Work Codex can perform now

- Design and run structured web searches using accessible scholarly and standards sources.
- Build and maintain the literature evidence matrix.
- Extract comparable claims, implementations, evaluation methods, and gaps from available papers.
- Draft the gap statement, research protocol, threat model, assurance model, and paper sections.
- Design schemas and deterministic claim-bundle formats.
- Implement the three software baselines, verifier, corruption tools, and automated tests.
- Automate experiments, analysis, statistical summaries, tables, and figures.
- Check consistency between research questions, methods, results, and claims.
- Prepare reproducibility instructions and submission materials.

## Work that requires the researcher

- Provide legally obtained full text for important paywalled papers when institutional access is required.
- Approve the final research question, scope, contribution claims, and journal.
- Purchase, receive, assemble, and physically connect optional hardware.
- Perform or supervise physical measurements and record environmental/experimental facts.
- Obtain access to borrowed reference equipment or laboratory facilities.
- Confirm authorship, affiliations, acknowledgements, funding, conflicts, and ethics requirements.
- Make all submission-account declarations and submit the manuscript.

## Joint work

- Decide whether the Week-1 novelty gap survives.
- Interpret unexpected results and distinguish bugs from findings.
- Review whether statements exceed the evidence.
- Select what can be released publicly and what must be redacted.

## Heavy-lifting estimate

| Work package | Main owner | Relative effort | Schedule risk |
|---|---|---:|---:|
| Closest-literature screening and gap synthesis | Codex + researcher access | High | High |
| Formal threat/assurance model | Codex, researcher approval | Medium | Medium |
| Software and independent verifier | Codex | High | Medium |
| Automated attack framework | Codex | High | Medium |
| Hardware assembly and troubleshooting | Researcher with Codex guidance | Medium | High |
| Experiment execution and quality control | Joint | High | Medium |
| Statistical analysis and figures | Codex | Medium | Low |
| Manuscript drafting and revision | Codex + researcher judgment | High | Medium |

The most difficult intellectual task is demonstrating novelty against the closest systems. The most difficult engineering task is producing a simple, deterministic verifier whose results survive intentional corruption and independent reproduction.

