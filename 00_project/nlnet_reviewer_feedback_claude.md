# External Technical Review & Gap Analysis: NLnet Restack Application

**Source:** Claude (Senior Reviewer & Systems Security Architect Persona)  
**Date Received:** October 22, 2026  
**Application Target:** NLnet Restack Fund (Call 1 — Horizon Europe Grant Agreement No. 101299072)  
**Focus:** Codebase audit vs. application claims, Restack fit, technical threat model, milestones, and proposal text.

---

## Raw Review Text

```text
Review: Verifiable Telemetry Engine, NLnet Restack application

I checked the claims in the draft against the repo, because a technical reviewer will click the GitHub link. That check turned up the most serious problems, so I start with it.

0. Problems a reviewer will find in the repo

Claim in the draft: "Silicon attestation" and --require-hardware-attestation
What the code does: The attestation is a JSON file with plain-text fields. The
verifier compares two strings and rejects only when attestation_mode ==
"SIMULATED_STUB". Writing "attestation_mode": "HARDWARE" gets past it. No
certificate chain to Microchip is checked.
Where: src/verifier/verify_bundle.py:357-367
────────────────────────────────────────
Claim in the draft: A fake attestation file
What the code does: The golden vector names "signer": "Microchip Technology
Production Root CA" and "attestation_status":
"verified_hardware_secure_element", yet it is a stub. To a reviewer, this
looks like the project is presenting a simulation as a real vendor
attestation.
Where: claim_bundle/device/hardware_attestation.json
────────────────────────────────────────
Claim in the draft: "7 universal core checks + 3 pluggable hooks"
What the code does: No shared core exists. SUPPORTED_PROFILE_DRIVERS passes the
whole job to one of two separate verifiers of about 750 lines each
(verify_biochar_bundle, verify_energy_bundle). The core logic is copied into
both, and the copies have already drifted apart: each expects a different
attestation status string (SILICON_HARDWARE_VERIFIED vs
verified_hardware_secure_element).
Where: :147, :890, :358 vs :1079
────────────────────────────────────────
Claim in the draft: The bundle decides which rules apply to it
What the code does: The profile is read from claim.json or manifest.json inside
the bundle, and defaults to energy. The auditor should choose the profile,
not the party being audited.
Where: :1662-1676
────────────────────────────────────────
Claim in the draft: "RFC 8785 (JCS)"
What the code does: The code is json.dumps(sort_keys=True, separators=…), which
is not JCS. Key order and number/Unicode serialisation differ from the RFC.
The output happens to match today only because you use integers and ASCII
keys. Your Rust port will implement real JCS, so this is exactly the
cross-language mismatch that M3 is supposed to prevent.
Where: :85-87
────────────────────────────────────────
Claim in the draft: "No floating point anywhere"
What the code does: The verifier calls float() on emission factors and accepts
float as a type for some fields.
Where: :725, :1442, :1453
────────────────────────────────────────
Claim in the draft: A mature project
What the code does: The repo has about 4.2k lines of Python, one contributor,
and all commits fall between Oct 4 and Oct 17. Simulated bundles are
duplicated at the repo root and inside 04_experiments/. There are
Medium/illuminem article drafts and a file named
bulletproof_hardening_tracker.md. Overall it reads as a research notebook,
not an engine.
Where: —

Fix these before submitting, or reword the claims to match the code. The first three would sink the application with any reviewer who reads code. Your strongest card, "I already built it", turns into a credibility problem if the code doesn't match what the text says.

1. Fit with Restack

The "Engine, Not the Car" framing works only partly. The text asserts it many times ("universal", "not a single-sector SaaS app"), but repeating it doesn't make it true. Three things work against it:

- Little internet-layer content. The design is an offline file format plus a CLI. There is no protocol, no network, and nothing shared publicly. Restack is about the trust layers of the internet commons. As written, this looks like a well-built compliance tool, which is closer to the vertical application the framing tries to avoid.
- The regulatory text dominates. MID, NAWI, CSRD, CRCF, ISO 17025 and conformity-assessment bodies take up more space than open standards and reuse. A reviewer will conclude this is mainly for a niche of EU auditors.
- The two drivers you chose look like your own market. One of them is biochar, which reinforces that impression.

The highest-leverage strategic change: align with IETF work and add a public transparency log.

- Standards: model attestation on RATS (RFC 9334) and EAT, and make signed statements SCITT-compatible. A reviewer is likely to ask "why not SCITT, COSE, RATS, Sigstore or in-toto?" Right now the draft doesn't mention any of them, which suggests you haven't looked.
- Transparency log: anchor chain heads in a public, append-only log (a C2SP tlog with witnesses, or a SCITT transparency service). This makes the project internet infrastructure, and it also fixes three of the security gaps in §2 (backdating, truncation and replay across auditors).

2. Technical architecture: gaps a reviewer will spot

1. Who holds the Producer Root Key? If the operator holds it, the insider threat model fails. The operator can certify a software key as a "device" and sign any data they like. The only defence is attestation verified against the manufacturer's CA. For the ATECC608 TrustFLEX/TNG parts, Microchip issues device certificates, and the auditor's trust store should pin that CA, not the producer's. This is the most important thing to fix, and the application should say explicitly how it is solved.
2. The gateway's clock belongs to the operator. Check 3 (calibration expiry) and the period checks rely on timestamps that the gateway itself signs. Setting the clock back keeps an expired instrument "in calibration" and moves readings into a different period. You need an external time source: RFC 3161 timestamps, Roughtime, or anchoring in the transparency log.
3. Readings can be withheld. Sequence numbers prove there are no gaps in the records, but if the gateway is switched off, nothing is recorded and the sequence stays unbroken. I found no check on the maximum time between records. An operator can also stop the gateway for a whole bad period, or drop the most recent records and issue a claim only for the good stretch. Signed heartbeats with a maximum-gap rule, plus logged chain heads, address this.
4. RS-485 / Modbus has no authentication. A passive tap cannot tell whether the meter or another device on the bus sent a response, so the operator can wire in something that imitates the meter. "Ahead of the PLC" has no meaning on a multidrop bus. Also, many MID meters have CT/VT ratio registers that can be written over Modbus, so the operator can rescale readings at the source, and your gateway would faithfully sign the wrong values. Be honest about this. The defence is physical: sealed terminals, MID seal records, and reading the meter's own configuration and event-log registers into the signed record.
5. The 2.5 kV isolation is not a security property. It protects against electrical faults and ground loops. Mentioning it four times as if it were a defence will read as padding to a security reviewer. The same goes for the 85–125 °C limits of secure elements.
6. The dual-register check is weaker than it sounds. If both registers pass through the same gateway before signing, Check 5 catches only edits made after signing, which the signatures already catch. It helps only if the meter reports both registers independently. Say which case applies.
7. The ATECC608 can be physically attacked. Fault-injection key-extraction attacks have been published against the 508A/608A family. Your text says fraud "requires physical hardware breach", so say what that costs and what evidence it leaves (tamper seals, revocation).
8. The claim ledger only stops replay within one auditor. The --claim-ledger file is local to one auditor, so the same bundle can be sold to a second registry or auditor without detection. Again, a public log is the answer.
9. The physical inputs remain open. The operator controls feedstock moisture, which lab samples are sent, and what goes on the scale. The mass-balance inequalities only stop the crudest inflation.

Is the "collusion-forcing" argument sound? Not yet. As built, it falls apart because of points 1 and 2: the operator can forge a device certificate and set the clock, with no one else involved. Once those are fixed, the argument holds and is defensible.

3. Milestones and budget

- About €50/h is normal for NLnet, and €38k is a sensible amount.
- Hours don't fit the calendar. 720 h in 5 months is about 36 h/week, and M3 is 220 h in one month, about 55 h/week. Your background section says you run telemetry pipelines for more than 100 facilities, so that is presumably a full-time job. Reviewers will ask about this. Either stretch the schedule to 8–9 months or state your availability, and confirm your employer has no IP claim on the work.
- M2 is too large. Supporting ATECC608B, TPM 2.0 and DICE on top of a Modbus daemon and provisioning tools is too much. Pick one secure element and leave a clean interface for the others.
- M3 ports a design that needs refactoring first. Do the shared-core refactor in M1 or before submitting. Otherwise you are porting two copies of the same logic into Rust.
- Make deliverables measurable. For example: "spec v0.1 tagged", "verifier passes N golden vectors in Python and Rust in CI", "crate published on crates.io", "external security audit findings resolved". NGI-style NLnet programmes usually offer partner services such as security audits and packaging. Check whether Restack does, and if so, say you will use them; it costs you nothing.
- "33/33 attacks caught" is your own test against your own verifier. Reviewers discount that. Present it as a regression suite, not as evidence of security.

4. The four objections most likely to get a "no"

1. "This duplicates SCITT, RATS and the German Eichrecht signed-metering ecosystem." Under Eichrecht, signed EV-charging meter readings (OCMF) are already verified offline by the open-source S.A.F.E. Transparenzsoftware, and smart-meter gateways have their own signed-reading framework. Your comparison section argues against Helium and Siemens, which nobody would confuse with this project, and leaves out the real prior art. Swap Web3 for this.
2. "The hardware root of trust is the operator's own key with a self-written JSON attestation." Fix point 1 in §2 and the code issue in §0.
3. "It's a vertical tool presented as infrastructure." Add the transparency log, align with the standards, and drop some of the regulatory detail.
4. "One part-time developer, a two-week-old repo, a heavy schedule." Add a realistic timeline. Also name any outside interest: a letter from a CAB, a contact at an Eclipse or LF Energy project, or an OEM willing to test. One named external party is worth more than the whole adopters list.

5. Edits you can paste in

Field 4 (Summary): 941 characters. It adds the transparency log; drop that sentence if you don't adopt it.

▎ Industrial compliance data (energy, emissions, mass balances) crosses an untrusted boundary: readings pass through operator-controlled PLCs, databases and vendor clouds, where they can be altered, truncated or cherry-picked before audit without trace. We build an open, local-first evidence format and toolchain for that boundary. An edge gateway reads legal-for-trade instruments over RS-485, signs integer readings with a secure-element key whose manufacturer attestation auditors verify independently, and hash-chains them. Chain heads are anchored in an append-only transparency log, so backdating, truncation and double-claiming become detectable. Evidence ships as self-contained bundles with W3C PROV-O lineage; independent Python and Rust verifiers check them fully offline through a shared core plus pluggable domain profiles. Two reference profiles (MID energy submetering, NAWI/CRCF pyrolysis mass balance) demonstrate generality.

Field 7 (Comparison): cut the Web3 paragraph to two sentences and add this as a new point 4 (661 characters).

▎ 4. Signed-metering and attestation prior art:
▎    German Eichrecht already requires signed meter readings for EV charging (OCMF, verified offline by the open-source S.A.F.E. Transparenzsoftware), and IETF RATS (RFC 9334), EAT and SCITT standardise device attestation and transparency-logged signed statements. These prove the building blocks are sound, but each covers one meter type or one layer. We reuse them rather than reinvent: attestation follows RATS roles, chain heads are SCITT-compatible, and our contribution is the missing open layer joining fieldbus capture, legal-metrology pedigree, lineage and domain conservation checks into one verifiable bundle.

Other cuts and fixes:
- Field 9 says the CRA has "hardware root-of-trust mandates". It doesn't. Change it to "supports CRA secure-by-design obligations".
- Field 7 calls named companies (Isometric, Carbonfuture) "dark stacks". That is unnecessary and could backfire if a reviewer knows them. Describe the architecture instead of labelling vendors.
- Field 8, item 1, lists all 7 core checks again. You already list them in Fields 4 and 6. Use the space to describe the hook interface (its inputs, outputs, and what a profile can and cannot override).
- Field 8, item 2. Delete the temperature and ATEX sentence. Replace it with an honest paragraph on the limits of an unauthenticated bus (§2, point 4). Reviewers trust applicants who state their limits.
- Field 10, "mathematically verify" and "deterministically catches 33 fraud vectors". Tone these down. "Equipped to deliver… without institutional overhead" can also go.
- Citations. I couldn't confirm "Kleppmann et al., ACM e-Energy" or "Delegated Regulation 2026/285" from memory. Check both before submitting.
- Title. Drop "for Industrial IoT" and consider "Open Evidence Format and Hardware Root-of-Trust for Verifiable Sensor Telemetry". That is broader and reads more like infrastructure.

Bottom line: the problem is real and you have a working prototype, which counts for a lot. In its current form I would expect a "no" or a request to revise. The main reason is not the writing: the attestation and root-key design don't support the insider threat model the text claims, and the repo shows it. Fix §0 and points 1–3 in §2, add the standards and transparency-log framing, and stretch the timeline. That makes this a strong application. The deadline is November 3, which leaves 12 days; the code changes in §0 take about a weekend, so do them first.
```
