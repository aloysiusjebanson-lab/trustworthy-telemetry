# Security Fix Tracker — Verifier Re-Audit (Oct 10, 2026)

**Created:** Oct 11, 2026 · **Deadline:** Oct 17, 2026, before Task 3.5 (demo recording) in `nlnet_application_tracker.md`
**Acceptance test:** `python3 04_experiments/security_reaudit/poc_exploits.py` must print `Result: 0 vulnerable PoC(s)` and exit `0`
**Current state:** ✅ **Closed.** 0 / 6 PoCs vulnerable (v1.2, Oct 11) and still 0 / 6 after the port to bundle format v1.3 (Oct 22).

> **Historical record.** This tracker documents the Oct 10–16 re-audit of the **v1.2** verifier.
> Function names and line numbers below (`verify_biochar_bundle()`, `hardware_attestation.json`,
> `--require-hardware-attestation`, root-level `biochar_bundle/`) refer to code that was replaced
> on Oct 22 by the shared core (`src/verifier/core.py`) and bundle format v1.3. The P1–P6
> regressions were ported to self-contained fixtures and still run in `make test`. Current
> remediation work: `review_remediation_tracker.md`.

---

## 0. Briefing for the executing agent (read first)

You are fixing confirmed security bugs in a zero-dependency Python + OpenSSL evidence-bundle verifier. Work through the tasks **in order**. Each task has **Problem → Files → Steps → Acceptance**. Do not mark a task ✅ until its Acceptance commands pass. Paste the command output into the Log at the bottom.

### Hard rules
1. **No new pip dependencies.** Use only the Python standard library and the `openssl` CLI.
2. **Never commit private keys.** `.gitignore` already blocks `*private_key*.pem`. Do not weaken it. Run `git ls-files | grep -i private` before every commit; it must print nothing.
3. **Never touch `09_confidential_commercial/`.**
4. **Do not delete existing attack tests.** Fix them and add new ones.
5. **Keep both profiles working:** `biochar_pyrolysis` (primary) and `energy_submetering` (secondary).
6. Run all commands from the repo root: `/Users/aloysiusjebanson/Documents/Trustworthy telemetry`.
7. **Commit after each phase** with message `fix(security): <task ids> ...`. Do not push until Phase E passes.
8. If a step is ambiguous, choose the **fail-closed** option (reject rather than accept) and note it in the Log.

### Key files
| File | Role |
|---|---|
| `src/verifier/verify_bundle.py` | Verifier. `verify_biochar_bundle()` ≈ L78–592, `verify_energy_bundle()` ≈ L599–1202, dispatcher + CLI ≈ L1205–1270 |
| `src/device_simulator/mock_biochar_edge.py` | Biochar edge simulator (creates device keys, cert, attestation, observations) |
| `src/pipeline/biochar_claim_generator.py` | Builds claim, transformations, provenance, manifest, seal |
| `src/device_simulator/mock_edge.py`, `src/pipeline/claim_generator.py` | Energy-profile equivalents (already keep device keys in `src/device_simulator/keys/`; use as the reference pattern) |
| `src/verifier/trusted_references.json` | Auditor-pinned registry (dataset hashes) |
| `src/attacks/biochar_attacks.py`, `outsider_attacks.py`, `insider_fraud_suite.py` | Attack suites |
| `04_experiments/golden_test_vector_biochar/`, `04_experiments/golden_test_vector/` | Frozen conformance vectors |
| `04_experiments/security_reaudit/poc_exploits.py` | **Acceptance test** for this tracker (P1–P6) |

### Baseline (run once before starting; expected output shown)
```bash
python3 04_experiments/security_reaudit/poc_exploits.py   # Result: 6 vulnerable PoC(s), exit 1
python3 src/attacks/biochar_attacks.py | tail -2          # 10/10 (but see Task D1: these are partly false positives)
```

---

## Status board

| ID | Phase | Task | Severity | Fixes | Status |
|---|---|---|:---:|---|:---:|
| A1 | A: Key hygiene | Move biochar device private key out of the bundle | 🔴 | P1, fresh-clone fail | ✅ |
| A2 | A | Verifier rejects any private-key file inside a bundle (both profiles) | 🔴 | P1 | ✅ |
| A3 | A | Regenerate `biochar_bundle/` and update registry if hashes change | 🔴 | — | ✅ |
| B1 | B: Biochar identity | Bind device public key ↔ certificate and re-derive `device_id` | 🔴 | P2 | ✅ |
| B2 | B | Algorithm allow-list + mandatory cert validity window | 🟠 | hardening | ✅ |
| B3 | B | Attestation: bind to the key hash and label it as a stub | 🟠 | P2 (partial) | ✅ |
| B4 | B | Biochar sequence and `batch_id` uniqueness checks | 🟡 | hardening | ✅ |
| C1 | C: Physics & metrology | Calibration validity vs every batch timestamp (biochar) | 🟠 | P3 | ✅ |
| C2 | C | MID metrology check for the energy profile (claimed S7, missing) | 🟠 | tracker gap | ✅ |
| C3 | C | Per-batch mass balance + max dry-yield bound | 🟡 | P5, P6 | ✅ |
| C4 | C | Lab value range/type validation + lab ↔ batch binding | 🟡 | defense in depth | ✅ |
| C5 | C | Auditor claim ledger against double counting | 🟠 | P4 | ✅ |
| C6 | C | Smaller fixes (energy Check 8 loop, trust-anchor fallback, energy Check 6 optional fields) | 🟢 | hardening | ✅ |
| D1 | D: Test harness | Harness asserts baseline PASS + exact failing check; crash ≠ caught | 🔴 | false positives | ✅ |
| D2 | D | Self-contained fixtures (temp keys, tracked reference data) so suites run on a fresh clone | 🔴 | reviewer breakage | ✅ |
| D3 | D | Add B11–B16 attack vectors (P1–P6) to `biochar_attacks.py` | 🟠 | regression | ✅ |
| E1 | E: Release | Refreeze both golden vectors | 🔴 | fresh-clone fail | ✅ |
| E2 | E | Fresh-clone end-to-end verification | 🔴 | — | ✅ |
| E3 | E | Docs honesty pass (README, threat model, hardening tracker, NLnet draft) | 🟠 | — | ✅ |

---

## Phase A: Key hygiene

### A1. Move the biochar device private key out of the bundle
**Problem:** `mock_biochar_edge.py` → `ensure_device_keys(device_dir)` writes `device_private_key.pem` into `biochar_bundle/device/`. The generator then adds it to the manifest and seals it. Anyone with the bundle can forge batches. Because the file is gitignored, a fresh clone also fails Check 1.

**Files:** `src/device_simulator/mock_biochar_edge.py`, `src/pipeline/biochar_claim_generator.py`

**Steps:**
1. In `mock_biochar_edge.py`, change `ensure_device_keys(device_dir)` to take a separate key directory:
   ```python
   def ensure_device_keys(device_dir, keys_dir):
       os.makedirs(keys_dir, exist_ok=True)
       dev_priv = os.path.join(keys_dir, "biochar_device_private_key.pem")
       dev_pub = os.path.join(device_dir, "public_key.pem")
       if not os.path.exists(dev_priv):
           run_openssl(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", dev_priv])
           os.chmod(dev_priv, 0o600)
       run_openssl(["openssl", "ec", "-in", dev_priv, "-pubout", "-out", dev_pub])   # always re-derive pub from priv
       return dev_priv, dev_pub
   ```
2. Give `generate_biochar_telemetry()` two new keyword args, `keys_dir=None` and `producer_keys_dir=None`:
   - default `keys_dir` = `<project_root>/src/device_simulator/keys`
   - default `producer_keys_dir` = `project_root`, keeping current behaviour
   - CLI: keep `argv[1]` = bundle dir; add optional `--keys-dir` / `--producer-keys-dir` using `argparse`.
3. **Migration:** if a legacy `biochar_bundle/device/device_private_key.pem` exists and the external key does not, **move** it (`os.replace`) to `src/device_simulator/keys/biochar_device_private_key.pem`. This keeps the existing `device_id` stable.
4. In `biochar_claim_generator.py`:
   - Add a `producer_priv_key_path=None` parameter to `build_biochar_claim_bundle()`. The default is the current `project_root/producer_root_private_key.pem`.
   - In the manifest loop (step 8, ≈ L228), **raise `RuntimeError`** if any filename contains `private` or ends with `.key`. Never silently skip it.

**Acceptance:**
```bash
python3 src/device_simulator/mock_biochar_edge.py biochar_bundle && python3 src/pipeline/biochar_claim_generator.py biochar_bundle
find biochar_bundle -iname "*private*"          # prints nothing
ls src/device_simulator/keys/biochar_device_private_key.pem
git ls-files | grep -i private                   # prints nothing
```

### A2. Verifier rejects private keys inside bundles (both profiles)
**Problem:** The biochar verifier accepts a manifested private key. The energy verifier explicitly *whitelists* `device_private_key.pem` in its unmanifested-file loop (≈ L691).

**Steps:**
1. Add a helper near the top of `verify_bundle.py`:
   ```python
   FORBIDDEN_SUBSTRINGS = ("private", ".key")
   def find_forbidden_key_files(bundle_dir):
       hits = []
       for root, _, files in os.walk(bundle_dir):
           for f in files:
               lf = f.lower()
               if any(s in lf for s in FORBIDDEN_SUBSTRINGS):
                   hits.append(os.path.relpath(os.path.join(root, f), bundle_dir))
       return hits
   ```
   Optionally also scan file contents for `-----BEGIN` + `PRIVATE KEY-----`. Do this for `.pem` files only.
2. In **Check 1 of both profiles**, call it. Every hit appends `"Security: private key material found in bundle: <path>"` and sets the check to failed.
3. In the energy loop (≈ L691), remove `"device_private_key.pem"` from the skip list. Keep only `manifest.json`, `checksums.txt` and `.DS_Store`.

**Acceptance:** a bundle containing any `*private*` file fails `check1_manifest_and_seal` in both profiles. This is covered by D3 test B11 and an energy-profile equivalent `O11`.

### A3. Regenerate the demo bundle and keep the registry consistent
**Steps:**
1. Re-run the simulator and generator (A1 acceptance commands).
2. `compute sha256` of `biochar_bundle/reference_data/lab_analysis.json` and `feedstock_manifest.json`. The generator reuses existing files, so the hashes should stay `f3706c09…` and `b6e8b104…`. If they changed, update the keys in `src/verifier/trusted_references.json` and note it in the Log.
3. Run `python3 src/verifier/verify_bundle.py biochar_bundle --company-key producer_root_public_key.pem -v`. It must PASS.

**Commit:** `fix(security): A1-A3 remove device private key from biochar bundles`

---

## Phase B: Biochar device identity (port the energy-profile hardening)

### B1. Bind the device public key to the certificate and re-derive `device_id`
**Problem (P2):** biochar Check 2 never compares `device/public_key.pem` with `certificate_body.device_public_key`, and never re-derives `device_id`. An insider can swap in a software key.

**Steps** (in `verify_biochar_bundle()`, Check 2 block ≈ L189–239):
1. Initialise `certified_device_id = None`, `cert_valid_from = None`, `cert_valid_until = None` **before** the `try` (≈ L113). This avoids `NameError` paths.
2. After the certificate signature is verified:
   ```python
   with open(device_pubkey_path) as f:
       actual_pub_pem = f.read().strip()
   if actual_pub_pem != c_body.get("device_public_key", "").strip():
       audit_errors.append("Device certificate public key does not match device/public_key.pem")
       dev_ok = False
   b64 = "".join(l.strip() for l in actual_pub_pem.splitlines() if not l.startswith("-----"))
   derived_id = "device_biochar_" + hashlib.sha256(b64.encode()).hexdigest()[:12]
   if derived_id != c_body.get("device_id"):
       audit_errors.append(f"Derived device ID {derived_id} != certified {c_body.get('device_id')}")
       dev_ok = False
   ```
   The derivation **must match** `derive_device_id()` in `mock_biochar_edge.py` (SHA-256 over the base64 body without PEM header lines).
3. If `device/public_key.pem` is missing, fail Check 2.

**Acceptance:** PoC **P2** → `defended (FAILED)`.

### B2. Algorithm allow-list + mandatory validity window
**Steps:**
1. Check 2: require `cert_doc.get("algorithm") == "ECDSA_P256_SHA256"`.
2. Check 3: for every record, require `record.get("algorithm") == "ECDSA_P256_SHA256"`.
3. Check 2: require `valid_from` and `valid_until` to be `int` with `valid_from < valid_until`, otherwise fail. Then in Check 3, remove the `if cert_valid_from and …` short-circuit (≈ L281) and **always** enforce `valid_from <= timestamp_start <= timestamp_end <= valid_until`.

**Acceptance:** stripping `valid_from` from the cert (and re-signing it) fails Check 2. A record with `"algorithm": "none"` fails Check 3.

### B3. Attestation: bind to the key hash and label it as a stub
**Problem:** attestation is a self-asserted string. Real ATECC608 chain verification is Milestone 2 scope, so it cannot be fully fixed now. Make it as strong as possible and **honest**.

**Steps:**
1. Both profiles: require `attestation_doc["device_public_key_sha256"] == sha256(actual_pub_pem.encode()).hexdigest()`. The biochar simulator already writes this field. Check that the energy simulator (`mock_edge.py`) writes it too; add it if missing.
2. Add `"attestation_mode": "SIMULATED_STUB"` to the attestation docs written by both simulators.
3. In both audit reports, add `"audit_findings"."hardware_attestation_mode"` with the value read from the doc. If the value is `SIMULATED_STUB`, append a **warning** to a new `audit_warnings` list (not an error): `"Hardware attestation is a simulator stub; manufacturer certificate chain not verified (Milestone 2)."` Print warnings in human mode.
4. Change the human-readable "Physical sensor & silicon hardware verified" wording so it does **not** claim silicon verification when the mode is a stub.

**Acceptance:** P2 still defended. The JSON report shows `hardware_attestation_mode: SIMULATED_STUB` and one warning.

### B4. Biochar sequence and `batch_id` uniqueness
**Steps** (new logic at the end of Check 4, biochar):
- Sequences must start at `claim.first_sequence` and increase by exactly 1.
- `record["sequence"] == record["payload"]["sequence"]` and `record["batch_id"] == record["payload"]["batch_id"]`.
- `batch_id` values must be unique.
- `timestamp_start < timestamp_end`, and each batch's `timestamp_start >= previous timestamp_end`.

**Acceptance:** existing B5 is still caught. A hand-made duplicate `batch_id` (re-signed with the device key) fails.

**Commit:** `fix(security): B1-B4 biochar identity binding and envelope hardening`

---

## Phase C: Physics, metrology, double counting

### C1. Calibration validity vs batch timestamps (biochar)
**Problem (P3):** `metrology.calibration_valid_until <= 1700000000` is a hard-coded 2023 constant.

**Steps:**
1. Delete the constant comparison (≈ L210).
2. Store `scale_cal_until = metrology.get("calibration_valid_until")` and `tc_cal_until = c_body.get("thermocouple_module", {}).get("calibration_valid_until")`. Both are required and must be `int`; otherwise Check 2 fails.
3. In Check 3, for every batch: `timestamp_end <= scale_cal_until` and `timestamp_end <= tc_cal_until`. Otherwise append `"Batch N: scale/thermocouple calibration expired before batch end"` and fail Check 3.
4. Also require `metrology.accuracy_class` ∈ `{"Class_I","Class_II","Class_III"}`.

**Acceptance:** PoC **P3** → `defended (FAILED)`.

### C2. MID metrology check for the energy profile
**Problem:** `security_hardening_tracker.md` S7 is marked done, but `verify_energy_bundle()` never checks metrology.

**Steps** (energy Check 2 + Check 3):
- Require `metrology.standard == "MID_2014_32_EU"` and `metrology.accuracy_class` ∈ `{"Class_A_EN50470","Class_B_EN50470","Class_C_EN50470"}`. The current certificate uses `Class_B_EN50470`.
- Require an integer `calibration_valid_until`. In Check 3, every observation `timestamp <= calibration_valid_until`.

**Acceptance:** an energy cert with an expired calibration (re-signed with `company_root_private_key.pem`) fails. The energy golden vector still passes after E1.

### C3. Per-batch mass balance + maximum dry yield
**Problem (P5, P6):** only the sums are compared, and the bound `M_dry ≤ M_feedstock` allows physically impossible yields (pyrolysis tops out around 25–35% by dry mass).

**Steps:**
1. Add an auditor-controlled parameter block to `src/verifier/trusted_references.json`. It sits at the top level, **not** inside `datasets`:
   ```json
   "methodology_parameters": {
     "biochar_max_dry_yield_bps": 4000,
     "biochar_min_temp_c": 500,
     "biochar_process_deduction_g": 1200000
   }
   ```
   Fail-closed defaults if the block is missing: `4000`, `500`, `1200000`.
2. Biochar Check 9: for **each** batch,
   `dry_i = wet_i * (10000 - moisture_bps) // 10000` and require
   `dry_i * 10000 <= feedstock_i * max_dry_yield_bps`. On violation: `"Batch N: dry yield X bps exceeds max Y bps"`.
   Keep the aggregate checks as well.
3. Replace the literal `500` in Check 5 and `1200000` in Check 9 with the parameters. Update `biochar_claim_generator.py` to use the same `1200000` (it can stay a constant there) and record it in `carbon_calculation.json`.
4. Use integer math only. No floats in the comparisons.

**Acceptance:** PoC **P5** and **P6** → `defended (FAILED)`. The demo bundle (27.2% yield) still PASSES.

### C4. Lab value validation + lab ↔ batch binding
**Steps** (biochar Check 9, before any math):
1. Require `moisture_bps`, `c_org_bps` and `permanence_factor_bps` to be present, of type `int` (not `bool`: use `type(x) is int`), with `0 <= v <= 10000`. **No `.get(..., 0)` defaults.**
2. Require every batch's `scale_wet_mass_g` and `feedstock_input_g` to be `int` (not `bool`) and `> 0`, and `temp_min_c` to be `int`/`float` (not `bool`).
3. Lab binding: require `lab_analysis["sample_batch_ref"] == f"{first_batch_id}_to_{last_batch_id}"`, where the batch IDs come from the first and last observation. Do **not** change the lab file format, so the pinned hash stays valid.
4. Feedstock binding: every batch's `payload.feedstock_delivery_ref` must equal `feedstock_manifest["delivery_ref"]`.

**Acceptance:** demo bundle PASSES. Changing `sample_batch_ref` fails Check 8 or 9 (it also breaks pinning, which is fine). A batch with `feedstock_delivery_ref: "other"` (re-signed) fails.

### C5. Auditor claim ledger (double counting)
**Problem (P4):** the same signed batches can be re-sealed under a new `claim_id` and pass. A single offline bundle cannot prove that it is unique, so the auditor needs local state.

**Steps:**
1. Add CLI flags `--claim-ledger PATH` and `--record-ledger` (store_true). Pass them through `verify_bundle()` to both profile functions as `claim_ledger=None, record_ledger=False`.
2. Ledger format (JSON, created if missing):
   ```json
   {"ledger_version": "1.0", "entries": [
     {"claim_id": "...", "profile": "biochar_pyrolysis", "device_id": "...",
      "batch_ids": ["..."], "terminal_hash": "...", "recorded_at": 1791000000}
   ]}
   ```
   For energy, store `sequences` instead of `batch_ids` (use `f"{device_id}:{seq}"` strings).
3. New sub-check inside **Check 6** (both profiles), run only if `claim_ledger` is given: fail if any batch ID / device-sequence or the `terminal_hash` already appears in **another** entry. Error: `"Double-counting: batch <id> already claimed in <claim_id>"`. Re-verifying the *same* `claim_id` with an identical terminal hash is allowed (idempotent).
4. Only if `record_ledger` is set **and** the overall verdict is PASSED, append the entry. Write it atomically: write `PATH.tmp`, then `os.replace`.
5. If `--claim-ledger` is **not** given, add an `audit_warnings` entry: `"No claim ledger supplied: cross-claim double counting not checked."`

**Acceptance:** PoC **P4** → `defended (FAILED)`. The PoC auto-detects `--claim-ledger` in `--help`.

### C6. Smaller fixes
1. **Energy Check 8 (≈ L1068–1076):** require **every** CSV row's `kg_co2e_per_unit` to match the pinned factor. Any mismatch sets `ref_ok = False` (do not let a later row overwrite it).
2. **Dispatcher (≈ L1225):** remove the silent fallback to `producer_root_public_key.pem` in the current directory. The trust anchor must come from `--company-key`. If the file is missing, fail with a clear error.
3. **Energy Check 6:** make `reporting_period.first_sequence`, `last_sequence`, `record_count`, `start_timestamp` and `end_timestamp` **required**; missing means FAIL. Also require `claim.device_id == certified_device_id`.
4. **Unknown profile:** if `claim.json` `profile` is neither `biochar_pyrolysis` nor `energy_submetering` and `--profile` is not given, fail. Do not silently default to energy. Accept a missing `profile` key as energy for backward compatibility **only if** `manifest.json` also has no biochar profile. Otherwise fail.
5. **Duplicate JSON keys:** load every bundle JSON through a helper using `json.loads(s, object_pairs_hook=reject_duplicates)` that raises on duplicate keys. Apply it to manifest, cert, attestation, claim, lab, feedstock, provenance and every NDJSON line.
6. **`openssl` path:** resolve once with `shutil.which("openssl")`. Fail closed if it is missing, and print the resolved path in the report header (`audit_findings.openssl_path`).

**Acceptance:** all existing suites still green (after D1/D2). Manual spot checks noted in the Log.

**Commit:** `fix(security): C1-C6 metrology, mass balance, claim ledger, hardening`

---

## Phase D: Test harness

### D1. Harness must not report false positives
**Problem:** `verify_and_check()` in all three suites returns "caught" on any non-zero exit or JSON parse failure. A crash or a broken environment shows up as 10/10.

**Steps** (create `src/attacks/harness.py` and import it from all three suites):
```python
def verify_and_check(bundle_path, root_key, expected_failed_check, extra_args=None, registry=None):
    # returns (caught: bool, detail: str)
    # 1. run verifier with --json (+ --trusted-registry registry if given)
    # 2. if stdout is not valid JSON -> return (False, "HARNESS ERROR: verifier crashed: <stderr tail>")
    # 3. verdict must be FAILED AND checks[expected_failed_check] == "FAILED"
    # expected_failed_check is REQUIRED (no None default)
def assert_baseline_passes(bundle_path, root_key, registry=None):
    # run verifier on the clean fixture; if verdict != PASSED: print and sys.exit(2)
```
- Every suite calls `assert_baseline_passes()` **before** running attacks.
- The suite exit code is non-zero if any attack is not caught **or** any harness error occurred.
- Print the detail string for every attack that is not caught.

**Acceptance:** temporarily break the baseline (e.g. delete `biochar_bundle/claim.json` in a temp copy used as the fixture). The suite must exit `2` with a baseline error, **not** report 10/10.

### D2. Self-contained fixtures (must run on a fresh clone)
**Problem:** the suites need gitignored files: `producer_root_private_key.pem`, `company_root_private_key.pem` and `05_data/external/` (emission factor CSV). On a fresh clone the biochar and insider suites crash.

**Steps:**
1. Copy `05_data/external/emission_factor.csv` and `emission_factor_metadata.json` to a **tracked** path `04_experiments/reference_data/`. Check the CSV hash is still `8e6cc7a7…` (pinned). Update the defaults in `claim_generator.py`, `insider_fraud_suite.py` and `outsider_attacks.py` to use the tracked path. Keep `05_data/external` as an optional override.
2. Create `src/attacks/fixtures.py` with:
   ```python
   def build_biochar_fixture(workdir) -> dict   # returns {"bundle", "root_pub", "root_priv", "device_priv", "registry"}
   def build_energy_fixture(workdir) -> dict
   ```
   Each one creates fresh producer/company and device keys **inside `workdir`** (via the new `keys_dir` / `producer_keys_dir` / `producer_priv_key_path` args from A1, plus the energy equivalents). It then runs the simulator and generator and copies `src/verifier/trusted_references.json` to `workdir/registry.json`. If lab/feedstock hashes differ from the repo registry, it adds the fixture's hashes to the **copy only**.
3. Each suite: `workdir = tempfile.mkdtemp()`, build the fixture, run every attack against copies inside `workdir`, pass `--trusted-registry fixture["registry"]`, and `shutil.rmtree(workdir)` in a `finally:`.
4. The suites must no longer read any repo-root `*_private_key.pem`.

**Acceptance:**
```bash
D=$(mktemp -d) && git clone -q . "$D/c" && cd "$D/c" && \
python3 src/attacks/biochar_attacks.py && python3 src/attacks/outsider_attacks.py && python3 src/attacks/insider_fraud_suite.py; echo "exit=$?"
```
All three suites green, `exit=0`. Commit your changes first so the clone includes them.

### D3. Add B11–B16 to `biochar_attacks.py`
Use the fixture from D2. Each test re-seals with the fixture's producer key (the insider model) and asserts the exact failing check:

| ID | Attack (from PoC) | Expected failed check |
|---|---|---|
| B11 | Private key file placed inside the bundle and manifested | `check1_manifest_and_seal` |
| B12 | Rogue software device key, certificate untouched (P2) | `check2_device_cert_and_attestation` |
| B13 | Scale calibration expired before batches, cert re-signed (P3) | `check3_observation_signatures` (or `check2_…` if you put it there; be consistent with C1) |
| B14 | Same batches under a new `claim_id` with `--claim-ledger` (P4) | `check6_claim_boundary_bounds` |
| B15 | Single batch dry output > own feedstock, re-signed with device key (P5) | `check9_independent_recomputation` |
| B16 | 95% dry yield across all batches (P6) | `check9_independent_recomputation` |

Also add **O11** to `outsider_attacks.py`: energy bundle containing `device/device_private_key.pem` → `check1_manifest_and_seal`.

Update the totals in output strings, README and docs: biochar **16**, outsider **11**, insider **5** → **32 vectors**.

**Acceptance:** `biochar_attacks.py` prints 16/16. `outsider_attacks.py` prints 11/11.

**Commit:** `test(security): D1-D3 strict harness, self-contained fixtures, B11-B16, O11`

---

## Phase E: Release

### E1. Refreeze golden vectors
**Steps:**
1. Biochar: copy the regenerated `biochar_bundle/` to `04_experiments/golden_test_vector_biochar/biochar_bundle/` (replace the folder) and copy `producer_root_public_key.pem` next to it. Regenerate `expected_audit_verdict.json` with:
   `python3 src/verifier/verify_bundle.py 04_experiments/golden_test_vector_biochar/biochar_bundle --company-key 04_experiments/golden_test_vector_biochar/producer_root_public_key.pem --json-out 04_experiments/golden_test_vector_biochar/expected_audit_verdict.json`
2. Energy: re-run the same for `04_experiments/golden_test_vector/` (report fields changed in B3/C5/C6).
3. Update both vector `README.md` files: note the v1.3 freeze date and that no private keys are included.
4. `find 04_experiments -iname "*private*"` must print nothing.

### E2. Fresh-clone end-to-end verification (the reviewer's experience)
Commit everything, then run:
```bash
D=$(mktemp -d) && git clone -q . "$D/c" && cd "$D/c" && \
python3 src/verifier/verify_bundle.py 04_experiments/golden_test_vector_biochar/biochar_bundle --company-key 04_experiments/golden_test_vector_biochar/producer_root_public_key.pem && \
python3 src/verifier/verify_bundle.py 04_experiments/golden_test_vector/claim_bundle --company-key 04_experiments/golden_test_vector/company_root_public_key.pem && \
python3 src/verifier/verify_bundle.py biochar_bundle --company-key producer_root_public_key.pem && \
python3 src/attacks/biochar_attacks.py && python3 src/attacks/outsider_attacks.py && python3 src/attacks/insider_fraud_suite.py && \
echo "FRESH CLONE: ALL GREEN"
```
Then in the **original** repo (it has the local producer key):
```bash
python3 04_experiments/security_reaudit/poc_exploits.py    # Result: 0 vulnerable PoC(s), exit 0
git ls-files | grep -i private                              # prints nothing
```

### E3. Documentation honesty pass
Update these files so nothing claims more than the code does:
1. `README.md`: attack counts (32); test matrix rows B11–B16 and O11; replace "silicon hardware verified" with "hardware attestation (simulated stub until Milestone 2)"; describe the claim ledger and `methodology_parameters`; mass-conservation section now cites the per-batch **max dry-yield bound (40%)**, not just `M_dry ≤ M_feedstock`.
2. `03_system/threat_model.md`: add P1–P6 as resolved findings. Add **residual risks**: (a) attestation is a stub until M2; (b) tail truncation without an external anchor (RFC 3161 / transparency log) is only detectable with `--expected-count` or `--prev-terminal-hash`; (c) canonicalization is `json.dumps(sort_keys)` and **not yet** RFC 8785 JCS (planned for M1, required for the M3 Rust parity claim); (d) the claim ledger is local auditor state, not a global registry.
3. `00_project/security_hardening_tracker.md`: un-tick S7 history (note it was implemented on the fix date) and link this tracker.
4. `02_protocol/evidence_bundle_spec.md`: document the new verifier rules (key binding, calibration-vs-timestamp, per-batch yield, lab binding, ledger, no private keys in bundles, duplicate-key rejection).
5. `00_project/nlnet_restack_application_draft.md`: replace any "RFC 8785" claim about the *current* prototype with "RFC 8785 (JCS) canonicalization will be implemented in Milestone 1". Keep character counts within limits and update the count annotations.
6. `00_project/nlnet_application_tracker.md`: add a Log entry for this security fix sprint.

**Final commit:** `docs(security): E1-E3 refreeze vectors and align docs with verified behaviour`. Then push: `git push origin main`.

---

## Definition of Done
- [x] `poc_exploits.py` → `Result: 0 vulnerable PoC(s)`, exit 0
- [x] Fresh-clone script in E2 prints `FRESH CLONE: ALL GREEN`
- [x] Suites: biochar 16/16, outsider 11/11, insider 5/5, each starting with a baseline-PASS assertion
- [x] `git ls-files | grep -i private` prints nothing
- [x] `find biochar_bundle claim_bundle 04_experiments -iname "*private*"` prints nothing
- [x] No new pip dependencies: `grep -rhn "^import \|^from " src | sort -u` lists only Python stdlib modules and the project's own modules
- [x] README, threat model, spec, hardening tracker and NLnet draft updated (E3)
- [x] All ⬜ above are ✅ with Log evidence

---

## Log
| Date | Task | Result / evidence |
|---|---|---|
| 2026-10-10 | Re-audit | 6/6 PoCs vulnerable; fresh-clone biochar golden vector FAILED (`device_private_key.pem` missing); biochar + insider suites crash on fresh clone |
| 2026-10-11 | Tracker | Tracker + portable acceptance test `04_experiments/security_reaudit/poc_exploits.py` created (baseline: 6 vulnerable, exit 1) |
| 2026-10-11 | Phase A (A1-A3) | Moved device private key to `src/device_simulator/keys/`; verifier Check 1 rejects any private key material in both profiles; `biochar_bundle/` regenerated; lab & feedstock hashes unchanged; P1 defended in `poc_exploits.py` (5 vulnerable remain); 10/10 verifier checks PASS. |
| 2026-10-11 | Phase B (B1-B4) | Bound device public key to certificate & re-derived device_id; algorithm allowlist & mandatory validity window enforced; attestation key hash checked & labeled as SIMULATED_STUB with audit warnings; sequence strict increment, payload/envelope match, batch_id uniqueness, and monotonic timestamps verified in Check 4; P2 defended in `poc_exploits.py` (4 vulnerable remain); biochar & energy bundles PASS with 10/10 checks. |
| 2026-10-11 | Phase C (C1-C6) | Dynamic calibration validity vs batch timestamps (C1, P3); MID metrology check in energy profile (C2); methodology parameters (40% max dry yield, 500°C min temp, 1.2t process deduction) and per-batch mass balance (C3, P5, P6); lab type/range validation and sample_batch_ref/feedstock binding (C4); auditor claim ledger with --claim-ledger / --record-ledger against double counting (C5, P4); energy Check 8 loop, trust-anchor requirement, energy Check 6 required fields, unknown profile fail-closed, duplicate JSON keys rejected, openssl path resolved (C6). `poc_exploits.py` passes with 0 vulnerable PoCs (exit 0). |
| 2026-10-11 | Phase D (D1-D3) | Strict test harness created (`src/attacks/harness.py`: baseline-PASS assertion, exact check matching, verifier crashes counted as test failures); self-contained fixtures created (`src/attacks/fixtures.py`, `mock_edge.py` parameterized, reference data tracked under `04_experiments/reference_data/`); attack suites refactored: `biochar_attacks.py` 16/16 vectors (added B11-B16), `outsider_attacks.py` 11/11 vectors (added O11), `insider_fraud_suite.py` 5/5 vectors. All 32 attack vectors caught. |
| 2026-10-11 | Phase E (E1-E3) | Refroze both golden vectors (`04_experiments/golden_test_vector_biochar/` and `04_experiments/golden_test_vector/`) with regenerated `expected_audit_verdict.json`; verified zero private keys in `04_experiments/`; updated README.md (32 vectors, B11-B16, O11, ledger, 40% dry yield bound), threat_model.md (resolved P1-P6 and residual risks), evidence_bundle_spec.md (hardened 10-check standard), security_hardening_tracker.md, and nlnet_application_tracker.md. Fresh-clone end-to-end verification passed (`FRESH CLONE: ALL GREEN`). |
| 2026-10-16 | Post-Audit Follow-up | Independent verification confirmed all Phases A-E green; qualified Adversary B attestation limitation in `03_system/threat_model.md`; added `--require-hardware-attestation` CLI flag to `src/verifier/verify_bundle.py` to fail closed on `SIMULATED_STUB`; added Attack Vector B17 to `src/attacks/biochar_attacks.py` (33/33 total vectors caught). |
| 2026-10-22 | Port to v1.3 | Verifier replaced by shared core + profiles (bundle v1.3); `poc_exploits.py` rewritten on self-contained fixtures (no repo-root keys or bundles); P1–P6 still 0 vulnerable; `--require-hardware-attestation` superseded by mandatory X.509 chain validation against `--manufacturer-ca`; regression suite now 40 vectors. See `review_remediation_tracker.md`. |
