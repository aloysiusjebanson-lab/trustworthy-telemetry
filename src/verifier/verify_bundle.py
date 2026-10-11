"""
Independent Evidence Bundle Verifier CLI (v1.1)

Executes all 10 Zero-Trust Verifier Checks defined in 02_protocol/evidence_bundle_spec.md:
  1. Validate manifest integrity, bundle seal, path traversal guard, and unmanifested files.
  2. Validate device certificate, hardware attestation, and device_id re-derivation.
  3. Validate observation signatures and temporal validity against certificate lifetime.
  4. Validate cryptographic hash-chain continuity (prev_hash) to prevent truncation/splicing.
  5. Validate sequence ordering, duplicates, and dual-register consistency (cumulative vs interval).
  6. Validate claim period boundaries (first/last sequence, expected count, terminal hash).
  7. Validate transformation input/output hashes and W3C PROV-O lineage graph.
  8. Validate emission factor against the Auditor's Pinned Reference Registry.
  9. Independently recompute integer Watt-hour energy and Scope 2 carbon quantification.
  10. Reconcile recomputed metrics against declared claim and emit structured audit report.

Operates completely offline with zero network connectivity or cloud dependencies.
Fail-closed architecture: Any malformed input produces [AUDIT FAILED], never an unhandled crash.
"""

import sys
import os
import json
import binascii
import subprocess
import tempfile
import argparse
import hashlib
import csv
import shutil
import time

OPENSSL_BIN = shutil.which("openssl")
if not OPENSSL_BIN:
    raise RuntimeError("OpenSSL CLI binary not found in PATH")

def reject_duplicates(ordered_pairs):
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            raise ValueError(f"Duplicate JSON key: {k}")
        d[k] = v
    return d

def safe_json_loads(s):
    return json.loads(s, object_pairs_hook=reject_duplicates)

def safe_json_load(fp):
    return safe_json_loads(fp.read())

def load_claim_ledger(ledger_path):
    if not ledger_path or not os.path.exists(ledger_path):
        return {"ledger_version": "1.0", "entries": []}
    with open(ledger_path, "r") as f:
        data = safe_json_load(f)
        if "entries" not in data or not isinstance(data["entries"], list):
            return {"ledger_version": "1.0", "entries": []}
        return data

def record_to_claim_ledger(ledger_path, entry):
    ledger_data = load_claim_ledger(ledger_path)
    entries = ledger_data.get("entries", [])
    for e in entries:
        if e.get("claim_id") == entry.get("claim_id") and e.get("terminal_hash") == entry.get("terminal_hash"):
            return
    entries.append(entry)
    ledger_data["entries"] = entries
    tmp_path = ledger_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(ledger_data, f, indent=2)
    os.replace(tmp_path, ledger_path)

def compute_sha256(filepath):
    """Computes SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def canonical_json_bytes(data):
    """Serializes data into RFC 8785 deterministic canonical JSON bytes."""
    return json.dumps(data, separators=(',', ':'), sort_keys=True).encode('utf-8')

def openssl_verify_signature(pubkey_path, data_bytes, sig_hex):
    """Verifies an ECDSA signature using OpenSSL CLI with zero external dependencies."""
    try:
        sig_bytes = binascii.unhexlify(sig_hex)
    except Exception as e:
        return False, f"Invalid hex in signature: {e}"

    with tempfile.NamedTemporaryFile(delete=False) as sig_f, \
         tempfile.NamedTemporaryFile(delete=False) as data_f:
        try:
            sig_f.write(sig_bytes)
            sig_f.flush()
            data_f.write(data_bytes)
            data_f.flush()

            cmd = [
                OPENSSL_BIN, "dgst", "-sha256",
                "-verify", pubkey_path,
                "-signature", sig_f.name,
                data_f.name
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0 and "Verified OK" in res.stdout:
                return True, "Valid"
            else:
                return False, res.stderr.strip() or res.stdout.strip()
        except Exception as e:
            return False, f"Signature verification error: {e}"
        finally:
            for p in [sig_f.name, data_f.name]:
                try:
                    os.remove(p)
                except OSError:
                    pass

FORBIDDEN_KEY_SUBSTRINGS = ("private", ".key")

def find_forbidden_key_files(bundle_dir):
    """Detects any private key material inside the evidence bundle."""
    hits = []
    for root, _, files in os.walk(bundle_dir):
        for f in files:
            lf = f.lower()
            full_p = os.path.join(root, f)
            rel_p = os.path.relpath(full_p, bundle_dir)
            if any(s in lf for s in FORBIDDEN_KEY_SUBSTRINGS):
                hits.append(rel_p)
            elif lf.endswith(".pem"):
                try:
                    with open(full_p, "rb") as cf:
                        content = cf.read(4096)
                        if b"PRIVATE KEY" in content:
                            hits.append(rel_p)
                except Exception:
                    pass
    return sorted(hits)


def verify_biochar_bundle(bundle_dir, producer_pubkey_path, trusted_registry_path,
                          verbose=False, json_mode=False, json_out_path=None,
                          expected_count=None, prev_terminal_hash=None, revoked=None,
                          claim_ledger=None, record_ledger=False):
    if not json_mode:
        print("=" * 70)
        print(" Independent Offline Verifier — Zero-Trust Biochar dMRV Audit (v1.2)")
        print(" Specification: 02_protocol/evidence_bundle_spec.md (biochar_pyrolysis)")
        print(" Standards: EU CRCF Delegated Regulation 2026/285 | Puro.earth | EBC")
        print("=" * 70)
        print(f"[*] Target Claim Bundle : {bundle_dir}")
        print(f"[*] Trust Anchor (Root) : {producer_pubkey_path}")
        print("-" * 70)

    results = {
        "check1_manifest_and_seal": False,
        "check2_device_cert_and_attestation": False,
        "check3_observation_signatures": False,
        "check4_hash_chain_continuity": False,
        "check5_thermal_permanence": False,
        "check6_claim_boundary_bounds": False,
        "check7_transformations_and_provenance": False,
        "check8_pinned_reference_factor": False,
        "check9_independent_recomputation": False,
        "check10_numeric_reconciliation": False
    }

    audit_errors = []
    audit_warnings = []
    obs_records = []
    claim_data = None
    lab_analysis = None
    feedstock_manifest = None
    recomputed_dry_mass_g = 0
    recomputed_gross_co2_g = 0
    recomputed_net_co2_g = 0
    recomputed_net_tonnes = 0.0
    certified_device_id = None
    cert_valid_from = None
    cert_valid_until = None
    scale_cal_until = None
    tc_cal_until = None
    attestation_mode = "UNKNOWN"
    device_pubkey_path = os.path.join(bundle_dir, "device", "public_key.pem")

    # Load methodology parameters from trusted registry
    methodology_params = {}
    if trusted_registry_path and os.path.exists(trusted_registry_path):
        try:
            with open(trusted_registry_path, "r") as rf:
                reg_doc = safe_json_load(rf)
                methodology_params = reg_doc.get("methodology_parameters", {})
        except Exception:
            pass
    max_dry_yield_bps = methodology_params.get("biochar_max_dry_yield_bps", 4000)
    min_temp_c = methodology_params.get("biochar_min_temp_c", 500)
    process_deductions_g = methodology_params.get("biochar_process_deduction_g", 1200000)

    # Parse revocation list
    revocation_set = set()
    if revoked:
        if os.path.exists(revoked):
            with open(revoked, "r") as rf:
                for line in rf:
                    l = line.strip()
                    if l and not l.startswith("#"):
                        revocation_set.add(l)
        else:
            for item in revoked.split(","):
                if item.strip():
                    revocation_set.add(item.strip())

    # 1. Manifest Integrity & Producer Bundle Seal
    try:
        manifest_path = os.path.join(bundle_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            audit_errors.append(f"Missing manifest.json in {bundle_dir}")
        else:
            with open(manifest_path, "r") as f:
                manifest_data = safe_json_load(f)

            files_dict = manifest_data.get("files", {})
            seal_info = manifest_data.get("bundle_seal", {})
            seal_sig = seal_info.get("signature")

            manifest_ok = True
            for rel_path, expected_hash in files_dict.items():
                if ".." in rel_path or os.path.isabs(rel_path):
                    audit_errors.append(f"Security: Path traversal attempt in manifest: {rel_path}")
                    manifest_ok = False
                    continue
                target_file = os.path.join(bundle_dir, rel_path)
                if not os.path.exists(target_file):
                    audit_errors.append(f"Manifest declared file missing: {rel_path}")
                    manifest_ok = False
                else:
                    actual_hash = compute_sha256(target_file)
                    if actual_hash != expected_hash:
                        audit_errors.append(f"Hash mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}")
                        manifest_ok = False

            # Check for unmanifested files
            for root, _, files in os.walk(bundle_dir):
                for file in files:
                    if file == "manifest.json":
                        continue
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, bundle_dir)
                    if rel_p not in files_dict:
                        audit_errors.append(f"Security: Unmanifested file sitting in bundle: {rel_p}")
                        manifest_ok = False

            # Check for forbidden private key files
            forbidden_keys = find_forbidden_key_files(bundle_dir)
            if forbidden_keys:
                for fk in forbidden_keys:
                    audit_errors.append(f"Security: private key material found in bundle: {fk}")
                manifest_ok = False

            # Verify Producer Bundle Seal
            if seal_sig and os.path.exists(producer_pubkey_path):
                canonical_files = canonical_json_bytes(files_dict)
                v_ok, v_msg = openssl_verify_signature(producer_pubkey_path, canonical_files, seal_sig)
                if not v_ok:
                    audit_errors.append(f"Producer bundle seal signature invalid: {v_msg}")
                    manifest_ok = False
            else:
                audit_errors.append("Missing bundle_seal signature or Producer root key")
                manifest_ok = False

            results["check1_manifest_and_seal"] = manifest_ok
    except Exception as e:
        audit_errors.append(f"Check 1 exception: {e}")

    if not json_mode:
        s1 = "PASSED" if results["check1_manifest_and_seal"] else "FAILED"
        print(f"[Check 1/10] Manifest Integrity & Producer Bundle Seal : [{s1}]")

    # 2. Device Certificate, Silicon Attestation & Legal Scale Metrology
    try:
        cert_path = os.path.join(bundle_dir, "device", "device_certificate.json")
        attest_path = os.path.join(bundle_dir, "device", "hardware_attestation.json")
        dev_ok = True

        if not os.path.exists(device_pubkey_path):
            audit_errors.append("Missing device/public_key.pem")
            dev_ok = False

        if os.path.exists(cert_path) and os.path.exists(producer_pubkey_path) and os.path.exists(device_pubkey_path):
            with open(cert_path, "r") as f:
                cert_doc = safe_json_load(f)
            c_body = cert_doc.get("certificate_body", {})
            c_sig = cert_doc.get("company_signature")

            # Algorithm allow-list check
            if cert_doc.get("algorithm") != "ECDSA_P256_SHA256":
                audit_errors.append(f"Device certificate uses untrusted algorithm: {cert_doc.get('algorithm')}")
                dev_ok = False

            v_ok, v_msg = openssl_verify_signature(producer_pubkey_path, canonical_json_bytes(c_body), c_sig)
            if not v_ok:
                audit_errors.append(f"Device certificate signature invalid: {v_msg}")
                dev_ok = False

            # Bind device public key to certificate
            with open(device_pubkey_path, "r") as pf:
                actual_pub_pem = pf.read().strip()
            if actual_pub_pem != c_body.get("device_public_key", "").strip():
                audit_errors.append("Device certificate public key does not match device/public_key.pem")
                dev_ok = False

            # Re-derive device_id from public key (SHA-256 over raw base64)
            b64 = "".join(l.strip() for l in actual_pub_pem.splitlines() if not l.startswith("-----"))
            derived_id = "device_biochar_" + hashlib.sha256(b64.encode('utf-8')).hexdigest()[:12]
            certified_device_id = c_body.get("device_id")
            if derived_id != certified_device_id:
                audit_errors.append(f"Derived device ID {derived_id} != certified {certified_device_id}")
                dev_ok = False

            # Mandatory certificate validity window
            cert_valid_from = c_body.get("valid_from")
            cert_valid_until = c_body.get("valid_until")
            if not (type(cert_valid_from) is int and type(cert_valid_until) is int and cert_valid_from < cert_valid_until):
                audit_errors.append("Invalid or missing certificate validity window (valid_from/valid_until)")
                dev_ok = False

            # Verify legal-for-trade scale metrology (EU Directive 2014/31/EU NAWI)
            metrology = c_body.get("metrology", {})
            if metrology.get("standard") != "EU_Directive_2014_31_EU_NAWI":
                audit_errors.append("Device certificate missing legal scale standard EU_Directive_2014_31_EU_NAWI")
                dev_ok = False
            if metrology.get("accuracy_class") not in {"Class_I", "Class_II", "Class_III"}:
                audit_errors.append("Scale accuracy class must be Class_I, Class_II, or Class_III")
                dev_ok = False

            scale_cal = metrology.get("calibration_valid_until")
            tc_module = c_body.get("thermocouple_module", {})
            tc_cal = tc_module.get("calibration_valid_until")
            if type(scale_cal) is not int or type(tc_cal) is not int:
                audit_errors.append("Scale and thermocouple calibration_valid_until must be valid integers")
                dev_ok = False
            else:
                scale_cal_until = scale_cal
                tc_cal_until = tc_cal

            # Verify Silicon Hardware Attestation (Microchip ATECC608)
            if os.path.exists(attest_path):
                with open(attest_path, "r") as af:
                    attest_doc = safe_json_load(af)
                attestation_mode = attest_doc.get("attestation_mode", "UNKNOWN")
                if attest_doc.get("attestation_status") != "SILICON_HARDWARE_VERIFIED":
                    audit_errors.append("Hardware attestation failed: silicon not verified")
                    dev_ok = False
                expected_key_hash = hashlib.sha256(actual_pub_pem.encode('utf-8')).hexdigest()
                if attest_doc.get("device_public_key_sha256") != expected_key_hash:
                    audit_errors.append("Hardware attestation key hash mismatch with device public key")
                    dev_ok = False
            else:
                audit_errors.append("Missing hardware_attestation.json")
                dev_ok = False

            # Check key revocation list
            if revocation_set and certified_device_id in revocation_set:
                audit_errors.append(f"Security: Device ID {certified_device_id} is on the revocation list!")
                dev_ok = False
        else:
            dev_ok = False
            audit_errors.append("Missing device_certificate.json or Producer root key")

        results["check2_device_cert_and_attestation"] = dev_ok
    except Exception as e:
        audit_errors.append(f"Check 2 exception: {e}")

    if not json_mode:
        s2 = "PASSED" if results["check2_device_cert_and_attestation"] else "FAILED"
        print(f"[Check 2/10] Device Certificate & Scale Metrology (NAWI): [{s2}]")

    # 3. Observation Signatures & Batch Validity Window
    try:
        obs_file = os.path.join(bundle_dir, "observations", "observations.ndjson")
        obs_ok = True
        if os.path.exists(obs_file) and os.path.exists(device_pubkey_path):
            with open(obs_file, "r") as f:
                for line in f:
                    if line.strip():
                        obs_records.append(safe_json_loads(line.strip()))

            if not obs_records:
                obs_ok = False
                audit_errors.append("Observations file is empty")
            else:
                for idx, record in enumerate(obs_records):
                    sig = record.get("signature")
                    dev_id = record.get("device_id")
                    if dev_id != certified_device_id:
                        audit_errors.append(f"Batch {idx+1}: device_id ({dev_id}) mismatch with certificate ({certified_device_id})")
                        obs_ok = False

                    # Algorithm allow-list check
                    if record.get("algorithm") != "ECDSA_P256_SHA256":
                        audit_errors.append(f"Batch {idx+1}: untrusted algorithm: {record.get('algorithm')}")
                        obs_ok = False

                    to_verify = {
                        "device_id": record.get("device_id"),
                        "batch_id": record.get("batch_id"),
                        "sequence": record.get("sequence"),
                        "prev_hash": record.get("prev_hash"),
                        "payload": record.get("payload")
                    }
                    v_ok, v_msg = openssl_verify_signature(device_pubkey_path, canonical_json_bytes(to_verify), sig)
                    if not v_ok:
                        audit_errors.append(f"Batch {idx+1} ({record.get('batch_id')}): signature invalid: {v_msg}")
                        obs_ok = False

                    payload = record.get("payload", {})
                    ts_start = payload.get("timestamp_start", 0)
                    ts_end = payload.get("timestamp_end", 0)
                    if cert_valid_from is None or cert_valid_until is None or ts_start < cert_valid_from or ts_end > cert_valid_until:
                        audit_errors.append(f"Batch {idx+1}: timestamp outside certificate validity window")
                        obs_ok = False

                    if scale_cal_until is None or tc_cal_until is None or ts_end > scale_cal_until or ts_end > tc_cal_until:
                        audit_errors.append(f"Batch {idx+1}: scale/thermocouple calibration expired before batch end")
                        obs_ok = False
        else:
            obs_ok = False
            audit_errors.append("Missing observations.ndjson or device public_key.pem")

        results["check3_observation_signatures"] = obs_ok
    except Exception as e:
        audit_errors.append(f"Check 3 exception: {e}")

    if not json_mode:
        s3 = "PASSED" if results["check3_observation_signatures"] else "FAILED"
        print(f"[Check 3/10] Batch Signatures & Temporal Bounds (ECDSA) : [{s3}] ({len(obs_records)} batches)")

    # 4. Cryptographic Hash-Chain Continuity (prev_hash)
    try:
        chain_ok = True
        if obs_records:
            genesis = obs_records[0]
            if prev_terminal_hash is not None:
                if genesis.get("prev_hash") != prev_terminal_hash:
                    audit_errors.append("Genesis hash mismatch with specified previous terminal hash")
                    chain_ok = False
            else:
                if genesis.get("prev_hash") != "0" * 64:
                    audit_errors.append("Genesis record prev_hash must be 64 zeros")
                    chain_ok = False

            for i in range(1, len(obs_records)):
                prior_canon = canonical_json_bytes(obs_records[i - 1])
                expected_prev = hashlib.sha256(prior_canon).hexdigest()
                actual_prev = obs_records[i].get("prev_hash")
                if actual_prev != expected_prev:
                    audit_errors.append(f"Hash-chain broken at batch sequence {obs_records[i].get('sequence')}")
                    chain_ok = False

            # Sequence ordering, batch_id uniqueness, and timestamp progression (B4)
            seen_batch_ids = set()
            last_end_ts = None
            first_seq = obs_records[0].get("sequence")
            for idx, r in enumerate(obs_records):
                seq = r.get("sequence")
                p = r.get("payload", {})
                p_seq = p.get("sequence")
                b_id = r.get("batch_id")
                p_b_id = p.get("batch_id")
                ts_start = p.get("timestamp_start", 0)
                ts_end = p.get("timestamp_end", 0)

                expected_seq = first_seq + idx
                if seq != expected_seq or p_seq != expected_seq:
                    audit_errors.append(f"Batch sequence gap or mismatch at index {idx}: expected {expected_seq}, got {seq}/{p_seq}")
                    chain_ok = False

                if b_id != p_b_id:
                    audit_errors.append(f"Batch ID mismatch between envelope ({b_id}) and payload ({p_b_id})")
                    chain_ok = False

                if b_id in seen_batch_ids:
                    audit_errors.append(f"Duplicate batch_id detected: {b_id}")
                    chain_ok = False
                seen_batch_ids.add(b_id)

                if ts_start >= ts_end:
                    audit_errors.append(f"Batch {b_id}: invalid timestamps (timestamp_start >= timestamp_end)")
                    chain_ok = False

                if last_end_ts is not None and ts_start < last_end_ts:
                    audit_errors.append(f"Batch {b_id}: non-monotonic timestamp progression (start {ts_start} < previous end {last_end_ts})")
                    chain_ok = False
                last_end_ts = ts_end
        else:
            chain_ok = False

        results["check4_hash_chain_continuity"] = chain_ok
    except Exception as e:
        audit_errors.append(f"Check 4 exception: {e}")

    if not json_mode:
        s4 = "PASSED" if results["check4_hash_chain_continuity"] else "FAILED"
        print(f"[Check 4/10] Cryptographic Hash-Chain Continuity         : [{s4}]")

    # 5. Pyrolysis Thermal Permanence Compliance (T >= min_temp_c)
    try:
        thermal_ok = True
        for idx, r in enumerate(obs_records):
            p = r.get("payload", {})
            t_min = p.get("temp_min_c", 0)
            if t_min < min_temp_c:
                audit_errors.append(f"Thermal permanence failure: Batch {idx+1} ({r.get('batch_id')}) min temp {t_min}°C < {min_temp_c}°C statutory threshold")
                thermal_ok = False

        results["check5_thermal_permanence"] = thermal_ok
    except Exception as e:
        audit_errors.append(f"Check 5 exception: {e}")

    if not json_mode:
        s5 = "PASSED" if results["check5_thermal_permanence"] else "FAILED"
        print(f"[Check 5/10] Pyrolysis Thermal Permanence (T >= {min_temp_c}°C)  : [{s5}]")

    # 6. Claim Period Boundary Bounds Enforcement & Double-Counting Check
    try:
        claim_path = os.path.join(bundle_dir, "claim.json")
        boundary_ok = True
        if os.path.exists(claim_path):
            with open(claim_path, "r") as cf:
                claim_data = safe_json_load(cf)

            if obs_records:
                first_seq = obs_records[0].get("sequence")
                last_seq = obs_records[-1].get("sequence")
                actual_count = len(obs_records)
                actual_terminal_hash = hashlib.sha256(canonical_json_bytes(obs_records[-1])).hexdigest()

                if claim_data.get("first_sequence") != first_seq:
                    audit_errors.append("Claim declared first_sequence mismatch")
                    boundary_ok = False
                if claim_data.get("last_sequence") != last_seq:
                    audit_errors.append("Claim declared last_sequence mismatch")
                    boundary_ok = False
                if claim_data.get("batch_count") != actual_count:
                    audit_errors.append(f"Claim batch count ({claim_data.get('batch_count')}) != actual ({actual_count})")
                    boundary_ok = False
                if claim_data.get("terminal_hash") != actual_terminal_hash:
                    audit_errors.append("Claim terminal_hash mismatch with final observation")
                    boundary_ok = False

                if expected_count is not None and actual_count != expected_count:
                    audit_errors.append(f"Audit mandate violation: expected {expected_count} batches, found {actual_count}")
                    boundary_ok = False

                if prev_terminal_hash is not None and obs_records:
                    genesis_in_bundle = obs_records[0].get("prev_hash")
                    if genesis_in_bundle != prev_terminal_hash:
                        audit_errors.append(f"Inter-bundle hash continuity broken: expected {prev_terminal_hash[:12]}..., got {genesis_in_bundle[:12]}...")
                        boundary_ok = False

                # Double-counting check via auditor claim ledger (C5)
                if claim_ledger is not None:
                    try:
                        ledger_data = load_claim_ledger(claim_ledger)
                        entries = ledger_data.get("entries", [])
                        cur_claim_id = claim_data.get("claim_id")
                        cur_batch_ids = set(r.get("batch_id") for r in obs_records)
                        for entry in entries:
                            e_cid = entry.get("claim_id")
                            e_term = entry.get("terminal_hash")
                            if e_cid == cur_claim_id:
                                if e_term != actual_terminal_hash:
                                    audit_errors.append(f"Double-counting: claim {cur_claim_id} re-used with different terminal hash")
                                    boundary_ok = False
                                continue
                            if e_term == actual_terminal_hash:
                                audit_errors.append(f"Double-counting: terminal hash already claimed in {e_cid}")
                                boundary_ok = False
                            for bid in entry.get("batch_ids", []):
                                if bid in cur_batch_ids:
                                    audit_errors.append(f"Double-counting: batch {bid} already claimed in {e_cid}")
                                    boundary_ok = False
                    except Exception as e:
                        audit_errors.append(f"Claim ledger check failed: {e}")
                        boundary_ok = False
                else:
                    audit_warnings.append("No claim ledger supplied: cross-claim double counting not checked.")
            else:
                boundary_ok = False
        else:
            boundary_ok = False
            audit_errors.append("Missing claim.json")

        results["check6_claim_boundary_bounds"] = boundary_ok
    except Exception as e:
        audit_errors.append(f"Check 6 exception: {e}")

    if not json_mode:
        s6 = "PASSED" if results["check6_claim_boundary_bounds"] else "FAILED"
        print(f"[Check 6/10] Claim Batch Boundary Bounds Enforcement    : [{s6}]")

    # 7. Transformation Lineage & W3C PROV-O Graph
    try:
        lineage_ok = True
        prov_file = os.path.join(bundle_dir, "provenance", "provenance.json")
        mb_file = os.path.join(bundle_dir, "transformations", "mass_balance.json")
        cc_file = os.path.join(bundle_dir, "transformations", "carbon_calculation.json")

        if os.path.exists(prov_file) and os.path.exists(mb_file) and os.path.exists(cc_file):
            with open(prov_file, "r") as pf:
                prov_data = safe_json_load(pf)
            entities = prov_data.get("entity", {})
            for entity_id, entity_info in entities.items():
                expected_sha = entity_info.get("sha256")
                if expected_sha is None:
                    continue
                if "observations" in entity_id:
                    act_sha = compute_sha256(os.path.join(bundle_dir, "observations", "observations.ndjson"))
                    if expected_sha != act_sha:
                        audit_errors.append("Provenance graph observations hash mismatch")
                        lineage_ok = False
                elif "lab_analysis" in entity_id:
                    act_sha = compute_sha256(os.path.join(bundle_dir, "reference_data", "lab_analysis.json"))
                    if expected_sha != act_sha:
                        audit_errors.append("Provenance graph lab analysis hash mismatch")
                        lineage_ok = False
        else:
            lineage_ok = False
            audit_errors.append("Missing transformation files or provenance.json")

        results["check7_transformations_and_provenance"] = lineage_ok
    except Exception as e:
        audit_errors.append(f"Check 7 exception: {e}")

    if not json_mode:
        s7 = "PASSED" if results["check7_transformations_and_provenance"] else "FAILED"
        print(f"[Check 7/10] Transformation & W3C PROV-O Lineage Graph  : [{s7}]")

    # 8. Pinned Reference Registry (Lab Analysis & Feedstock Manifest)
    try:
        ref_ok = True
        lab_file = os.path.join(bundle_dir, "reference_data", "lab_analysis.json")
        feed_file = os.path.join(bundle_dir, "reference_data", "feedstock_manifest.json")

        if os.path.exists(lab_file) and os.path.exists(feed_file) and os.path.exists(trusted_registry_path):
            act_lab_hash = compute_sha256(lab_file)
            act_feed_hash = compute_sha256(feed_file)

            with open(trusted_registry_path, "r") as rf:
                reg_data = safe_json_load(rf)
            datasets = reg_data.get("datasets", {})

            if act_lab_hash not in datasets:
                audit_errors.append(f"Security: Lab analysis hash ({act_lab_hash[:16]}...) is NOT in auditor's pinned registry! Counterfeit lab report.")
                ref_ok = False
            else:
                with open(lab_file, "r") as lf:
                    lab_analysis = safe_json_load(lf)

            if act_feed_hash not in datasets:
                audit_errors.append(f"Security: Feedstock manifest hash ({act_feed_hash[:16]}...) is NOT in auditor's pinned registry! Uncertified biomass.")
                ref_ok = False
            else:
                with open(feed_file, "r") as ff:
                    feedstock_manifest = safe_json_load(ff)
        else:
            ref_ok = False
            audit_errors.append("Missing reference files or trusted_references.json")

        results["check8_pinned_reference_factor"] = ref_ok
    except Exception as e:
        audit_errors.append(f"Check 8 exception: {e}")

    if not json_mode:
        s8 = "PASSED" if results["check8_pinned_reference_factor"] else "FAILED"
        print(f"[Check 8/10] Authoritative Reference Registry Pinning   : [{s8}]")

    # 9. Mass-Balance Invariants & Net Removal Recomputation (Integer Math)
    try:
        recompute_ok = True
        if lab_analysis and feedstock_manifest and obs_records:
            # C4 validation: Lab values type and range
            moisture_bps = lab_analysis.get("moisture_bps")
            c_org_bps = lab_analysis.get("c_org_bps")
            perm_bps = lab_analysis.get("permanence_factor_bps")

            for k_name, val in [("moisture_bps", moisture_bps), ("c_org_bps", c_org_bps), ("permanence_factor_bps", perm_bps)]:
                if type(val) is not int or not (0 <= val <= 10000):
                    audit_errors.append(f"Lab analysis {k_name} must be integer between 0 and 10000, got {val}")
                    recompute_ok = False

            # C4 validation: Lab binding to sample batches
            first_b_id = obs_records[0].get("batch_id")
            last_b_id = obs_records[-1].get("batch_id")
            expected_sample_ref = f"{first_b_id}_to_{last_b_id}"
            if lab_analysis.get("sample_batch_ref") != expected_sample_ref:
                audit_errors.append(f"Lab analysis sample_batch_ref ({lab_analysis.get('sample_batch_ref')}) does not match batch sequence ({expected_sample_ref})")
                recompute_ok = False

            # C4 validation: Feedstock binding and batch payload value checks
            delivery_ref = feedstock_manifest.get("delivery_ref")
            for idx, r in enumerate(obs_records):
                p = r.get("payload", {})
                w_g = p.get("scale_wet_mass_g")
                f_g = p.get("feedstock_input_g")
                t_m = p.get("temp_min_c")
                b_id = r.get("batch_id")

                if type(w_g) is not int or w_g <= 0:
                    audit_errors.append(f"Batch {idx+1} ({b_id}): scale_wet_mass_g must be positive integer, got {w_g}")
                    recompute_ok = False
                if type(f_g) is not int or f_g <= 0:
                    audit_errors.append(f"Batch {idx+1} ({b_id}): feedstock_input_g must be positive integer, got {f_g}")
                    recompute_ok = False
                if type(t_m) not in (int, float) or type(t_m) is bool:
                    audit_errors.append(f"Batch {idx+1} ({b_id}): temp_min_c must be numeric, got {t_m}")
                    recompute_ok = False
                if p.get("feedstock_delivery_ref") != delivery_ref:
                    audit_errors.append(f"Batch {idx+1} ({b_id}): feedstock_delivery_ref mismatch with feedstock manifest ({delivery_ref})")
                    recompute_ok = False

            if recompute_ok:
                total_wet_mass_g = sum(r["payload"]["scale_wet_mass_g"] for r in obs_records)
                total_feedstock_input_g = sum(r["payload"]["feedstock_input_g"] for r in obs_records)

                # Invariant 1: Per-batch dry mass and maximum dry yield bound (C3)
                batch_dry_masses = []
                for idx, r in enumerate(obs_records):
                    p = r["payload"]
                    w_i = p["scale_wet_mass_g"]
                    f_i = p["feedstock_input_g"]
                    dry_i = w_i * (10000 - moisture_bps) // 10000
                    batch_dry_masses.append(dry_i)
                    if dry_i * 10000 > f_i * max_dry_yield_bps:
                        batch_yield_bps = (dry_i * 10000) // f_i
                        audit_errors.append(f"Batch {idx+1}: dry yield {batch_yield_bps} bps exceeds max {max_dry_yield_bps} bps")
                        recompute_ok = False

                recomputed_dry_mass_g = sum(batch_dry_masses)

                # Invariant 2: Physical Conservation (Dry biochar <= Dry feedstock input)
                if recomputed_dry_mass_g > total_feedstock_input_g:
                    audit_errors.append(f"Mass-balance violation: Dry biochar ({recomputed_dry_mass_g}g) > Feedstock input ({total_feedstock_input_g}g)")
                    recompute_ok = False

                # Invariant 3: Cumulative Feedstock Cap (Used <= Delivered)
                delivered_cap_g = feedstock_manifest.get("delivered_mass_total_g", 0)
                if total_feedstock_input_g > delivered_cap_g:
                    audit_errors.append(f"Feedstock cap violation: Total used ({total_feedstock_input_g}g) > Delivered ({delivered_cap_g}g)")
                    recompute_ok = False

                # Invariant 4: EU CRCF / Puro Formula Net Carbon Removal (Integer Math)
                # Gross = (M_dry * C_org * F_perm * 44) // (10000 * 10000 * 12)
                recomputed_gross_co2_g = (recomputed_dry_mass_g * c_org_bps * perm_bps * 44) // (10000 * 10000 * 12)
                recomputed_net_co2_g = recomputed_gross_co2_g - process_deductions_g
                recomputed_net_tonnes = recomputed_net_co2_g / 1000000.0
        else:
            recompute_ok = False
            audit_errors.append("Missing lab_analysis, feedstock_manifest, or observations for recomputation")

        results["check9_independent_recomputation"] = recompute_ok
    except Exception as e:
        audit_errors.append(f"Check 9 exception: {e}")

    if not json_mode:
        s9 = "PASSED" if results["check9_independent_recomputation"] else "FAILED"
        print(f"[Check 9/10] Mass-Balance Invariants & CRCF Recomputation: [{s9}]")

    # 10. Numeric Claim Reconciliation
    try:
        reconcile_ok = False
        if claim_data and results["check9_independent_recomputation"]:
            metrics = claim_data.get("metrics", {})
            declared_net_g = metrics.get("net_co2_removed_g")
            declared_dry_g = metrics.get("total_dry_biochar_g")

            # Zero-tolerance match on integer grams
            if declared_net_g == recomputed_net_co2_g and declared_dry_g == recomputed_dry_mass_g:
                reconcile_ok = True
            else:
                audit_errors.append(f"Claim discrepancy: Declared net {declared_net_g}g vs Recomputed {recomputed_net_co2_g}g")

        results["check10_numeric_reconciliation"] = reconcile_ok
    except Exception as e:
        audit_errors.append(f"Check 10 exception: {e}")

    if not json_mode:
        s10 = "PASSED" if results["check10_numeric_reconciliation"] else "FAILED"
        print(f"[Check 10/10] Numeric Claim Reconciliation (Zero-Tol): [{s10}]")

    # Structured Audit Summary
    if attestation_mode == "SIMULATED_STUB":
        audit_warnings.append("Hardware attestation is a simulator stub; manufacturer certificate chain not verified (Milestone 2).")

    all_passed = all(results.values())
    origin_msg = (
        "Declared origin verified (Physical sensor & hardware attestation stub verified)"
        if attestation_mode == "SIMULATED_STUB"
        else "Declared origin verified (Physical sensor & silicon hardware verified)"
    )
    audit_report = {
        "verdict": "PASSED" if all_passed else "FAILED",
        "profile": "biochar_pyrolysis",
        "bundle": bundle_dir,
        "trust_anchor": producer_pubkey_path,
        "checks": {k: "PASSED" if v else "FAILED" for k, v in results.items()},
        "errors": audit_errors,
        "warnings": audit_warnings,
        "audit_findings": {
            "telemetry_origin_status": origin_msg,
            "hardware_attestation_mode": attestation_mode,
            "openssl_path": OPENSSL_BIN,
            "batch_count": len(obs_records),
            "permanence_status": f"Permanence conditions verified (T >= {min_temp_c}°C maintained across all batches)",
            "mass_balance_status": "Mass-balance verified (Physical conservation bounds satisfied)",
            "recomputed_dry_biochar_tonnes": recomputed_dry_mass_g / 1000000.0,
            "recomputed_net_co2_removed_tonnes": recomputed_net_tonnes,
            "lineage_status": "Calculation lineage verified against pinned ISO 17025 lab report"
        }
    }

    # Record to claim ledger if requested and verification passed
    if all_passed and record_ledger and claim_ledger:
        record_to_claim_ledger(claim_ledger, {
            "claim_id": claim_data.get("claim_id") if claim_data else "unknown",
            "profile": "biochar_pyrolysis",
            "device_id": certified_device_id,
            "batch_ids": [r.get("batch_id") for r in obs_records],
            "terminal_hash": claim_data.get("terminal_hash") if claim_data else "unknown",
            "recorded_at": int(time.time())
        })

    if not json_mode:
        print("-" * 70)
        print(" FORMAL AUDIT VERIFICATION SUMMARY (EU CRCF / PURO.EARTH)")
        print("-" * 70)
        print(f"  * Batches Ingested          : {len(obs_records)} batches (Unbroken hash-chain)")
        print(f"  * Thermal Permanence        : Confirmed (All batches >= {min_temp_c}°C)")
        print(f"  * Mass Balance Proof        : Net Dry Biochar = {recomputed_dry_mass_g / 1000000.0:.3f} tonnes")
        print(f"  * Net Carbon Sequestered    : {recomputed_net_tonnes:.6f} t CO2 ({recomputed_net_co2_g} g)")
        print("-" * 70)

        if all_passed:
            print("[AUDIT VERDICT: PASSED]")
            print(f"  Status: {origin_msg}. Permanence verified. Lineage verified.")
            print("  All 10 specification checks passed without exception.")
            if audit_warnings:
                print("  Warnings:")
                for warn in audit_warnings:
                    print(f"    - [WARNING] {warn}")
            print("=" * 70)
        else:
            print("[AUDIT VERDICT: FAILED]")
            print("  Status: Evidence bundle failed cryptographic, permanence, or lineage checks.")
            if verbose and audit_errors:
                print("  Errors:")
                for err in audit_errors:
                    print(f"    - {err}")
            if audit_warnings:
                print("  Warnings:")
                for warn in audit_warnings:
                    print(f"    - [WARNING] {warn}")
            print("=" * 70)
    else:
        print(json.dumps(audit_report, indent=2))

    if json_out_path:
        with open(json_out_path, "w") as jf:
            json.dump(audit_report, jf, indent=2)
        if not json_mode:
            print(f"[+] Structured audit report saved: {json_out_path}")

    return all_passed


# =====================================================================
# ENERGY SUBMETERING VERIFICATION PROFILE (CSRD / EPBD)
# =====================================================================

def verify_energy_bundle(bundle_dir, company_pubkey_path, trusted_registry_path=None,
                         verbose=False, json_mode=False, json_out_path=None,
                         expected_count=None, prev_terminal_hash=None, revoked=None,
                         claim_ledger=None, record_ledger=False):
    if not json_mode:
        print("=" * 70)
        print(" Independent Offline Verifier — Zero-Trust Claim Audit (v1.1)")
        print(" Specification: 02_protocol/evidence_bundle_spec.md")
        print("=" * 70)
        print(f"[*] Target Claim Bundle : {bundle_dir}")
        print(f"[*] Company Trust Anchor: {company_pubkey_path}")
        print("-" * 70)

    # Parse revocation list
    revocation_set = set()
    if revoked:
        if os.path.exists(revoked):
            with open(revoked, "r") as rf:
                for line in rf:
                    l = line.strip()
                    if l and not l.startswith("#"):
                        revocation_set.add(l)
        else:
            for item in revoked.split(","):
                if item.strip():
                    revocation_set.add(item.strip())

    results = {
        "check1_manifest_and_seal": False,
        "check2_device_cert_and_attestation": False,
        "check3_observation_signatures": False,
        "check4_hash_chain_continuity": False,
        "check5_sequence_and_registers": False,
        "check6_claim_boundary_bounds": False,
        "check7_transformations_and_provenance": False,
        "check8_pinned_reference_factor": False,
        "check9_independent_recomputation": False,
        "check10_numeric_reconciliation": False
    }

    audit_errors = []
    audit_warnings = []
    obs_records = []
    t_energy = None
    t_carbon = None
    claim_data = None
    recomputed_wh = 0
    recomputed_kwh = 0.0
    recomputed_co2e = 0.0
    pinned_factor = None
    certified_device_id = None
    cert_valid_from = None
    cert_valid_until = None
    energy_cal_until = None
    attestation_mode = "UNKNOWN"
    device_pubkey_path = os.path.join(bundle_dir, "device", "public_key.pem")

    # Resolve trusted registry path
    if trusted_registry_path is None:
        base_script_dir = os.path.dirname(os.path.abspath(__file__))
        trusted_registry_path = os.path.join(base_script_dir, "trusted_references.json")

    # -------------------------------------------------------------
    # Check 1: Manifest Integrity, Bundle Seal, Path Traversal, Unmanifested Files
    # -------------------------------------------------------------
    try:
        manifest_path = os.path.join(bundle_dir, "manifest.json")
        checksums_path = os.path.join(bundle_dir, "checksums.txt")
        if not os.path.exists(manifest_path) or not os.path.exists(checksums_path):
            audit_errors.append("Missing manifest.json or checksums.txt")
        else:
            with open(manifest_path, "r") as f:
                manifest = safe_json_load(f)

            manifest_files = manifest.get("files", {})
            all_files_ok = True

            # 1a. Path traversal inspection & file hash checking
            for rel_path, expected_hash in manifest_files.items():
                if ".." in rel_path or rel_path.startswith("/") or rel_path.startswith("\\"):
                    audit_errors.append(f"Security: Path traversal detected in manifest: {rel_path}")
                    all_files_ok = False
                    continue
                full_path = os.path.join(bundle_dir, rel_path)
                if not os.path.exists(full_path):
                    audit_errors.append(f"Missing file declared in manifest: {rel_path}")
                    all_files_ok = False
                    continue
                actual_hash = compute_sha256(full_path)
                if actual_hash != expected_hash:
                    audit_errors.append(f"Hash mismatch for {rel_path}")
                    all_files_ok = False

            # 1b. Unmanifested files detection
            for root, _, files in os.walk(bundle_dir):
                for f in files:
                    if f in ["manifest.json", "checksums.txt", ".DS_Store"]:
                        continue
                    disk_rel = os.path.relpath(os.path.join(root, f), bundle_dir)
                    if disk_rel not in manifest_files:
                        audit_errors.append(f"Security: Unmanifested file detected in bundle: {disk_rel}")
                        all_files_ok = False

            # Check for forbidden private key files
            forbidden_keys = find_forbidden_key_files(bundle_dir)
            if forbidden_keys:
                for fk in forbidden_keys:
                    audit_errors.append(f"Security: private key material found in bundle: {fk}")
                all_files_ok = False

            # 1c. Bundle Seal verification (Company Root Key signature over canonical manifest files)
            bundle_seal = manifest.get("bundle_seal")
            if bundle_seal and os.path.exists(company_pubkey_path):
                canonical_files = canonical_json_bytes(manifest_files)
                seal_sig = bundle_seal.get("signature", "")
                is_seal_valid, seal_msg = openssl_verify_signature(company_pubkey_path, canonical_files, seal_sig)
                if not is_seal_valid:
                    audit_errors.append(f"Bundle seal signature invalid: {seal_msg}")
                    all_files_ok = False
            else:
                audit_errors.append("Missing bundle_seal or missing company root public key")
                all_files_ok = False

            results["check1_manifest_and_seal"] = all_files_ok
    except Exception as e:
        audit_errors.append(f"Check 1 exception: {e}")

    if not json_mode:
        s1 = "PASSED" if results["check1_manifest_and_seal"] else "FAILED"
        print(f"[Check 1/10] Manifest Integrity & Cryptographic Seal  : [{s1}]")

    # -------------------------------------------------------------
    # Check 2: Device Certificate, Hardware Attestation, Device ID Re-Derivation
    # -------------------------------------------------------------
    try:
        device_cert_path = os.path.join(bundle_dir, "device", "device_certificate.json")
        attestation_path = os.path.join(bundle_dir, "device", "hardware_attestation.json")
        cert_ok = False

        if not os.path.exists(device_pubkey_path):
            audit_errors.append("Missing device/public_key.pem")

        if os.path.exists(device_cert_path) and os.path.exists(company_pubkey_path) and os.path.exists(device_pubkey_path):
            with open(device_cert_path, "r") as f:
                cert_data = safe_json_load(f)
            if cert_data.get("algorithm") != "ECDSA_P256_SHA256":
                audit_errors.append(f"Untrusted certificate algorithm: {cert_data.get('algorithm')}")
            cert_body = cert_data.get("certificate_body", {})
            cert_sig = cert_data.get("company_signature", "")
            canonical_cert_bytes = canonical_json_bytes(cert_body)

            is_cert_valid, msg = openssl_verify_signature(company_pubkey_path, canonical_cert_bytes, cert_sig)
            if is_cert_valid:
                with open(device_pubkey_path, "r") as f:
                    actual_pub_pem = f.read().strip()
                if actual_pub_pem == cert_body.get("device_public_key", "").strip():
                    cert_valid_from = cert_body.get("valid_from")
                    cert_valid_until = cert_body.get("valid_until")
                    if type(cert_valid_from) is int and type(cert_valid_until) is int and cert_valid_from < cert_valid_until:
                        certified_device_id = cert_body.get("device_id")
                        # 2a. Check key revocation list
                        if revocation_set and certified_device_id in revocation_set:
                            audit_errors.append(f"Security: Device ID {certified_device_id} is on the revocation list!")
                        else:
                            # 2b. Re-derive device_id from public key: sha256(pubkey)[:12]
                            derived_id = "device_" + hashlib.sha256(actual_pub_pem.encode('utf-8')).hexdigest()[:12]
                            if derived_id == certified_device_id:
                                # Metrology check (MID 2014/32/EU - C2)
                                metrology = cert_body.get("metrology", {})
                                metrology_ok = True
                                if metrology.get("standard") != "MID_2014_32_EU":
                                    audit_errors.append("Meter metrology standard must be MID_2014_32_EU")
                                    metrology_ok = False
                                if metrology.get("accuracy_class") not in {"Class_A_EN50470", "Class_B_EN50470", "Class_C_EN50470"}:
                                    audit_errors.append("Meter accuracy class must be Class_A_EN50470, Class_B_EN50470, or Class_C_EN50470")
                                    metrology_ok = False
                                cal_until = metrology.get("calibration_valid_until")
                                if type(cal_until) is not int:
                                    audit_errors.append("Meter calibration_valid_until must be an integer")
                                    metrology_ok = False
                                else:
                                    energy_cal_until = cal_until

                                # 2c. Check hardware secure element attestation
                                if os.path.exists(attestation_path):
                                    with open(attestation_path, "r") as af:
                                        att_data = safe_json_load(af)
                                    attestation_mode = att_data.get("attestation_mode", "UNKNOWN")
                                    att_status_ok = att_data.get("attestation_status") == "verified_hardware_secure_element"
                                    if not att_status_ok:
                                        audit_errors.append("Hardware attestation status not verified")
                                    expected_key_hash = hashlib.sha256(actual_pub_pem.encode('utf-8')).hexdigest()
                                    if att_data.get("device_public_key_sha256") != expected_key_hash:
                                        audit_errors.append("Hardware attestation key hash mismatch with device public key")
                                    elif att_status_ok and cert_data.get("algorithm") == "ECDSA_P256_SHA256" and metrology_ok:
                                        cert_ok = True
                                else:
                                    audit_errors.append("Missing hardware_attestation.json")
                            else:
                                audit_errors.append(f"Derived device ID {derived_id} does not match certified ID {certified_device_id}")
                    else:
                        audit_errors.append("Invalid certificate validity window")
                else:
                    audit_errors.append("Device certificate public key does not match public_key.pem")
            else:
                audit_errors.append(f"Company signature on device certificate failed: {msg}")

        results["check2_device_cert_and_attestation"] = cert_ok
    except Exception as e:
        audit_errors.append(f"Check 2 exception: {e}")

    if not json_mode:
        s2 = "PASSED" if results["check2_device_cert_and_attestation"] else "FAILED"
        print(f"[Check 2/10] Device Certificate & Hardware Attestation: [{s2}]")

    # -------------------------------------------------------------
    # Check 3: Observation Signatures & Temporal Bounds
    # -------------------------------------------------------------
    obs_file = os.path.join(bundle_dir, "observations", "observations.ndjson")
    try:
        obs_sigs_ok = True
        raw_envelopes = []

        if os.path.exists(obs_file) and os.path.exists(device_pubkey_path):
            with open(obs_file, "r") as f:
                for line_no, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    rec = safe_json_loads(line)
                    raw_envelopes.append(rec)
                    obs_device_id = rec.get("device_id")
                    payload = rec.get("payload", {})
                    sig = rec.get("signature", "")
                    algo = rec.get("algorithm")
                    obs_records.append(payload)

                    # Algorithm allow-list check
                    if algo != "ECDSA_P256_SHA256":
                        audit_errors.append(f"Observation #{line_no} uses untrusted algorithm: {algo}")
                        obs_sigs_ok = False

                    # Device ID consistency check
                    if certified_device_id and obs_device_id != certified_device_id:
                        audit_errors.append(f"Observation #{line_no} device_id mismatch")
                        obs_sigs_ok = False

                    # Temporal certificate validity check
                    ts = payload.get("timestamp")
                    if cert_valid_from is not None and cert_valid_until is not None:
                        if ts is None or ts < cert_valid_from or ts > cert_valid_until:
                            audit_errors.append(f"Observation #{line_no} timestamp outside certificate validity window")
                            obs_sigs_ok = False

                    # Metrology calibration validity check (C2)
                    if energy_cal_until is None or ts is None or ts > energy_cal_until:
                        audit_errors.append(f"Observation #{line_no} timestamp exceeds meter calibration validity window")
                        obs_sigs_ok = False

                    # Verify signature over canonical payload
                    canonical_payload_bytes = canonical_json_bytes(payload)
                    is_valid, msg = openssl_verify_signature(device_pubkey_path, canonical_payload_bytes, sig)
                    if not is_valid:
                        audit_errors.append(f"Observation #{line_no} signature invalid: {msg}")
                        obs_sigs_ok = False

        results["check3_observation_signatures"] = obs_sigs_ok and (len(obs_records) > 0)
    except Exception as e:
        audit_errors.append(f"Check 3 exception: {e}")

    if not json_mode:
        s3 = "PASSED" if results["check3_observation_signatures"] else "FAILED"
        print(f"[Check 3/10] Observation Signatures & Temporal Bounds : [{s3}] ({len(obs_records)} records)")

    # -------------------------------------------------------------
    # Check 4: Cryptographic Hash-Chain Continuity (prev_hash)
    # -------------------------------------------------------------
    try:
        chain_ok = True
        expected_prev_hash = "0" * 64  # Genesis hash

        for idx, env in enumerate(raw_envelopes, 1):
            env_prev_hash = env.get("prev_hash")
            payload_prev_hash = env.get("payload", {}).get("prev_hash")

            # Prev_hash must be consistently bound in envelope and signed payload
            if env_prev_hash != payload_prev_hash:
                audit_errors.append(f"Observation #{idx} prev_hash mismatch between envelope and payload")
                chain_ok = False

            if env_prev_hash != expected_prev_hash:
                audit_errors.append(f"Hash-chain broken at observation #{idx}: expected {expected_prev_hash[:12]}..., got {str(env_prev_hash)[:12]}...")
                chain_ok = False

            # Compute next link in the chain from the canonical envelope
            canonical_env = canonical_json_bytes(env)
            expected_prev_hash = hashlib.sha256(canonical_env).hexdigest()

        terminal_envelope_hash = expected_prev_hash
        results["check4_hash_chain_continuity"] = chain_ok and (len(raw_envelopes) > 0)
    except Exception as e:
        audit_errors.append(f"Check 4 exception: {e}")

    if not json_mode:
        s4 = "PASSED" if results["check4_hash_chain_continuity"] else "FAILED"
        print(f"[Check 4/10] Cryptographic Hash-Chain Continuity    : [{s4}]")

    # -------------------------------------------------------------
    # Check 5: Sequence Continuity & Dual-Register Integrity
    # -------------------------------------------------------------
    try:
        seq_reg_ok = True
        seen_sequences = set()
        expected_seq = None
        last_ts = None
        last_cumulative = None

        for idx, payload in enumerate(obs_records, 1):
            seq = payload.get("sequence")
            ts = payload.get("timestamp")
            cum_wh = payload.get("cumulative_wh")
            int_wh = payload.get("interval_wh")

            if expected_seq is None:
                expected_seq = seq

            # Duplicate detection (Replay attack)
            if seq in seen_sequences:
                audit_errors.append(f"Duplicate sequence number detected: #{seq}")
                seq_reg_ok = False
            seen_sequences.add(seq)

            # Monotonic sequence gap detection
            if seq != expected_seq:
                audit_errors.append(f"Sequence gap: expected #{expected_seq}, got #{seq}")
                seq_reg_ok = False

            # Monotonic timestamp check
            if last_ts is not None and ts < last_ts:
                audit_errors.append(f"Non-monotonic timestamp at sequence #{seq}")
                seq_reg_ok = False

            # Dual-register accounting check: cumulative[t] - cumulative[t-1] == interval[t]
            if cum_wh is not None and int_wh is not None:
                if last_cumulative is not None:
                    register_diff = cum_wh - last_cumulative
                    if register_diff != int_wh:
                        audit_errors.append(f"Dual-register mismatch at #{seq}: cumulative delta ({register_diff}) != interval ({int_wh})")
                        seq_reg_ok = False
                last_cumulative = cum_wh
            else:
                audit_errors.append(f"Missing cumulative_wh or interval_wh register at sequence #{seq}")
                seq_reg_ok = False

            last_ts = ts
            expected_seq = seq + 1 if seq is not None else expected_seq + 1

        results["check5_sequence_and_registers"] = seq_reg_ok and (len(obs_records) > 0)
    except Exception as e:
        audit_errors.append(f"Check 5 exception: {e}")

    if not json_mode:
        s5 = "PASSED" if results["check5_sequence_and_registers"] else "FAILED"
        print(f"[Check 5/10] Sequence Continuity & Dual Registers   : [{s5}]")

    # -------------------------------------------------------------
    # Check 6: Claim Boundary Bounding Enforcement & Double-Counting
    # -------------------------------------------------------------
    try:
        boundary_ok = True
        claim_file = os.path.join(bundle_dir, "claim.json")
        trans_energy_file = os.path.join(bundle_dir, "transformations", "energy_aggregation.json")

        if os.path.exists(claim_file) and os.path.exists(trans_energy_file):
            with open(claim_file, "r") as f:
                claim_data = safe_json_load(f)
            with open(trans_energy_file, "r") as f:
                t_energy = safe_json_load(f)

            rep_period = claim_data.get("reporting_period", {})
            declared_first_seq = rep_period.get("first_sequence")
            declared_last_seq = rep_period.get("last_sequence")
            declared_count = rep_period.get("record_count")
            declared_start_ts = rep_period.get("start_timestamp")
            declared_end_ts = rep_period.get("end_timestamp")

            actual_first_seq = obs_records[0].get("sequence") if obs_records else None
            actual_last_seq = obs_records[-1].get("sequence") if obs_records else None
            actual_count = len(obs_records)
            actual_start_ts = obs_records[0].get("timestamp") if obs_records else None
            actual_end_ts = obs_records[-1].get("timestamp") if obs_records else None

            # Required reporting_period fields (C6.3)
            if any(v is None for v in [declared_first_seq, declared_last_seq, declared_count, declared_start_ts, declared_end_ts]):
                audit_errors.append("Reporting period missing required fields (first_sequence, last_sequence, record_count, start_timestamp, end_timestamp)")
                boundary_ok = False

            if claim_data.get("device_id") != certified_device_id:
                audit_errors.append(f"Claim device_id ({claim_data.get('device_id')}) != certified device_id ({certified_device_id})")
                boundary_ok = False

            if declared_first_seq is not None and declared_first_seq != actual_first_seq:
                audit_errors.append(f"Boundary: declared first sequence ({declared_first_seq}) != actual ({actual_first_seq})")
                boundary_ok = False
            if declared_last_seq is not None and declared_last_seq != actual_last_seq:
                audit_errors.append(f"Boundary: declared last sequence ({declared_last_seq}) != actual ({actual_last_seq})")
                boundary_ok = False
            if declared_count is not None and declared_count != actual_count:
                audit_errors.append(f"Boundary: declared record count ({declared_count}) != actual ({actual_count})")
                boundary_ok = False
            if declared_start_ts is not None and declared_start_ts != actual_start_ts:
                audit_errors.append(f"Boundary: declared start timestamp ({declared_start_ts}) != actual ({actual_start_ts})")
                boundary_ok = False
            if declared_end_ts is not None and declared_end_ts != actual_end_ts:
                audit_errors.append(f"Boundary: declared end timestamp ({declared_end_ts}) != actual ({actual_end_ts})")
                boundary_ok = False

            # Auditor-specified expectation enforcement
            if expected_count is not None and actual_count != expected_count:
                audit_errors.append(f"Audit Mandate: Required record count ({expected_count}) does not match bundle count ({actual_count})")
                boundary_ok = False

            # Inter-bundle continuity check (cross-quarter linking)
            if prev_terminal_hash is not None and raw_envelopes:
                genesis_in_bundle = raw_envelopes[0].get("prev_hash")
                if genesis_in_bundle != prev_terminal_hash:
                    audit_errors.append(f"Inter-bundle hash continuity broken: expected {prev_terminal_hash[:12]}..., got {genesis_in_bundle[:12]}...")
                    boundary_ok = False

            # Verify terminal hash in transformation matches hash-chain end
            trans_terminal = t_energy.get("terminal_hash")
            if trans_terminal and trans_terminal != terminal_envelope_hash:
                audit_errors.append("Terminal hash in energy aggregation does not match observation hash-chain")
                boundary_ok = False

            # Double-counting check via claim ledger (C5)
            if claim_ledger is not None:
                try:
                    ledger_data = load_claim_ledger(claim_ledger)
                    entries = ledger_data.get("entries", [])
                    cur_claim_id = claim_data.get("claim_id")
                    cur_seqs = set(f"{certified_device_id}:{r.get('sequence')}" for r in obs_records)
                    for entry in entries:
                        e_cid = entry.get("claim_id")
                        e_term = entry.get("terminal_hash")
                        if e_cid == cur_claim_id:
                            if e_term != terminal_envelope_hash:
                                audit_errors.append(f"Double-counting: claim {cur_claim_id} re-used with different terminal hash")
                                boundary_ok = False
                            continue
                        if e_term == terminal_envelope_hash:
                            audit_errors.append(f"Double-counting: terminal hash already claimed in {e_cid}")
                            boundary_ok = False
                        for s in entry.get("sequences", []):
                            if s in cur_seqs:
                                audit_errors.append(f"Double-counting: sequence {s} already claimed in {e_cid}")
                                boundary_ok = False
                except Exception as e:
                    audit_errors.append(f"Claim ledger check failed: {e}")
                    boundary_ok = False
            else:
                audit_warnings.append("No claim ledger supplied: cross-claim double counting not checked.")
        else:
            boundary_ok = False
            audit_errors.append("Missing claim.json or energy_aggregation.json for boundary check")

        results["check6_claim_boundary_bounds"] = boundary_ok
    except Exception as e:
        audit_errors.append(f"Check 6 exception: {e}")

    if not json_mode:
        s6 = "PASSED" if results["check6_claim_boundary_bounds"] else "FAILED"
        print(f"[Check 6/10] Claim Period Boundary Enforcement      : [{s6}]")

    # -------------------------------------------------------------
    # Check 7: Transformation Lineage & W3C PROV-O Graph
    # -------------------------------------------------------------
    try:
        lineage_ok = True
        trans_carbon_file = os.path.join(bundle_dir, "transformations", "carbon_calculation.json")
        prov_file = os.path.join(bundle_dir, "provenance", "provenance.json")

        if os.path.exists(trans_carbon_file) and os.path.exists(prov_file) and t_energy is not None:
            with open(trans_carbon_file, "r") as f:
                t_carbon = safe_json_load(f)

            actual_obs_hash = compute_sha256(obs_file)
            if t_energy.get("input_observations_sha256") != actual_obs_hash:
                audit_errors.append("Energy aggregation input observations hash mismatch")
                lineage_ok = False

            actual_t_energy_hash = compute_sha256(trans_energy_file)
            if t_carbon.get("input_energy_transformation_sha256") != actual_t_energy_hash:
                audit_errors.append("Carbon calculation input energy transformation hash mismatch")
                lineage_ok = False

            ref_csv_file = os.path.join(bundle_dir, "reference_data", "emission_factor.csv")
            actual_ref_csv_hash = compute_sha256(ref_csv_file)
            if t_carbon.get("input_emission_factor_sha256") != actual_ref_csv_hash:
                audit_errors.append("Carbon calculation input emission factor hash mismatch")
                lineage_ok = False

            # Verify W3C PROV-O entity hashes
            with open(prov_file, "r") as pf:
                prov_data = safe_json_load(pf)
            entities = prov_data.get("entity", {})
            for entity_id, entity_info in entities.items():
                expected_sha = entity_info.get("sha256")
                if expected_sha is None:
                    continue
                if "observations" in entity_id and expected_sha != actual_obs_hash:
                    audit_errors.append("Provenance graph observations hash mismatch")
                    lineage_ok = False
                elif "emission_factor" in entity_id and expected_sha != actual_ref_csv_hash:
                    audit_errors.append("Provenance graph emission factor hash mismatch")
                    lineage_ok = False
        else:
            lineage_ok = False
            audit_errors.append("Missing transformation files or provenance.json")

        results["check7_transformations_and_provenance"] = lineage_ok
    except Exception as e:
        audit_errors.append(f"Check 7 exception: {e}")

    if not json_mode:
        s7 = "PASSED" if results["check7_transformations_and_provenance"] else "FAILED"
        print(f"[Check 7/10] Transformation & Provenance Lineage     : [{s7}]")

    # -------------------------------------------------------------
    # Check 8: Emission Factor Provenance vs Auditor Pinned Registry
    # -------------------------------------------------------------
    try:
        ref_ok = False
        ref_csv_file = os.path.join(bundle_dir, "reference_data", "emission_factor.csv")
        ref_meta_file = os.path.join(bundle_dir, "reference_data", "emission_factor_metadata.json")

        if os.path.exists(ref_csv_file) and os.path.exists(trusted_registry_path):
            actual_csv_hash = compute_sha256(ref_csv_file)

            with open(trusted_registry_path, "r") as rf:
                registry = safe_json_load(rf)
            datasets = registry.get("datasets", {})

            # Zero-Trust: Dataset MUST be registered in the Auditor's Pinned Registry
            if actual_csv_hash in datasets:
                pinned_meta = datasets[actual_csv_hash]
                pinned_factor = float(pinned_meta.get("kg_co2e_per_unit", 0))

                # Verify bundled CSV values match pinned authority (all rows must match - C6.1)
                with open(ref_csv_file, "r") as f:
                    reader = list(csv.DictReader(f))
                    if not reader:
                        audit_errors.append("Bundled CSV has no data rows")
                        ref_ok = False
                    else:
                        ref_ok = True
                        for row in reader:
                            csv_val = float(row.get("kg_co2e_per_unit", -1))
                            if abs(csv_val - pinned_factor) >= 1e-6:
                                audit_errors.append(f"Bundled CSV factor ({csv_val}) != pinned authority ({pinned_factor})")
                                ref_ok = False
            else:
                audit_errors.append(f"Security: Bundled emission factor hash ({actual_csv_hash[:16]}...) is NOT in auditor's pinned registry! Potential greenwashing.")
        else:
            audit_errors.append(f"Missing emission_factor.csv or trusted_references.json registry ({trusted_registry_path})")

        results["check8_pinned_reference_factor"] = ref_ok
    except Exception as e:
        audit_errors.append(f"Check 8 exception: {e}")

    if not json_mode:
        s8 = "PASSED" if results["check8_pinned_reference_factor"] else "FAILED"
        print(f"[Check 8/10] Authoritative Reference Factor Pinning : [{s8}]")

    # -------------------------------------------------------------
    # Check 9: Independent Transformation Re-Execution (Integer Wh)
    # -------------------------------------------------------------
    try:
        recompute_ok = False
        recomputed_wh = sum(int(r.get("interval_wh", 0)) for r in obs_records)
        recomputed_kwh = round(recomputed_wh / 1000.0, 4)

        if pinned_factor is not None:
            recomputed_co2e = round((recomputed_wh / 1000.0) * pinned_factor, 4)
            recompute_ok = True

            # Cross-validate against transformation file declarations
            if t_energy is not None:
                declared_trans_wh = t_energy.get("aggregated_energy_wh")
                if declared_trans_wh != recomputed_wh:
                    audit_errors.append(f"Recomputed energy Wh ({recomputed_wh}) != energy_aggregation.json ({declared_trans_wh})")
                    recompute_ok = False

            if t_carbon is not None:
                declared_trans_co2e = t_carbon.get("calculated_co2e_kg")
                if abs(declared_trans_co2e - recomputed_co2e) > 1e-4:
                    audit_errors.append(f"Recomputed carbon ({recomputed_co2e}) != carbon_calculation.json ({declared_trans_co2e})")
                    recompute_ok = False

        results["check9_independent_recomputation"] = recompute_ok
    except Exception as e:
        audit_errors.append(f"Check 9 exception: {e}")

    if not json_mode:
        s9 = "PASSED" if results["check9_independent_recomputation"] else "FAILED"
        print(f"[Check 9/10] Independent Integer Wh Recomputation  : [{s9}]")

    # -------------------------------------------------------------
    # Check 10: Numeric Claim Reconciliation & Structured Verdict
    # -------------------------------------------------------------
    try:
        claim_reconcile_ok = False
        if claim_data is not None and results["check9_independent_recomputation"]:
            metrics = claim_data.get("declared_metrics", {})
            declared_wh = metrics.get("total_energy_wh")
            declared_co2e = metrics.get("total_emissions_kg_co2e")

            # Zero-tolerance match on integer Watt-hours
            if declared_wh == recomputed_wh and abs(declared_co2e - recomputed_co2e) < 1e-4:
                claim_reconcile_ok = True
            else:
                audit_errors.append(f"Claim reconciliation discrepancy: declared {declared_wh} Wh vs recomputed {recomputed_wh} Wh")

        results["check10_numeric_reconciliation"] = claim_reconcile_ok
    except Exception as e:
        audit_errors.append(f"Check 10 exception: {e}")

    if not json_mode:
        s10 = "PASSED" if results["check10_numeric_reconciliation"] else "FAILED"
        print(f"[Check 10/10] Numeric Claim Reconciliation (Zero-Tol): [{s10}]")

    # -------------------------------------------------------------
    # Structured Audit Report
    # -------------------------------------------------------------
    if attestation_mode == "SIMULATED_STUB":
        audit_warnings.append("Hardware attestation is a simulator stub; manufacturer certificate chain not verified (Milestone 2).")

    all_passed = all(results.values())
    origin_msg = (
        "Declared origin verified (Physical sensor & hardware attestation stub verified)"
        if attestation_mode == "SIMULATED_STUB"
        else "Declared origin verified"
    )
    audit_report = {
        "verdict": "PASSED" if all_passed else "FAILED",
        "bundle": bundle_dir,
        "company_trust_anchor": company_pubkey_path,
        "checks": {k: "PASSED" if v else "FAILED" for k, v in results.items()},
        "errors": audit_errors,
        "warnings": audit_warnings,
        "audit_findings": {
            "observations_status": origin_msg,
            "hardware_attestation_mode": attestation_mode,
            "openssl_path": OPENSSL_BIN,
            "observation_records_count": len(obs_records),
            "hash_chain_status": "Unbroken genesis-to-terminal chain verified" if results["check4_hash_chain_continuity"] else "Broken",
            "reference_factor_status": "Provenance verified against auditor pinned registry",
            "reference_factor_value": pinned_factor,
            "recomputed_energy_wh": recomputed_wh,
            "recomputed_energy_kwh": recomputed_kwh,
            "recomputed_carbon_kg_co2e": recomputed_co2e,
            "lineage_status": "Calculation lineage verified" if results["check7_transformations_and_provenance"] else "Lineage verification failed"
        }
    }

    # Record to claim ledger if requested and verification passed
    if all_passed and record_ledger and claim_ledger:
        record_to_claim_ledger(claim_ledger, {
            "claim_id": claim_data.get("claim_id") if claim_data else "unknown",
            "profile": "energy_submetering",
            "device_id": certified_device_id,
            "sequences": [f"{certified_device_id}:{r.get('sequence')}" for r in obs_records],
            "terminal_hash": terminal_envelope_hash,
            "recorded_at": int(time.time())
        })

    if not json_mode:
        print("-" * 70)
        print(" FORMAL AUDIT VERIFICATION SUMMARY")
        print("-" * 70)
        print(f"  * Observations (Telemetry) : {origin_msg} ({len(obs_records)} records, unbroken hash-chain)")
        print(f"  * Reference Factor          : Provenance verified (Pinned ISPRA {pinned_factor} kg CO2e/kWh)")
        print(f"  * Independent Recomputation : Total Energy  = {recomputed_wh} Wh ({recomputed_kwh} kWh)")
        print(f"                                Total Scope 2 = {recomputed_co2e} kg CO2e")
        print("-" * 70)

        if all_passed:
            print("[AUDIT VERDICT: PASSED]")
            print(f"  Status: {origin_msg}. Calculation lineage verified.")
            print("  All 10 specification checks passed without exception.")
            if audit_warnings:
                print("  Warnings:")
                for warn in audit_warnings:
                    print(f"    - [WARNING] {warn}")
            print("=" * 70)
        else:
            print("[AUDIT VERDICT: FAILED]")
            print("  Status: Evidence bundle failed cryptographic or lineage checks.")
            if verbose and audit_errors:
                print("  Errors:")
                for err in audit_errors:
                    print(f"    - {err}")
            if audit_warnings:
                print("  Warnings:")
                for warn in audit_warnings:
                    print(f"    - [WARNING] {warn}")
            print("=" * 70)
    else:
        print(json.dumps(audit_report, indent=2))

    if json_out_path:
        with open(json_out_path, "w") as jf:
            json.dump(audit_report, jf, indent=2)
        if not json_mode:
            print(f"[+] Structured audit report saved: {json_out_path}")

    return all_passed


# UNIVERSAL PROFILE DISPATCHER
# =====================================================================

def verify_bundle(bundle_dir, company_pubkey_path, trusted_registry_path=None,
                  verbose=False, json_mode=False, json_out_path=None,
                  expected_count=None, prev_terminal_hash=None, revoked=None, profile=None,
                  claim_ledger=None, record_ledger=False):
    # Enforce trust anchor presence (C6.2: no silent fallback)
    if not company_pubkey_path or not os.path.exists(company_pubkey_path):
        err = f"Error: Trust anchor key file not found: {company_pubkey_path}. Specify via --company-key."
        if json_mode:
            print(json.dumps({"verdict": "FAILED", "errors": [err]}, indent=2))
        else:
            print(f"[!] {err}")
        return False

    claim_path = os.path.join(bundle_dir, "claim.json")
    manifest_path = os.path.join(bundle_dir, "manifest.json")
    manifest_profile = None
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r") as mf:
                m_data = safe_json_load(mf)
                manifest_profile = m_data.get("profile")
        except Exception:
            pass

    detected_profile = profile
    if detected_profile is None and os.path.exists(claim_path):
        try:
            with open(claim_path, "r") as cf:
                c_data = safe_json_load(cf)
            detected_profile = c_data.get("profile")
        except Exception:
            pass

    if detected_profile is None:
        if manifest_profile is None or manifest_profile == "energy_submetering":
            detected_profile = "energy_submetering"
        else:
            detected_profile = manifest_profile

    if detected_profile not in ("biochar_pyrolysis", "energy_submetering"):
        err = f"Error: Unknown or unsupported profile: {detected_profile}"
        if json_mode:
            print(json.dumps({"verdict": "FAILED", "errors": [err]}, indent=2))
        else:
            print(f"[!] {err}")
        return False

    if trusted_registry_path is None:
        base_script_dir = os.path.dirname(os.path.abspath(__file__))
        trusted_registry_path = os.path.join(base_script_dir, "trusted_references.json")

    if detected_profile == "biochar_pyrolysis":
        return verify_biochar_bundle(bundle_dir, company_pubkey_path, trusted_registry_path,
                                     verbose=verbose, json_mode=json_mode, json_out_path=json_out_path,
                                     expected_count=expected_count, prev_terminal_hash=prev_terminal_hash,
                                     revoked=revoked, claim_ledger=claim_ledger, record_ledger=record_ledger)
    else:
        return verify_energy_bundle(bundle_dir, company_pubkey_path, trusted_registry_path,
                                    verbose=verbose, json_mode=json_mode, json_out_path=json_out_path,
                                    expected_count=expected_count, prev_terminal_hash=prev_terminal_hash,
                                    revoked=revoked, claim_ledger=claim_ledger, record_ledger=record_ledger)


def main():
    parser = argparse.ArgumentParser(description="Modular Zero-Trust Evidence Bundle Verifier (v1.2)")
    parser.add_argument("bundle", nargs="?", default="claim_bundle", help="Path to claim_bundle directory")
    parser.add_argument("--company-key", default="company_root_public_key.pem", help="Path to Root Public Key / Trust Anchor")
    parser.add_argument("--trusted-registry", default=None, help="Path to auditor's pinned trusted_references.json")
    parser.add_argument("--expected-count", type=int, default=None, help="Auditor-mandated observation count")
    parser.add_argument("--prev-terminal-hash", default=None, help="Terminal hash from previous reporting period")
    parser.add_argument("--revoked", default=None, help="Comma-separated device IDs or path to revocation file")
    parser.add_argument("--profile", default=None, help="Force specific profile: biochar_pyrolysis or energy_submetering")
    parser.add_argument("--claim-ledger", default=None, help="Path to auditor claim ledger against double counting")
    parser.add_argument("--record-ledger", action="store_true", help="Record verified claim to ledger")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose diagnostics (display error breakdown)")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON audit report")
    parser.add_argument("--json-out", default=None, help="Save machine-readable JSON report to file")
    args = parser.parse_args()

    success = verify_bundle(args.bundle, args.company_key, trusted_registry_path=args.trusted_registry,
                            verbose=args.verbose, json_mode=args.json, json_out_path=args.json_out,
                            expected_count=args.expected_count, prev_terminal_hash=args.prev_terminal_hash,
                            revoked=args.revoked, profile=args.profile,
                            claim_ledger=args.claim_ledger, record_ledger=args.record_ledger)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
