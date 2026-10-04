"""
Outsider Adversarial Attack Benchmark (v1.1)

Tests outsider attacks where an adversary intercepts or tampers with
an existing evidence bundle without holding the Company Root Key:
  1. Attack O1: Falsified sensor reading Wh.
  2. Attack O2: Rogue uncertified device key.
  3. Attack O3: Dropped middle record (sequence gap).
  4. Attack O4: Duplicate record (replay attack).
  5. Attack O5: Device ID mismatch in envelope.
  6. Attack O6: Observation timestamp outside certificate validity window.
  7. Attack O7: Sophisticated re-hash (tamper file + update SHA-256 in manifest).
  8. Attack O8: Path traversal injection in manifest (e.g., ../malicious).
  9. Attack O9: Rogue unmanifested file injected into bundle.
"""

import os
import shutil
import json
import subprocess
import sys
import hashlib

def clone_bundle(src_bundle, dest_bundle):
    if os.path.exists(dest_bundle):
        shutil.rmtree(dest_bundle)
    shutil.copytree(src_bundle, dest_bundle)

def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def verify_and_check(bundle_path, company_key, expected_failed_check=None, extra_args=None):
    cmd = [
        sys.executable, "src/verifier/verify_bundle.py", bundle_path,
        "--company-key", company_key, "--json"
    ]
    if extra_args:
        cmd.extend(extra_args)
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        return False
    try:
        data = json.loads(res.stdout)
        if data.get("verdict") != "FAILED":
            return False
        if expected_failed_check:
            return data.get("checks", {}).get(expected_failed_check) == "FAILED"
        return True
    except Exception:
        return res.returncode != 0

def run_outsider_tests(clean_bundle="claim_bundle", company_key="company_root_public_key.pem"):
    print("=" * 70)
    print(" Outsider Adversarial Attack Benchmark (Programmatic Assertions)")
    print("=" * 70)

    attacks = []

    # O1: Falsify sensor reading
    d1 = "bundle_atk_o1_reading"
    clone_bundle(clean_bundle, d1)
    obs_file = os.path.join(d1, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    rec = json.loads(lines[0])
    rec["payload"]["cumulative_wh"] = 99999999
    lines[0] = json.dumps(rec) + "\n"
    with open(obs_file, "w") as f:
        f.writelines(lines)
    c1 = verify_and_check(d1, company_key, "check3_observation_signatures")
    attacks.append(("O1: Falsified Reading Wh", c1))

    # O2: Rogue uncertified key
    d2 = "bundle_atk_o2_rogue_cert"
    clone_bundle(clean_bundle, d2)
    cert_file = os.path.join(d2, "device", "device_certificate.json")
    with open(cert_file, "r") as f:
        cert_data = json.load(f)
    cert_data["certificate_body"]["device_id"] = "device_rogue_adversary_99"
    with open(cert_file, "w") as f:
        json.dump(cert_data, f, indent=2)
    c2 = verify_and_check(d2, company_key, "check2_device_cert_and_attestation")
    attacks.append(("O2: Rogue Uncertified Key", c2))

    # O3: Dropped middle record (sequence gap)
    d3 = "bundle_atk_o3_gap"
    clone_bundle(clean_bundle, d3)
    obs_file = os.path.join(d3, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    if len(lines) >= 3:
        del lines[1]
    with open(obs_file, "w") as f:
        f.writelines(lines)
    c3 = verify_and_check(d3, company_key, "check5_sequence_and_registers")
    attacks.append(("O3: Dropped Middle Record", c3))

    # O4: Duplicate record (replay attack)
    d4 = "bundle_atk_o4_replay"
    clone_bundle(clean_bundle, d4)
    obs_file = os.path.join(d4, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    lines.append(lines[0])
    with open(obs_file, "w") as f:
        f.writelines(lines)
    c4 = verify_and_check(d4, company_key, "check5_sequence_and_registers")
    attacks.append(("O4: Duplicate Replay", c4))

    # O5: Device ID mismatch in envelope
    d5 = "bundle_atk_o5_device_mismatch"
    clone_bundle(clean_bundle, d5)
    obs_file = os.path.join(d5, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    rec = json.loads(lines[0])
    rec["device_id"] = "device_foreign_9999"
    lines[0] = json.dumps(rec) + "\n"
    with open(obs_file, "w") as f:
        f.writelines(lines)
    c5 = verify_and_check(d5, company_key, "check3_observation_signatures")
    attacks.append(("O5: Device ID Envelope Mismatch", c5))

    # O6: Timestamp out of cert validity range
    d6 = "bundle_atk_o6_timestamp"
    clone_bundle(clean_bundle, d6)
    obs_file = os.path.join(d6, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    rec = json.loads(lines[0])
    rec["payload"]["timestamp"] = 1577836800  # 2020
    lines[0] = json.dumps(rec) + "\n"
    with open(obs_file, "w") as f:
        f.writelines(lines)
    c6 = verify_and_check(d6, company_key, "check3_observation_signatures")
    attacks.append(("O6: Timestamp Validity Violation", c6))

    # O7: Re-hash seal bypass attack
    d7 = "bundle_atk_o7_rehash"
    clone_bundle(clean_bundle, d7)
    obs_file = os.path.join(d7, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    rec = json.loads(lines[0])
    rec["payload"]["interval_wh"] = 10
    lines[0] = json.dumps(rec) + "\n"
    with open(obs_file, "w") as f:
        f.writelines(lines)
    new_obs_hash = compute_sha256(obs_file)
    manifest_path = os.path.join(d7, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    manifest["files"]["observations/observations.ndjson"] = new_obs_hash
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    c7 = verify_and_check(d7, company_key, "check1_manifest_and_seal")
    attacks.append(("O7: Re-Hash Manifest Seal Bypass", c7))

    # O8: Path traversal injection
    d8 = "bundle_atk_o8_traversal"
    clone_bundle(clean_bundle, d8)
    manifest_path = os.path.join(d8, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    manifest["files"]["../../etc/passwd"] = "0000000000000000000000000000000000000000000000000000000000000000"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    c8 = verify_and_check(d8, company_key, "check1_manifest_and_seal")
    attacks.append(("O8: Path Traversal Injection", c8))

    # O9: Unmanifested file injection
    d9 = "bundle_atk_o9_unmanifested"
    clone_bundle(clean_bundle, d9)
    with open(os.path.join(d9, "injected_backdoor.sh"), "w") as f:
        f.write("#!/bin/sh\necho malicious\n")
    c9 = verify_and_check(d9, company_key, "check1_manifest_and_seal")
    attacks.append(("O9: Unmanifested File Injection", c9))

    # O10: Revoked Gateway / Stolen Key Attempt
    d10 = "bundle_atk_o10_revoked"
    clone_bundle(clean_bundle, d10)
    # Read certified device_id
    with open(os.path.join(d10, "device", "identity.json"), "r") as f:
        dev_id = json.load(f).get("device_id")
    c10 = verify_and_check(d10, company_key, "check2_device_cert_and_attestation", extra_args=["--revoked", dev_id])
    attacks.append(("O10: Revoked Gateway Rejection", c10))

    # Cleanup
    for d in [d1, d2, d3, d4, d5, d6, d7, d8, d9, d10]:
        shutil.rmtree(d, ignore_errors=True)

    print("-" * 70)
    for name, caught in attacks:
        status = "[CAUGHT BY VERIFIER]" if caught else "[BYPASSED]"
        print(f"  * {name:<45} : {status}")
    print("-" * 70)
    all_caught = all(c for _, c in attacks)
    if all_caught:
        print(f"[SUCCESS] All {len(attacks)}/{len(attacks)} outsider attack vectors detected and rejected.")
    else:
        print("[WARN] Some outsider attacks bypassed verification!")
    print("=" * 70)
    return all_caught

if __name__ == "__main__":
    success = run_outsider_tests()
    sys.exit(0 if success else 1)
