#!/usr/bin/env python3
"""
Outsider Adversarial Attack Benchmark (v1.3)

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
  10. Attack O10: Revoked gateway rejection via verifier revocation list.
  11. Attack O11: Bundle contains private key material (device_private_key.pem).
"""

import os
import shutil
import json
import subprocess
import sys
import hashlib
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from src.attacks.harness import verify_and_check, assert_baseline_passes
from src.attacks.fixtures import build_energy_fixture

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

def run_outsider_tests():
    print("=" * 70)
    print(" Outsider Adversarial Attack Benchmark (Programmatic Assertions)")
    print("=" * 70)

    workdir = tempfile.mkdtemp(prefix="outsider_attacks_")
    attacks = []

    try:
        # Build clean fixture inside workdir
        fixture = build_energy_fixture(workdir)
        clean_bundle = fixture["bundle"]
        company_pub = fixture["root_pub"]
        registry = fixture["registry"]

        # Baseline assertion (must pass before running attacks)
        assert_baseline_passes(clean_bundle, company_pub, registry=registry)

        # -------------------------------------------------------------
        # O1: Falsify sensor reading Wh
        # -------------------------------------------------------------
        d1 = os.path.join(workdir, "bundle_atk_o1_reading")
        clone_bundle(clean_bundle, d1)
        obs_file = os.path.join(d1, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            lines = f.readlines()
        rec = json.loads(lines[0])
        rec["payload"]["cumulative_wh"] = 99999999
        lines[0] = json.dumps(rec) + "\n"
        with open(obs_file, "w") as f:
            f.writelines(lines)
        c1, det1 = verify_and_check(d1, company_pub, "check3_observation_signatures", registry=registry)
        attacks.append(("O1: Falsified Reading Wh", c1, det1))

        # -------------------------------------------------------------
        # O2: Rogue uncertified key
        # -------------------------------------------------------------
        d2 = os.path.join(workdir, "bundle_atk_o2_rogue_cert")
        clone_bundle(clean_bundle, d2)
        cert_file = os.path.join(d2, "device", "device_certificate.json")
        with open(cert_file, "r") as f:
            cert_data = json.load(f)
        cert_data["certificate_body"]["device_id"] = "device_rogue_adversary_99"
        with open(cert_file, "w") as f:
            json.dump(cert_data, f, indent=2)
        c2, det2 = verify_and_check(d2, company_pub, "check2_device_cert_and_attestation", registry=registry)
        attacks.append(("O2: Rogue Uncertified Key", c2, det2))

        # -------------------------------------------------------------
        # O3: Dropped middle record (sequence gap)
        # -------------------------------------------------------------
        d3 = os.path.join(workdir, "bundle_atk_o3_gap")
        clone_bundle(clean_bundle, d3)
        obs_file = os.path.join(d3, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            lines = f.readlines()
        if len(lines) >= 3:
            del lines[1]
        with open(obs_file, "w") as f:
            f.writelines(lines)
        c3, det3 = verify_and_check(d3, company_pub, "check5_sequence_and_registers", registry=registry)
        attacks.append(("O3: Dropped Middle Record", c3, det3))

        # -------------------------------------------------------------
        # O4: Duplicate record (replay attack)
        # -------------------------------------------------------------
        d4 = os.path.join(workdir, "bundle_atk_o4_replay")
        clone_bundle(clean_bundle, d4)
        obs_file = os.path.join(d4, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            lines = f.readlines()
        lines.append(lines[0])
        with open(obs_file, "w") as f:
            f.writelines(lines)
        c4, det4 = verify_and_check(d4, company_pub, "check5_sequence_and_registers", registry=registry)
        attacks.append(("O4: Duplicate Replay", c4, det4))

        # -------------------------------------------------------------
        # O5: Device ID mismatch in envelope
        # -------------------------------------------------------------
        d5 = os.path.join(workdir, "bundle_atk_o5_device_mismatch")
        clone_bundle(clean_bundle, d5)
        obs_file = os.path.join(d5, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            lines = f.readlines()
        rec = json.loads(lines[0])
        rec["device_id"] = "device_foreign_9999"
        lines[0] = json.dumps(rec) + "\n"
        with open(obs_file, "w") as f:
            f.writelines(lines)
        c5, det5 = verify_and_check(d5, company_pub, "check3_observation_signatures", registry=registry)
        attacks.append(("O5: Device ID Envelope Mismatch", c5, det5))

        # -------------------------------------------------------------
        # O6: Timestamp out of cert validity range
        # -------------------------------------------------------------
        d6 = os.path.join(workdir, "bundle_atk_o6_timestamp")
        clone_bundle(clean_bundle, d6)
        obs_file = os.path.join(d6, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            lines = f.readlines()
        rec = json.loads(lines[0])
        rec["payload"]["timestamp"] = 1577836800  # 2020
        lines[0] = json.dumps(rec) + "\n"
        with open(obs_file, "w") as f:
            f.writelines(lines)
        c6, det6 = verify_and_check(d6, company_pub, "check3_observation_signatures", registry=registry)
        attacks.append(("O6: Timestamp Validity Violation", c6, det6))

        # -------------------------------------------------------------
        # O7: Re-hash seal bypass attack
        # -------------------------------------------------------------
        d7 = os.path.join(workdir, "bundle_atk_o7_rehash")
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
        c7, det7 = verify_and_check(d7, company_pub, "check1_manifest_and_seal", registry=registry)
        attacks.append(("O7: Re-Hash Manifest Seal Bypass", c7, det7))

        # -------------------------------------------------------------
        # O8: Path traversal injection
        # -------------------------------------------------------------
        d8 = os.path.join(workdir, "bundle_atk_o8_traversal")
        clone_bundle(clean_bundle, d8)
        manifest_path = os.path.join(d8, "manifest.json")
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        manifest["files"]["../../etc/passwd"] = "0000000000000000000000000000000000000000000000000000000000000000"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        c8, det8 = verify_and_check(d8, company_pub, "check1_manifest_and_seal", registry=registry)
        attacks.append(("O8: Path Traversal Injection", c8, det8))

        # -------------------------------------------------------------
        # O9: Unmanifested file injection
        # -------------------------------------------------------------
        d9 = os.path.join(workdir, "bundle_atk_o9_unmanifested")
        clone_bundle(clean_bundle, d9)
        with open(os.path.join(d9, "injected_backdoor.sh"), "w") as f:
            f.write("#!/bin/sh\necho malicious\n")
        c9, det9 = verify_and_check(d9, company_pub, "check1_manifest_and_seal", registry=registry)
        attacks.append(("O9: Unmanifested File Injection", c9, det9))

        # -------------------------------------------------------------
        # O10: Revoked Gateway / Stolen Key Attempt
        # -------------------------------------------------------------
        d10 = os.path.join(workdir, "bundle_atk_o10_revoked")
        clone_bundle(clean_bundle, d10)
        with open(os.path.join(d10, "device", "identity.json"), "r") as f:
            dev_id = json.load(f).get("device_id")
        c10, det10 = verify_and_check(d10, company_pub, "check2_device_cert_and_attestation", extra_args=["--revoked", dev_id], registry=registry)
        attacks.append(("O10: Revoked Gateway Rejection", c10, det10))

        # -------------------------------------------------------------
        # O11: Private key material inside bundle
        # -------------------------------------------------------------
        d11 = os.path.join(workdir, "bundle_atk_o11_priv_key")
        clone_bundle(clean_bundle, d11)
        with open(os.path.join(d11, "device", "device_private_key.pem"), "w") as f:
            f.write("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFAKEKEY\n-----END EC PRIVATE KEY-----\n")
        c11, det11 = verify_and_check(d11, company_pub, "check1_manifest_and_seal", registry=registry)
        attacks.append(("O11: Private Key Material Inside Bundle", c11, det11))

    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("-" * 70)
    all_caught = True
    for name, caught, detail in attacks:
        status = "[CAUGHT BY VERIFIER]" if caught else "[BYPASSED]"
        print(f"  * {name:<45} : {status}")
        if not caught:
            print(f"    -> Detail: {detail}")
            all_caught = False
    print("-" * 70)

    if all_caught:
        print(f"[SUCCESS] All {len(attacks)}/{len(attacks)} outsider attack vectors detected and rejected.")
    else:
        missed = [name for name, caught, _ in attacks if not caught]
        print(f"[WARN] {len(missed)} outsider attack(s) bypassed verification: {', '.join(missed)}")
    print("=" * 70)
    return all_caught

if __name__ == "__main__":
    success = run_outsider_tests()
    sys.exit(0 if success else 1)
