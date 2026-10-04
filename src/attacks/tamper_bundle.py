"""
Adversarial Attack Simulation & Tamper Benchmark

Generates 8 distinct corrupted claim bundle variants to prove that
the Offline Verifier detects real-world telemetry fraud:
  1. Attack A (Observation Tampering): Falsifies raw sensor kWh reading.
  2. Attack B (Sequence Truncation/Omission): Deletes interval record (peak shaving).
  3. Attack C (Rogue Device Impersonation): Signs with uncertified key.
  4. Attack D (Greenwashing Reference Manipulation): Undervaluates grid emission factor.
  5. Attack E (Replay / Duplicate Sequence): Injects duplicated observation.
  6. Attack F (Device ID Mismatch): Swaps device_id in observation envelope.
  7. Attack G (Timestamp Backdating / Range Violation): Uses timestamp outside cert window.
  8. Attack H (Sophisticated Re-Hash): Tampers AND recomputes hashes — caught only by bundle seal.
"""

import os
import shutil
import json
import csv
import subprocess
import sys
import hashlib

def clone_bundle(src_bundle, dest_bundle):
    if os.path.exists(dest_bundle):
        shutil.rmtree(dest_bundle)
    shutil.copytree(src_bundle, dest_bundle)

def compute_sha256(filepath):
    """Computes SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def run_attack_suite(clean_bundle="claim_bundle", company_key="company_root_public_key.pem"):
    print("=" * 70)
    print(" Adversarial Attack Suite — Comprehensive Tamper Benchmark")
    print("=" * 70)

    attacks = []

    # ------------------------------------------------------------------
    # Attack A: Falsify raw sensor kWh observation
    # ------------------------------------------------------------------
    attack_a_dir = "bundle_attack_a_tampered_kwh"
    clone_bundle(clean_bundle, attack_a_dir)
    obs_file = os.path.join(attack_a_dir, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    if lines:
        rec = json.loads(lines[0])
        rec["payload"]["reading_kwh"] = 9999.99  # Altered reading
        lines[0] = json.dumps(rec) + "\n"
        with open(obs_file, "w") as f:
            f.writelines(lines)
    
    print("\n[+] Running Attack A: Falsified sensor kWh reading...")
    res = subprocess.run([sys.executable, "src/verifier/verify_bundle.py", attack_a_dir, "--company-key", company_key], capture_output=True, text=True)
    caught_a = "AUDIT VERDICT: FAILED" in res.stdout
    attacks.append(("Attack A (Observation Tampering)", caught_a))
    print(f"    Result: {'[CAUGHT BY VERIFIER]' if caught_a else '[MISSED]'}")

    # ------------------------------------------------------------------
    # Attack B: Delete sequence interval (peak-shaving fraud)
    # ------------------------------------------------------------------
    attack_b_dir = "bundle_attack_b_deleted_row"
    clone_bundle(clean_bundle, attack_b_dir)
    obs_file = os.path.join(attack_b_dir, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    if len(lines) >= 3:
        del lines[1]  # Delete sequence #2
        with open(obs_file, "w") as f:
            f.writelines(lines)

    print("\n[+] Running Attack B: Deleted sequence row (selective omission)...")
    res = subprocess.run([sys.executable, "src/verifier/verify_bundle.py", attack_b_dir, "--company-key", company_key], capture_output=True, text=True)
    caught_b = res.returncode != 0 and "AUDIT VERDICT: FAILED" in res.stdout
    attacks.append(("Attack B (Sequence Omission)", caught_b))
    print(f"    Result: {'[CAUGHT BY VERIFIER]' if caught_b else '[MISSED]'}")

    # ------------------------------------------------------------------
    # Attack C: Rogue device impersonation (uncertified key)
    # ------------------------------------------------------------------
    attack_c_dir = "bundle_attack_c_rogue_device"
    clone_bundle(clean_bundle, attack_c_dir)
    cert_file = os.path.join(attack_c_dir, "device", "device_certificate.json")
    with open(cert_file, "r") as f:
        cert_data = json.load(f)
    cert_data["certificate_body"]["device_id"] = "device_rogue_attacker_99"
    with open(cert_file, "w") as f:
        json.dump(cert_data, f, indent=2)

    print("\n[+] Running Attack C: Rogue uncertified device identity...")
    res = subprocess.run([sys.executable, "src/verifier/verify_bundle.py", attack_c_dir, "--company-key", company_key], capture_output=True, text=True)
    caught_c = res.returncode != 0 and "AUDIT VERDICT: FAILED" in res.stdout
    attacks.append(("Attack C (Rogue Device)", caught_c))
    print(f"    Result: {'[CAUGHT BY VERIFIER]' if caught_c else '[MISSED]'}")

    # ------------------------------------------------------------------
    # Attack D: Reference emission factor tampering (greenwashing)
    # ------------------------------------------------------------------
    attack_d_dir = "bundle_attack_d_greenwash_factor"
    clone_bundle(clean_bundle, attack_d_dir)
    csv_file = os.path.join(attack_d_dir, "reference_data", "emission_factor.csv")
    with open(csv_file, "w") as f:
        f.write("country,factor_year,activity_type,unit,kg_co2e_per_unit,source\n")
        f.write("IT,2026,electricity_grid_mix,kWh,0.0500,Fabricated Low Carbon Grid\n")

    print("\n[+] Running Attack D: Greenwashed reference emission factor...")
    res = subprocess.run([sys.executable, "src/verifier/verify_bundle.py", attack_d_dir, "--company-key", company_key], capture_output=True, text=True)
    caught_d = res.returncode != 0 and "AUDIT VERDICT: FAILED" in res.stdout
    attacks.append(("Attack D (Greenwashed Factor)", caught_d))
    print(f"    Result: {'[CAUGHT BY VERIFIER]' if caught_d else '[MISSED]'}")

    # ------------------------------------------------------------------
    # Attack E: Duplicate Sequence / Replay Attack
    # ------------------------------------------------------------------
    attack_e_dir = "bundle_attack_e_replay"
    clone_bundle(clean_bundle, attack_e_dir)
    obs_file = os.path.join(attack_e_dir, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    if lines:
        lines.append(lines[0])  # Duplicate record 1 at the end
        with open(obs_file, "w") as f:
            f.writelines(lines)

    print("\n[+] Running Attack E: Duplicate sequence number (replay attack)...")
    res = subprocess.run([sys.executable, "src/verifier/verify_bundle.py", attack_e_dir, "--company-key", company_key], capture_output=True, text=True)
    caught_e = res.returncode != 0 and "AUDIT VERDICT: FAILED" in res.stdout
    attacks.append(("Attack E (Duplicate Sequence)", caught_e))
    print(f"    Result: {'[CAUGHT BY VERIFIER]' if caught_e else '[MISSED]'}")

    # ------------------------------------------------------------------
    # Attack F: Device ID Mismatch in Observation Envelope
    # ------------------------------------------------------------------
    attack_f_dir = "bundle_attack_f_device_mismatch"
    clone_bundle(clean_bundle, attack_f_dir)
    obs_file = os.path.join(attack_f_dir, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    if lines:
        rec = json.loads(lines[0])
        rec["device_id"] = "device_foreign_999999"
        lines[0] = json.dumps(rec) + "\n"
        with open(obs_file, "w") as f:
            f.writelines(lines)

    print("\n[+] Running Attack F: Observation envelope device_id mismatch...")
    res = subprocess.run([sys.executable, "src/verifier/verify_bundle.py", attack_f_dir, "--company-key", company_key], capture_output=True, text=True)
    caught_f = res.returncode != 0 and "AUDIT VERDICT: FAILED" in res.stdout
    attacks.append(("Attack F (Device ID Mismatch)", caught_f))
    print(f"    Result: {'[CAUGHT BY VERIFIER]' if caught_f else '[MISSED]'}")

    # ------------------------------------------------------------------
    # Attack G: Observation timestamp outside certificate validity range
    # ------------------------------------------------------------------
    attack_g_dir = "bundle_attack_g_timestamp_range"
    clone_bundle(clean_bundle, attack_g_dir)
    obs_file = os.path.join(attack_g_dir, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    if lines:
        rec = json.loads(lines[0])
        rec["payload"]["timestamp"] = 1577836800  # 2020 — before cert valid_from: 2026
        lines[0] = json.dumps(rec) + "\n"
        with open(obs_file, "w") as f:
            f.writelines(lines)

    print("\n[+] Running Attack G: Observation timestamp outside cert window...")
    res = subprocess.run([sys.executable, "src/verifier/verify_bundle.py", attack_g_dir, "--company-key", company_key], capture_output=True, text=True)
    caught_g = res.returncode != 0 and "AUDIT VERDICT: FAILED" in res.stdout
    attacks.append(("Attack G (Timestamp Range Violation)", caught_g))
    print(f"    Result: {'[CAUGHT BY VERIFIER]' if caught_g else '[MISSED]'}")

    # ------------------------------------------------------------------
    # Attack H: Sophisticated Re-Hash Attack (tamper + recompute hashes)
    # This is the critical test for the Bundle Seal. The attacker:
    #   1. Modifies a file (observations.ndjson)
    #   2. Recomputes the SHA-256 of the modified file
    #   3. Updates manifest.json and checksums.txt with correct hashes
    # Without the bundle seal, Check 1 would PASS (hashes are consistent).
    # WITH the bundle seal, Check 1 FAILS (seal was signed over original hashes).
    # ------------------------------------------------------------------
    attack_h_dir = "bundle_attack_h_rehash"
    clone_bundle(clean_bundle, attack_h_dir)
    obs_file = os.path.join(attack_h_dir, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    if lines:
        rec = json.loads(lines[0])
        rec["payload"]["interval_kwh"] = 0.001  # Drastically reduce energy
        lines[0] = json.dumps(rec) + "\n"
        with open(obs_file, "w") as f:
            f.writelines(lines)

    # Sophisticated attacker: recompute hash and update manifest
    new_obs_hash = compute_sha256(obs_file)
    manifest_path = os.path.join(attack_h_dir, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    manifest["files"]["observations/observations.ndjson"] = new_obs_hash
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # Also update checksums.txt
    checksums_path = os.path.join(attack_h_dir, "checksums.txt")
    with open(checksums_path, "r") as f:
        cksum_lines = f.readlines()
    with open(checksums_path, "w") as f:
        for line in cksum_lines:
            if "observations/observations.ndjson" in line:
                f.write(f"{new_obs_hash}  observations/observations.ndjson\n")
            else:
                f.write(line)

    print("\n[+] Running Attack H: Tampered data + recomputed hashes (seal bypass attempt)...")
    res = subprocess.run([sys.executable, "src/verifier/verify_bundle.py", attack_h_dir, "--company-key", company_key], capture_output=True, text=True)
    caught_h = res.returncode != 0 and "AUDIT VERDICT: FAILED" in res.stdout
    attacks.append(("Attack H (Re-Hash / Seal Bypass)", caught_h))
    print(f"    Result: {'[CAUGHT BY VERIFIER]' if caught_h else '[MISSED]'}")

    # Cleanup attack directories
    all_dirs = [attack_a_dir, attack_b_dir, attack_c_dir, attack_d_dir,
                attack_e_dir, attack_f_dir, attack_g_dir, attack_h_dir]
    for d in all_dirs:
        shutil.rmtree(d, ignore_errors=True)

    print("-" * 70)
    all_caught = all(caught for _, caught in attacks)
    if all_caught:
        print(f"[SUCCESS] All {len(attacks)}/{len(attacks)} adversarial attack vectors detected and rejected.")
    else:
        missed = [name for name, caught in attacks if not caught]
        print(f"[WARN] {len(missed)} attack(s) bypassed verification: {', '.join(missed)}")
    print("=" * 70)


if __name__ == "__main__":
    run_attack_suite()
