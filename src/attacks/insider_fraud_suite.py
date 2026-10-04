"""
Insider Fraud Benchmark Suite (Zero-Trust vs Dishonest Enterprise)

Evaluates attacks where the REPORTING ENTERPRISE is the attacker:
The company holds the Company Root Key, runs the pipeline, can regenerate
transformations, and can sign a cryptographically valid Bundle Seal.

Demonstrates that Zero-Trust Verifier controls prevent insider fraud:
  1. Attack I1: Emission Factor Greenwashing (swapping factor + valid reseal).
  2. Attack I2: Dual-Register Shaving (tampering interval Wh vs cumulative totalizer).
  3. Attack I3: Head/Tail Truncation vs Audit Mandate (dropping peak hours + valid reseal).
  4. Attack I4: Software Simulator Impersonation (forging device without hardware attestation).
  5. Attack I5: Telemetry Splicing (splicing non-consecutive days / broken hash-chain).
"""

import os
import shutil
import json
import subprocess
import sys

sys.path.insert(0, "src/pipeline")
from claim_generator import generate_claim_bundle

def clone_bundle(src_bundle, dest_bundle):
    if os.path.exists(dest_bundle):
        shutil.rmtree(dest_bundle)
    shutil.copytree(src_bundle, dest_bundle)

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

def run_insider_tests(clean_bundle="claim_bundle", company_key="company_root_public_key.pem"):
    print("=" * 70)
    print(" Insider Fraud Benchmark Suite (Programmatic Assertions)")
    print("=" * 70)

    attacks = []

    # -------------------------------------------------------------
    # Attack I1: Emission Factor Greenwashing
    # Company modifies reference CSV to 0.0500, regenerates and reseals bundle
    # -------------------------------------------------------------
    d1 = "bundle_insider_i1_greenwash"
    ext1 = "tmp_ext_i1"
    os.makedirs(ext1, exist_ok=True)
    with open(os.path.join(ext1, "emission_factor.csv"), "w") as f:
        f.write("country,factor_year,activity_type,unit,kg_co2e_per_unit,source\nIT,2026,electricity_grid_mix,kWh,0.0500,Fabricated Fake Factor\n")
    with open(os.path.join(ext1, "emission_factor_metadata.json"), "w") as f:
        json.dump({"dataset_name": "Fabricated", "factor_value": 0.0500}, f)
    
    clone_bundle(clean_bundle, d1)
    generate_claim_bundle(bundle_root=d1, reference_dir=ext1, company_priv_key_path="company_root_private_key.pem")

    c1 = verify_and_check(d1, company_key, "check8_pinned_reference_factor")
    attacks.append(("I1: Emission Factor Greenwashing + Reseal", c1))

    # -------------------------------------------------------------
    # Attack I2: Dual-Register Shaving
    # Company modifies interval_wh in payload to shave carbon, but meter cumulative totalizer disagrees
    # -------------------------------------------------------------
    d2 = "bundle_insider_i2_register_tamper"
    clone_bundle(clean_bundle, d2)
    obs_file = os.path.join(d2, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    if len(lines) >= 2:
        rec = json.loads(lines[1])
        rec["payload"]["interval_wh"] = 500
        lines[1] = json.dumps(rec) + "\n"
        with open(obs_file, "w") as f:
            f.writelines(lines)
    generate_claim_bundle(bundle_root=d2, reference_dir="05_data/external", company_priv_key_path="company_root_private_key.pem")

    c2 = verify_and_check(d2, company_key, "check5_sequence_and_registers")
    attacks.append(("I2: Dual-Register Shaving (Meter Cumulative Disagreement)", c2))

    # -------------------------------------------------------------
    # Attack I3: Period Head/Tail Truncation vs Audit Mandate
    # Company drops peak hours (takes first 3 of 5 readings), regenerates and reseals
    # -------------------------------------------------------------
    d3 = "bundle_insider_i3_truncation"
    clone_bundle(clean_bundle, d3)
    obs_file = os.path.join(d3, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()[:3]
    with open(obs_file, "w") as f:
        f.writelines(lines)
    generate_claim_bundle(bundle_root=d3, reference_dir="05_data/external", company_priv_key_path="company_root_private_key.pem")

    # Auditor runs with expected record count for the reporting period (5 readings expected)
    c3 = verify_and_check(d3, company_key, "check6_claim_boundary_bounds", extra_args=["--expected-count", "5"])
    attacks.append(("I3: Period Head/Tail Truncation vs Audit Mandate", c3))

    # -------------------------------------------------------------
    # Attack I4: Software Device without Hardware Attestation
    # Company provisions a software keypair and signs cert, but has no valid hardware attestation
    # -------------------------------------------------------------
    d4 = "bundle_insider_i4_unattested"
    clone_bundle(clean_bundle, d4)
    att_file = os.path.join(d4, "device", "hardware_attestation.json")
    with open(att_file, "w") as f:
        json.dump({"attestation_status": "unverified_software_simulator"}, f)
    generate_claim_bundle(bundle_root=d4, reference_dir="05_data/external", company_priv_key_path="company_root_private_key.pem")

    c4 = verify_and_check(d4, company_key, "check2_device_cert_and_attestation")
    attacks.append(("I4: Software Key without Hardware Attestation", c4))

    # -------------------------------------------------------------
    # Attack I5: Spliced Telemetry / Broken Hash-Chain
    # Company stitches observations together, breaking the cryptographic prev_hash chain
    # -------------------------------------------------------------
    d5 = "bundle_insider_i5_broken_chain"
    clone_bundle(clean_bundle, d5)
    obs_file = os.path.join(d5, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        lines = f.readlines()
    if len(lines) >= 3:
        rec = json.loads(lines[2])
        rec["prev_hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        rec["payload"]["prev_hash"] = rec["prev_hash"]
        lines[2] = json.dumps(rec) + "\n"
        with open(obs_file, "w") as f:
            f.writelines(lines)
    generate_claim_bundle(bundle_root=d5, reference_dir="05_data/external", company_priv_key_path="company_root_private_key.pem")

    c5 = verify_and_check(d5, company_key, "check4_hash_chain_continuity")
    attacks.append(("I5: Telemetry Splicing / Broken Hash-Chain", c5))

    # Cleanup
    for d in [d1, d2, d3, d4, d5, ext1]:
        shutil.rmtree(d, ignore_errors=True)

    print("-" * 70)
    for name, caught in attacks:
        status = "[CAUGHT BY VERIFIER]" if caught else "[BYPASSED]"
        print(f"  * {name:<55} : {status}")
    print("-" * 70)
    all_caught = all(c for _, c in attacks)
    if all_caught:
        print(f"[SUCCESS] All {len(attacks)}/{len(attacks)} insider fraud attacks detected and rejected.")
    else:
        print("[WARN] Some insider fraud attacks bypassed verification!")
    print("=" * 70)
    return all_caught

if __name__ == "__main__":
    success = run_insider_tests()
    sys.exit(0 if success else 1)
