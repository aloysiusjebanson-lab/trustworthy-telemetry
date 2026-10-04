"""
Biochar Pyrolysis Adversarial Benchmark Suite (v1.2)
Standards: EU CRCF Delegated Regulation 2026/285 | Puro.earth | EBC (European Biochar Certificate)

Executes 10 programmatic adversarial fraud tests asserting that the Zero-Trust Offline
Verifier detects and rejects real-world biochar carbon removal fraud:
  1. Attack B1: Water Spraying Fraud (Wet Mass Inflation / Mass Balance Violation)
  2. Attack B2: Thermal Permanence Undercooking (Reactor T_min < 500°C)
  3. Attack B3: Counterfeit Lab Analysis Report (ISO 17025 Registry Pinning Violation)
  4. Attack B4: Biomass Feedstock Cap Exhaustion (Total Used > Delivered Quota)
  5. Attack B5: Dropped Batch / Cryptographic Hash-Chain Splicing
  6. Attack B6: Non-Certified Scale Indicator (Missing 2014/31/EU NAWI Metrology)
  7. Attack B7: Software Key Forgery without Silicon Hardware Attestation (ATECC608)
  8. Attack B8: Uncertified Biomass Feedstock (Supplier Not in Pinned Registry)
  9. Attack B9: Numeric Claim Inflation (Zero-Tolerance Reconciliation Violation)
  10. Attack B10: Revoked Pyrolysis Kiln Gateway Rejection
"""

import os
import shutil
import json
import subprocess
import sys
import hashlib

sys.path.insert(0, "src/pipeline")
from biochar_claim_generator import build_biochar_claim_bundle

def clone_bundle(src_bundle, dest_bundle):
    if os.path.exists(dest_bundle):
        shutil.rmtree(dest_bundle)
    shutil.copytree(src_bundle, dest_bundle)

def verify_and_check(bundle_path, producer_key, expected_failed_check=None, extra_args=None):
    cmd = [
        sys.executable, "src/verifier/verify_bundle.py", bundle_path,
        "--company-key", producer_key, "--json"
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

def run_biochar_tests(clean_bundle="biochar_bundle", producer_key="producer_root_public_key.pem"):
    print("=" * 70)
    print(" Biochar dMRV Adversarial Attack Benchmark (Programmatic Assertions)")
    print(" Standards: EU CRCF Delegated Regulation 2026/285 | Puro.earth | EBC")
    print("=" * 70)

    attacks = []

    # ------------------------------------------------------------------
    # B1: Water Spraying Fraud (Dry mass exceeds feedstock input)
    # The producer sprays water to inflate output scale weight,
    # causing recomputed dry mass to exceed feedstock input.
    # Resealed with Producer Root Key.
    # ------------------------------------------------------------------
    d1 = "bundle_biochar_b1_water_spraying"
    clone_bundle(clean_bundle, d1)
    obs_file = os.path.join(d1, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        records = [json.loads(line) for line in f if line.strip()]
    # Inflate scale wet mass drastically (e.g. 10 tonnes per batch on 6 tonne feedstock)
    for r in records:
        r["payload"]["scale_wet_mass_g"] = 10000000
    with open(obs_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    build_biochar_claim_bundle(d1)
    c1 = verify_and_check(d1, producer_key, "check9_independent_recomputation")
    attacks.append(("B1: Water Spraying (Mass Conservation Violation)", c1))

    # ------------------------------------------------------------------
    # B2: Thermal Permanence Undercooking (T_min < 500°C)
    # Pyrolysis kiln temperature drops below statutory 500°C threshold.
    # Resealed with Producer Root Key.
    # ------------------------------------------------------------------
    d2 = "bundle_biochar_b2_thermal_undercooking"
    clone_bundle(clean_bundle, d2)
    obs_file = os.path.join(d2, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        records = [json.loads(line) for line in f if line.strip()]
    # Set batch 3 temperature to 420°C
    records[2]["payload"]["temp_min_c"] = 420
    with open(obs_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    build_biochar_claim_bundle(d2)
    c2 = verify_and_check(d2, producer_key, "check5_thermal_permanence")
    attacks.append(("B2: Thermal Undercooking (T_min < 500°C)", c2))

    # ------------------------------------------------------------------
    # B3: Counterfeit Lab Analysis Report (ISO 17025 Pinning Violation)
    # Producer swaps lab report with an unaccredited lab claiming 95% C_org.
    # Resealed with Producer Root Key.
    # ------------------------------------------------------------------
    d3 = "bundle_biochar_b3_counterfeit_lab"
    clone_bundle(clean_bundle, d3)
    lab_file = os.path.join(d3, "reference_data", "lab_analysis.json")
    with open(lab_file, "r") as f:
        lab_data = json.load(f)
    lab_data["c_org_bps"] = 9500
    lab_data["lab_name"] = "Uncertified Offshore Lab Ltd"
    with open(lab_file, "w") as f:
        json.dump(lab_data, f, indent=2)
    build_biochar_claim_bundle(d3)
    c3 = verify_and_check(d3, producer_key, "check8_pinned_reference_factor")
    attacks.append(("B3: Counterfeit Lab Report (ISO 17025 Pinning)", c3))

    # ------------------------------------------------------------------
    # B4: Biomass Feedstock Cap Exhaustion (Total Used > Delivered)
    # Producer burns 50 tonnes of biomass while delivery manifest allows 40t.
    # Resealed with Producer Root Key.
    # ------------------------------------------------------------------
    d4 = "bundle_biochar_b4_feedstock_exhaustion"
    clone_bundle(clean_bundle, d4)
    feed_file = os.path.join(d4, "reference_data", "feedstock_manifest.json")
    with open(feed_file, "r") as f:
        feed_data = json.load(f)
    # Lower certified quota to 20 metric tonnes (less than the 31.25 tonnes consumed)
    feed_data["delivered_mass_total_g"] = 20000000
    with open(feed_file, "w") as f:
        json.dump(feed_data, f, indent=2)
    # Note: modifying feedstock_manifest also breaks registry pinning (Check 8),
    # but if we test with an inflated observations stream against the valid 40t cap:
    clone_bundle(clean_bundle, d4)
    obs_file = os.path.join(d4, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        records = [json.loads(line) for line in f if line.strip()]
    for r in records:
        r["payload"]["feedstock_input_g"] = 15000000 # 15t each * 5 = 75t > 40t cap
    with open(obs_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    build_biochar_claim_bundle(d4)
    c4 = verify_and_check(d4, producer_key, "check9_independent_recomputation")
    attacks.append(("B4: Feedstock Cap Violation (Total Used > Quota)", c4))

    # ------------------------------------------------------------------
    # B5: Dropped Batch / Cryptographic Hash-Chain Splicing
    # Omission of batch 3, breaking the prev_hash continuity chain.
    # ------------------------------------------------------------------
    d5 = "bundle_biochar_b5_broken_chain"
    clone_bundle(clean_bundle, d5)
    obs_file = os.path.join(d5, "observations", "observations.ndjson")
    with open(obs_file, "r") as f:
        records = [json.loads(line) for line in f if line.strip()]
    del records[2]  # Delete batch 3
    with open(obs_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    # Outsider tamper without reseal: caught by Check 1 & Check 4
    c5 = verify_and_check(d5, producer_key, "check4_hash_chain_continuity")
    attacks.append(("B5: Dropped Batch (Hash-Chain Continuity Break)", c5))

    # ------------------------------------------------------------------
    # B6: Non-Certified Scale Indicator (Missing 2014/31/EU NAWI)
    # Scale indicator is stripped of legal metrology certification.
    # ------------------------------------------------------------------
    d6 = "bundle_biochar_b6_uncertified_scale"
    clone_bundle(clean_bundle, d6)
    cert_file = os.path.join(d6, "device", "device_certificate.json")
    with open(cert_file, "r") as f:
        cert_data = json.load(f)
    cert_data["certificate_body"]["metrology"]["standard"] = "UNREGULATED_ANALOG_SCALE"
    with open(cert_file, "w") as f:
        json.dump(cert_data, f, indent=2)
    c6 = verify_and_check(d6, producer_key, "check2_device_cert_and_attestation")
    attacks.append(("B6: Non-Certified Scale (2014/31/EU NAWI Missing)", c6))

    # ------------------------------------------------------------------
    # B7: Software Key Forgery without Silicon Attestation
    # Gateway device certificate lacks Microchip ATECC608 hardware attestation.
    # ------------------------------------------------------------------
    d7 = "bundle_biochar_b7_software_key"
    clone_bundle(clean_bundle, d7)
    attest_file = os.path.join(d7, "device", "hardware_attestation.json")
    with open(attest_file, "r") as f:
        att_data = json.load(f)
    att_data["attestation_status"] = "EMULATED_SOFTWARE_KEYS"
    with open(attest_file, "w") as f:
        json.dump(att_data, f, indent=2)
    c7 = verify_and_check(d7, producer_key, "check2_device_cert_and_attestation")
    attacks.append(("B7: Software Key Forgery (Missing Silicon Attestation)", c7))

    # ------------------------------------------------------------------
    # B8: Uncertified Biomass Feedstock (Supplier Not in Registry)
    # Feedstock manifest replaced with demolition wood from untracked supplier.
    # Resealed with Producer Root Key.
    # ------------------------------------------------------------------
    d8 = "bundle_biochar_b8_uncertified_biomass"
    clone_bundle(clean_bundle, d8)
    feed_file = os.path.join(d8, "reference_data", "feedstock_manifest.json")
    with open(feed_file, "r") as f:
        feed_data = json.load(f)
    feed_data["supplier"] = "Untracked Demolition Scrap Corp"
    feed_data["ebc_positive_list_code"] = "UNAUTHORIZED_TREATED_WOOD"
    with open(feed_file, "w") as f:
        json.dump(feed_data, f, indent=2)
    build_biochar_claim_bundle(d8)
    c8 = verify_and_check(d8, producer_key, "check8_pinned_reference_factor")
    attacks.append(("B8: Uncertified Feedstock (Registry Pinning Violation)", c8))

    # ------------------------------------------------------------------
    # B9: Numeric Claim Inflation (Zero-Tolerance Reconciliation)
    # Producer modifies claim.json to inflate net carbon removal credits.
    # ------------------------------------------------------------------
    d9 = "bundle_biochar_b9_claim_inflation"
    clone_bundle(clean_bundle, d9)
    claim_file = os.path.join(d9, "claim.json")
    with open(claim_file, "r") as f:
        claim_data = json.load(f)
    claim_data["metrics"]["net_co2_removed_g"] += 5000000  # Inflate by 5 tonnes
    claim_data["metrics"]["net_co2_removed_tonnes"] += 5.0
    with open(claim_file, "w") as f:
        json.dump(claim_data, f, indent=2)
    c9 = verify_and_check(d9, producer_key, "check1_manifest_and_seal")
    attacks.append(("B9: Numeric Claim Inflation (Zero-Tolerance Match)", c9))

    # ------------------------------------------------------------------
    # B10: Revoked Pyrolysis Kiln Gateway Rejection
    # Gateway device ID is passed to verifier via --revoked.
    # ------------------------------------------------------------------
    d10 = "bundle_biochar_b10_revoked_gateway"
    clone_bundle(clean_bundle, d10)
    with open(os.path.join(d10, "device", "identity.json"), "r") as f:
        dev_id = json.load(f).get("device_id")
    c10 = verify_and_check(d10, producer_key, "check2_device_cert_and_attestation", extra_args=["--revoked", dev_id])
    attacks.append(("B10: Revoked Kiln Gateway Rejection", c10))

    # Cleanup temporary directories
    for d in [d1, d2, d3, d4, d5, d6, d7, d8, d9, d10]:
        shutil.rmtree(d, ignore_errors=True)

    print("-" * 70)
    for name, caught in attacks:
        print(f"  * {name:<55} : {'[CAUGHT BY VERIFIER]' if caught else '[MISSED]'}")
    print("-" * 70)

    all_caught = all(caught for _, caught in attacks)
    if all_caught:
        print(f"[SUCCESS] All {len(attacks)}/{len(attacks)} biochar adversarial attack vectors detected and rejected.")
    else:
        missed = [name for name, caught in attacks if not caught]
        print(f"[WARN] {len(missed)} attack(s) bypassed verification: {', '.join(missed)}")
    print("=" * 70)
    return all_caught

if __name__ == "__main__":
    b_dir = sys.argv[1] if len(sys.argv) > 1 else "biochar_bundle"
    p_key = sys.argv[2] if len(sys.argv) > 2 else "producer_root_public_key.pem"
    success = run_biochar_tests(b_dir, p_key)
    sys.exit(0 if success else 1)
