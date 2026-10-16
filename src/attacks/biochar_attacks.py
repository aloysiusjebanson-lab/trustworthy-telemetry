#!/usr/bin/env python3
"""
Biochar Pyrolysis Adversarial Benchmark Suite (v1.3)
Standards: EU CRCF Delegated Regulation 2026/285 | Puro.earth | EBC (European Biochar Certificate)

Executes 17 programmatic adversarial fraud tests asserting that the Zero-Trust Offline
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
  11. Attack B11: Private Key Material Inside Bundle / Manifest
  12. Attack B12: Rogue Software Device Key (Cert Not Bound to Public Key)
  13. Attack B13: Scale Calibration Expired Before Batches
  14. Attack B14: Double-Counting Re-issue Under New Claim ID
  15. Attack B15: Per-Batch Mass Balance Violation (Dry Output > Own Feedstock)
  16. Attack B16: Excessive 95% Dry Yield (Pyrolysis Physical Bound Violation)
  17. Attack B17: Software Simulator Key Rejection under Strict Hardware Attestation
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
from src.attacks.fixtures import build_biochar_fixture
from src.pipeline.biochar_claim_generator import build_biochar_claim_bundle

def clone_bundle(src_bundle, dest_bundle):
    if os.path.exists(dest_bundle):
        shutil.rmtree(dest_bundle)
    shutil.copytree(src_bundle, dest_bundle)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def sign_bytes(data_bytes, priv_key_path):
    cmd = ["openssl", "dgst", "-sha256", "-sign", priv_key_path]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    der_sig, err = p.communicate(input=data_bytes)
    if p.returncode != 0:
        raise RuntimeError(f"OpenSSL signing error: {err.decode('utf-8')}")
    return der_sig.hex()

def resign_biochar_chain(recs, dev_priv_path):
    prev = "0" * 64
    for r in recs:
        r["prev_hash"] = prev
        body = {k: r[k] for k in ("device_id", "batch_id", "sequence", "prev_hash", "payload")}
        body_canonical = json.dumps(body, separators=(',', ':'), sort_keys=True).encode('utf-8')
        r["signature"] = sign_bytes(body_canonical, dev_priv_path)
        r_canonical = json.dumps(r, separators=(',', ':'), sort_keys=True).encode('utf-8')
        prev = hashlib.sha256(r_canonical).hexdigest()

def reseal_manifest(bundle_path, prod_priv_path):
    manifest_path = os.path.join(bundle_path, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    files = {}
    for root, _, fs in sorted(os.walk(bundle_path)):
        for f in sorted(fs):
            if f in ("manifest.json", "checksums.txt", ".DS_Store"):
                continue
            rel = os.path.relpath(os.path.join(root, f), bundle_path)
            files[rel] = sha256_file(os.path.join(root, f))
    manifest["files"] = files
    canonical_bytes = json.dumps(files, separators=(',', ':'), sort_keys=True).encode('utf-8')
    manifest["bundle_seal"]["signature"] = sign_bytes(canonical_bytes, prod_priv_path)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

def run_biochar_tests():
    print("=" * 70)
    print(" Biochar dMRV Adversarial Attack Benchmark (Programmatic Assertions)")
    print(" Standards: EU CRCF Delegated Regulation 2026/285 | Puro.earth | EBC")
    print("=" * 70)

    workdir = tempfile.mkdtemp(prefix="biochar_attacks_")
    attacks = []

    try:
        # Build clean fixture inside workdir
        fixture = build_biochar_fixture(workdir)
        clean_bundle = fixture["bundle"]
        producer_pub = fixture["root_pub"]
        producer_priv = fixture["root_priv"]
        device_priv = fixture["device_priv"]
        registry = fixture["registry"]

        # Baseline assertion (must pass before running attacks)
        assert_baseline_passes(clean_bundle, producer_pub, registry=registry)

        # ------------------------------------------------------------------
        # B1: Water Spraying Fraud (Dry mass exceeds feedstock input)
        # ------------------------------------------------------------------
        d1 = os.path.join(workdir, "bundle_biochar_b1")
        clone_bundle(clean_bundle, d1)
        obs_file = os.path.join(d1, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            records = [json.loads(line) for line in f if line.strip()]
        for r in records:
            r["payload"]["scale_wet_mass_g"] = 10000000
        with open(obs_file, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        build_biochar_claim_bundle(d1, producer_priv_key_path=producer_priv)
        c1, det1 = verify_and_check(d1, producer_pub, "check9_independent_recomputation", registry=registry)
        attacks.append(("B1: Water Spraying (Mass Conservation Violation)", c1, det1))

        # ------------------------------------------------------------------
        # B2: Thermal Permanence Undercooking (T_min < 500°C)
        # ------------------------------------------------------------------
        d2 = os.path.join(workdir, "bundle_biochar_b2")
        clone_bundle(clean_bundle, d2)
        obs_file = os.path.join(d2, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            records = [json.loads(line) for line in f if line.strip()]
        records[2]["payload"]["temp_min_c"] = 420
        with open(obs_file, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        build_biochar_claim_bundle(d2, producer_priv_key_path=producer_priv)
        c2, det2 = verify_and_check(d2, producer_pub, "check5_thermal_permanence", registry=registry)
        attacks.append(("B2: Thermal Undercooking (T_min < 500°C)", c2, det2))

        # ------------------------------------------------------------------
        # B3: Counterfeit Lab Analysis Report (ISO 17025 Pinning Violation)
        # ------------------------------------------------------------------
        d3 = os.path.join(workdir, "bundle_biochar_b3")
        clone_bundle(clean_bundle, d3)
        lab_file = os.path.join(d3, "reference_data", "lab_analysis.json")
        with open(lab_file, "r") as f:
            lab_data = json.load(f)
        lab_data["c_org_bps"] = 9500
        lab_data["lab_name"] = "Uncertified Offshore Lab Ltd"
        with open(lab_file, "w") as f:
            json.dump(lab_data, f, indent=2)
        build_biochar_claim_bundle(d3, producer_priv_key_path=producer_priv)
        c3, det3 = verify_and_check(d3, producer_pub, "check8_pinned_reference_factor", registry=registry)
        attacks.append(("B3: Counterfeit Lab Report (ISO 17025 Pinning)", c3, det3))

        # ------------------------------------------------------------------
        # B4: Biomass Feedstock Cap Exhaustion (Total Used > Delivered)
        # ------------------------------------------------------------------
        d4 = os.path.join(workdir, "bundle_biochar_b4")
        clone_bundle(clean_bundle, d4)
        obs_file = os.path.join(d4, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            records = [json.loads(line) for line in f if line.strip()]
        for r in records:
            r["payload"]["feedstock_input_g"] = 15000000
        with open(obs_file, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        build_biochar_claim_bundle(d4, producer_priv_key_path=producer_priv)
        c4, det4 = verify_and_check(d4, producer_pub, "check9_independent_recomputation", registry=registry)
        attacks.append(("B4: Feedstock Cap Violation (Total Used > Quota)", c4, det4))

        # ------------------------------------------------------------------
        # B5: Dropped Batch / Cryptographic Hash-Chain Splicing
        # ------------------------------------------------------------------
        d5 = os.path.join(workdir, "bundle_biochar_b5")
        clone_bundle(clean_bundle, d5)
        obs_file = os.path.join(d5, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            records = [json.loads(line) for line in f if line.strip()]
        del records[2]
        with open(obs_file, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        c5, det5 = verify_and_check(d5, producer_pub, "check4_hash_chain_continuity", registry=registry)
        attacks.append(("B5: Dropped Batch (Hash-Chain Continuity Break)", c5, det5))

        # ------------------------------------------------------------------
        # B6: Non-Certified Scale Indicator (Missing 2014/31/EU NAWI)
        # ------------------------------------------------------------------
        d6 = os.path.join(workdir, "bundle_biochar_b6")
        clone_bundle(clean_bundle, d6)
        cert_file = os.path.join(d6, "device", "device_certificate.json")
        with open(cert_file, "r") as f:
            cert_data = json.load(f)
        cert_data["certificate_body"]["metrology"]["standard"] = "UNREGULATED_ANALOG_SCALE"
        with open(cert_file, "w") as f:
            json.dump(cert_data, f, indent=2)
        c6, det6 = verify_and_check(d6, producer_pub, "check2_device_cert_and_attestation", registry=registry)
        attacks.append(("B6: Non-Certified Scale (2014/31/EU NAWI Missing)", c6, det6))

        # ------------------------------------------------------------------
        # B7: Software Key Forgery without Silicon Attestation
        # ------------------------------------------------------------------
        d7 = os.path.join(workdir, "bundle_biochar_b7")
        clone_bundle(clean_bundle, d7)
        attest_file = os.path.join(d7, "device", "hardware_attestation.json")
        with open(attest_file, "r") as f:
            att_data = json.load(f)
        att_data["attestation_status"] = "EMULATED_SOFTWARE_KEYS"
        with open(attest_file, "w") as f:
            json.dump(att_data, f, indent=2)
        c7, det7 = verify_and_check(d7, producer_pub, "check2_device_cert_and_attestation", registry=registry)
        attacks.append(("B7: Software Key Forgery (Missing Silicon Attestation)", c7, det7))

        # ------------------------------------------------------------------
        # B8: Uncertified Biomass Feedstock (Supplier Not in Registry)
        # ------------------------------------------------------------------
        d8 = os.path.join(workdir, "bundle_biochar_b8")
        clone_bundle(clean_bundle, d8)
        feed_file = os.path.join(d8, "reference_data", "feedstock_manifest.json")
        with open(feed_file, "r") as f:
            feed_data = json.load(f)
        feed_data["supplier"] = "Untracked Demolition Scrap Corp"
        feed_data["ebc_positive_list_code"] = "UNAUTHORIZED_TREATED_WOOD"
        with open(feed_file, "w") as f:
            json.dump(feed_data, f, indent=2)
        build_biochar_claim_bundle(d8, producer_priv_key_path=producer_priv)
        c8, det8 = verify_and_check(d8, producer_pub, "check8_pinned_reference_factor", registry=registry)
        attacks.append(("B8: Uncertified Feedstock (Registry Pinning Violation)", c8, det8))

        # ------------------------------------------------------------------
        # B9: Numeric Claim Inflation (Zero-Tolerance Reconciliation)
        # ------------------------------------------------------------------
        d9 = os.path.join(workdir, "bundle_biochar_b9")
        clone_bundle(clean_bundle, d9)
        claim_file = os.path.join(d9, "claim.json")
        with open(claim_file, "r") as f:
            claim_data = json.load(f)
        claim_data["metrics"]["net_co2_removed_g"] += 5000000
        claim_data["metrics"]["net_co2_removed_tonnes"] += 5.0
        with open(claim_file, "w") as f:
            json.dump(claim_data, f, indent=2)
        c9, det9 = verify_and_check(d9, producer_pub, "check1_manifest_and_seal", registry=registry)
        attacks.append(("B9: Numeric Claim Inflation (Zero-Tolerance Match)", c9, det9))

        # ------------------------------------------------------------------
        # B10: Revoked Pyrolysis Kiln Gateway Rejection
        # ------------------------------------------------------------------
        d10 = os.path.join(workdir, "bundle_biochar_b10")
        clone_bundle(clean_bundle, d10)
        with open(os.path.join(d10, "device", "identity.json"), "r") as f:
            dev_id = json.load(f).get("device_id")
        c10, det10 = verify_and_check(d10, producer_pub, "check2_device_cert_and_attestation", extra_args=["--revoked", dev_id], registry=registry)
        attacks.append(("B10: Revoked Kiln Gateway Rejection", c10, det10))

        # ------------------------------------------------------------------
        # B11: Private Key File Inside Bundle / Manifest
        # ------------------------------------------------------------------
        d11 = os.path.join(workdir, "bundle_biochar_b11")
        clone_bundle(clean_bundle, d11)
        dummy_priv = os.path.join(d11, "device", "device_private_key.pem")
        with open(dummy_priv, "w") as f:
            f.write("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFAKEKEY\n-----END EC PRIVATE KEY-----\n")
        reseal_manifest(d11, producer_priv)
        c11, det11 = verify_and_check(d11, producer_pub, "check1_manifest_and_seal", registry=registry)
        attacks.append(("B11: Private Key Material Inside Bundle", c11, det11))

        # ------------------------------------------------------------------
        # B12: Rogue Software Device Key (P2: cert not bound to device key)
        # ------------------------------------------------------------------
        d12 = os.path.join(workdir, "bundle_biochar_b12")
        clone_bundle(clean_bundle, d12)
        rogue_key = os.path.join(workdir, "rogue_device_key.pem")
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", rogue_key], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "ec", "-in", rogue_key, "-pubout", "-out", os.path.join(d12, "device", "public_key.pem")], check=True, stderr=subprocess.DEVNULL)
        obs_file = os.path.join(d12, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            recs = [json.loads(line) for line in f if line.strip()]
        resign_biochar_chain(recs, rogue_key)
        with open(obs_file, "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
        build_biochar_claim_bundle(d12, producer_priv_key_path=producer_priv)
        c12, det12 = verify_and_check(d12, producer_pub, "check2_device_cert_and_attestation", registry=registry)
        attacks.append(("B12: Rogue Device Key (Cert-Key Binding Break)", c12, det12))

        # ------------------------------------------------------------------
        # B13: Scale Calibration Expired Before Batches (P3)
        # ------------------------------------------------------------------
        d13 = os.path.join(workdir, "bundle_biochar_b13")
        clone_bundle(clean_bundle, d13)
        cert_path = os.path.join(d13, "device", "device_certificate.json")
        with open(cert_path, "r") as f:
            cd = json.load(f)
        cd["certificate_body"]["metrology"]["calibration_valid_until"] = 1750000000
        cd["company_signature"] = sign_bytes(json.dumps(cd["certificate_body"], separators=(',', ':'), sort_keys=True).encode('utf-8'), producer_priv)
        with open(cert_path, "w") as f:
            json.dump(cd, f, indent=2)
        build_biochar_claim_bundle(d13, producer_priv_key_path=producer_priv)
        c13, det13 = verify_and_check(d13, producer_pub, "check3_observation_signatures", registry=registry)
        attacks.append(("B13: Expired Scale Calibration vs Batches", c13, det13))

        # ------------------------------------------------------------------
        # B14: Double Counting: Same Batches Re-Issued Under New Claim ID (P4)
        # ------------------------------------------------------------------
        d14 = os.path.join(workdir, "bundle_biochar_b14")
        clone_bundle(clean_bundle, d14)
        claim_path = os.path.join(d14, "claim.json")
        with open(claim_path, "r") as f:
            claim_data = json.load(f)
        claim_data["claim_id"] = "claim_biochar_removal_2026_q4_DUPLICATE"
        with open(claim_path, "w") as f:
            json.dump(claim_data, f, indent=2)
        reseal_manifest(d14, producer_priv)
        ledger_path = os.path.join(workdir, "claim_ledger.json")
        # Record legitimate clean fixture first
        subprocess.run([
            sys.executable, "src/verifier/verify_bundle.py", clean_bundle,
            "--company-key", producer_pub, "--trusted-registry", registry,
            "--claim-ledger", ledger_path, "--record-ledger", "--json"
        ], capture_output=True, check=True)
        c14, det14 = verify_and_check(d14, producer_pub, "check6_claim_boundary_bounds", extra_args=["--claim-ledger", ledger_path], registry=registry)
        attacks.append(("B14: Double-Counting Re-issue Under New Claim ID", c14, det14))

        # ------------------------------------------------------------------
        # B15: Per-Batch Mass Balance Violation (Dry Output > Own Feedstock) (P5)
        # ------------------------------------------------------------------
        d15 = os.path.join(workdir, "bundle_biochar_b15")
        clone_bundle(clean_bundle, d15)
        obs_file = os.path.join(d15, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            recs = [json.loads(line) for line in f if line.strip()]
        recs[0]["payload"]["scale_wet_mass_g"] = recs[0]["payload"]["feedstock_input_g"] * 2
        resign_biochar_chain(recs, device_priv)
        with open(obs_file, "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
        build_biochar_claim_bundle(d15, producer_priv_key_path=producer_priv)
        c15, det15 = verify_and_check(d15, producer_pub, "check9_independent_recomputation", registry=registry)
        attacks.append(("B15: Batch Dry Output > Feedstock (Mass Balance)", c15, det15))

        # ------------------------------------------------------------------
        # B16: Excessive 95% Dry Yield (Pyrolysis Physical Bound) (P6)
        # ------------------------------------------------------------------
        d16 = os.path.join(workdir, "bundle_biochar_b16")
        clone_bundle(clean_bundle, d16)
        obs_file = os.path.join(d16, "observations", "observations.ndjson")
        with open(obs_file, "r") as f:
            recs = [json.loads(line) for line in f if line.strip()]
        for r in recs:
            r["payload"]["scale_wet_mass_g"] = r["payload"]["feedstock_input_g"] * 95 // 85
        resign_biochar_chain(recs, device_priv)
        with open(obs_file, "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
        build_biochar_claim_bundle(d16, producer_priv_key_path=producer_priv)
        c16, det16 = verify_and_check(d16, producer_pub, "check9_independent_recomputation", registry=registry)
        attacks.append(("B16: Excessive 95% Dry Yield (Pyrolysis Max 40%)", c16, det16))

        # ------------------------------------------------------------------
        # B17: Software Simulator Key under Strict Hardware Attestation (X1)
        # ------------------------------------------------------------------
        d17 = os.path.join(workdir, "bundle_biochar_b17")
        clone_bundle(clean_bundle, d17)
        c17, det17 = verify_and_check(d17, producer_pub, "check2_device_cert_and_attestation",
                                      extra_args=["--require-hardware-attestation"], registry=registry)
        attacks.append(("B17: Simulator Stub Rejection (Strict Attestation)", c17, det17))

    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("-" * 70)
    all_caught = True
    for name, caught, detail in attacks:
        status = "[CAUGHT BY VERIFIER]" if caught else "[BYPASSED]"
        print(f"  * {name:<55} : {status}")
        if not caught:
            print(f"    -> Detail: {detail}")
            all_caught = False
    print("-" * 70)

    if all_caught:
        print(f"[SUCCESS] All {len(attacks)}/{len(attacks)} biochar adversarial attack vectors detected and rejected.")
    else:
        missed = [name for name, caught, _ in attacks if not caught]
        print(f"[WARN] {len(missed)} attack(s) bypassed verification: {', '.join(missed)}")
    print("=" * 70)
    return all_caught

if __name__ == "__main__":
    success = run_biochar_tests()
    sys.exit(0 if success else 1)
