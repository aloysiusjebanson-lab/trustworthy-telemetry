#!/usr/bin/env python3
"""
Biochar Adversarial Benchmark — biochar_pyrolysis (bundle format v1.3)

Insider vectors re-sign records through the gateway's secure element and re-seal with the
producer key, so they must be caught by physics, pinning, attestation or lineage controls.
  B1  Water spraying (dry yield far above feedstock)      B11 Private key material sealed into bundle
  B2  Thermal undercooking (T_min < threshold)            B12 Rogue software device key
  B3  Counterfeit lab assay                               B13 Instrument calibration expired
  B4  Feedstock used > delivered                          B14 Same batches re-issued under new claim id
  B5  Dropped batch (outsider)                            B15 One batch yields more than its feedstock
  B6  Non-NAWI scale certified                            B16 95% dry yield
  B7  Attestation of a different genuine chip             B17 Producer-forged manufacturer CA chain
  B8  Uncertified feedstock manifest                      B18 Profile substitution
  B9  Claim inflated, manifest re-sealed                  B19 Pinned dataset of the wrong type
  B10 Revoked gateway
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures import build_biochar_fixture  # noqa: E402
from harness import assert_baseline_passes, report, run_verifier, verify_and_check  # noqa: E402
from secure_element_sim import SimulatedManufacturer, SimulatedSecureElement  # noqa: E402
from tamper_tools import (clone, read_envelopes, read_json, read_lines, reissue_device_certificate,  # noqa: E402
                          repackage, resign_chain, reseal_only, write_json, write_lines)
import crypto  # noqa: E402

REF = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "04_experiments", "reference_data"))


def records_of(bundle):
    return [e["record"] for e in read_envelopes(bundle)]


def run_biochar_tests():
    print("=" * 78)
    print(" Biochar Adversarial Benchmark — biochar_pyrolysis (bundle v1.3)")
    print("=" * 78)
    workdir = tempfile.mkdtemp(prefix="biochar_attacks_")
    attacks = []
    try:
        fx = build_biochar_fixture(workdir)
        assert_baseline_passes(fx["bundle"], fx)
        dev = fx["device_priv"]

        def attack(name, bundle, check, extra=None):
            attacks.append((name, *verify_and_check(bundle, fx, check, extra)))

        def physics_attack(name, tag, mutate, check):
            d = clone(fx, tag)
            recs = records_of(d)
            mutate(recs)
            resign_chain(d, recs, dev)
            repackage(d, fx)
            attack(name, d, check)

        def set_all(field, value):
            def mutate(recs):
                for r in recs:
                    r["payload"][field] = value
            return mutate

        physics_attack("B1: Water spraying (yield above physical bound)", "b1",
                       set_all("scale_wet_mass_g", 10000000), "check9_independent_recomputation")
        physics_attack("B2: Thermal undercooking (T_min 420°C)", "b2",
                       lambda recs: recs[2]["payload"].update(temp_min_c=420), "check5_process_continuity")

        d = clone(fx, "b3")
        lab = read_json(os.path.join(REF, "biochar_lab_analysis.json"))
        lab.update(c_org_bps=9500, laboratory="Uncertified lab")
        fake_lab = os.path.join(workdir, "fake_lab.json")
        write_json(fake_lab, lab)
        repackage(d, fx, lab_file=fake_lab)
        attack("B3: Counterfeit lab assay + reseal", d, "check8_pinned_references")

        physics_attack("B4: Feedstock used > delivered", "b4",
                       set_all("feedstock_input_g", 15000000), "check9_independent_recomputation")

        d = clone(fx, "b5")
        lines = read_lines(d)
        del lines[2]
        write_lines(d, lines)
        attack("B5: Dropped batch (outsider)", d, "check4_hash_chain_continuity")

        d = clone(fx, "b6")
        reissue_device_certificate(d, fx, lambda body: body["instruments"][0].update(standard="UNREGULATED_SCALE"))
        repackage(d, fx)
        attack("B6: Non-NAWI scale certified + reseal", d, "check2_device_cert_and_attestation")

        d = clone(fx, "b7")
        other = SimulatedSecureElement(os.path.join(workdir, "other_chip"), "other")
        SimulatedManufacturer(os.path.join(fx["keys_dir"], "manufacturer_pki")).attest_device(
            other, os.path.join(d, "device", "attestation"))
        repackage(d, fx)
        attack("B7: Attestation of a different genuine chip", d, "check2_device_cert_and_attestation")

        d = clone(fx, "b8")
        feed = read_json(os.path.join(REF, "biochar_feedstock_manifest.json"))
        feed.update(supplier="Untracked demolition scrap", positive_list_code="UNAUTHORIZED")
        fake_feed = os.path.join(workdir, "fake_feed.json")
        write_json(fake_feed, feed)
        repackage(d, fx, feedstock_file=fake_feed)
        attack("B8: Uncertified feedstock manifest + reseal", d, "check8_pinned_references")

        d = clone(fx, "b9")
        claim = read_json(os.path.join(d, "claim.json"))
        claim["metrics"]["net_co2_removed_g"] += 5000000
        write_json(os.path.join(d, "claim.json"), claim)
        reseal_only(d, fx)
        attack("B9: Claim inflated, manifest re-sealed", d, "check10_numeric_reconciliation")

        attack("B10: Revoked gateway", clone(fx, "b10"), "check2_device_cert_and_attestation",
               ["--revoked", fx["device_id"]])

        d = clone(fx, "b11")
        with open(os.path.join(d, "device", "device_private_key.pem"), "w") as f:
            f.write("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFAKEKEY\n-----END EC PRIVATE KEY-----\n")
        reseal_only(d, fx)
        attack("B11: Private key sealed into bundle", d, "check1_manifest_and_seal")

        d = clone(fx, "b12")
        rogue = SimulatedSecureElement(os.path.join(workdir, "rogue_b12"), "rogue")
        shutil.copyfile(rogue.pub_path, os.path.join(d, "device", "public_key.pem"))
        recs = [dict(r, device_id=rogue.device_id) for r in records_of(d)]
        resign_chain(d, recs, rogue.priv_path)
        repackage(d, fx)
        attack("B12: Rogue software device key", d, "check2_device_cert_and_attestation")

        d = clone(fx, "b13")
        reissue_device_certificate(d, fx, lambda body: body["instruments"][0].update(calibration_valid_until=1750000000))
        repackage(d, fx)
        attack("B13: Scale calibration expired before batches", d, "check3_observation_signatures")

        d = clone(fx, "b14")
        ledger = os.path.join(workdir, "claim_ledger.json")
        first, _ = run_verifier(fx["bundle"], fx, ["--claim-ledger", ledger, "--record-ledger"])
        if not first or first["verdict"] != "PASSED":
            raise RuntimeError("Could not record the original claim in the ledger")
        repackage(d, fx, claim_id="claim_biochar_removal_2026_q4_DUPLICATE")
        attack("B14: Same batches re-issued under new claim id", d, "check6_claim_boundary_bounds",
               ["--claim-ledger", ledger])

        physics_attack("B15: One batch yields more than its feedstock", "b15",
                       lambda recs: recs[0]["payload"].update(scale_wet_mass_g=recs[0]["payload"]["feedstock_input_g"] * 2),
                       "check9_independent_recomputation")

        def yield_95(recs):
            for r in recs:
                r["payload"]["scale_wet_mass_g"] = r["payload"]["feedstock_input_g"] * 95 // 85
        physics_attack("B16: 95% dry yield", "b16", yield_95, "check9_independent_recomputation")

        # B17 (review §2.1): the operator mints its own "manufacturer" CA, attests a software key
        # under it, re-certifies the device with the producer key and re-signs all telemetry.
        d = clone(fx, "b17")
        soft = SimulatedSecureElement(os.path.join(workdir, "soft_b17"), "soft")
        SimulatedManufacturer(os.path.join(workdir, "forged_pki")).attest_device(soft, os.path.join(d, "device", "attestation"))
        shutil.copyfile(soft.pub_path, os.path.join(d, "device", "public_key.pem"))
        reissue_device_certificate(d, fx, lambda body: body.update(
            device_id=soft.device_id, device_public_key_sha256=crypto.sha256_hex(soft.pub_der)))
        resign_chain(d, [dict(r, device_id=soft.device_id) for r in records_of(d)], soft.priv_path)
        repackage(d, fx)
        attack("B17: Producer-forged manufacturer CA chain", d, "check2_device_cert_and_attestation")

        d = clone(fx, "b18")
        for name in ("claim.json",):
            doc = read_json(os.path.join(d, name))
            doc["profile"] = "energy_submetering"
            write_json(os.path.join(d, name), doc)
        reseal_only(d, fx, profile="energy_submetering")
        attack("B18: Profile substitution (auditor-bound profile)", d, "check0_profile_binding")

        d = clone(fx, "b19")
        shutil.copyfile(os.path.join(REF, "biochar_feedstock_manifest.json"),
                        os.path.join(d, "reference_data", "lab_analysis.json"))
        reseal_only(d, fx)
        attack("B19: Pinned dataset of the wrong type as lab assay", d, "check8_pinned_references")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return report("biochar", attacks)


if __name__ == "__main__":
    sys.exit(0 if run_biochar_tests() else 1)
