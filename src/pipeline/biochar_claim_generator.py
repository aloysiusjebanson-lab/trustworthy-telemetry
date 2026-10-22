"""
Claim Generator — biochar_pyrolysis profile (bundle format v1.3)

Applies the integer mass-balance and CRCF stoichiometry to signed batch records, binds the
ISO 17025 lab assay and feedstock delivery manifest, and packages claim, recipes, PROV
lineage and producer seal.
"""

import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "device_simulator")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "verifier")))
import jcs  # noqa: E402
from bundle_builder import read_records, seal_bundle, write_claim, write_json, write_provenance  # noqa: E402
from secure_element_sim import ProducerAuthority  # noqa: E402

PROFILE = "biochar_pyrolysis"
REF_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "04_experiments", "reference_data"))
DEFAULT_LAB = os.path.join(REF_DIR, "biochar_lab_analysis.json")
DEFAULT_FEEDSTOCK = os.path.join(REF_DIR, "biochar_feedstock_manifest.json")
LAB_REL = "reference_data/lab_analysis.json"
FEED_REL = "reference_data/feedstock_manifest.json"


def build_biochar_claim_bundle(bundle_root, keys_dir="build/keys", lab_file=DEFAULT_LAB,
                               feedstock_file=DEFAULT_FEEDSTOCK, process_deduction_g=1200000,
                               claim_id="claim_biochar_removal_2026_q4"):
    producer = ProducerAuthority(keys_dir)
    records = read_records(bundle_root)
    os.makedirs(os.path.join(bundle_root, "reference_data"), exist_ok=True)
    for src, rel in ((lab_file, LAB_REL), (feedstock_file, FEED_REL)):
        if os.path.abspath(src) != os.path.abspath(os.path.join(bundle_root, rel)):
            shutil.copyfile(src, os.path.join(bundle_root, rel))
    lab = jcs.load_file(os.path.join(bundle_root, LAB_REL))

    total_feed = sum(r["payload"]["feedstock_input_g"] for r in records)
    total_wet = sum(r["payload"]["scale_wet_mass_g"] for r in records)
    total_dry = sum(r["payload"]["scale_wet_mass_g"] * (10000 - lab["moisture_bps"]) // 10000 for r in records)
    gross = total_dry * lab["c_org_bps"] * lab["permanence_factor_bps"] * 44 // (10000 * 10000 * 12)
    net = gross - process_deduction_g

    write_json(os.path.join(bundle_root, "transformations", "mass_balance.json"), {
        "transformation_id": "biochar_mass_balance_v1",
        "method": "dry_g[batch] = floor(wet_g * (10000 - moisture_bps) / 10000); totals summed over batches",
        "invariants": ["dry_g * 10000 <= feedstock_g * max_dry_yield_bps (per batch)",
                       "sum(feedstock_g) <= delivered_mass_total_g"],
        "outputs": {"total_feedstock_input_g": total_feed, "total_wet_biochar_g": total_wet,
                    "total_dry_biochar_g": total_dry},
    })
    write_json(os.path.join(bundle_root, "transformations", "crcf_net_removal.json"), {
        "transformation_id": "biochar_crcf_net_removal_v1",
        "method": "gross_g = floor(dry_g * c_org_bps * permanence_factor_bps * 44 / (10000 * 10000 * 12)); net_g = gross_g - process_deduction_g",
        "rounding": "floor (never over-credit removals)",
        "outputs": {"gross_co2_removed_g": gross, "process_deductions_co2_g": process_deduction_g,
                    "net_co2_removed_g": net},
    })
    write_claim(bundle_root, claim_id, PROFILE, records[0]["device_id"], records, {
        "total_feedstock_input_g": total_feed,
        "total_wet_biochar_g": total_wet,
        "total_dry_biochar_g": total_dry,
        "gross_co2_removed_g": gross,
        "process_deductions_co2_g": process_deduction_g,
        "net_co2_removed_g": net,
    })
    write_provenance(bundle_root, {
        "obs": "observations/observations.ndjson",
        "lab": LAB_REL,
        "feedstock": FEED_REL,
        "recipe_mass_balance": "transformations/mass_balance.json",
        "recipe_crcf": "transformations/crcf_net_removal.json",
        "claim": "claim.json",
    }, {
        "act_mass_balance": {"recipe": "recipe_mass_balance", "used": ["obs", "lab", "feedstock"], "generated": []},
        "act_crcf_net_removal": {"recipe": "recipe_crcf", "used": ["lab"], "generated": ["claim"],
                                 "informed_by": ["act_mass_balance"]},
    })
    seal_bundle(bundle_root, PROFILE, claim_id, producer)
    return claim_id


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Biochar pyrolysis claim generator (bundle v1.3)")
    ap.add_argument("bundle", nargs="?", default="build/biochar_bundle")
    ap.add_argument("--keys-dir", default="build/keys")
    args = ap.parse_args()
    print(f"[+] Sealed {build_biochar_claim_bundle(args.bundle, args.keys_dir)}")
