"""
Claim Generator — energy_submetering profile (bundle format v1.3)

Aggregates signed interval records in integer Wh, applies the pinned grid emission factor
(integer mg CO2e/kWh), and packages claim, recipes, PROV lineage and producer seal.
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

PROFILE = "energy_submetering"
DEFAULT_FACTOR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "04_experiments",
                                              "reference_data", "emission_factor.json"))


def generate_claim_bundle(bundle_root, reference_file=DEFAULT_FACTOR, keys_dir="build/keys"):
    producer = ProducerAuthority(keys_dir)
    records = read_records(bundle_root)
    ef_rel = "reference_data/emission_factor.json"
    os.makedirs(os.path.join(bundle_root, "reference_data"), exist_ok=True)
    shutil.copyfile(reference_file, os.path.join(bundle_root, ef_rel))
    factor = jcs.load_file(reference_file)["factor_mg_co2e_per_kwh"]

    total_wh = sum(r["payload"]["interval_wh"] for r in records)
    emissions_g = -(-(total_wh * factor) // 1000000)

    write_json(os.path.join(bundle_root, "transformations", "energy_aggregation.json"), {
        "transformation_id": "energy_aggregation_v1",
        "method": "total_energy_wh = sum(record.payload.interval_wh)",
        "outputs": {"total_energy_wh": total_wh},
    })
    write_json(os.path.join(bundle_root, "transformations", "scope2_emissions.json"), {
        "transformation_id": "scope2_location_based_v1",
        "method": "total_emissions_g_co2e = ceil(total_energy_wh * factor_mg_co2e_per_kwh / 1000000)",
        "rounding": "ceiling to whole grams (never under-report emissions)",
        "outputs": {"emission_factor_mg_co2e_per_kwh": factor, "total_emissions_g_co2e": emissions_g},
    })

    claim_id = f"claim_{records[0]['device_id']}_{records[0]['timestamp_start']}_{records[-1]['timestamp_end']}"
    write_claim(bundle_root, claim_id, PROFILE, records[0]["device_id"], records, {
        "total_energy_wh": total_wh,
        "emission_factor_mg_co2e_per_kwh": factor,
        "total_emissions_g_co2e": emissions_g,
    })
    write_provenance(bundle_root, {
        "obs": "observations/observations.ndjson",
        "factor": ef_rel,
        "recipe_aggregation": "transformations/energy_aggregation.json",
        "recipe_scope2": "transformations/scope2_emissions.json",
        "claim": "claim.json",
    }, {
        "act_energy_aggregation": {"recipe": "recipe_aggregation", "used": ["obs"], "generated": []},
        "act_scope2_emissions": {"recipe": "recipe_scope2", "used": ["factor"], "generated": ["claim"],
                                 "informed_by": ["act_energy_aggregation"]},
    })
    seal_bundle(bundle_root, PROFILE, claim_id, producer)
    return claim_id


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Energy submetering claim generator (bundle v1.3)")
    ap.add_argument("bundle", nargs="?", default="build/energy_bundle")
    ap.add_argument("--reference", default=DEFAULT_FACTOR)
    ap.add_argument("--keys-dir", default="build/keys")
    args = ap.parse_args()
    print(f"[+] Sealed {generate_claim_bundle(args.bundle, args.reference, args.keys_dir)}")
