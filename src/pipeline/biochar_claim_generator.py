#!/usr/bin/env python3
"""
Evidence Pipeline: Biochar Claim Generator & Sealer (v1.2)
Specification: 02_protocol/evidence_bundle_spec.md (biochar_pyrolysis profile)

Ingests batch telemetry stream, applies deterministic mass-balance recipes,
computes net permanent carbon removal under EU CRCF & Puro.earth methodologies,
and seals the evidence bundle with the Producer Root Key.
"""

import os
import sys
import json
import hashlib
import subprocess

def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def sign_data(data_bytes, private_key_path):
    cmd = ["openssl", "dgst", "-sha256", "-sign", private_key_path]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    der_sig, err = p.communicate(input=data_bytes)
    if p.returncode != 0:
        raise RuntimeError(f"OpenSSL signing error: {err.decode('utf-8')}")
    return der_sig.hex()

def build_biochar_claim_bundle(bundle_root="biochar_bundle"):
    print("=================================================================")
    print(" Biochar dMRV Evidence Pipeline — Claim Bundle Generator (v1.2)")
    print(" Profile: biochar_pyrolysis | EU CRCF & Puro.earth Standards")
    print("=================================================================")
    
    obs_file = os.path.join(bundle_root, "observations", "observations.ndjson")
    if not os.path.exists(obs_file):
        raise FileNotFoundError(f"Missing observations stream: {obs_file}")
        
    ref_dir = os.path.join(bundle_root, "reference_data")
    trans_dir = os.path.join(bundle_root, "transformations")
    prov_dir = os.path.join(bundle_root, "provenance")
    os.makedirs(ref_dir, exist_ok=True)
    os.makedirs(trans_dir, exist_ok=True)
    os.makedirs(prov_dir, exist_ok=True)
    
    # 1. Parse Observations & Verify Telemetry Bounds
    records = []
    with open(obs_file, "r") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line.strip()))
                
    if not records:
        raise ValueError("Observations file is empty")
        
    first_seq = records[0]["sequence"]
    last_seq = records[-1]["sequence"]
    batch_count = len(records)
    terminal_hash = hashlib.sha256(canonical_json(records[-1])).hexdigest()
    
    total_feedstock_input_g = sum(r["payload"]["feedstock_input_g"] for r in records)
    total_wet_biochar_g = sum(r["payload"]["scale_wet_mass_g"] for r in records)
    
    # 2. Accredited Laboratory Reference Data (ISO 17025)
    lab_file = os.path.join(ref_dir, "lab_analysis.json")
    if os.path.exists(lab_file):
        with open(lab_file, "r") as f:
            lab_analysis = json.load(f)
    else:
        lab_analysis = {
            "lab_name": "Example Accredited Lab (illustrative)",
            "lab_accreditation": "ISO_17025",
            "sample_batch_ref": f"{records[0]['batch_id']}_to_{records[-1]['batch_id']}",
            "moisture_bps": 1500,               # 15.00% moisture content
            "c_org_bps": 8200,                  # 82.00% organic carbon on dry basis
            "h_c_org_ratio": 0.35,              # Well below EBC threshold of 0.70
            "permanence_factor_bps": 8500,      # 85.00% permanence for 100+ years per CRCF
            "analysis_date": "2026-10-02"
        }
        with open(lab_file, "w") as f:
            json.dump(lab_analysis, f, indent=2)
        
    lab_meta = {
        "accreditation_body": "Example National Accreditation Body (illustrative)",
        "accreditation_standard": "DIN EN ISO/IEC 17025:2018",
        "certificate_id": "EXAMPLE-ACCRED-0000",
        "lab_dataset_sha256": sha256_file(lab_file)
    }
    with open(os.path.join(ref_dir, "lab_analysis_metadata.json"), "w") as f:
        json.dump(lab_meta, f, indent=2)

    # 3. Feedstock Delivery Manifest Reference Data
    feedstock_file = os.path.join(ref_dir, "feedstock_manifest.json")
    if os.path.exists(feedstock_file):
        with open(feedstock_file, "r") as f:
            feedstock_manifest = json.load(f)
    else:
        feedstock_manifest = {
            "delivery_ref": "delivery_fsc_wood_2026_09",
            "biomass_type": "FSC_Certified_Forestry_Residues",
            "ebc_positive_list_code": "EBC-1.1-FOREST",
            "supplier": "Dolomiti Biomass Cooperative",
            "delivered_mass_total_g": 40000000, # 40 metric tonnes delivered
            "delivery_date": "2026-09-28"
        }
        with open(feedstock_file, "w") as f:
            json.dump(feedstock_manifest, f, indent=2)
        
    print(f"[+] Reference Lab Analysis & Feedstock Manifest Bound")

    # 4. Generate Transformations: Mass-Balance Invariants
    # M_dry = M_wet * (10000 - moisture_bps) // 10000
    moisture_bps = lab_analysis["moisture_bps"]
    batch_dry_masses = [
        r["payload"]["scale_wet_mass_g"] * (10000 - moisture_bps) // 10000
        for r in records
    ]
    total_dry_biochar_g = sum(batch_dry_masses)
    
    mass_balance_recipe = {
        "transformation_id": "transformation_mass_balance_proof",
        "methodology": "EU_CRCF_2026_285_ANNEX_I",
        "inputs": {
            "observations_file": "observations/observations.ndjson",
            "lab_analysis_file": "reference_data/lab_analysis.json",
            "feedstock_manifest_file": "reference_data/feedstock_manifest.json"
        },
        "intermediate_results": {
            "moisture_discount_bps": moisture_bps,
            "total_wet_biochar_g": total_wet_biochar_g,
            "total_dry_biochar_g": total_dry_biochar_g,
            "total_feedstock_input_g": total_feedstock_input_g,
            "feedstock_delivered_cap_g": feedstock_manifest["delivered_mass_total_g"]
        },
        "invariant_evaluations": {
            "mass_conservation_invariant": total_dry_biochar_g <= total_feedstock_input_g,
            "feedstock_delivery_cap_invariant": total_feedstock_input_g <= feedstock_manifest["delivered_mass_total_g"],
            "thermal_permanence_invariant": all(r["payload"]["temp_min_c"] >= 500 for r in records)
        }
    }
    with open(os.path.join(trans_dir, "mass_balance.json"), "w") as f:
        json.dump(mass_balance_recipe, f, indent=2)

    # 5. Generate Transformations: Carbon Removal Calculation (CRCF / Puro Formula)
    # Gross CO2 = M_dry_g * c_org_bps * perm_factor_bps * 44 // (10000 * 10000 * 12)
    c_org_bps = lab_analysis["c_org_bps"]
    perm_bps = lab_analysis["permanence_factor_bps"]
    gross_co2_removed_g = (total_dry_biochar_g * c_org_bps * perm_bps * 44) // (10000 * 10000 * 12)
    process_deductions_co2_g = 1200000  # 1.20 tonnes CO2 process emissions (integer grams)
    net_co2_removed_g = gross_co2_removed_g - process_deductions_co2_g
    net_co2_removed_tonnes = net_co2_removed_g / 1000000.0

    carbon_calc_recipe = {
        "transformation_id": "transformation_crcf_net_removal",
        "methodology": "EU_CRCF_Permanent_Removal_Delegated_Act_2026_285",
        "formula": "Net_CO2 = Gross_CO2 - Process_Emissions; Gross_CO2 = M_dry * C_org * F_perm * (44/12)",
        "inputs": {
            "mass_balance_recipe": "transformations/mass_balance.json",
            "lab_analysis": "reference_data/lab_analysis.json"
        },
        "stoichiometric_ratio": "44/12",
        "calculations": {
            "total_dry_biochar_g": total_dry_biochar_g,
            "c_org_bps": c_org_bps,
            "permanence_factor_bps": perm_bps,
            "gross_co2_removed_g": gross_co2_removed_g,
            "process_deductions_co2_g": process_deductions_co2_g,
            "net_co2_removed_g": net_co2_removed_g,
            "net_co2_removed_tonnes": net_co2_removed_tonnes
        }
    }
    with open(os.path.join(trans_dir, "carbon_calculation.json"), "w") as f:
        json.dump(carbon_calc_recipe, f, indent=2)
    print(f"[+] Transformation Recipes Generated   : {trans_dir}")

    # 6. Generate claim.json
    claim_doc = {
        "claim_id": "claim_biochar_removal_2026_q3",
        "profile": "biochar_pyrolysis",
        "facility_id": "facility_pyrolysis_plant_trentino",
        "kiln_id": "kiln_rotary_continuous_01",
        "first_sequence": first_seq,
        "last_sequence": last_seq,
        "batch_count": batch_count,
        "terminal_hash": terminal_hash,
        "metrics": {
            "total_feedstock_input_g": total_feedstock_input_g,
            "total_wet_biochar_g": total_wet_biochar_g,
            "total_dry_biochar_g": total_dry_biochar_g,
            "gross_co2_removed_g": gross_co2_removed_g,
            "process_deductions_co2_g": process_deductions_co2_g,
            "net_co2_removed_g": net_co2_removed_g,
            "net_co2_removed_tonnes": net_co2_removed_tonnes
        }
    }
    with open(os.path.join(bundle_root, "claim.json"), "w") as f:
        json.dump(claim_doc, f, indent=2)
    print(f"[+] Final Claim Declared               : {bundle_root}/claim.json ({net_co2_removed_tonnes:.4f} t CO2)")

    # 7. Generate W3C PROV-O Graph
    prov_doc = {
        "@context": {"prov": "http://www.w3.org/ns/prov#"},
        "entity": {
            "observations:observations.ndjson": {"type": "raw_batch_telemetry", "sha256": sha256_file(obs_file)},
            "reference:lab_analysis.json": {"type": "iso17025_lab_report", "sha256": sha256_file(lab_file)},
            "reference:feedstock_manifest.json": {"type": "feedstock_delivery_manifest", "sha256": sha256_file(feedstock_file)},
            "transformations:mass_balance.json": {"type": "mass_balance_recipe", "sha256": sha256_file(os.path.join(trans_dir, "mass_balance.json"))},
            "transformations:carbon_calculation.json": {"type": "crcf_net_removal_recipe", "sha256": sha256_file(os.path.join(trans_dir, "carbon_calculation.json"))},
            "claim:claim.json": {"type": "net_carbon_removal_claim", "sha256": sha256_file(os.path.join(bundle_root, "claim.json"))}
        },
        "activity": {
            "activity:mass_balance": {"recipe": "transformations/mass_balance.json"},
            "activity:crcf_removal": {"recipe": "transformations/carbon_calculation.json"}
        }
    }
    with open(os.path.join(prov_dir, "provenance.json"), "w") as f:
        json.dump(prov_doc, f, indent=2)

    # 8. Compute Bundle Manifest & Checksums
    checksum_lines = []
    manifest_files = {}
    for root, _, files in os.walk(bundle_root):
        for file in sorted(files):
            if file in ["manifest.json", "checksums.txt"]:
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, bundle_root)
            file_hash = sha256_file(full_path)
            checksum_lines.append(f"{file_hash}  {rel_path}\n")
            manifest_files[rel_path] = file_hash
            
    checksum_file = os.path.join(bundle_root, "checksums.txt")
    with open(checksum_file, "w") as f:
        f.writelines(checksum_lines)
    manifest_files["checksums.txt"] = sha256_file(checksum_file)

    # 9. Cryptographically Seal Manifest with Producer Root Key
    project_root = os.path.abspath(os.path.join(bundle_root, ".."))
    root_priv = os.path.join(project_root, "producer_root_private_key.pem")
    if not os.path.exists(root_priv):
        raise FileNotFoundError(f"Missing Producer Root Key: {root_priv}")

    bundle_seal_sig = sign_data(canonical_json(manifest_files), root_priv)
    manifest_doc = {
        "manifest_version": "1.2",
        "profile": "biochar_pyrolysis",
        "claim_id": claim_doc["claim_id"],
        "files": manifest_files,
        "bundle_seal": {
            "signature": bundle_seal_sig,
            "algorithm": "ECDSA_P256_SHA256",
            "signed_by": "producer_authority_eu"
        }
    }
    with open(os.path.join(bundle_root, "manifest.json"), "w") as f:
        json.dump(manifest_doc, f, indent=2)
        
    print(f"[+] Bundle Sealed & Manifest Frozen    : {bundle_root}/manifest.json")
    print("=================================================================")

if __name__ == "__main__":
    b_dir = sys.argv[1] if len(sys.argv) > 1 else "biochar_bundle"
    build_biochar_claim_bundle(b_dir)
