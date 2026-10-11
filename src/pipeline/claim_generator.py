"""
Claim Generator & Evidence Bundle Builder (v1.1)

Takes raw signed, hash-chained observations from edge gateways,
aggregates energy in exact integer Watt-hours (Wh),
applies verified reference emission factors, and packages everything into an
immutable, verifiable claim bundle according to 02_protocol/evidence_bundle_spec.md.

The final manifest is cryptographically sealed with the Company Root Key.
"""

import json
import os
import shutil
import hashlib
import time
import csv
import subprocess
import binascii
import sys

def compute_sha256(filepath):
    """Computes SHA-256 digest of a local file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def openssl_sign(priv_path, data_bytes):
    """Signs bytes using OpenSSL dgst -sha256 -sign and returns hex-encoded DER signature."""
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", priv_path],
        input=data_bytes,
        capture_output=True,
        check=True
    )
    return binascii.hexlify(proc.stdout).decode('utf-8')

def generate_claim_bundle(bundle_root="claim_bundle", reference_dir=None,
                          company_priv_key_path="company_root_private_key.pem"):
    print("=" * 65)
    print(" Evidence Pipeline — Claim Bundle Generator (v1.1)")
    print("=" * 65)

    if reference_dir is None:
        if os.path.exists("04_experiments/reference_data"):
            reference_dir = "04_experiments/reference_data"
        else:
            reference_dir = "05_data/external"

    obs_file = os.path.join(bundle_root, "observations", "observations.ndjson")
    if not os.path.exists(obs_file):
        raise FileNotFoundError(f"Missing observation file: {obs_file}")

    # 1. Setup bundle directory tree
    for subdir in ["reference_data", "transformations", "provenance"]:
        os.makedirs(os.path.join(bundle_root, subdir), exist_ok=True)

    # 2. Copy reference emission factor and metadata into bundle
    ref_csv_src = os.path.join(reference_dir, "emission_factor.csv")
    ref_meta_src = os.path.join(reference_dir, "emission_factor_metadata.json")
    ref_csv_dest = os.path.join(bundle_root, "reference_data", "emission_factor.csv")
    ref_meta_dest = os.path.join(bundle_root, "reference_data", "emission_factor_metadata.json")

    shutil.copy2(ref_csv_src, ref_csv_dest)
    shutil.copy2(ref_meta_src, ref_meta_dest)
    print(f"[+] Reference Emission Factor Imported : {ref_csv_dest}")

    # 3. Read observations and compute integer Watt-hour aggregation
    observations = []
    total_energy_wh = 0
    first_ts = None
    last_ts = None
    first_seq = None
    last_seq = None
    meter_id = None
    device_id = None
    terminal_hash = None

    with open(obs_file, "r") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            payload = rec.get("payload", {})
            observations.append(rec)
            
            # Integer Wh accounting
            interval_wh = payload.get("interval_wh", 0)
            total_energy_wh += int(interval_wh)
            
            ts = payload.get("timestamp")
            seq = rec.get("sequence", payload.get("sequence"))
            
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts
                
            if first_seq is None or seq < first_seq:
                first_seq = seq
            if last_seq is None or seq > last_seq:
                last_seq = seq
                
            meter_id = payload.get("meter_id", meter_id)
            if device_id is None:
                device_id = rec.get("device_id", "unknown")
                
            envelope_canonical = json.dumps(rec, separators=(',', ':'), sort_keys=True).encode('utf-8')
            terminal_hash = hashlib.sha256(envelope_canonical).hexdigest()

    total_energy_kwh = round(total_energy_wh / 1000.0, 4)
    obs_sha256 = compute_sha256(obs_file)

    # Record energy aggregation transformation
    energy_trans = {
        "transformation_id": "trans_energy_aggregation_v1",
        "description": "Summation of discrete interval meter readings in integer Watt-hours",
        "input_observations_sha256": obs_sha256,
        "record_count": len(observations),
        "period_start_timestamp": first_ts,
        "period_end_timestamp": last_ts,
        "first_sequence": first_seq,
        "last_sequence": last_seq,
        "terminal_hash": terminal_hash,
        "aggregated_energy_wh": total_energy_wh,
        "aggregated_energy_kwh": total_energy_kwh,
        "algorithm": "sum_interval_wh",
        "executed_at": int(time.time())
    }
    energy_trans_file = os.path.join(bundle_root, "transformations", "energy_aggregation.json")
    with open(energy_trans_file, "w") as f:
        json.dump(energy_trans, f, indent=2)

    # 4. Lookup emission factor from reference data
    ref_country = "IT"
    ref_activity = "electricity_grid_mix"
    emission_factor = None
    with open(ref_csv_dest, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("country") == ref_country and row.get("activity_type") == ref_activity:
                emission_factor = float(row.get("kg_co2e_per_unit"))
                break

    if emission_factor is None:
        raise ValueError(f"Could not find matching emission factor for {ref_country} {ref_activity}")

    # 5. Compute carbon calculation in fixed-point decimal
    total_co2e_kg = round((total_energy_wh / 1000.0) * emission_factor, 4)
    ref_csv_sha256 = compute_sha256(ref_csv_dest)
    energy_trans_sha256 = compute_sha256(energy_trans_file)

    carbon_trans = {
        "transformation_id": "trans_carbon_calculation_v1",
        "description": "GHG Scope 2 location-based carbon quantification",
        "input_energy_transformation_sha256": energy_trans_sha256,
        "input_emission_factor_sha256": ref_csv_sha256,
        "reference_country": ref_country,
        "reference_activity_type": ref_activity,
        "energy_wh": total_energy_wh,
        "energy_kwh": total_energy_kwh,
        "emission_factor_kg_per_kwh": emission_factor,
        "calculated_co2e_kg": total_co2e_kg,
        "standard": "GHG Protocol Scope 2 Guidance / ISO 14064-1",
        "executed_at": int(time.time())
    }
    carbon_trans_file = os.path.join(bundle_root, "transformations", "carbon_calculation.json")
    with open(carbon_trans_file, "w") as f:
        json.dump(carbon_trans, f, indent=2)

    # 6. Generate final declared Claim JSON with sequence bounds
    claim_id = f"claim_{device_id}_{first_ts}_{last_ts}"
    claim = {
        "claim_id": claim_id,
        "target_facility": "Milan Commercial Facility #01",
        "meter_id": meter_id,
        "device_id": device_id,
        "reporting_period": {
            "start_timestamp": first_ts,
            "end_timestamp": last_ts,
            "first_sequence": first_seq,
            "last_sequence": last_seq,
            "record_count": len(observations)
        },
        "declared_metrics": {
            "total_energy_wh": total_energy_wh,
            "total_energy_kwh": total_energy_kwh,
            "emission_factor_value": emission_factor,
            "emission_factor_unit": "kg_co2e_per_kwh",
            "total_emissions_kg_co2e": total_co2e_kg
        },
        "status": "declared_claim",
        "generated_at": int(time.time())
    }
    claim_file = os.path.join(bundle_root, "claim.json")
    with open(claim_file, "w") as f:
        json.dump(claim, f, indent=2)

    # 7. Generate W3C PROV-O lineage graph
    provenance = {
        "prefix": {"prov": "http://www.w3.org/ns/prov#"},
        "entity": {
            "observations:observations.ndjson": {"type": "raw_telemetry_stream", "sha256": obs_sha256},
            "reference:emission_factor.csv": {"type": "authoritative_factor", "sha256": ref_csv_sha256},
            "claim:claim.json": {"type": "final_sustainability_claim"}
        },
        "activity": {
            "act:energy_aggregation": {"type": "transformation", "recipe": "energy_aggregation.json"},
            "act:carbon_calculation": {"type": "transformation", "recipe": "carbon_calculation.json"}
        },
        "wasGeneratedBy": {
            "claim:claim.json": "act:carbon_calculation"
        }
    }
    prov_file = os.path.join(bundle_root, "provenance", "provenance.json")
    with open(prov_file, "w") as f:
        json.dump(provenance, f, indent=2)

    # 8. Compute Checksums & Manifest over all files in bundle
    bundle_files = []
    for root, _, files in sorted(os.walk(bundle_root)):
        for f in sorted(files):
            if f in ["manifest.json", "checksums.txt", ".DS_Store"]:
                continue
            lf = f.lower()
            if any(s in lf for s in ("private", ".key")):
                raise RuntimeError(f"Security: private key material detected in bundle: {f}")
            rel_path = os.path.relpath(os.path.join(root, f), bundle_root)
            full_path = os.path.join(root, f)
            bundle_files.append((rel_path, compute_sha256(full_path)))

    # Write checksums.txt
    checksums_path = os.path.join(bundle_root, "checksums.txt")
    with open(checksums_path, "w") as f:
        for rel_path, digest in bundle_files:
            f.write(f"{digest}  {rel_path}\n")

    # 9. Cryptographically seal the manifest with Company Root Key
    files_dict = {rel_path: digest for rel_path, digest in bundle_files}
    canonical_files = json.dumps(files_dict, separators=(',', ':'), sort_keys=True).encode('utf-8')
    bundle_seal_sig = openssl_sign(company_priv_key_path, canonical_files)

    manifest = {
        "manifest_version": "1.1",
        "bundle_spec": "02_protocol/evidence_bundle_spec.md",
        "created_at": int(time.time()),
        "claim_id": claim["claim_id"],
        "files": files_dict,
        "bundle_seal": {
            "signature": bundle_seal_sig,
            "algorithm": "ECDSA_P256_SHA256",
            "signed_content": "canonical_json(files, separators=(',',':'), sort_keys=True)"
        }
    }
    manifest_path = os.path.join(bundle_root, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] Transformations Generated          : {energy_trans_file}")
    print(f"[+] Final Claim Declared               : {claim_file} ({total_energy_wh} Wh / {total_co2e_kg} kg CO2e)")
    print(f"[+] Bundle Sealed & Manifest Frozen    : {manifest_path}")
    print("=" * 65)


if __name__ == "__main__":
    key_path = sys.argv[1] if len(sys.argv) > 1 else "company_root_private_key.pem"
    generate_claim_bundle(company_priv_key_path=key_path)
