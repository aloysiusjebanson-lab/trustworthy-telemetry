#!/usr/bin/env python3
"""
Hardware Simulator: Biochar Pyrolysis dMRV Edge Gateway (v1.2)
Specification: 02_protocol/evidence_bundle_spec.md (biochar_pyrolysis profile)

Simulates a hardened edge gateway located in an unclassified control room
tapping an industrial pyrolysis kiln over galvanically isolated RS-485 Modbus RTU:
1. Microchip ATECC608 Hardware Secure Element key generation & factory CA attestation.
2. Producer Root Key certificate signing with EU Directive 2014/31/EU NAWI scale metrology.
3. Modbus RTU Type-K thermocouple acquisition (pyrolysis temperatures > 500°C).
4. Industrial floor scale load-cell indicator acquisition (integer grams).
5. Sequential hash-chaining (prev_hash) and NIST P-256 ECDSA silicon signatures per batch.
"""

import os
import sys
import json
import subprocess
import hashlib
import time

def run_openssl(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        raise RuntimeError(f"OpenSSL error ({p.returncode}): {err.decode('utf-8')}")
    return out

def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

def sign_data(data_bytes, private_key_path):
    cmd = ["openssl", "dgst", "-sha256", "-sign", private_key_path]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    der_sig, err = p.communicate(input=data_bytes)
    if p.returncode != 0:
        raise RuntimeError(f"OpenSSL signing error: {err.decode('utf-8')}")
    return der_sig.hex()

def ensure_producer_root_keys(keys_dir):
    root_priv = os.path.join(keys_dir, "producer_root_private_key.pem")
    root_pub = os.path.join(keys_dir, "producer_root_public_key.pem")
    if not (os.path.exists(root_priv) and os.path.exists(root_pub)):
        run_openssl(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", root_priv])
        os.chmod(root_priv, 0o600)
        run_openssl(["openssl", "ec", "-in", root_priv, "-pubout", "-out", root_pub])
    return root_priv, root_pub

def ensure_device_keys(device_dir, keys_dir):
    os.makedirs(keys_dir, exist_ok=True)
    legacy_priv = os.path.join(device_dir, "device_private_key.pem")
    dev_priv = os.path.join(keys_dir, "biochar_device_private_key.pem")
    dev_pub = os.path.join(device_dir, "public_key.pem")

    # Migration: if legacy key in device_dir exists and external does not, move it
    if os.path.exists(legacy_priv) and not os.path.exists(dev_priv):
        os.replace(legacy_priv, dev_priv)
    elif os.path.exists(legacy_priv) and os.path.exists(dev_priv):
        os.remove(legacy_priv)

    if not os.path.exists(dev_priv):
        run_openssl(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", dev_priv])
        os.chmod(dev_priv, 0o600)
    run_openssl(["openssl", "ec", "-in", dev_priv, "-pubout", "-out", dev_pub])
    return dev_priv, dev_pub

def derive_device_id(pub_key_path):
    with open(pub_key_path, "r") as f:
        lines = [line.strip() for line in f if not line.startswith("-----")]
    raw_b64 = "".join(lines)
    return f"device_biochar_{hashlib.sha256(raw_b64.encode('utf-8')).hexdigest()[:12]}"

def generate_biochar_telemetry(bundle_root="biochar_bundle", num_batches=5, keys_dir=None, producer_keys_dir=None):
    print("=================================================================")
    print(" Biochar dMRV Hardware Simulator — Edge Gateway Daemon (v1.2)")
    print(" Profile: biochar_pyrolysis | EU CRCF & Puro.earth Standards")
    print("=================================================================")
    
    device_dir = os.path.join(bundle_root, "device")
    obs_dir = os.path.join(bundle_root, "observations")
    os.makedirs(device_dir, exist_ok=True)
    os.makedirs(obs_dir, exist_ok=True)
    
    project_root = os.path.abspath(os.path.join(bundle_root, ".."))
    if producer_keys_dir is None:
        producer_keys_dir = project_root
    if keys_dir is None:
        keys_dir = os.path.join(project_root, "src", "device_simulator", "keys")

    root_priv, root_pub = ensure_producer_root_keys(producer_keys_dir)
    dev_priv, dev_pub = ensure_device_keys(device_dir, keys_dir)
    
    device_id = derive_device_id(dev_pub)
    print(f"[+] Device ID Derived from Silicon PubKey : {device_id}")
    
    with open(dev_pub, "r") as f:
        device_pub_pem = f.read().strip()
        
    # 1. Device Certificate with EU Directive 2014/31/EU NAWI Legal Scale Metrology
    cert_body = {
        "device_id": device_id,
        "device_type": "pyrolysis_dMRV_gateway",
        "kiln_binding": "kiln_rotary_continuous_01",
        "metrology": {
            "scale_model": "Mettler Toledo IND570",
            "standard": "EU_Directive_2014_31_EU_NAWI",
            "accuracy_class": "Class_III",
            "max_capacity_g": 5000000,
            "scale_serial_number": "MT-IND570-984321",
            "calibration_cert_sha256": "4b92b67f1839d084c8a2b5e28a479b1d98a2e41f6c8d7e9b1a2c3d4e5f6a7b8c",
            "calibration_valid_until": 1893456000
        },
        "thermocouple_module": {
            "module_model": "Advantech ADAM-4015",
            "sensor_type": "Type_K_Thermocouple",
            "calibration_valid_until": 1893456000
        },
        "device_public_key": device_pub_pem,
        "valid_from": 1767225600,
        "valid_until": 1830297600,
        "issued_by": "producer_authority_eu"
    }
    cert_sig = sign_data(canonical_json(cert_body), root_priv)
    device_cert = {
        "certificate_body": cert_body,
        "company_signature": cert_sig,
        "algorithm": "ECDSA_P256_SHA256"
    }
    with open(os.path.join(device_dir, "device_certificate.json"), "w") as f:
        json.dump(device_cert, f, indent=2)
    print(f"[+] Device Certificate Issued & Signed   : {os.path.join(device_dir, 'device_certificate.json')}")
    
    # 2. Hardware Silicon Attestation Certificate (Microchip ATECC608)
    attestation_doc = {
        "secure_element": "Microchip ATECC608B",
        "manufacturer_ca": "Microchip Technology Root CA 2026",
        "device_public_key_sha256": hashlib.sha256(device_pub_pem.encode('utf-8')).hexdigest(),
        "attestation_status": "SILICON_HARDWARE_VERIFIED",
        "attestation_mode": "SIMULATED_STUB",
        "pcr_quote": "c84f1092a83bd782019482710384729104820194820194820194820194820194"
    }
    with open(os.path.join(device_dir, "hardware_attestation.json"), "w") as f:
        json.dump(attestation_doc, f, indent=2)
        
    identity_doc = {
        "device_id": device_id,
        "device_type": "pyrolysis_dMRV_gateway",
        "kiln_id": "kiln_rotary_continuous_01",
        "scale_id": "scale_floor_indicator_01",
        "thermocouple_id": "tc_kiln_primary_zone_01",
        "facility": "Biochar Pyrolysis Facility Trentino"
    }
    with open(os.path.join(device_dir, "identity.json"), "w") as f:
        json.dump(identity_doc, f, indent=2)

    # 3. Batch Telemetry Generation with Sequential Hash-Chaining
    obs_file = os.path.join(obs_dir, "observations.ndjson")
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    base_time = 1790800000  # Epoch timestamp within cert validity window
    
    feedstock_per_batch = 6250000   # 6.25 tonnes dry feedstock (g)
    wet_biochar_per_batch = 2000000 # 2.0 tonnes wet biochar (g)
    
    records = []
    print(f"[*] Simulating {num_batches} consecutive pyrolysis batches (T > 500°C)...")
    
    for i in range(1, num_batches + 1):
        batch_id = f"batch_2026_10_{i:03d}"
        t_start = base_time + (i - 1) * 14400
        t_end = t_start + 14400  # 4 hours per continuous batch
        
        # Continuous pyrolysis temperatures: min 580-600°C, avg 620-635°C (well above 500°C threshold)
        t_min = 585 + (i % 3) * 5
        t_avg = 625 + (i % 4) * 3
        t_max = 645 + (i % 3) * 4
        
        payload = {
            "timestamp_start": t_start,
            "timestamp_end": t_end,
            "batch_id": batch_id,
            "feedstock_input_g": feedstock_per_batch,
            "feedstock_delivery_ref": "delivery_fsc_wood_2026_09",
            "scale_wet_mass_g": wet_biochar_per_batch,
            "temp_min_c": t_min,
            "temp_avg_c": t_avg,
            "temp_max_c": t_max,
            "scale_id": "scale_floor_indicator_01",
            "sequence": i
        }
        
        envelope_to_sign = {
            "device_id": device_id,
            "batch_id": batch_id,
            "sequence": i,
            "prev_hash": prev_hash,
            "payload": payload
        }
        
        sig = sign_data(canonical_json(envelope_to_sign), dev_priv)
        
        full_record = {
            "device_id": device_id,
            "batch_id": batch_id,
            "sequence": i,
            "prev_hash": prev_hash,
            "payload": payload,
            "signature": sig,
            "algorithm": "ECDSA_P256_SHA256"
        }
        records.append(full_record)
        prev_hash = hashlib.sha256(canonical_json(full_record)).hexdigest()
        print(f"    - Batch {i}: {batch_id} | T_min={t_min}°C, Mass={wet_biochar_per_batch}g | Hash={prev_hash[:12]}...")
        
    with open(obs_file, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
            
    print(f"[+] Signed Telemetry Stream Written      : {obs_file} ({len(records)} batches)")
    print(f"[+] Terminal Hash-Chain Anchor           : {prev_hash}")
    return records

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Biochar dMRV Hardware Simulator (v1.2)")
    parser.add_argument("bundle", nargs="?", default="biochar_bundle", help="Output bundle directory")
    parser.add_argument("--batches", type=int, default=5, help="Number of batches to simulate")
    parser.add_argument("--keys-dir", default=None, help="Directory to store device private keys")
    parser.add_argument("--producer-keys-dir", default=None, help="Directory containing producer root keys")
    args = parser.parse_args()
    generate_biochar_telemetry(args.bundle, args.batches, keys_dir=args.keys_dir, producer_keys_dir=args.producer_keys_dir)
