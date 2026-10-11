"""
Mock Edge Gateway & Secure Element Simulator (v1.1)

Simulates an industrial edge gateway reading Modbus energy meters.
Implements the 3-level cryptographic key hierarchy:
  1. Microchip Factory Attestation: Proves device key was generated in hardware secure element.
  2. Company Root Key: Certifies edge devices (issues Device Certificates)
  3. Hardware Secure Element: Signs raw telemetry observations using ECDSA P-256 + SHA-256
     in an unbroken cryptographic hash-chain with integer Wh dual registers.
Outputs standard bundle structure adhering to 02_protocol/evidence_bundle_spec.md
Uses standard native OpenSSL with zero pip dependencies.
"""

import json
import time
import hashlib
import binascii
import os
import subprocess
import sys

def openssl_gen_ec_key(priv_path, pub_path):
    """Generates an EC NIST P-256 keypair using native OpenSSL with restricted permissions."""
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", priv_path],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    os.chmod(priv_path, 0o600)
    subprocess.run(
        ["openssl", "ec", "-in", priv_path, "-pubout", "-out", pub_path],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

def openssl_sign(priv_path, data_bytes):
    """Signs bytes using OpenSSL dgst -sha256 -sign and returns hex-encoded DER signature."""
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", priv_path],
        input=data_bytes,
        capture_output=True,
        check=True
    )
    return binascii.hexlify(proc.stdout).decode('utf-8')


class CompanyAuthority:
    """Simulates the deploying enterprise holding a Company Root Key (trust anchor)."""
    def __init__(self, key_dir="."):
        self.priv_path = os.path.join(key_dir, "company_root_private_key.pem")
        self.pub_path = os.path.join(key_dir, "company_root_public_key.pem")
        if not os.path.exists(self.priv_path):
            openssl_gen_ec_key(self.priv_path, self.pub_path)
        else:
            try:
                os.chmod(self.priv_path, 0o600)
            except OSError:
                pass

    def certify_device(self, device_id, device_pub_pem, meter_id):
        """Issues an unforgeable Device Certificate signed by the Company Root Key."""
        cert_body = {
            "device_id": device_id,
            "device_type": "edge_gateway_modbus_p256",
            "meter_binding": meter_id,
            "metrology": {
                "meter_model": "Carlo Gavazzi EM24",
                "standard": "MID_2014_32_EU",
                "accuracy_class": "Class_B_EN50470",
                "calibration_cert_sha256": "8e6cc7a7359fb935c5bdf236bd193fa996dfb990a40873f719f99ae5d5f69442",
                "calibration_valid_until": 1893456000
            },
            "device_public_key": device_pub_pem.strip(),
            "valid_from": 1767225600,   # 2026-01-01
            "valid_until": 1830297600,  # 2028-01-01
            "issued_by": "company_authority_milan"
        }
        canonical_bytes = json.dumps(cert_body, separators=(',', ':'), sort_keys=True).encode('utf-8')
        signature = openssl_sign(self.priv_path, canonical_bytes)
        
        return {
            "certificate_body": cert_body,
            "company_signature": signature,
            "algorithm": "ECDSA_P256_SHA256"
        }


class MockEdgeDevice:
    """
    Simulates the physical edge gateway equipped with a Secure Element (ATECC608).
    Maintains its private key strictly on-device (outside the claim bundle).
    """
    def __init__(self, bundle_device_dir, private_key_dir="src/device_simulator/keys"):
        os.makedirs(bundle_device_dir, exist_ok=True)
        os.makedirs(private_key_dir, exist_ok=True)
        self.device_dir = bundle_device_dir
        self.priv_path = os.path.join(private_key_dir, "device_private_key.pem")
        self.pub_path = os.path.join(bundle_device_dir, "public_key.pem")
        
        if not os.path.exists(self.priv_path):
            openssl_gen_ec_key(self.priv_path, self.pub_path)
        elif not os.path.exists(self.pub_path):
            subprocess.run(
                ["openssl", "ec", "-in", self.priv_path, "-pubout", "-out", self.pub_path],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
        with open(self.pub_path, "r") as f:
            self.pub_pem = f.read().strip()
            
        pub_bytes = self.pub_pem.encode('utf-8')
        self.device_id = "device_" + hashlib.sha256(pub_bytes).hexdigest()[:12]

    def sign_observation(self, payload_dict):
        """Signs an observation payload using deterministic canonical JSON."""
        canonical_bytes = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode('utf-8')
        return openssl_sign(self.priv_path, canonical_bytes)


def generate_simulated_readings(num_intervals=5, base_wh=15420000, interval_wh=2500):
    """
    Generates continuous interval energy readings simulating a physical meter.
    Uses exact integer Watt-hours (Wh) for both cumulative totalizer and interval.
    """
    base_time = int(time.time()) - (num_intervals * 900)  # 15-min intervals
    readings = []
    current_wh = base_wh
    for seq in range(1, num_intervals + 1):
        current_wh += interval_wh
        readings.append({
            "timestamp": base_time + (seq * 900),
            "meter_id": "meter_main_switchgear_01",
            "cumulative_wh": current_wh,
            "interval_wh": interval_wh,
            "reading_kwh": round(current_wh / 1000.0, 3),      # Display helper
            "interval_kwh": round(interval_wh / 1000.0, 3),    # Display helper
            "sequence": seq
        })
    return readings


def provision_and_simulate(bundle_root="claim_bundle", num_intervals=5, company_keys_dir=".", device_keys_dir="src/device_simulator/keys"):
    print("=" * 65)
    print(" Verifiable Telemetry Engine — Edge Provisioning & Simulation (v1.1)")
    print("=" * 65)

    # 1. Company Authority
    authority = CompanyAuthority(key_dir=company_keys_dir)
    print(f"[+] Company Root Authority Active : {authority.pub_path}")

    # 2. Edge Device Provisioning
    device_dir = os.path.join(bundle_root, "device")
    edge_device = MockEdgeDevice(bundle_device_dir=device_dir, private_key_dir=device_keys_dir)
    meter_id = "meter_main_switchgear_01"
    print(f"[+] Edge Device Provisioned      : {edge_device.device_id}")

    # 3. Issue and save Device Certificate signed by Company Authority
    device_cert = authority.certify_device(edge_device.device_id, edge_device.pub_pem, meter_id)
    cert_path = os.path.join(device_dir, "device_certificate.json")
    with open(cert_path, "w") as f:
        json.dump(device_cert, f, indent=2)
    print(f"[+] Device Certificate Issued    : {cert_path}")

    # 4. Save Microchip Factory Hardware Attestation
    attestation_info = {
        "attestation_type": "microchip_atecc608_factory_attestation",
        "chip_serial": f"0123{hashlib.sha256(edge_device.pub_pem.encode()).hexdigest()[:12].upper()}",
        "device_public_key": edge_device.pub_pem.strip(),
        "device_public_key_sha256": hashlib.sha256(edge_device.pub_pem.strip().encode('utf-8')).hexdigest(),
        "signer": "Microchip Technology Production Root CA",
        "attestation_status": "verified_hardware_secure_element",
        "attestation_mode": "SIMULATED_STUB",
        "secure_element_part": "ATECC608A-TNGTLS",
        "features": [
            "hardware_private_key_isolation",
            "true_random_number_generator",
            "anti_tamper_active_shield"
        ]
    }
    attestation_path = os.path.join(device_dir, "hardware_attestation.json")
    with open(attestation_path, "w") as f:
        json.dump(attestation_info, f, indent=2)
    print(f"[+] Hardware Attestation Pinned  : {attestation_path}")

    # 5. Save device identity descriptor
    identity_info = {
        "device_id": edge_device.device_id,
        "device_type": "edge_gateway_modbus_p256",
        "hardware_secure_element": "Microchip ATECC608A",
        "meter_id": meter_id,
        "public_key_file": "public_key.pem",
        "certificate_file": "device_certificate.json",
        "attestation_file": "hardware_attestation.json"
    }
    with open(os.path.join(device_dir, "identity.json"), "w") as f:
        json.dump(identity_info, f, indent=2)

    # 6. Generate, hash-chain, and sign observation telemetry
    obs_dir = os.path.join(bundle_root, "observations")
    os.makedirs(obs_dir, exist_ok=True)
    obs_file = os.path.join(obs_dir, "observations.ndjson")
    
    raw_readings = generate_simulated_readings(num_intervals=num_intervals)
    current_prev_hash = "0" * 64  # Genesis hash for the reporting sequence

    with open(obs_file, "w") as f:
        for reading in raw_readings:
            # Bind sequence and prev_hash directly inside the signed payload
            payload_to_sign = {
                "sequence": reading["sequence"],
                "prev_hash": current_prev_hash,
                "timestamp": reading["timestamp"],
                "meter_id": reading["meter_id"],
                "cumulative_wh": reading["cumulative_wh"],
                "interval_wh": reading["interval_wh"],
                "reading_kwh": reading["reading_kwh"],
                "interval_kwh": reading["interval_kwh"]
            }
            sig = edge_device.sign_observation(payload_to_sign)
            envelope = {
                "device_id": edge_device.device_id,
                "sequence": reading["sequence"],
                "prev_hash": current_prev_hash,
                "payload": payload_to_sign,
                "signature": sig,
                "algorithm": "ECDSA_P256_SHA256"
            }
            # Next observation's prev_hash is the SHA-256 of this canonical envelope
            envelope_canonical = json.dumps(envelope, separators=(',', ':'), sort_keys=True).encode('utf-8')
            current_prev_hash = hashlib.sha256(envelope_canonical).hexdigest()
            f.write(json.dumps(envelope) + "\n")

    print(f"[+] Generated {num_intervals} hash-chained observations : {obs_file}")
    print("=" * 65)
    return edge_device.device_id


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    provision_and_simulate(num_intervals=count)
