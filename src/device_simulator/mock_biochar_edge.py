"""
Mock Edge Gateway — biochar_pyrolysis profile (bundle format v1.3)

Simulates an edge gateway in the control cabinet reading an EU NAWI weighing indicator and a
Modbus Type-K thermocouple module over RS-485, and signing one record per pyrolysis batch
(integer grams, integer °C) inside a simulated ATECC608B secure element.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secure_element_sim import (ProducerAuthority, SimulatedManufacturer,  # noqa: E402
                                SimulatedSecureElement, provision_device, write_observation_chain)

PROFILE = "biochar_pyrolysis"
BASE_TIME = 1790800000      # 2026-10-01, inside the certificate window
BATCH_S = 14400             # 4-hour continuous batches
DELIVERY_REF = "delivery_fsc_wood_2026_09"


def biochar_instruments(scale_cal_until=1893456000, tc_cal_until=1893456000):
    return [
        {
            "role": "weighing_indicator",
            "instrument_id": "scale_floor_indicator_01",
            "model": "Floor scale weighing indicator (example)",
            "serial": "WI-984321",
            "standard": "NAWI_2014_31_EU",
            "accuracy_class": "Class_III",
            "max_capacity_g": 5000000,
            "calibration_cert_sha256": "4b92b67f1839d084c8a2b5e28a479b1d98a2e41f6c8d7e9b1a2c3d4e5f6a7b8c",
            "calibration_valid_until": scale_cal_until,
        },
        {
            "role": "thermocouple_module",
            "instrument_id": "tc_kiln_primary_zone_01",
            "model": "Modbus Type-K thermocouple module (example)",
            "serial": "TC-201554",
            "standard": "IEC_60584_1",
            "accuracy_class": "Class_1",
            "calibration_cert_sha256": "9f2c1a7e5b3d8c6a4e2f0b9d7c5a3e1f8b6d4c2a0e9f7d5b3c1a8e6f4d2b0c9a",
            "calibration_valid_until": tc_cal_until,
        },
    ]


def simulated_batches(num_batches=5, feedstock_g=6250000, wet_biochar_g=2000000):
    batches = []
    for i in range(1, num_batches + 1):
        t_start = BASE_TIME + (i - 1) * BATCH_S
        batches.append((t_start, t_start + BATCH_S, {
            "batch_id": f"batch_2026_10_{i:03d}",
            "feedstock_delivery_ref": DELIVERY_REF,
            "feedstock_input_g": feedstock_g,
            "scale_wet_mass_g": wet_biochar_g,
            "temp_min_c": 585 + (i % 3) * 5,
            "temp_avg_c": 625 + (i % 4) * 3,
            "temp_max_c": 645 + (i % 3) * 4,
        }))
    return batches


def generate_biochar_telemetry(bundle_root, num_batches=5, keys_dir="build/keys"):
    """Provisions the device and writes device/ and observations/. Returns key/CA paths."""
    manufacturer = SimulatedManufacturer(os.path.join(keys_dir, "manufacturer_pki"))
    producer = ProducerAuthority(keys_dir)
    se = SimulatedSecureElement(keys_dir, "biochar_device")
    provision_device(bundle_root, PROFILE, biochar_instruments(), se, producer, manufacturer,
                     valid_from=1767225600, valid_until=1830297600, issued_by="producer_authority_eu")
    write_observation_chain(bundle_root, se, simulated_batches(num_batches))
    return {"device_id": se.device_id, "device_priv": se.priv_path, "producer_priv": producer.priv_path,
            "producer_pub": producer.pub_path, "manufacturer_ca": manufacturer.root_cert}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Biochar pyrolysis edge gateway simulator (bundle v1.3)")
    ap.add_argument("bundle", nargs="?", default="build/biochar_bundle")
    ap.add_argument("--batches", type=int, default=5)
    ap.add_argument("--keys-dir", default="build/keys")
    args = ap.parse_args()
    out = generate_biochar_telemetry(args.bundle, args.batches, args.keys_dir)
    print(f"[+] Device {out['device_id']} wrote {args.batches} signed batches to {args.bundle}")
