"""
Mock Edge Gateway — energy_submetering profile (bundle format v1.3)

Simulates an edge gateway reading an EU MID energy submeter over RS-485 Modbus RTU and
signing 15-minute interval records (integer Wh cumulative and interval registers) inside a
simulated ATECC608B secure element, linked into a prev_hash chain.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secure_element_sim import (ProducerAuthority, SimulatedManufacturer,  # noqa: E402
                                SimulatedSecureElement, provision_device, write_observation_chain)

PROFILE = "energy_submetering"
BASE_TIME = 1790800000          # 2026-10-01, inside the certificate window
INTERVAL_S = 900                # 15-minute metering interval
METER_ID = "meter_main_switchgear_01"
CALIBRATION_CERT_SHA256 = "8e6cc7a7359fb935c5bdf236bd193fa996dfb990a40873f719f99ae5d5f69442"


def energy_instruments(calibration_valid_until=1893456000):
    return [{
        "role": "energy_meter",
        "instrument_id": METER_ID,
        "model": "Three-phase MID submeter (example)",
        "serial": "EM-000123",
        "standard": "MID_2014_32_EU",
        "accuracy_class": "Class_B_EN50470",
        "calibration_cert_sha256": CALIBRATION_CERT_SHA256,
        "calibration_valid_until": calibration_valid_until,
    }]


def simulated_intervals(num_intervals=5, base_wh=15420000, interval_wh=2500):
    intervals, cumulative = [], base_wh
    for i in range(num_intervals):
        cumulative += interval_wh
        t_start = BASE_TIME + i * INTERVAL_S
        intervals.append((t_start, t_start + INTERVAL_S,
                          {"meter_id": METER_ID, "cumulative_wh": cumulative, "interval_wh": interval_wh}))
    return intervals


def provision_and_simulate(bundle_root, num_intervals=5, keys_dir="build/keys"):
    """Provisions the device and writes device/ and observations/. Returns key/CA paths."""
    manufacturer = SimulatedManufacturer(os.path.join(keys_dir, "manufacturer_pki"))
    producer = ProducerAuthority(keys_dir)
    se = SimulatedSecureElement(keys_dir, "energy_device")
    provision_device(bundle_root, PROFILE, energy_instruments(), se, producer, manufacturer,
                     valid_from=1767225600, valid_until=1830297600, issued_by="producer_authority_milan")
    write_observation_chain(bundle_root, se, simulated_intervals(num_intervals))
    return {"device_id": se.device_id, "device_priv": se.priv_path, "producer_priv": producer.priv_path,
            "producer_pub": producer.pub_path, "manufacturer_ca": manufacturer.root_cert}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Energy submetering edge gateway simulator (bundle v1.3)")
    ap.add_argument("bundle", nargs="?", default="build/energy_bundle")
    ap.add_argument("--intervals", type=int, default=5)
    ap.add_argument("--keys-dir", default="build/keys")
    args = ap.parse_args()
    out = provision_and_simulate(args.bundle, args.intervals, args.keys_dir)
    print(f"[+] Device {out['device_id']} wrote {args.intervals} signed records to {args.bundle}")
