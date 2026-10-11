#!/usr/bin/env python3
"""
Self-contained test fixtures for adversarial attack benchmark suites.
Builds isolated, fresh cryptographic fixtures inside a temporary working directory.
"""

import os
import sys
import json
import shutil
import hashlib

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src", "device_simulator"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src", "pipeline"))

from mock_biochar_edge import generate_biochar_telemetry
from biochar_claim_generator import build_biochar_claim_bundle
from mock_edge import provision_and_simulate
from claim_generator import generate_claim_bundle


def build_biochar_fixture(workdir: str) -> dict:
    """
    Builds a complete, valid biochar claim bundle fixture in workdir.
    Returns:
        {
            "bundle": <path_to_bundle>,
            "root_pub": <path_to_producer_root_public_key>,
            "root_priv": <path_to_producer_root_private_key>,
            "device_priv": <path_to_biochar_device_private_key>,
            "registry": <path_to_trusted_registry_json>
        }
    """
    keys_dir = os.path.join(workdir, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    bundle_dir = os.path.join(workdir, "biochar_bundle")

    # Generate edge observations and device identity
    generate_biochar_telemetry(
        bundle_root=bundle_dir,
        num_batches=5,
        keys_dir=keys_dir,
        producer_keys_dir=keys_dir
    )

    root_priv = os.path.join(keys_dir, "producer_root_private_key.pem")
    root_pub = os.path.join(keys_dir, "producer_root_public_key.pem")
    device_priv = os.path.join(keys_dir, "biochar_device_private_key.pem")

    # Build claim transformations, provenance, and seal
    build_biochar_claim_bundle(
        bundle_root=bundle_dir,
        producer_priv_key_path=root_priv
    )

    # Copy trusted registry and ensure fixture reference hashes are included
    registry_dst = os.path.join(workdir, "registry.json")
    registry_src = os.path.join(PROJECT_ROOT, "src", "verifier", "trusted_references.json")
    shutil.copyfile(registry_src, registry_dst)

    with open(registry_dst, "r") as f:
        reg_data = json.load(f)
    datasets = reg_data.setdefault("datasets", {})

    lab_file = os.path.join(bundle_dir, "reference_data", "lab_analysis.json")
    if os.path.exists(lab_file):
        with open(lab_file, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        if h not in datasets:
            with open(lab_file, "r") as f:
                lab_content = json.load(f)
            datasets[h] = {
                "dataset_id": "fixture_lab",
                "type": "iso17025_accredited_lab_report",
                "lab": lab_content.get("lab_name"),
                "accreditation": "DIN EN ISO/IEC 17025:2018",
                "c_org_bps": lab_content.get("c_org_bps"),
                "moisture_bps": lab_content.get("moisture_bps"),
                "permanence_factor_bps": lab_content.get("permanence_factor_bps")
            }

    feedstock_file = os.path.join(bundle_dir, "reference_data", "feedstock_manifest.json")
    if os.path.exists(feedstock_file):
        with open(feedstock_file, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        if h not in datasets:
            with open(feedstock_file, "r") as f:
                feed_content = json.load(f)
            datasets[h] = {
                "dataset_id": feed_content.get("delivery_ref"),
                "type": "feedstock_delivery_manifest",
                "supplier": feed_content.get("supplier"),
                "ebc_positive_list_code": feed_content.get("ebc_positive_list_code"),
                "delivered_mass_total_g": feed_content.get("delivered_mass_total_g")
            }

    with open(registry_dst, "w") as f:
        json.dump(reg_data, f, indent=2)

    return {
        "bundle": bundle_dir,
        "root_pub": root_pub,
        "root_priv": root_priv,
        "device_priv": device_priv,
        "registry": registry_dst
    }


def build_energy_fixture(workdir: str) -> dict:
    """
    Builds a complete, valid energy claim bundle fixture in workdir.
    Returns:
        {
            "bundle": <path_to_bundle>,
            "root_pub": <path_to_company_root_public_key>,
            "root_priv": <path_to_company_root_private_key>,
            "device_priv": <path_to_device_private_key>,
            "registry": <path_to_trusted_registry_json>
        }
    """
    keys_dir = os.path.join(workdir, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    bundle_dir = os.path.join(workdir, "claim_bundle")

    # Generate edge observations and device identity
    provision_and_simulate(
        bundle_root=bundle_dir,
        num_intervals=5,
        company_keys_dir=keys_dir,
        device_keys_dir=keys_dir
    )

    root_priv = os.path.join(keys_dir, "company_root_private_key.pem")
    root_pub = os.path.join(keys_dir, "company_root_public_key.pem")
    device_priv = os.path.join(keys_dir, "device_private_key.pem")

    ref_dir = os.path.join(PROJECT_ROOT, "04_experiments", "reference_data")
    if not os.path.exists(ref_dir):
        ref_dir = os.path.join(PROJECT_ROOT, "05_data", "external")

    generate_claim_bundle(
        bundle_root=bundle_dir,
        reference_dir=ref_dir,
        company_priv_key_path=root_priv
    )

    registry_dst = os.path.join(workdir, "registry.json")
    registry_src = os.path.join(PROJECT_ROOT, "src", "verifier", "trusted_references.json")
    shutil.copyfile(registry_src, registry_dst)

    return {
        "bundle": bundle_dir,
        "root_pub": root_pub,
        "root_priv": root_priv,
        "device_priv": device_priv,
        "registry": registry_dst
    }
