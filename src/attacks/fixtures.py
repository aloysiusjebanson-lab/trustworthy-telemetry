#!/usr/bin/env python3
"""
Self-contained test fixtures (bundle format v1.3).
Each fixture builds a fresh simulated manufacturer PKI, producer root, device key and a
valid sealed bundle inside a temporary working directory.
"""

import os
import shutil
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for sub in ("verifier", "device_simulator", "pipeline"):
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "src", sub))

from biochar_claim_generator import build_biochar_claim_bundle  # noqa: E402
from claim_generator import generate_claim_bundle  # noqa: E402
from mock_biochar_edge import generate_biochar_telemetry  # noqa: E402
from mock_edge import provision_and_simulate  # noqa: E402

REGISTRY_SRC = os.path.join(PROJECT_ROOT, "src", "verifier", "trusted_references.json")


def _fixture(workdir, profile, bundle_name, out):
    registry = os.path.join(workdir, "registry.json")
    shutil.copyfile(REGISTRY_SRC, registry)
    return {
        "profile": profile,
        "bundle": os.path.join(workdir, bundle_name),
        "keys_dir": os.path.join(workdir, "keys"),
        "producer_pub": out["producer_pub"],
        "producer_priv": out["producer_priv"],
        "device_priv": out["device_priv"],
        "device_id": out["device_id"],
        "manufacturer_ca": out["manufacturer_ca"],
        "registry": registry,
        "workdir": workdir,
    }


def build_energy_fixture(workdir, num_intervals=5):
    keys = os.path.join(workdir, "keys")
    bundle = os.path.join(workdir, "energy_bundle")
    out = provision_and_simulate(bundle, num_intervals, keys)
    generate_claim_bundle(bundle, keys_dir=keys)
    return _fixture(workdir, "energy_submetering", "energy_bundle", out)


def build_biochar_fixture(workdir, num_batches=5):
    keys = os.path.join(workdir, "keys")
    bundle = os.path.join(workdir, "biochar_bundle")
    out = generate_biochar_telemetry(bundle, num_batches, keys)
    build_biochar_claim_bundle(bundle, keys_dir=keys)
    return _fixture(workdir, "biochar_pyrolysis", "biochar_bundle", out)
