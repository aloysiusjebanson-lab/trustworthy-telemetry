#!/usr/bin/env python3
"""
Freezes the cross-language golden conformance vectors (bundle format v1.3).

For each reference profile, builds a fresh fixture, copies the sealed bundle plus the
auditor-side trust inputs (producer public key, manufacturer root CA, registry) and records
the expected verdict. All private keys stay in a temporary directory and are destroyed.

Usage: python3 src/tools/freeze_golden_vectors.py
"""

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src", "attacks"))
from fixtures import build_biochar_fixture, build_energy_fixture  # noqa: E402
from harness import run_verifier  # noqa: E402

TARGETS = {
    "energy_submetering": (build_energy_fixture, os.path.join(ROOT, "04_experiments", "golden_test_vector")),
    "biochar_pyrolysis": (build_biochar_fixture, os.path.join(ROOT, "04_experiments", "golden_test_vector_biochar")),
}
STABLE_FINDINGS = ("device_id", "hardware_attestation", "record_count", "terminal_hash", "recomputed_metrics")


def conformance_command(rel_dir, profile):
    return ("python3 src/verifier/verify_bundle.py {d}/bundle --profile {p} "
            "--producer-key {d}/trust/producer_root_public_key.pem "
            "--manufacturer-ca {d}/trust/manufacturer_root_ca.pem "
            "--trusted-registry {d}/trust/registry.json --json").format(d=rel_dir, p=profile)


def freeze(profile, builder, out_dir):
    workdir = tempfile.mkdtemp(prefix="golden_")
    try:
        fx = builder(workdir)
        shutil.rmtree(out_dir, ignore_errors=True)
        shutil.copytree(fx["bundle"], os.path.join(out_dir, "bundle"))
        trust = os.path.join(out_dir, "trust")
        os.makedirs(trust)
        shutil.copyfile(fx["producer_pub"], os.path.join(trust, "producer_root_public_key.pem"))
        shutil.copyfile(fx["manufacturer_ca"], os.path.join(trust, "manufacturer_root_ca.pem"))
        shutil.copyfile(fx["registry"], os.path.join(trust, "registry.json"))

        frozen = dict(fx, bundle=os.path.join(out_dir, "bundle"),
                      producer_pub=os.path.join(trust, "producer_root_public_key.pem"),
                      manufacturer_ca=os.path.join(trust, "manufacturer_root_ca.pem"),
                      registry=os.path.join(trust, "registry.json"))
        report, crash = run_verifier(frozen["bundle"], frozen)
        if report is None or report["verdict"] != "PASSED":
            raise RuntimeError(f"Frozen {profile} vector does not pass: {report or crash}")
        rel_dir = os.path.relpath(out_dir, ROOT)
        expected = {
            "profile": profile,
            "bundle_format": report["bundle_format"],
            "verdict": report["verdict"],
            "checks": report["checks"],
            "findings": {k: report["findings"][k] for k in STABLE_FINDINGS},
            "conformance_command": conformance_command(rel_dir, profile),
        }
        with open(os.path.join(out_dir, "expected_audit_verdict.json"), "w") as f:
            json.dump(expected, f, indent=2)
            f.write("\n")
        leaked = [f for r, _, fs in os.walk(out_dir) for f in fs if "private" in f.lower()]
        if leaked:
            raise RuntimeError(f"Private key material in golden vector: {leaked}")
        print(f"[+] Froze {profile} -> {rel_dir} ({report['findings']['record_count']} records)")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    for profile, (builder, out_dir) in TARGETS.items():
        freeze(profile, builder, out_dir)
