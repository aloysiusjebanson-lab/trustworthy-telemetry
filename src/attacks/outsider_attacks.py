#!/usr/bin/env python3
"""
Outsider Attack Benchmark — energy_submetering (bundle format v1.3)

The adversary intercepts a sealed bundle and edits it without holding any key:
  O1  Falsified meter reading                    O8  Path traversal entry in manifest
  O2  Rogue device id in certificate             O9  Unmanifested file injected
  O3  Dropped middle record                      O10 Revoked gateway
  O4  Replayed (duplicated) record               O11 Private key material in bundle
  O5  Foreign device id in a record              O12 Duplicate JSON key (parser differential)
  O6  Timestamp moved outside certificate window O13 Float injected into a signed payload
  O7  File edited and manifest re-hashed (no seal)
"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures import build_energy_fixture  # noqa: E402
from harness import assert_baseline_passes, report, verify_and_check  # noqa: E402
from tamper_tools import clone, read_envelopes, read_json, read_lines, write_envelopes, write_json, write_lines  # noqa: E402
import crypto  # noqa: E402


def run_outsider_tests():
    print("=" * 78)
    print(" Outsider Attack Benchmark — energy_submetering (bundle v1.3)")
    print("=" * 78)
    workdir = tempfile.mkdtemp(prefix="outsider_attacks_")
    attacks = []
    try:
        fx = build_energy_fixture(workdir)
        assert_baseline_passes(fx["bundle"], fx)

        def attack(name, bundle, check, extra=None):
            attacks.append((name, *verify_and_check(bundle, fx, check, extra)))

        d = clone(fx, "o1")
        envs = read_envelopes(d)
        envs[0]["record"]["payload"]["cumulative_wh"] = 99999999
        write_envelopes(d, envs)
        attack("O1: Falsified meter reading", d, "check3_observation_signatures")

        d = clone(fx, "o2")
        p = os.path.join(d, "device", "device_certificate.json")
        cert = read_json(p)
        cert["body"]["device_id"] = "dev-rogueadversary99"
        write_json(p, cert)
        attack("O2: Rogue device id in certificate", d, "check2_device_cert_and_attestation")

        d = clone(fx, "o3")
        lines = read_lines(d)
        del lines[1]
        write_lines(d, lines)
        attack("O3: Dropped middle record", d, "check4_hash_chain_continuity")

        d = clone(fx, "o4")
        lines = read_lines(d)
        write_lines(d, lines + [lines[0]])
        attack("O4: Replayed (duplicated) record", d, "check4_hash_chain_continuity")

        d = clone(fx, "o5")
        envs = read_envelopes(d)
        envs[0]["record"]["device_id"] = "dev-foreign00000000"
        write_envelopes(d, envs)
        attack("O5: Foreign device id in record", d, "check3_observation_signatures")

        d = clone(fx, "o6")
        envs = read_envelopes(d)
        envs[0]["record"]["timestamp_start"] = 1577836800
        write_envelopes(d, envs)
        attack("O6: Timestamp outside certificate window", d, "check3_observation_signatures")

        d = clone(fx, "o7")
        envs = read_envelopes(d)
        envs[0]["record"]["payload"]["interval_wh"] = 10
        write_envelopes(d, envs)
        mp = os.path.join(d, "manifest.json")
        m = read_json(mp)
        m["files"]["observations/observations.ndjson"] = crypto.sha256_file(os.path.join(d, "observations", "observations.ndjson"))
        write_json(mp, m)
        attack("O7: Edited file + re-hashed manifest (seal bypass)", d, "check1_manifest_and_seal")

        d = clone(fx, "o8")
        m = read_json(os.path.join(d, "manifest.json"))
        m["files"]["../../etc/passwd"] = "0" * 64
        write_json(os.path.join(d, "manifest.json"), m)
        attack("O8: Path traversal entry in manifest", d, "check1_manifest_and_seal")

        d = clone(fx, "o9")
        with open(os.path.join(d, "injected_backdoor.sh"), "w") as f:
            f.write("#!/bin/sh\necho malicious\n")
        attack("O9: Unmanifested file injected", d, "check1_manifest_and_seal")

        d = clone(fx, "o10")
        attack("O10: Revoked gateway", d, "check2_device_cert_and_attestation", ["--revoked", fx["device_id"]])

        d = clone(fx, "o11")
        with open(os.path.join(d, "device", "device_private_key.pem"), "w") as f:
            f.write("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFAKEKEY\n-----END EC PRIVATE KEY-----\n")
        attack("O11: Private key material in bundle", d, "check1_manifest_and_seal")

        d = clone(fx, "o12")
        lines = read_lines(d)
        # Two parsers may keep different values for a duplicated key; the strict parser rejects it.
        lines[0] = lines[0].replace('"interval_wh": 2500', '"interval_wh": 2500, "interval_wh": 25', 1)
        write_lines(d, lines)
        attack("O12: Duplicate JSON key (parser differential)", d, "check3_observation_signatures")

        d = clone(fx, "o13")
        lines = read_lines(d)
        lines[0] = lines[0].replace('"interval_wh": 2500', '"interval_wh": 2500.0', 1)
        write_lines(d, lines)
        attack("O13: Float injected into signed payload", d, "check3_observation_signatures")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return report("outsider", attacks)


if __name__ == "__main__":
    sys.exit(0 if run_outsider_tests() else 1)
