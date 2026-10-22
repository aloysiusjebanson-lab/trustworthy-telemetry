#!/usr/bin/env python3
"""
Zero-Trust Test Harness (bundle format v1.3)
Asserts that each attack vector fails for the exact expected reason, verifies that
baselines pass, and never counts a verifier crash as a catch.
"""

import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VERIFIER = os.path.join(PROJECT_ROOT, "src", "verifier", "verify_bundle.py")


def verifier_command(bundle_path, fx, extra_args=None):
    """Auditor invocation: every trust anchor comes from the fixture, never from the bundle."""
    cmd = [sys.executable, VERIFIER, bundle_path, "--json",
           "--profile", fx["profile"],
           "--producer-key", fx["producer_pub"],
           "--manufacturer-ca", fx["manufacturer_ca"],
           "--trusted-registry", fx["registry"]]
    return cmd + list(extra_args or [])


def run_verifier(bundle_path, fx, extra_args=None):
    res = subprocess.run(verifier_command(bundle_path, fx, extra_args), capture_output=True, text=True)
    try:
        return json.loads(res.stdout), None
    except ValueError:
        return None, (res.stderr or res.stdout)[-400:]


def verify_and_check(bundle_path, fx, expected_failed_check, extra_args=None):
    """Returns (caught, detail). caught only if verdict == FAILED and the expected check FAILED."""
    data, crash = run_verifier(bundle_path, fx, extra_args)
    if data is None:
        return False, f"HARNESS ERROR: verifier crashed: {crash}"
    verdict = data.get("verdict")
    status = data.get("checks", {}).get(expected_failed_check)
    if verdict == "FAILED" and status == "FAILED":
        return True, "OK"
    return False, (f"expected {expected_failed_check} to FAIL, got verdict={verdict}, check={status}; "
                   f"errors={data.get('errors')}")


def assert_baseline_passes(bundle_path, fx):
    data, crash = run_verifier(bundle_path, fx)
    if data is None or data.get("verdict") != "PASSED":
        print("[HARNESS BASELINE ERROR] Clean fixture did not PASS")
        print(json.dumps(data, indent=2) if data else crash)
        sys.exit(2)


def report(title, attacks):
    """Prints results; returns True when every vector was caught."""
    print("-" * 78)
    all_caught = True
    for name, caught, detail in attacks:
        print(f"  * {name:<62}: {'[CAUGHT]' if caught else '[BYPASSED]'}")
        if not caught:
            print(f"    -> {detail}")
            all_caught = False
    print("-" * 78)
    n = len(attacks)
    if all_caught:
        print(f"[SUCCESS] {n}/{n} {title} vectors detected and rejected for the expected reason.")
    else:
        print(f"[FAIL] {sum(1 for _, c, _ in attacks if not c)}/{n} {title} vectors bypassed.")
    print("=" * 78)
    return all_caught
