#!/usr/bin/env python3
"""
Zero-Trust Test Harness (v1.3)
Asserts that test vectors fail for the exact expected reason,
verifies that baselines pass, and ensures verifier crashes are never counted as passes.
"""

import os
import sys
import json
import subprocess

def verify_and_check(bundle_path, root_key, expected_failed_check, extra_args=None, registry=None):
    """
    Runs verify_bundle.py on bundle_path using root_key.
    Returns (caught: bool, detail: str).
    caught is True ONLY if verdict == "FAILED" and checks[expected_failed_check] == "FAILED".
    """
    cmd = [
        sys.executable, "src/verifier/verify_bundle.py", bundle_path,
        "--company-key", root_key, "--json"
    ]
    if registry:
        cmd.extend(["--trusted-registry", registry])
    if extra_args:
        cmd.extend(extra_args)

    res = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(res.stdout)
    except Exception:
        err_tail = res.stderr[-300:] if res.stderr else res.stdout[-300:]
        return (False, f"HARNESS ERROR: verifier crashed: {err_tail}")

    verdict = data.get("verdict")
    status = data.get("checks", {}).get(expected_failed_check)
    if verdict == "FAILED" and status == "FAILED":
        return (True, "OK")
    return (False, f"expected {expected_failed_check} to FAIL, got verdict={verdict}, check={status}")

def assert_baseline_passes(bundle_path, root_key, registry=None):
    """
    Runs verifier on the clean fixture; if verdict != PASSED, prints error and exits with code 2.
    """
    cmd = [
        sys.executable, "src/verifier/verify_bundle.py", bundle_path,
        "--company-key", root_key, "--json"
    ]
    if registry:
        cmd.extend(["--trusted-registry", registry])
    res = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(res.stdout)
        if data.get("verdict") != "PASSED":
            print(f"[HARNESS BASELINE ERROR] Expected PASSED, got verdict={data.get('verdict')}")
            print(f"Errors: {json.dumps(data.get('audit_errors', []), indent=2)}")
            if res.stderr:
                print(f"Stderr: {res.stderr}")
            sys.exit(2)
    except Exception as e:
        print(f"[HARNESS BASELINE CRASH] Verifier failed to produce JSON: {e}")
        print(f"Stdout: {res.stdout}")
        print(f"Stderr: {res.stderr}")
        sys.exit(2)
