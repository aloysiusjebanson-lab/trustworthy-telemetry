"""Re-verifies the frozen golden conformance vectors (run: python3 -m unittest discover tests)."""
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VECTORS = ["golden_test_vector", "golden_test_vector_biochar"]


class GoldenVectors(unittest.TestCase):
    def test_frozen_vectors_reproduce_expected_verdict(self):
        for name in VECTORS:
            with self.subTest(name):
                d = os.path.join(ROOT, "04_experiments", name)
                with open(os.path.join(d, "expected_audit_verdict.json")) as f:
                    expected = json.load(f)
                cmd = [sys.executable, os.path.join(ROOT, "src", "verifier", "verify_bundle.py"),
                       os.path.join(d, "bundle"), "--json", "--profile", expected["profile"],
                       "--producer-key", os.path.join(d, "trust", "producer_root_public_key.pem"),
                       "--manufacturer-ca", os.path.join(d, "trust", "manufacturer_root_ca.pem"),
                       "--trusted-registry", os.path.join(d, "trust", "registry.json")]
                report = json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
                self.assertEqual(report["verdict"], expected["verdict"], report["errors"])
                self.assertEqual(report["checks"], expected["checks"])
                for k, v in expected["findings"].items():
                    self.assertEqual(report["findings"][k], v, k)

    def test_no_private_keys_in_vectors(self):
        for name in VECTORS:
            for root, _, files in os.walk(os.path.join(ROOT, "04_experiments", name)):
                for f in files:
                    self.assertNotIn("private", f.lower())
                    if f.endswith(".pem"):
                        with open(os.path.join(root, f), "rb") as fh:
                            self.assertNotIn(b"PRIVATE KEY", fh.read())


if __name__ == "__main__":
    unittest.main()
