"""RFC 8785 conformance tests for src/verifier/jcs.py (run: python3 -m unittest discover tests)."""
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src", "verifier"))
import jcs  # noqa: E402

VECTORS = os.path.join(ROOT, "04_experiments", "conformance", "jcs_vectors.json")


class JcsConformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS, "r", encoding="utf-8") as f:
            cls.doc = json.load(f)

    def test_vectors(self):
        for v in self.doc["vectors"]:
            with self.subTest(v["id"]):
                self.assertEqual(jcs.canonicalize(jcs.loads(v["input"])), v["expected"].encode("utf-8"))

    def test_error_vectors(self):
        for v in self.doc["error_vectors"]:
            with self.subTest(v["id"]):
                with self.assertRaises(ValueError):
                    jcs.canonicalize(jcs.loads(v["input"]))

    def test_canonicalize_rejects_python_floats(self):
        with self.assertRaises(jcs.CanonicalizationError):
            jcs.canonicalize({"a": 0.275})

    def test_bool_is_not_integer(self):
        self.assertEqual(jcs.canonicalize({"t": True, "n": 1}), b'{"n":1,"t":true}')


if __name__ == "__main__":
    unittest.main()
