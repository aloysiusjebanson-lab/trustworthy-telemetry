"""
Cryptographic primitives for the offline verifier, built on the POSIX OpenSSL CLI
(zero pip dependencies): ECDSA P-256 signature checks, X.509 chain validation
against an auditor-pinned manufacturer CA, and public-key fingerprinting.
"""

import base64
import binascii
import hashlib
import os
import shutil
import subprocess
import tempfile

OPENSSL_BIN = shutil.which("openssl")
if not OPENSSL_BIN:
    raise RuntimeError("OpenSSL CLI binary not found in PATH")

SIGNATURE_ALGORITHM = "ECDSA_P256_SHA256"


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _run(args, input_bytes=None):
    return subprocess.run([OPENSSL_BIN] + args, input=input_bytes, capture_output=True)


def verify_signature(pubkey_path, data_bytes, sig_hex):
    """Verifies a hex-encoded DER ECDSA signature over data_bytes. Returns (ok, message)."""
    if not isinstance(sig_hex, str):
        return False, "Signature missing or not a string"
    try:
        sig_bytes = binascii.unhexlify(sig_hex)
    except (binascii.Error, ValueError) as e:
        return False, f"Invalid hex in signature: {e}"

    fd, sig_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(sig_bytes)
        res = _run(["dgst", "-sha256", "-verify", pubkey_path, "-signature", sig_path], data_bytes)
        out = res.stdout.decode("utf-8", "replace")
        if res.returncode == 0 and "Verified OK" in out:
            return True, "Valid"
        return False, (res.stderr.decode("utf-8", "replace").strip() or out.strip())
    finally:
        os.remove(sig_path)


def pem_to_der(pem_text):
    """Decodes the base64 body of a single PEM block."""
    body = "".join(line.strip() for line in pem_text.strip().splitlines() if not line.startswith("-----"))
    return base64.b64decode(body, validate=True)


def public_key_der(pubkey_pem_path):
    """Returns the DER SubjectPublicKeyInfo of a PEM public key, normalised by OpenSSL."""
    res = _run(["pkey", "-pubin", "-in", pubkey_pem_path, "-outform", "DER"])
    if res.returncode != 0:
        raise ValueError(f"Unreadable public key {pubkey_pem_path}: {res.stderr.decode('utf-8', 'replace').strip()}")
    return res.stdout


def is_p256_public_key(pubkey_pem_path):
    res = _run(["pkey", "-pubin", "-in", pubkey_pem_path, "-noout", "-text"])
    text = res.stdout.decode("utf-8", "replace")
    return res.returncode == 0 and ("prime256v1" in text or "P-256" in text)


def device_id_from_public_key(pubkey_der):
    """Device identifier = 'dev-' + first 16 hex chars of SHA-256(DER SubjectPublicKeyInfo)."""
    return "dev-" + sha256_hex(pubkey_der)[:16]


def verify_x509_chain(leaf_pem_path, intermediate_pem_path, trusted_root_pem_path):
    """Validates leaf -> intermediate -> trusted root with OpenSSL. The root is supplied
    by the auditor (pinned out-of-band); nothing in the bundle can act as a trust anchor."""
    args = ["verify", "-x509_strict", "-CAfile", trusted_root_pem_path]
    if intermediate_pem_path:
        args += ["-untrusted", intermediate_pem_path]
    args.append(leaf_pem_path)
    res = _run(args)
    out = res.stdout.decode("utf-8", "replace").strip()
    if res.returncode == 0 and out.endswith("OK"):
        return True, "Chain valid"
    return False, (res.stderr.decode("utf-8", "replace").strip() or out)


def certificate_public_key_der(cert_pem_path):
    """Extracts the DER SubjectPublicKeyInfo from an X.509 certificate."""
    res = _run(["x509", "-in", cert_pem_path, "-noout", "-pubkey"])
    if res.returncode != 0:
        raise ValueError(f"Unreadable certificate {cert_pem_path}: {res.stderr.decode('utf-8', 'replace').strip()}")
    return pem_to_der(res.stdout.decode("utf-8"))


def certificate_subject(cert_pem_path):
    res = _run(["x509", "-in", cert_pem_path, "-noout", "-subject", "-nameopt", "RFC2253"])
    return res.stdout.decode("utf-8", "replace").strip().replace("subject=", "", 1)
