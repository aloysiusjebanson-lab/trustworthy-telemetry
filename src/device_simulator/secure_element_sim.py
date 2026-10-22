"""
Secure-Element & PKI Simulator (bundle format v1.3)

Simulates the three independent parties behind an evidence bundle:

  1. SimulatedManufacturer — a secure-element vendor PKI (root CA -> signer CA -> per-device
     X.509 certificate), mirroring the shape of Microchip ATECC608 TrustFLEX/TNG provisioning.
     Every certificate is labelled "SIMULATED ... (TEST ONLY)". In production the auditor pins
     the real vendor root instead, and the producer cannot mint device certificates under it.
  2. ProducerAuthority — the facility operator's root key: certifies which metrology
     instruments a device is wired to, and seals the bundle manifest.
  3. SimulatedSecureElement — the device key. The private key never enters the bundle.

Uses the OpenSSL CLI only (zero pip dependencies).
"""

import json
import os
import secrets
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "verifier")))
import crypto  # noqa: E402
import jcs  # noqa: E402

SIM_ORG = "SIMULATED Secure Element Manufacturer (TEST ONLY)"
GENESIS_PREV_HASH = "0" * 64

_EXTENSIONS = """
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[v3_device]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


def openssl(*args, input_bytes=None):
    res = subprocess.run(["openssl"] + list(args), input=input_bytes, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(f"openssl {args[0]} failed: {res.stderr.decode('utf-8', 'replace').strip()}")
    return res.stdout


def generate_p256_key(priv_path, pub_path=None):
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", priv_path)
    os.chmod(priv_path, 0o600)
    if pub_path:
        openssl("ec", "-in", priv_path, "-pubout", "-out", pub_path)


def sign_bytes(priv_path, data):
    return openssl("dgst", "-sha256", "-sign", priv_path, input_bytes=data).hex()


def write_json(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


class SimulatedManufacturer(object):
    def __init__(self, pki_dir):
        os.makedirs(pki_dir, exist_ok=True)
        self.dir = pki_dir
        self.root_key = os.path.join(pki_dir, "manufacturer_root_private_key.pem")
        self.root_cert = os.path.join(pki_dir, "manufacturer_root_ca.pem")
        self.signer_key = os.path.join(pki_dir, "manufacturer_signer_private_key.pem")
        self.signer_cert = os.path.join(pki_dir, "manufacturer_signer_ca.pem")
        self.ext_file = os.path.join(pki_dir, "x509_extensions.cnf")
        with open(self.ext_file, "w") as f:
            f.write(_EXTENSIONS)
        if not os.path.exists(self.root_cert):
            self._create_ca_hierarchy()

    def _create_ca_hierarchy(self):
        generate_p256_key(self.root_key)
        openssl("req", "-x509", "-new", "-key", self.root_key, "-sha256", "-days", "7300",
                "-subj", f"/O={SIM_ORG}/CN=SIMULATED Manufacturer Root CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-out", self.root_cert)
        generate_p256_key(self.signer_key)
        self._issue(self.signer_key, f"/O={SIM_ORG}/CN=SIMULATED Signer CA",
                    self.root_cert, self.root_key, "v3_ca", self.signer_cert)

    def _issue(self, subject_key, subject, ca_cert, ca_key, extensions, out_path):
        with tempfile.TemporaryDirectory() as tmp:
            csr = os.path.join(tmp, "req.csr")
            openssl("req", "-new", "-key", subject_key, "-subj", subject, "-out", csr)
            openssl("x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
                    "-set_serial", str(secrets.randbits(63)), "-days", "7300", "-sha256",
                    "-extfile", self.ext_file, "-extensions", extensions, "-out", out_path)

    def attest_device(self, se, out_dir):
        """Issues the secure element's X.509 device certificate (factory provisioning)."""
        os.makedirs(out_dir, exist_ok=True)
        leaf = os.path.join(out_dir, "se_device_cert.pem")
        self._issue(se.priv_path, f"/O={SIM_ORG}/CN=sn{se.serial}", self.signer_cert, self.signer_key,
                    "v3_device", leaf)
        with open(self.signer_cert, "rb") as src, open(os.path.join(out_dir, "se_signer_ca.pem"), "wb") as dst:
            dst.write(src.read())


class ProducerAuthority(object):
    def __init__(self, keys_dir):
        os.makedirs(keys_dir, exist_ok=True)
        self.priv_path = os.path.join(keys_dir, "producer_root_private_key.pem")
        self.pub_path = os.path.join(keys_dir, "producer_root_public_key.pem")
        if not os.path.exists(self.priv_path):
            generate_p256_key(self.priv_path, self.pub_path)

    def sign(self, data):
        return sign_bytes(self.priv_path, data)


class SimulatedSecureElement(object):
    def __init__(self, keys_dir, name="device"):
        os.makedirs(keys_dir, exist_ok=True)
        self.priv_path = os.path.join(keys_dir, f"{name}_private_key.pem")
        self.pub_path = os.path.join(keys_dir, f"{name}_public_key.pem")
        if not os.path.exists(self.priv_path):
            generate_p256_key(self.priv_path, self.pub_path)
        self.pub_der = crypto.public_key_der(self.pub_path)
        self.device_id = crypto.device_id_from_public_key(self.pub_der)
        self.serial = crypto.sha256_hex(self.pub_der)[:18].upper()

    def sign(self, data):
        return sign_bytes(self.priv_path, data)


def provision_device(bundle_root, profile, instruments, se, producer, manufacturer,
                     valid_from, valid_until, issued_by):
    """Writes device/public_key.pem, the manufacturer attestation chain and the
    producer-signed device certificate. Returns the device_id."""
    device_dir = os.path.join(bundle_root, "device")
    os.makedirs(device_dir, exist_ok=True)
    with open(se.pub_path, "rb") as src, open(os.path.join(device_dir, "public_key.pem"), "wb") as dst:
        dst.write(src.read())
    manufacturer.attest_device(se, os.path.join(device_dir, "attestation"))
    body = {
        "device_id": se.device_id,
        "profile": profile,
        "device_public_key_sha256": crypto.sha256_hex(se.pub_der),
        "secure_element": {"part": "ATECC608B (simulated)", "serial": se.serial},
        "instruments": instruments,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "issued_by": issued_by,
    }
    write_json(os.path.join(device_dir, "device_certificate.json"), {
        "body": body,
        "algorithm": crypto.SIGNATURE_ALGORITHM,
        "signature": producer.sign(jcs.canonicalize(body)),
    })
    return se.device_id


def write_observation_chain(bundle_root, se, intervals, first_sequence=1, genesis=GENESIS_PREV_HASH):
    """intervals: list of (timestamp_start, timestamp_end, payload). Signs each record inside
    the (simulated) secure element and links it to its predecessor. Returns the records."""
    obs_dir = os.path.join(bundle_root, "observations")
    os.makedirs(obs_dir, exist_ok=True)
    records, prev = [], genesis
    with open(os.path.join(obs_dir, "observations.ndjson"), "w", encoding="utf-8") as f:
        for i, (t_start, t_end, payload) in enumerate(intervals):
            rec = {"device_id": se.device_id, "sequence": first_sequence + i, "prev_hash": prev,
                   "timestamp_start": t_start, "timestamp_end": t_end, "payload": payload}
            canonical = jcs.canonicalize(rec)
            env = {"record": rec, "algorithm": crypto.SIGNATURE_ALGORITHM, "signature": se.sign(canonical)}
            f.write(json.dumps(env, ensure_ascii=False) + "\n")
            records.append(rec)
            prev = crypto.sha256_hex(canonical)
    return records
