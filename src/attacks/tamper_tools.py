#!/usr/bin/env python3
"""
Adversary toolkit for the attack suites (bundle format v1.3).

Outsider tools edit files without any key. Insider tools model the facility operator, who
holds the producer root key and physically controls the gateway: the secure element will
sign whatever its host asks, so an insider can re-sign records and re-seal the bundle.
Insider attacks must therefore be caught by attestation, physics, lineage or mandates.
"""

import json
import os
import shutil
import sys

from fixtures import PROJECT_ROOT  # noqa: F401  (sets sys.path for verifier/simulator/pipeline)
import crypto  # noqa: E402
import jcs  # noqa: E402
from biochar_claim_generator import build_biochar_claim_bundle  # noqa: E402
from bundle_builder import seal_bundle  # noqa: E402
from claim_generator import generate_claim_bundle  # noqa: E402
from secure_element_sim import ProducerAuthority, sign_bytes  # noqa: E402


def clone(fx, name):
    dst = os.path.join(fx["workdir"], name)
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(fx["bundle"], dst)
    return dst


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path, doc):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)


def obs_path(bundle):
    return os.path.join(bundle, "observations", "observations.ndjson")


def read_lines(bundle):
    with open(obs_path(bundle), "r", encoding="utf-8") as f:
        return [ln for ln in f.read().split("\n") if ln.strip()]


def write_lines(bundle, lines):
    with open(obs_path(bundle), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def read_envelopes(bundle):
    return [json.loads(ln) for ln in read_lines(bundle)]


def write_envelopes(bundle, envs):
    write_lines(bundle, [json.dumps(e, ensure_ascii=False) for e in envs])


def sign_envelope(record, device_priv):
    """Insider: asks the gateway's secure element to sign an arbitrary record."""
    return {"record": record, "algorithm": crypto.SIGNATURE_ALGORITHM,
            "signature": sign_bytes(device_priv, jcs.canonicalize(record))}


def link_hash(record):
    return crypto.sha256_hex(jcs.canonicalize(record))


def resign_chain(bundle, records, device_priv, genesis="0" * 64, renumber=False):
    """Insider: re-signs arbitrary records and relinks them into a valid chain."""
    envs, prev = [], genesis
    first_seq = records[0]["sequence"] if records else 1
    for i, rec in enumerate(records):
        rec = dict(rec, prev_hash=prev)
        if renumber:
            rec["sequence"] = first_seq + i
        envs.append(sign_envelope(rec, device_priv))
        prev = link_hash(rec)
    write_envelopes(bundle, envs)


def reissue_device_certificate(bundle, fx, mutate_body):
    """Insider: edits the device certificate body and re-signs it with the producer root key."""
    path = os.path.join(bundle, "device", "device_certificate.json")
    cert = read_json(path)
    mutate_body(cert["body"])
    cert["signature"] = sign_bytes(fx["producer_priv"], jcs.canonicalize(cert["body"]))
    write_json(path, cert)


def repackage(bundle, fx, **kwargs):
    """Insider: regenerates claim, recipes and lineage from the (tampered) records and re-seals."""
    if fx["profile"] == "energy_submetering":
        generate_claim_bundle(bundle, keys_dir=fx["keys_dir"], **kwargs)
    else:
        build_biochar_claim_bundle(bundle, keys_dir=fx["keys_dir"], **kwargs)


def reseal_only(bundle, fx, profile=None, claim_id=None):
    """Insider: re-hashes every file and re-seals the manifest without touching anything else.
    Unlike the honest builder, it does not refuse private-key files."""
    manifest = read_json(os.path.join(bundle, "manifest.json"))
    files = {}
    for root, _, names in os.walk(bundle):
        for name in sorted(names):
            rel = os.path.relpath(os.path.join(root, name), bundle).replace(os.sep, "/")
            if rel != "manifest.json":
                files[rel] = crypto.sha256_file(os.path.join(root, name))
    body = {"manifest_version": manifest["manifest_version"],
            "profile": profile or manifest["profile"],
            "claim_id": claim_id or manifest["claim_id"],
            "files": files}
    body["seal"] = {"algorithm": crypto.SIGNATURE_ALGORITHM,
                    "signature": sign_bytes(fx["producer_priv"], jcs.canonicalize(body))}
    write_json(os.path.join(bundle, "manifest.json"), body)


def producer(fx):
    return ProducerAuthority(fx["keys_dir"])


def honest_seal(bundle, fx, claim_id):
    seal_bundle(bundle, fx["profile"], claim_id, producer(fx))
