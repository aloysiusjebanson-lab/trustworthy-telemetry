"""
Universal Verifier Core (bundle format v1.3).

Runs the fail-closed verification state machine defined in
02_protocol/evidence_bundle_spec.md. The core implements every domain-agnostic
check once; a profile driver (profiles/) contributes only data (instrument
requirements, pinned reference types, methodology parameters) and three hooks.

  Check 0  : Profile binding — auditor-selected profile == profile declared in the bundle.
  Check 1  : Manifest integrity, path safety, private-key exclusion, producer seal.
  Check 2  : Device certificate, manufacturer attestation chain, metrology instruments, revocation.
  Check 3  : Per-record ECDSA P-256 signatures, certificate window, calibration expiry.
  Check 4  : prev_hash chain, sequence contiguity, timestamp progression, maximum record gap.
  Check 5  : [profile hook] process continuity invariants.
  Check 6  : Claim period boundaries, auditor mandates, cross-claim ledger.
  Check 7  : W3C PROV lineage graph: completeness, hashes, acyclicity, derivation of the claim.
  Check 8  : [profile hook] pinned authority references.
  Check 9  : [profile hook] conservation invariants & deterministic integer recomputation.
  Check 10 : Zero-tolerance reconciliation of declared metrics against recomputed metrics.

Any malformed input yields a FAILED verdict, never an unhandled crash.
"""

import json
import os
import re
import time

import crypto
import jcs

BUNDLE_FORMAT_VERSION = "1.3"
GENESIS_PREV_HASH = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")

CHECK_KEYS = [
    "check1_manifest_and_seal",
    "check2_device_cert_and_attestation",
    "check3_observation_signatures",
    "check4_hash_chain_continuity",
    "check5_process_continuity",
    "check6_claim_boundary_bounds",
    "check7_transformations_and_provenance",
    "check8_pinned_references",
    "check9_independent_recomputation",
    "check10_numeric_reconciliation",
]

CHECK_TITLES = {
    "check1_manifest_and_seal": "Manifest Integrity & Producer Seal",
    "check2_device_cert_and_attestation": "Device Cert & Manufacturer Attestation",
    "check3_observation_signatures": "Record Signatures & Calibration Windows",
    "check4_hash_chain_continuity": "Hash-Chain, Sequence & Gap Continuity",
    "check5_process_continuity": "[Profile] Process Continuity",
    "check6_claim_boundary_bounds": "Claim Boundaries, Mandates & Ledger",
    "check7_transformations_and_provenance": "W3C PROV Lineage Graph",
    "check8_pinned_references": "[Profile] Pinned Authority References",
    "check9_independent_recomputation": "[Profile] Conservation & Recomputation",
    "check10_numeric_reconciliation": "Zero-Tolerance Claim Reconciliation",
}

FORBIDDEN_KEY_SUBSTRINGS = ("private", ".key")
LINEAGE_DIRS = ("observations/", "reference_data/", "transformations/")
PROV_PATH = "tte:path"
PROV_SHA = "tte:sha256"


class AuditOptions(object):
    def __init__(self, producer_key, manufacturer_ca=None, registry=None, expected_count=None,
                 prev_terminal_hash=None, revoked=None, claim_ledger=None, record_ledger=False,
                 period_start=None, period_end=None):
        self.producer_key = producer_key
        self.manufacturer_ca = manufacturer_ca
        self.registry = registry
        self.expected_count = expected_count
        self.prev_terminal_hash = prev_terminal_hash
        self.revoked = revoked
        self.claim_ledger = claim_ledger
        self.record_ledger = record_ledger
        self.period_start = period_start
        self.period_end = period_end


class Audit(object):
    """Mutable state shared by the core checks and the profile hooks."""

    def __init__(self, bundle_dir, profile, options):
        self.bundle_dir = bundle_dir
        self.profile = profile
        self.options = options
        self.errors = []
        self.warnings = []
        self.manifest = None
        self.manifest_files = {}
        self.registry = None
        self.params = {}
        self.device_id = None
        self.device_pubkey_path = os.path.join(bundle_dir, "device", "public_key.pem")
        self.cert_valid_from = None
        self.cert_valid_until = None
        self.instruments = []
        self.calibration_until = None
        self.attestation_root_subject = None
        self.records = []
        self.terminal_hash = None
        self.claim = None
        self.references = {}
        self.metrics = None

    def path(self, rel):
        return os.path.join(self.bundle_dir, rel)

    def fail(self, check, msg):
        self.errors.append(f"[{check}] {msg}")
        return False

    def load_json(self, rel):
        return jcs.load_file(self.path(rel))

    def pin_reference(self, rel_path, expected_type, check):
        """Core helper for profile Check 8 hooks: the file must be manifested, its SHA-256
        must be pinned in the auditor's registry, and the pinned dataset type must match."""
        if rel_path not in self.manifest_files:
            self.fail(check, f"Required reference file not manifested: {rel_path}")
            return None, None
        if self.registry is None:
            self.fail(check, "No auditor registry loaded")
            return None, None
        digest = crypto.sha256_file(self.path(rel_path))
        entry = self.registry.get("datasets", {}).get(digest)
        if entry is None:
            self.fail(check, f"{rel_path} (sha256 {digest[:16]}...) is NOT pinned in the auditor registry")
            return None, None
        if entry.get("type") != expected_type:
            self.fail(check, f"{rel_path} is pinned as type '{entry.get('type')}', expected '{expected_type}'")
            return None, None
        return self.load_json(rel_path), entry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _safe_rel_path(rel):
    if not isinstance(rel, str) or not rel:
        return False
    if rel.startswith("/") or "\\" in rel or "\x00" in rel:
        return False
    parts = rel.split("/")
    return all(p not in ("", ".", "..") for p in parts)


def _parse_revocations(revoked):
    revoked_set = set()
    if not revoked:
        return revoked_set
    if os.path.exists(revoked):
        with open(revoked, "r") as f:
            for line in f:
                item = line.strip()
                if item and not item.startswith("#"):
                    revoked_set.add(item)
    else:
        revoked_set.update(item.strip() for item in revoked.split(",") if item.strip())
    return revoked_set


def record_hash(record):
    """Chain link: SHA-256 over the canonical signed record (excludes the malleable signature)."""
    return crypto.sha256_hex(jcs.canonicalize(record))


def manifest_seal_payload(manifest):
    return jcs.canonicalize({
        "manifest_version": manifest.get("manifest_version"),
        "profile": manifest.get("profile"),
        "claim_id": manifest.get("claim_id"),
        "files": manifest.get("files"),
    })


def load_claim_ledger(ledger_path):
    if not ledger_path or not os.path.exists(ledger_path):
        return {"ledger_version": "1.3", "entries": []}
    data = jcs.load_file(ledger_path)
    if not isinstance(data.get("entries"), list):
        raise ValueError("Claim ledger has no 'entries' list")
    return data


def record_to_claim_ledger(ledger_path, entry):
    ledger = load_claim_ledger(ledger_path)
    for e in ledger["entries"]:
        if e.get("claim_id") == entry["claim_id"] and e.get("terminal_hash") == entry["terminal_hash"]:
            return
    ledger["entries"].append(entry)
    tmp_path = ledger_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(ledger, f, indent=2)
    os.replace(tmp_path, ledger_path)


# ---------------------------------------------------------------------------
# Check 0: Profile binding
# ---------------------------------------------------------------------------

def check0_profile_binding(bundle_dir, profile_id):
    """Returns None if the bundle declares exactly the auditor-selected profile, else an error."""
    try:
        declared_claim = jcs.load_file(os.path.join(bundle_dir, "claim.json")).get("profile")
        declared_manifest = jcs.load_file(os.path.join(bundle_dir, "manifest.json")).get("profile")
    except Exception as e:
        return f"Cannot read declared profile from bundle: {e}"
    if declared_claim != profile_id:
        return f"Profile mismatch: auditor selected '{profile_id}' but claim.json declares '{declared_claim}'"
    if declared_manifest != profile_id:
        return f"Profile mismatch: auditor selected '{profile_id}' but manifest.json declares '{declared_manifest}'"
    return None


# ---------------------------------------------------------------------------
# Check 1: Manifest integrity & producer seal
# ---------------------------------------------------------------------------

def check1_manifest_and_seal(a):
    c = "check1"
    ok = True
    if not os.path.exists(a.path("manifest.json")):
        return a.fail(c, "Missing manifest.json")
    m = a.load_json("manifest.json")
    a.manifest = m
    if m.get("manifest_version") != BUNDLE_FORMAT_VERSION:
        ok = a.fail(c, f"Unsupported manifest_version {m.get('manifest_version')!r} (expected {BUNDLE_FORMAT_VERSION})")
    files = m.get("files")
    if not isinstance(files, dict) or not files:
        return a.fail(c, "Manifest 'files' must be a non-empty object")

    for rel, digest in files.items():
        if not _safe_rel_path(rel) or rel == "manifest.json":
            ok = a.fail(c, f"Security: unsafe or reserved path in manifest: {rel!r}")
            continue
        if not isinstance(digest, str) or not HEX64.match(digest):
            ok = a.fail(c, f"Malformed SHA-256 for {rel}")
            continue
        full = a.path(rel)
        if os.path.islink(full) or not os.path.isfile(full):
            ok = a.fail(c, f"Manifest file missing or not a regular file: {rel}")
            continue
        if crypto.sha256_file(full) != digest:
            ok = a.fail(c, f"Hash mismatch for {rel}")
        else:
            a.manifest_files[rel] = digest

    bundle_real = os.path.realpath(a.bundle_dir)
    for root, dirs, fs in os.walk(a.bundle_dir):
        for name in dirs + fs:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, a.bundle_dir).replace(os.sep, "/")
            if os.path.islink(full) or not os.path.realpath(full).startswith(bundle_real + os.sep):
                ok = a.fail(c, f"Security: symlink or out-of-bundle path: {rel}")
            if name in fs and rel != "manifest.json" and rel not in files:
                ok = a.fail(c, f"Security: unmanifested file in bundle: {rel}")
            if name in fs:
                lname = name.lower()
                is_key = any(s in lname for s in FORBIDDEN_KEY_SUBSTRINGS)
                if not is_key and lname.endswith(".pem"):
                    with open(full, "rb") as pf:
                        is_key = b"PRIVATE KEY" in pf.read(65536)
                if is_key:
                    ok = a.fail(c, f"Security: private key material in bundle: {rel}")

    seal = m.get("seal")
    if not isinstance(seal, dict) or seal.get("algorithm") != crypto.SIGNATURE_ALGORITHM:
        return a.fail(c, "Missing seal or untrusted seal algorithm")
    v_ok, v_msg = crypto.verify_signature(a.options.producer_key, manifest_seal_payload(m), seal.get("signature"))
    if not v_ok:
        ok = a.fail(c, f"Producer seal signature invalid: {v_msg}")
    return ok


# ---------------------------------------------------------------------------
# Check 2: Device certificate, manufacturer attestation, instruments
# ---------------------------------------------------------------------------

def check2_device(a):
    c = "check2"
    ok = True
    if not os.path.isfile(a.device_pubkey_path):
        return a.fail(c, "Missing device/public_key.pem")
    if not crypto.is_p256_public_key(a.device_pubkey_path):
        return a.fail(c, "Device public key is not an EC P-256 key")
    device_der = crypto.public_key_der(a.device_pubkey_path)
    derived_id = crypto.device_id_from_public_key(device_der)

    # 2a. Manufacturer attestation: X.509 chain to the auditor-pinned manufacturer root.
    leaf = a.path("device/attestation/se_device_cert.pem")
    signer = a.path("device/attestation/se_signer_ca.pem")
    if not a.options.manufacturer_ca or not os.path.isfile(a.options.manufacturer_ca):
        ok = a.fail(c, "No auditor-pinned manufacturer CA supplied (--manufacturer-ca); hardware key origin unverifiable")
    elif not os.path.isfile(leaf) or not os.path.isfile(signer):
        ok = a.fail(c, "Missing secure-element attestation chain (device/attestation/se_device_cert.pem, se_signer_ca.pem)")
    else:
        chain_ok, chain_msg = crypto.verify_x509_chain(leaf, signer, a.options.manufacturer_ca)
        if not chain_ok:
            ok = a.fail(c, f"Secure-element certificate does not chain to the pinned manufacturer CA: {chain_msg}")
        elif crypto.certificate_public_key_der(leaf) != device_der:
            ok = a.fail(c, "Attested secure-element key does not match device/public_key.pem")
        else:
            a.attestation_root_subject = crypto.certificate_subject(a.options.manufacturer_ca)

    # 2b. Producer-issued device certificate binding the attested key to instruments.
    cert_rel = "device/device_certificate.json"
    if not os.path.isfile(a.path(cert_rel)):
        return a.fail(c, "Missing device/device_certificate.json")
    cert = a.load_json(cert_rel)
    body = cert.get("body")
    if not isinstance(body, dict):
        return a.fail(c, "Device certificate has no body")
    if cert.get("algorithm") != crypto.SIGNATURE_ALGORITHM:
        ok = a.fail(c, f"Untrusted certificate algorithm: {cert.get('algorithm')}")
    s_ok, s_msg = crypto.verify_signature(a.options.producer_key, jcs.canonicalize(body), cert.get("signature"))
    if not s_ok:
        ok = a.fail(c, f"Producer signature on device certificate invalid: {s_msg}")
    if body.get("profile") != a.profile.profile_id:
        ok = a.fail(c, f"Device certificate issued for profile {body.get('profile')!r}")
    if body.get("device_public_key_sha256") != crypto.sha256_hex(device_der):
        ok = a.fail(c, "Device certificate is not bound to device/public_key.pem")
    if body.get("device_id") != derived_id:
        ok = a.fail(c, f"Certified device_id {body.get('device_id')!r} != id derived from attested key {derived_id}")
    else:
        a.device_id = derived_id

    vf, vu = body.get("valid_from"), body.get("valid_until")
    if _is_int(vf) and _is_int(vu) and vf < vu:
        a.cert_valid_from, a.cert_valid_until = vf, vu
    else:
        ok = a.fail(c, "Invalid or missing certificate validity window")

    # 2c. Legal-metrology instruments required by the profile.
    instruments = body.get("instruments")
    if not isinstance(instruments, list) or not instruments:
        ok = a.fail(c, "Device certificate lists no metrology instruments")
        instruments = []
    roles_seen = {}
    cal_untils = []
    for inst in instruments:
        role = inst.get("role") if isinstance(inst, dict) else None
        req = a.profile.instrument_requirements.get(role)
        if req is None:
            ok = a.fail(c, f"Instrument with unknown role {role!r} for this profile")
            continue
        roles_seen[role] = roles_seen.get(role, 0) + 1
        if inst.get("standard") not in req["standards"]:
            ok = a.fail(c, f"Instrument '{role}' standard {inst.get('standard')!r} not accepted ({sorted(req['standards'])})")
        if inst.get("accuracy_class") not in req["accuracy_classes"]:
            ok = a.fail(c, f"Instrument '{role}' accuracy class {inst.get('accuracy_class')!r} not accepted")
        if not isinstance(inst.get("calibration_cert_sha256"), str) or not HEX64.match(inst["calibration_cert_sha256"]):
            ok = a.fail(c, f"Instrument '{role}' has no calibration certificate digest")
        if _is_int(inst.get("calibration_valid_until")):
            cal_untils.append(inst["calibration_valid_until"])
        else:
            ok = a.fail(c, f"Instrument '{role}' calibration_valid_until must be an integer")
    for role in a.profile.instrument_requirements:
        if roles_seen.get(role, 0) != 1:
            ok = a.fail(c, f"Profile requires exactly one '{role}' instrument, found {roles_seen.get(role, 0)}")
    a.instruments = instruments
    a.calibration_until = min(cal_untils) if cal_untils else None

    if derived_id in _parse_revocations(a.options.revoked):
        ok = a.fail(c, f"Security: device {derived_id} is on the revocation list")
    return ok


# ---------------------------------------------------------------------------
# Check 3: Record signatures, certificate window, calibration
# ---------------------------------------------------------------------------

RECORD_KEYS = {"device_id", "sequence", "prev_hash", "timestamp_start", "timestamp_end", "payload"}
ENVELOPE_KEYS = {"record", "algorithm", "signature"}


def check3_signatures(a):
    c = "check3"
    obs_rel = "observations/observations.ndjson"
    if not os.path.isfile(a.path(obs_rel)):
        return a.fail(c, "Missing observations/observations.ndjson")
    if not os.path.isfile(a.device_pubkey_path):
        return a.fail(c, "Missing device public key")
    ok = True
    with open(a.path(obs_rel), "r", encoding="utf-8") as f:
        lines = [ln for ln in f.read().split("\n") if ln.strip()]
    if not lines:
        return a.fail(c, "Observation stream is empty")
    for n, line in enumerate(lines, 1):
        env = jcs.loads(line)
        if not isinstance(env, dict) or set(env) != ENVELOPE_KEYS:
            ok = a.fail(c, f"Record #{n}: envelope must contain exactly {sorted(ENVELOPE_KEYS)}")
            continue
        rec = env["record"]
        if not isinstance(rec, dict) or set(rec) != RECORD_KEYS:
            ok = a.fail(c, f"Record #{n}: record must contain exactly {sorted(RECORD_KEYS)}")
            continue
        if not all(_is_int(rec[k]) for k in ("sequence", "timestamp_start", "timestamp_end")) or not isinstance(rec["payload"], dict):
            ok = a.fail(c, f"Record #{n}: sequence/timestamps must be integers and payload an object")
            continue
        a.records.append(rec)
        if env["algorithm"] != crypto.SIGNATURE_ALGORITHM:
            ok = a.fail(c, f"Record #{n}: untrusted algorithm {env['algorithm']!r}")
        if a.device_id is None or rec["device_id"] != a.device_id:
            ok = a.fail(c, f"Record #{n}: device_id {rec['device_id']!r} does not match the certified device")
        s_ok, s_msg = crypto.verify_signature(a.device_pubkey_path, jcs.canonicalize(rec), env["signature"])
        if not s_ok:
            ok = a.fail(c, f"Record #{n}: signature invalid: {s_msg}")
        if a.cert_valid_from is None or rec["timestamp_start"] < a.cert_valid_from or rec["timestamp_end"] > a.cert_valid_until:
            ok = a.fail(c, f"Record #{n}: outside device certificate validity window")
        if a.calibration_until is None or rec["timestamp_end"] > a.calibration_until:
            ok = a.fail(c, f"Record #{n}: instrument calibration expired before record end")
    return ok


# ---------------------------------------------------------------------------
# Check 4: Hash chain, sequence, timestamps, gaps
# ---------------------------------------------------------------------------

def check4_chain(a):
    c = "check4"
    if not a.records:
        return a.fail(c, "No valid records to chain")
    ok = True
    expected_prev = a.options.prev_terminal_hash or GENESIS_PREV_HASH
    max_gap = a.params.get("max_record_gap_s")
    if not _is_int(max_gap) or max_gap < 0:
        ok = a.fail(c, "Registry methodology parameter max_record_gap_s missing or invalid")
        max_gap = None
    first_seq = a.records[0]["sequence"]
    prev_end = None
    for i, rec in enumerate(a.records):
        if rec["prev_hash"] != expected_prev:
            ok = a.fail(c, f"Hash-chain broken at sequence {rec['sequence']}")
        expected_prev = record_hash(rec)
        if rec["sequence"] != first_seq + i:
            ok = a.fail(c, f"Sequence gap/duplicate at index {i}: expected {first_seq + i}, got {rec['sequence']}")
        if rec["timestamp_start"] >= rec["timestamp_end"]:
            ok = a.fail(c, f"Sequence {rec['sequence']}: timestamp_start >= timestamp_end")
        if prev_end is not None:
            if rec["timestamp_start"] < prev_end:
                ok = a.fail(c, f"Sequence {rec['sequence']}: overlaps previous record")
            elif max_gap is not None and rec["timestamp_start"] - prev_end > max_gap:
                ok = a.fail(c, f"Sequence {rec['sequence']}: {rec['timestamp_start'] - prev_end}s gap exceeds max_record_gap_s={max_gap} (withheld data)")
        prev_end = rec["timestamp_end"]
    a.terminal_hash = expected_prev
    return ok


# ---------------------------------------------------------------------------
# Check 6: Claim boundaries, auditor mandates, ledger
# ---------------------------------------------------------------------------

def check6_claim(a):
    c = "check6"
    if not os.path.isfile(a.path("claim.json")):
        return a.fail(c, "Missing claim.json")
    claim = a.load_json("claim.json")
    a.claim = claim
    ok = True
    if a.manifest is None or claim.get("claim_id") != a.manifest.get("claim_id"):
        ok = a.fail(c, "claim_id does not match the sealed manifest")
    if a.device_id is None or claim.get("device_id") != a.device_id:
        ok = a.fail(c, "Claim device_id does not match the certified device")
    if not a.records:
        return a.fail(c, "No records to bound the claim")
    period = claim.get("period")
    if not isinstance(period, dict):
        return a.fail(c, "Claim has no period object")
    actual = {
        "first_sequence": a.records[0]["sequence"],
        "last_sequence": a.records[-1]["sequence"],
        "record_count": len(a.records),
        "start_timestamp": a.records[0]["timestamp_start"],
        "end_timestamp": a.records[-1]["timestamp_end"],
        "genesis_prev_hash": a.records[0]["prev_hash"],
        "terminal_hash": a.terminal_hash,
    }
    for k, v in actual.items():
        if period.get(k) != v:
            ok = a.fail(c, f"Claim period.{k} = {period.get(k)!r} but evidence shows {v!r}")
    extra = set(period) - set(actual)
    if extra:
        ok = a.fail(c, f"Claim period has unverifiable fields: {sorted(extra)}")

    o = a.options
    max_gap = a.params.get("max_record_gap_s", 0) if _is_int(a.params.get("max_record_gap_s")) else 0
    if o.expected_count is not None and len(a.records) != o.expected_count:
        ok = a.fail(c, f"Audit mandate: expected {o.expected_count} records, bundle has {len(a.records)}")
    if o.period_start is not None and actual["start_timestamp"] - o.period_start > max_gap:
        ok = a.fail(c, f"Audit mandate: first record starts {actual['start_timestamp'] - o.period_start}s after mandated period start (head truncation)")
    if o.period_end is not None and o.period_end - actual["end_timestamp"] > max_gap:
        ok = a.fail(c, f"Audit mandate: last record ends {o.period_end - actual['end_timestamp']}s before mandated period end (tail truncation)")

    if o.claim_ledger is not None:
        ledger = load_claim_ledger(o.claim_ledger)
        cur_id = claim.get("claim_id")
        cur_seqs = set(f"{a.device_id}:{r['sequence']}" for r in a.records)
        for e in ledger["entries"]:
            if e.get("claim_id") == cur_id:
                if e.get("terminal_hash") != a.terminal_hash:
                    ok = a.fail(c, f"Double counting: claim_id {cur_id} already recorded with different evidence")
                continue
            if e.get("terminal_hash") == a.terminal_hash:
                ok = a.fail(c, f"Double counting: evidence chain already claimed as {e.get('claim_id')}")
            overlap = cur_seqs.intersection(e.get("sequences", []))
            if overlap:
                ok = a.fail(c, f"Double counting: {len(overlap)} record(s) already claimed in {e.get('claim_id')}")
    else:
        a.warnings.append("No claim ledger supplied: cross-claim double counting not checked.")
    return ok


# ---------------------------------------------------------------------------
# Check 7: W3C PROV lineage graph
# ---------------------------------------------------------------------------

def check7_lineage(a):
    """Validates the W3C PROV graph (PROV-JSON layout). Entities are bundle files; activities
    are transformation steps, each tied to a recipe entity. Relations: used (activity <- entity),
    wasGeneratedBy (entity <- activity), wasInformedBy (activity <- activity). Rules:
    every lineage file is exactly one entity with a matching hash; only claim.json is generated;
    the graph is acyclic; every observation, reference and recipe is an ancestor of the claim."""
    c = "check7"
    if not os.path.isfile(a.path("provenance/provenance.json")):
        return a.fail(c, "Missing provenance/provenance.json")
    prov = a.load_json("provenance/provenance.json")
    entities = prov.get("entity")
    activities = prov.get("activity")
    relations = {k: prov.get(k, {}) for k in ("used", "wasGeneratedBy", "wasInformedBy")}
    if not isinstance(entities, dict) or not isinstance(activities, dict) or \
            not all(isinstance(r, dict) for r in relations.values()):
        return a.fail(c, "provenance.json must contain entity, activity and relation objects")
    ok = True

    path_to_entity = {}
    for eid, e in entities.items():
        p = e.get(PROV_PATH) if isinstance(e, dict) else None
        if p not in a.manifest_files:
            ok = a.fail(c, f"Entity {eid} refers to unmanifested path {p!r}")
            continue
        if e.get(PROV_SHA) != a.manifest_files[p]:
            ok = a.fail(c, f"Entity {eid} hash does not match {p}")
        if p in path_to_entity:
            ok = a.fail(c, f"Path {p} described by more than one entity")
        path_to_entity[p] = eid
    for p in a.manifest_files:
        if (p == "claim.json" or p.startswith(LINEAGE_DIRS)) and p not in path_to_entity:
            ok = a.fail(c, f"Lineage incomplete: {p} is not a provenance entity")
    if not ok:
        return False

    # Directed graph: node -> parents. Nodes are ("e", id) and ("a", id).
    parents = {}
    for aid, act in activities.items():
        recipe = act.get("tte:recipe") if isinstance(act, dict) else None
        if recipe not in entities or not entities[recipe][PROV_PATH].startswith("transformations/"):
            ok = a.fail(c, f"Activity {aid} must reference a transformation recipe entity")
            continue
        parents.setdefault(("a", aid), set()).add(("e", recipe))
    endpoints = {
        "used": ("prov:activity", "a", "prov:entity", "e"),
        "wasGeneratedBy": ("prov:entity", "e", "prov:activity", "a"),
        "wasInformedBy": ("prov:informed", "a", "prov:informant", "a"),
    }
    generated = set()
    for kind, (child_key, child_t, parent_key, parent_t) in endpoints.items():
        for rid, rel in relations[kind].items():
            child = rel.get(child_key) if isinstance(rel, dict) else None
            parent = rel.get(parent_key) if isinstance(rel, dict) else None
            known = {"a": activities, "e": entities}
            if child not in known[child_t] or parent not in known[parent_t]:
                ok = a.fail(c, f"{kind} relation {rid} references an unknown node")
                continue
            if kind == "wasGeneratedBy":
                if child in generated:
                    ok = a.fail(c, f"Entity {child} generated by more than one activity")
                generated.add(child)
            parents.setdefault((child_t, child), set()).add((parent_t, parent))

    claim_eid = path_to_entity["claim.json"]
    if generated != {claim_eid}:
        ok = a.fail(c, f"Exactly claim.json must be generated; generated entities: {sorted(generated)}")
    if not ok:
        return False

    ancestors, on_stack = set(), set()
    stack = [(("e", claim_eid), False)]
    while stack:
        node, done = stack.pop()
        if done:
            on_stack.discard(node)
            ancestors.add(node)
            continue
        if node in ancestors:
            continue
        if node in on_stack:
            return a.fail(c, f"Lineage graph contains a cycle through {node[1]}")
        on_stack.add(node)
        stack.append((node, True))
        for parent in parents.get(node, ()):
            if parent in on_stack:
                return a.fail(c, f"Lineage graph contains a cycle through {parent[1]}")
            stack.append((parent, False))

    for p, eid in path_to_entity.items():
        if p.startswith(LINEAGE_DIRS) and ("e", eid) not in ancestors:
            ok = a.fail(c, f"{p} does not contribute to the claim (orphan or unused input)")
    for aid in activities:
        if ("a", aid) not in ancestors:
            ok = a.fail(c, f"Activity {aid} does not contribute to the claim")
    return ok


# ---------------------------------------------------------------------------
# Check 10: Reconciliation
# ---------------------------------------------------------------------------

def check10_reconcile(a):
    c = "check10"
    if a.metrics is None:
        return a.fail(c, "No recomputed metrics (Check 9 failed)")
    if a.claim is None:
        return a.fail(c, "No claim loaded")
    ok = True
    declared = a.claim.get("metrics")
    if declared != a.metrics:
        if not isinstance(declared, dict):
            return a.fail(c, "Claim metrics missing")
        for k in sorted(set(declared) | set(a.metrics)):
            if declared.get(k) != a.metrics.get(k):
                ok = a.fail(c, f"Metric {k}: declared {declared.get(k)!r} != recomputed {a.metrics.get(k)!r}")
    for rel in sorted(p for p in a.manifest_files if p.startswith("transformations/") and p.endswith(".json")):
        outputs = a.load_json(rel).get("outputs", {})
        for k, v in outputs.items():
            if k not in a.metrics:
                ok = a.fail(c, f"{rel} declares unverifiable output {k}")
            elif v != a.metrics[k]:
                ok = a.fail(c, f"{rel} output {k} = {v!r} != recomputed {a.metrics[k]!r}")
    return ok


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

def _load_registry(a):
    if not a.options.registry or not os.path.isfile(a.options.registry):
        a.errors.append("[registry] Auditor registry (--trusted-registry) not found")
        return
    try:
        a.registry = jcs.load_file(a.options.registry)
    except Exception as e:
        a.errors.append(f"[registry] Unreadable auditor registry: {e}")
        return
    params = a.registry.get("methodology_parameters", {}).get(a.profile.profile_id)
    if not isinstance(params, dict):
        a.errors.append(f"[registry] No methodology_parameters for profile {a.profile.profile_id}")
        return
    a.params = params


def run_audit(bundle_dir, profile, options):
    a = Audit(bundle_dir, profile, options)
    results = {}
    _load_registry(a)

    def run(key, fn):
        try:
            results[key] = bool(fn())
        except Exception as e:
            a.errors.append(f"[{key.split('_')[0]}] Exception: {type(e).__name__}: {e}")
            results[key] = False

    def hook5():
        if not a.records:
            return a.fail("check5", "No verified records")
        errs = profile.check5_process_continuity(a)
        a.errors.extend(f"[check5] {e}" for e in errs)
        return not errs

    def hook8():
        before = len(a.errors)
        a.references = profile.check8_pinned_references(a)
        return a.references is not None and len(a.errors) == before

    def hook9():
        if not a.references or not a.records:
            return a.fail("check9", "Cannot recompute without verified records and pinned references")
        errs, metrics = profile.check9_recompute(a)
        a.errors.extend(f"[check9] {e}" for e in errs)
        if errs or metrics is None:
            return False
        for k, v in metrics.items():
            if not _is_int(v):
                a.errors.append(f"[check9] Profile produced non-integer metric {k}")
                return False
        a.metrics = metrics
        return True

    run("check1_manifest_and_seal", lambda: check1_manifest_and_seal(a))
    run("check2_device_cert_and_attestation", lambda: check2_device(a))
    run("check3_observation_signatures", lambda: check3_signatures(a))
    run("check4_hash_chain_continuity", lambda: check4_chain(a))
    run("check5_process_continuity", hook5)
    run("check6_claim_boundary_bounds", lambda: check6_claim(a))
    run("check7_transformations_and_provenance", lambda: check7_lineage(a))
    run("check8_pinned_references", hook8)
    run("check9_independent_recomputation", hook9)
    run("check10_numeric_reconciliation", lambda: check10_reconcile(a))

    registry_ok = not any(e.startswith("[registry]") for e in a.errors)
    passed = registry_ok and all(results.values())

    simulated = a.attestation_root_subject is not None and "SIMULATED" in a.attestation_root_subject
    if simulated:
        a.warnings.append("Pinned manufacturer CA is a SIMULATION root: hardware key origin is not established for production use.")

    report = {
        "verdict": "PASSED" if passed else "FAILED",
        "bundle_format": BUNDLE_FORMAT_VERSION,
        "profile": profile.profile_id,
        "bundle": bundle_dir,
        "checks": dict([("check0_profile_binding", "PASSED")] +
                       [(k, "PASSED" if results.get(k) else "FAILED") for k in CHECK_KEYS]),
        "errors": a.errors,
        "warnings": a.warnings,
        "trust_anchors": {
            "producer_key": options.producer_key,
            "manufacturer_ca": options.manufacturer_ca,
            "manufacturer_ca_subject": a.attestation_root_subject,
            "registry": options.registry,
        },
        "findings": {
            "device_id": a.device_id,
            "hardware_attestation": ("SIMULATED_MANUFACTURER_CA" if simulated else
                                     "MANUFACTURER_CA_VERIFIED" if a.attestation_root_subject else "NOT_VERIFIED"),
            "record_count": len(a.records),
            "terminal_hash": a.terminal_hash,
            "recomputed_metrics": a.metrics,
        },
    }

    if passed and options.record_ledger and options.claim_ledger:
        record_to_claim_ledger(options.claim_ledger, {
            "claim_id": a.claim.get("claim_id"),
            "profile": profile.profile_id,
            "device_id": a.device_id,
            "sequences": [f"{a.device_id}:{r['sequence']}" for r in a.records],
            "terminal_hash": a.terminal_hash,
            "recorded_at": int(time.time()),
        })
    return report
