"""
Evidence Bundle Builder (bundle format v1.3) — profile-agnostic packaging steps:
claim.json, transformation recipes, W3C PROV lineage graph, manifest and producer seal.
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "verifier")))
import crypto  # noqa: E402
import jcs  # noqa: E402

BUNDLE_FORMAT_VERSION = "1.3"
PROV_PREFIXES = {
    "prov": "http://www.w3.org/ns/prov#",
    "tte": "https://github.com/aloysiusjebanson-lab/trustworthy-telemetry/ns#",
}


def write_json(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


def read_records(bundle_root):
    with open(os.path.join(bundle_root, "observations", "observations.ndjson"), "r", encoding="utf-8") as f:
        return [jcs.loads(line)["record"] for line in f if line.strip()]


def period_of(records):
    return {
        "first_sequence": records[0]["sequence"],
        "last_sequence": records[-1]["sequence"],
        "record_count": len(records),
        "start_timestamp": records[0]["timestamp_start"],
        "end_timestamp": records[-1]["timestamp_end"],
        "genesis_prev_hash": records[0]["prev_hash"],
        "terminal_hash": crypto.sha256_hex(jcs.canonicalize(records[-1])),
    }


def write_claim(bundle_root, claim_id, profile, device_id, records, metrics, extra=None):
    claim = {"claim_id": claim_id, "profile": profile, "device_id": device_id,
             "period": period_of(records), "metrics": metrics}
    claim.update(extra or {})
    write_json(os.path.join(bundle_root, "claim.json"), claim)
    return claim


def write_provenance(bundle_root, entities, activities):
    """entities: {entity_id: relative_path}
    activities: {activity_id: {"recipe": entity_id, "used": [entity_ids], "generated": [entity_ids],
                               "informed_by": [activity_ids]}}"""
    prov = {"prefix": PROV_PREFIXES, "entity": {}, "activity": {}, "used": {}, "wasGeneratedBy": {},
            "wasInformedBy": {}}
    for eid, rel in entities.items():
        prov["entity"][eid] = {"tte:path": rel, "tte:sha256": crypto.sha256_file(os.path.join(bundle_root, rel))}
    for aid, act in activities.items():
        prov["activity"][aid] = {"tte:recipe": act["recipe"]}
        for i, ent in enumerate(act["used"], 1):
            prov["used"][f"_:{aid}_used{i}"] = {"prov:activity": aid, "prov:entity": ent}
        for i, ent in enumerate(act["generated"], 1):
            prov["wasGeneratedBy"][f"_:{aid}_gen{i}"] = {"prov:entity": ent, "prov:activity": aid}
        for i, informant in enumerate(act.get("informed_by", []), 1):
            prov["wasInformedBy"][f"_:{aid}_inf{i}"] = {"prov:informed": aid, "prov:informant": informant}
    write_json(os.path.join(bundle_root, "provenance", "provenance.json"), prov)


def seal_bundle(bundle_root, profile, claim_id, producer):
    """Hashes every file in the bundle and seals {version, profile, claim_id, files} with the producer key."""
    files = {}
    for root, _, names in os.walk(bundle_root):
        for name in sorted(names):
            rel = os.path.relpath(os.path.join(root, name), bundle_root).replace(os.sep, "/")
            if rel == "manifest.json" or name == ".DS_Store":
                continue
            if "private" in name.lower() or name.lower().endswith(".key"):
                raise RuntimeError(f"Refusing to seal private key material into the bundle: {rel}")
            files[rel] = crypto.sha256_file(os.path.join(root, name))
    manifest = {"manifest_version": BUNDLE_FORMAT_VERSION, "profile": profile, "claim_id": claim_id, "files": files}
    manifest["seal"] = {"algorithm": crypto.SIGNATURE_ALGORITHM, "signature": producer.sign(jcs.canonicalize(manifest))}
    write_json(os.path.join(bundle_root, "manifest.json"), manifest)
    return manifest
