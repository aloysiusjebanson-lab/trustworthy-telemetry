#!/usr/bin/env python3
"""
Insider Fraud Benchmark — energy_submetering (bundle format v1.3)

The adversary is the facility operator: holds the producer root key, controls the gateway
(its secure element signs on request) and re-packages and re-seals the bundle. Signatures and
seals are therefore valid; each attack must be caught by an independent control.
  I1  Greenwashed emission factor (not pinned by auditor)       -> Check 8
  I2  Interval register shaved and re-signed                     -> Check 5 (dual register)
  I3  Peak records truncated vs auditor-mandated count           -> Check 6
  I4  Software key, attestation chain removed                    -> Check 2
  I5  Spliced telemetry (prev_hash rewritten, record re-signed)  -> Check 4
  I6  Bad window withheld, chain re-signed and renumbered        -> Check 4 (max record gap)
  I7  Tail truncated vs auditor-mandated reporting period        -> Check 6
  I8  Undeclared adjustment recipe added to bundle               -> Check 7 (lineage)
"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures import build_energy_fixture  # noqa: E402
from harness import assert_baseline_passes, report, verify_and_check  # noqa: E402
from tamper_tools import (clone, link_hash, read_envelopes, repackage, resign_chain, reseal_only,  # noqa: E402
                          sign_envelope, write_envelopes)

SPLICE_PREV = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def records_of(bundle):
    return [e["record"] for e in read_envelopes(bundle)]


def run_insider_tests():
    print("=" * 78)
    print(" Insider Fraud Benchmark — energy_submetering (bundle v1.3)")
    print("=" * 78)
    workdir = tempfile.mkdtemp(prefix="insider_fraud_")
    attacks = []
    try:
        fx = build_energy_fixture(workdir)
        assert_baseline_passes(fx["bundle"], fx)
        dev = fx["device_priv"]

        def attack(name, bundle, check, extra=None):
            attacks.append((name, *verify_and_check(bundle, fx, check, extra)))

        d = clone(fx, "i1")
        fake = os.path.join(workdir, "fake_factor.json")
        with open(fake, "w") as f:
            json.dump({"dataset_id": "fabricated", "unit": "mg_co2e_per_kwh", "factor_mg_co2e_per_kwh": 50000}, f)
        repackage(d, fx, reference_file=fake)
        attack("I1: Greenwashed emission factor + reseal", d, "check8_pinned_references")

        d = clone(fx, "i2")
        recs = records_of(d)
        recs[1]["payload"]["interval_wh"] = 500
        resign_chain(d, recs, dev)
        repackage(d, fx)
        attack("I2: Interval register shaved + re-signed", d, "check5_process_continuity")

        d = clone(fx, "i3")
        resign_chain(d, records_of(d)[:3], dev)
        repackage(d, fx)
        attack("I3: Truncation vs mandated record count", d, "check6_claim_boundary_bounds", ["--expected-count", "5"])

        d = clone(fx, "i4")
        shutil.rmtree(os.path.join(d, "device", "attestation"))
        repackage(d, fx)
        attack("I4: Attestation chain removed + reseal", d, "check2_device_cert_and_attestation")

        d = clone(fx, "i5")
        envs, prev = [], "0" * 64
        for i, rec in enumerate(records_of(d)):
            # Record 3 is spliced in from another stream: it links to a foreign predecessor.
            rec = dict(rec, prev_hash=SPLICE_PREV if i == 2 else prev)
            envs.append(sign_envelope(rec, dev))
            prev = link_hash(rec)
        write_envelopes(d, envs)
        repackage(d, fx)
        attack("I5: Spliced telemetry (prev_hash rewritten)", d, "check4_hash_chain_continuity")

        d = clone(fx, "i6")
        recs = records_of(d)
        kept = [recs[0]] + recs[3:]
        resign_chain(d, kept, dev, renumber=True)
        repackage(d, fx)
        attack("I6: Withheld window, chain re-signed + renumbered", d, "check4_hash_chain_continuity")

        d = clone(fx, "i7")
        recs = records_of(d)
        start, end = recs[0]["timestamp_start"], recs[-1]["timestamp_end"]
        resign_chain(d, recs[:3], dev)
        repackage(d, fx)
        attack("I7: Tail truncated vs mandated period", d, "check6_claim_boundary_bounds",
               ["--period-start", str(start), "--period-end", str(end)])

        d = clone(fx, "i8")
        with open(os.path.join(d, "transformations", "manual_adjustment.json"), "w") as f:
            json.dump({"transformation_id": "manual_adjustment", "outputs": {}}, f)
        reseal_only(d, fx)
        attack("I8: Undeclared adjustment recipe (orphan lineage)", d, "check7_transformations_and_provenance")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return report("insider", attacks)


if __name__ == "__main__":
    sys.exit(0 if run_insider_tests() else 1)
