"""
Verifiable Telemetry Engine — Offline Verifier CLI (bundle format v1.3)

Executes the fail-closed verification state machine defined in
02_protocol/evidence_bundle_spec.md (see core.py for the check list).
All trust anchors are supplied by the auditor, never by the bundle:

  --profile          rule set to apply (the bundle must declare the same profile)
  --producer-key     producer root public key (signs device certificates and the bundle seal)
  --manufacturer-ca  secure-element manufacturer root CA (attests that the device key is hardware-held)
  --trusted-registry pinned reference datasets and methodology parameters

Operates 100% offline with zero third-party dependencies (Python 3 stdlib + OpenSSL CLI).
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core  # noqa: E402
from profiles import PROFILE_DRIVERS  # noqa: E402


def _fail_early(err, json_mode, check="check0_profile_binding"):
    report = {"verdict": "FAILED", "errors": [err], "checks": {check: "FAILED"}}
    if json_mode:
        print(json.dumps(report, indent=2))
    else:
        print(f"[!] {err}\n[AUDIT VERDICT: FAILED]")
    return report


def verify_bundle(bundle_dir, profile_id, options, json_mode=False, verbose=False):
    """Returns the audit report dict. report['verdict'] is 'PASSED' or 'FAILED'."""
    if not options.producer_key or not os.path.isfile(options.producer_key):
        return _fail_early(f"Producer trust anchor not found: {options.producer_key}", json_mode, "trust_anchor")
    if profile_id is None:
        return _fail_early("No profile specified. The auditor must select one via --profile "
                           f"({', '.join(PROFILE_DRIVERS)}).", json_mode)
    profile = PROFILE_DRIVERS.get(profile_id)
    if profile is None:
        return _fail_early(f"Unknown or unsupported profile: {profile_id}", json_mode)
    err = core.check0_profile_binding(bundle_dir, profile_id)
    if err:
        return _fail_early(err, json_mode)

    report = core.run_audit(bundle_dir, profile, options)

    if json_mode:
        print(json.dumps(report, indent=2))
        return report

    print("=" * 72)
    print(f" Verifiable Telemetry Engine — Offline Audit (bundle v{core.BUNDLE_FORMAT_VERSION})")
    print(f" Profile : {profile.profile_id} — {profile.description}")
    print(f" Bundle  : {bundle_dir}")
    print("=" * 72)
    for n, key in enumerate(core.CHECK_KEYS, 1):
        print(f"[Check {n:>2}/10] {core.CHECK_TITLES[key]:<44}: [{report['checks'][key]}]")
    print("-" * 72)
    f = report["findings"]
    print(f"  Device            : {f['device_id']} ({f['hardware_attestation']})")
    print(f"  Records           : {f['record_count']} (terminal hash {str(f['terminal_hash'])[:16]}...)")
    for k, v in (f["recomputed_metrics"] or {}).items():
        print(f"  {k:<32}: {v}")
    print("-" * 72)
    print(f"[AUDIT VERDICT: {report['verdict']}]")
    if report["errors"] and (verbose or report["verdict"] == "FAILED"):
        print("  Errors:")
        for e in report["errors"]:
            print(f"    - {e}")
    for w in report["warnings"]:
        print(f"  [WARNING] {w}")
    print("=" * 72)
    return report


def list_profiles(json_mode):
    if json_mode:
        print(json.dumps({pid: {"description": p.description, "metrology_standard": p.metrology_standard,
                                "hooks": p.hooks,
                                "instrument_roles": sorted(p.instrument_requirements)}
                          for pid, p in PROFILE_DRIVERS.items()}, indent=2))
        return
    for pid, p in PROFILE_DRIVERS.items():
        print(f"[*] {pid}: {p.description}")
        print(f"    Metrology   : {p.metrology_standard}")
        print(f"    Instruments : {', '.join(sorted(p.instrument_requirements))}")
        for hook, desc in p.hooks.items():
            print(f"    {hook} hook : {desc}")


def main():
    ap = argparse.ArgumentParser(description="Verifiable Telemetry Engine — Offline Verifier (bundle v1.3)")
    ap.add_argument("bundle", nargs="?", help="Path to evidence bundle directory")
    ap.add_argument("--profile", help=f"Auditor-selected profile (required): {', '.join(PROFILE_DRIVERS)}")
    ap.add_argument("--producer-key", "--company-key", dest="producer_key", help="Producer root public key (trust anchor)")
    ap.add_argument("--manufacturer-ca", help="Pinned secure-element manufacturer root CA certificate (PEM)")
    ap.add_argument("--trusted-registry", help="Auditor's pinned reference registry (JSON)")
    ap.add_argument("--expected-count", type=int, help="Audit mandate: exact number of records")
    ap.add_argument("--period-start", type=int, help="Audit mandate: reporting period start (unix seconds)")
    ap.add_argument("--period-end", type=int, help="Audit mandate: reporting period end (unix seconds)")
    ap.add_argument("--prev-terminal-hash", help="Terminal hash of the previous reporting period (chain genesis)")
    ap.add_argument("--revoked", help="Comma-separated device IDs or path to a revocation file")
    ap.add_argument("--claim-ledger", help="Auditor claim ledger (double-counting protection)")
    ap.add_argument("--record-ledger", action="store_true", help="Record a PASSED claim into the ledger")
    ap.add_argument("--list-profiles", action="store_true", help="List registered profile drivers and hooks")
    ap.add_argument("-v", "--verbose", action="store_true", help="Always print error details")
    ap.add_argument("--json", action="store_true", help="Machine-readable JSON report on stdout")
    ap.add_argument("--json-out", help="Also write the JSON report to this file")
    args = ap.parse_args()

    if args.list_profiles:
        list_profiles(args.json)
        sys.exit(0)
    if not args.bundle:
        ap.error("bundle path is required")

    options = core.AuditOptions(
        producer_key=args.producer_key, manufacturer_ca=args.manufacturer_ca, registry=args.trusted_registry,
        expected_count=args.expected_count, prev_terminal_hash=args.prev_terminal_hash, revoked=args.revoked,
        claim_ledger=args.claim_ledger, record_ledger=args.record_ledger,
        period_start=args.period_start, period_end=args.period_end)
    report = verify_bundle(args.bundle, args.profile, options, json_mode=args.json, verbose=args.verbose)
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(report, f, indent=2)
    sys.exit(0 if report["verdict"] == "PASSED" else 1)


if __name__ == "__main__":
    main()
