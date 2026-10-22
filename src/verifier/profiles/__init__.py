"""
Profile driver registry.

A profile driver is the only domain-specific code in the verifier. It declares:
  * profile_id, description, metrology_standard, hook descriptions
  * instrument_requirements: {role: {"standards": set, "accuracy_classes": set}}
    (enforced by core Check 2; every role must appear exactly once)
and implements three hooks, each receiving the core Audit object:
  * check5_process_continuity(audit) -> [errors]
  * check8_pinned_references(audit)  -> refs dict, or None on failure
        (use audit.pin_reference(path, dataset_type, "check8") for registry pinning)
  * check9_recompute(audit)          -> ([errors], {metric_name: int})
The core reconciles the returned metrics against claim.json in Check 10.
"""

from profiles.biochar_pyrolysis import BiocharPyrolysisProfile
from profiles.energy_submetering import EnergySubmeteringProfile

PROFILE_DRIVERS = {
    p.profile_id: p for p in (EnergySubmeteringProfile(), BiocharPyrolysisProfile())
}
