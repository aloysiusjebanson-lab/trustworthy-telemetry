"""
Reference profile 1: energy_submetering — continuous linear cumulative metrology
(EU MID 2014/32/EU, EN 50470-3; Scope 2 location-based emissions).
"""


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


class EnergySubmeteringProfile(object):
    profile_id = "energy_submetering"
    description = "Continuous linear flow metrology (EU MID / CSRD Scope 2)"
    metrology_standard = "EU Directive 2014/32/EU (MID), EN 50470-3"
    hooks = {
        "check5": "Dual-register continuity: cumulative_wh[i] - cumulative_wh[i-1] == interval_wh[i]; single certified meter",
        "check8": "Grid emission factor pinned by SHA-256 in the auditor registry (integer mg CO2e/kWh)",
        "check9": "Integer Wh summation; emissions_g = ceil(total_wh * factor_mg_per_kwh / 1e6)",
    }
    instrument_requirements = {
        "energy_meter": {
            "standards": {"MID_2014_32_EU"},
            "accuracy_classes": {"Class_A_EN50470", "Class_B_EN50470", "Class_C_EN50470"},
        },
    }
    payload_keys = {"meter_id", "cumulative_wh", "interval_wh"}
    factor_path = "reference_data/emission_factor.json"

    def check5_process_continuity(self, a):
        errs = []
        meter = next((i for i in a.instruments if isinstance(i, dict) and i.get("role") == "energy_meter"), {})
        prev_cum = None
        for r in a.records:
            p, seq = r["payload"], r["sequence"]
            if set(p) != self.payload_keys:
                errs.append(f"Sequence {seq}: payload must contain exactly {sorted(self.payload_keys)}")
                prev_cum = None
                continue
            if p["meter_id"] != meter.get("instrument_id"):
                errs.append(f"Sequence {seq}: meter_id {p['meter_id']!r} is not the certified meter")
            if not (_is_int(p["cumulative_wh"]) and _is_int(p["interval_wh"]) and p["cumulative_wh"] >= 0 and p["interval_wh"] >= 0):
                errs.append(f"Sequence {seq}: registers must be non-negative integers")
                prev_cum = None
                continue
            if prev_cum is not None and p["cumulative_wh"] - prev_cum != p["interval_wh"]:
                errs.append(f"Sequence {seq}: dual-register mismatch (cumulative delta {p['cumulative_wh'] - prev_cum} != interval {p['interval_wh']})")
            prev_cum = p["cumulative_wh"]
        return errs

    def check8_pinned_references(self, a):
        factor, entry = a.pin_reference(self.factor_path, "grid_emission_factor", "check8")
        if factor is None:
            return None
        value = factor.get("factor_mg_co2e_per_kwh")
        if not _is_int(value) or value <= 0:
            a.fail("check8", "Emission factor must be a positive integer factor_mg_co2e_per_kwh")
            return None
        if entry.get("factor_mg_co2e_per_kwh") != value:
            a.fail("check8", f"Bundled factor {value} != registry-pinned factor {entry.get('factor_mg_co2e_per_kwh')}")
            return None
        return {"factor_mg_co2e_per_kwh": value}

    def check9_recompute(self, a):
        errs = []
        total_wh = 0
        for r in a.records:
            v = r["payload"].get("interval_wh")
            if not _is_int(v) or v < 0:
                errs.append(f"Sequence {r['sequence']}: interval_wh not a non-negative integer")
            else:
                total_wh += v
        if errs:
            return errs, None
        mg_per_kwh = a.references["factor_mg_co2e_per_kwh"]
        # Wh * mg/kWh = micrograms; round up to whole grams (never under-report emissions).
        emissions_g = -(-(total_wh * mg_per_kwh) // 1000000)
        return [], {
            "total_energy_wh": total_wh,
            "emission_factor_mg_co2e_per_kwh": mg_per_kwh,
            "total_emissions_g_co2e": emissions_g,
        }
