"""
Reference profile 2: biochar_pyrolysis — non-linear multi-sensor mass & thermal
transformation (EU NAWI 2014/31/EU weighing, IEC 60584-1 thermocouples, EU CRCF).
"""


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


REQUIRED_PARAMS = ("min_pyrolysis_temp_c", "max_dry_yield_bps", "max_h_c_org_bps", "process_deduction_g")
LAB_BPS_FIELDS = ("moisture_bps", "c_org_bps", "permanence_factor_bps", "h_c_org_bps")


class BiocharPyrolysisProfile(object):
    profile_id = "biochar_pyrolysis"
    description = "Non-linear mass & thermal transformation (EU NAWI / CRCF)"
    metrology_standard = "EU Directive 2014/31/EU (NAWI), IEC 60584-1"
    hooks = {
        "check5": "Thermal permanence: T_min >= min_pyrolysis_temp_c per batch; T_min <= T_avg <= T_max; unique batch IDs",
        "check8": "ISO 17025 lab assay and feedstock delivery manifest pinned by SHA-256; lab bound to batch range",
        "check9": "Per-batch dry yield <= max_dry_yield_bps, feedstock <= delivered, H/C_org cap; integer CRCF stoichiometry",
    }
    instrument_requirements = {
        "weighing_indicator": {
            "standards": {"NAWI_2014_31_EU"},
            "accuracy_classes": {"Class_I", "Class_II", "Class_III"},
        },
        "thermocouple_module": {
            "standards": {"IEC_60584_1"},
            "accuracy_classes": {"Class_1", "Class_2"},
        },
    }
    payload_keys = {"batch_id", "feedstock_delivery_ref", "feedstock_input_g", "scale_wet_mass_g",
                    "temp_min_c", "temp_avg_c", "temp_max_c"}
    lab_path = "reference_data/lab_analysis.json"
    feedstock_path = "reference_data/feedstock_manifest.json"

    def check5_process_continuity(self, a):
        errs = []
        min_temp = a.params.get("min_pyrolysis_temp_c")
        if not _is_int(min_temp):
            return ["Registry parameter min_pyrolysis_temp_c missing"]
        seen = set()
        for r in a.records:
            p, seq = r["payload"], r["sequence"]
            if set(p) != self.payload_keys:
                errs.append(f"Sequence {seq}: payload must contain exactly {sorted(self.payload_keys)}")
                continue
            temps = (p["temp_min_c"], p["temp_avg_c"], p["temp_max_c"])
            if not all(_is_int(t) for t in temps):
                errs.append(f"Sequence {seq}: temperatures must be integers (°C)")
                continue
            if not temps[0] <= temps[1] <= temps[2]:
                errs.append(f"Sequence {seq}: inconsistent temperatures (min/avg/max = {temps})")
            if temps[0] < min_temp:
                errs.append(f"Sequence {seq}: thermal permanence failure, T_min {temps[0]}°C < {min_temp}°C")
            if p["batch_id"] in seen:
                errs.append(f"Sequence {seq}: duplicate batch_id {p['batch_id']}")
            seen.add(p["batch_id"])
        return errs

    def check8_pinned_references(self, a):
        lab, _ = a.pin_reference(self.lab_path, "iso17025_accredited_lab_report", "check8")
        feed, _ = a.pin_reference(self.feedstock_path, "feedstock_delivery_manifest", "check8")
        if lab is None or feed is None:
            return None
        ok = True
        for k in LAB_BPS_FIELDS:
            if not _is_int(lab.get(k)) or not 0 <= lab[k] <= 10000:
                ok = a.fail("check8", f"Lab analysis {k} must be an integer in 0..10000 bps")
        batch_ids = [r["payload"].get("batch_id") for r in a.records]
        if batch_ids and lab.get("sample_batch_ref") != f"{batch_ids[0]}_to_{batch_ids[-1]}":
            ok = a.fail("check8", f"Lab sample_batch_ref {lab.get('sample_batch_ref')!r} does not cover this batch range")
        if not _is_int(feed.get("delivered_mass_total_g")) or feed["delivered_mass_total_g"] <= 0:
            ok = a.fail("check8", "Feedstock manifest delivered_mass_total_g must be a positive integer")
        for r in a.records:
            if r["payload"].get("feedstock_delivery_ref") != feed.get("delivery_ref"):
                ok = a.fail("check8", f"Sequence {r['sequence']}: feedstock_delivery_ref not covered by the pinned delivery manifest")
        return {"lab": lab, "feedstock": feed} if ok else None

    def check9_recompute(self, a):
        params = a.params
        missing = [k for k in REQUIRED_PARAMS if not _is_int(params.get(k))]
        if missing:
            return [f"Registry parameters missing: {missing}"], None
        lab, feed = a.references["lab"], a.references["feedstock"]
        moisture = lab["moisture_bps"]
        errs = []
        total_feed = total_wet = total_dry = 0
        for r in a.records:
            p, seq = r["payload"], r["sequence"]
            w, f = p.get("scale_wet_mass_g"), p.get("feedstock_input_g")
            if not (_is_int(w) and _is_int(f) and w > 0 and f > 0):
                errs.append(f"Sequence {seq}: masses must be positive integer grams")
                continue
            dry = w * (10000 - moisture) // 10000
            if dry * 10000 > f * params["max_dry_yield_bps"]:
                errs.append(f"Sequence {seq}: dry yield {dry * 10000 // f} bps exceeds max {params['max_dry_yield_bps']} bps")
            total_feed += f
            total_wet += w
            total_dry += dry
        if total_feed > feed["delivered_mass_total_g"]:
            errs.append(f"Feedstock used {total_feed} g exceeds delivered {feed['delivered_mass_total_g']} g")
        if lab["h_c_org_bps"] > params["max_h_c_org_bps"]:
            errs.append(f"H/C_org {lab['h_c_org_bps']} bps exceeds stability cap {params['max_h_c_org_bps']} bps")
        if errs:
            return errs, None
        # Gross CO2 = M_dry * C_org * F_perm * 44/12, integer grams, rounded down (never over-credit removals).
        gross = total_dry * lab["c_org_bps"] * lab["permanence_factor_bps"] * 44 // (10000 * 10000 * 12)
        net = gross - params["process_deduction_g"]
        if net <= 0:
            return [f"Net removal is non-positive ({net} g)"], None
        return [], {
            "total_feedstock_input_g": total_feed,
            "total_wet_biochar_g": total_wet,
            "total_dry_biochar_g": total_dry,
            "gross_co2_removed_g": gross,
            "process_deductions_co2_g": params["process_deduction_g"],
            "net_co2_removed_g": net,
        }
