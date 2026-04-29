"""
m10_battery_health.py — Nielsoln Rescue Toolkit: laptop battery health check.

Reads battery information from /sys/class/power_supply/ on the live Linux
(RescueZilla) environment.  The target Windows installation is offline —
no Windows APIs are called.

Detects: healthy, worn, poor, failing, dead, or absent batteries.
Collects AC adapter state, calculates health_percent and estimated runtime.

Verdicts:
  GOOD        — health_percent >= 70%
  WORN        — health_percent 40–70%
  POOR        — health_percent 20–40%
  FAILING     — health_percent < 20%
  DEAD        — present but full capacity is zero, or stuck at 0% despite AC
  NOT_PRESENT — no battery device found
  UNKNOWN     — battery found but telemetry insufficient to assess

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m10_battery_health --target /mnt/windows

Output:
    Prints battery health report to stdout.
    Writes a JSON log to <USB>/logs/battery_health_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DESCRIPTION = (
    "Battery health: reads /sys/class/power_supply/ from the live Linux "
    "environment to report battery wear, capacity, and estimated runtime — "
    "requires --target /mnt/windows"
)

# ---------------------------------------------------------------------------
# Verdict priority (higher = more severe; used to pick overall from multiple)
# ---------------------------------------------------------------------------

_VERDICT_SEVERITY: dict[str, int] = {
    "DEAD":        6,
    "FAILING":     5,
    "POOR":        4,
    "WORN":        3,
    "GOOD":        2,
    "UNKNOWN":     1,
    "NOT_PRESENT": 0,
}


# ---------------------------------------------------------------------------
# sysfs helpers
# ---------------------------------------------------------------------------

def _sysfs_str(p: Path) -> str:
    try:
        return p.read_text(encoding="ascii", errors="replace").strip()
    except Exception:
        return ""


def _sysfs_int(p: Path) -> Optional[int]:
    v = _sysfs_str(p)
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _read_supply_raw(supply_path: Path) -> dict[str, str]:
    """Return dict of all readable files under a power_supply directory."""
    raw: dict[str, str] = {}
    for f in sorted(supply_path.iterdir()):
        if f.is_file():
            try:
                v = f.read_text(encoding="ascii", errors="replace").strip()
                raw[f.name] = v
            except Exception:
                pass
    return raw


# ---------------------------------------------------------------------------
# Battery probe
# ---------------------------------------------------------------------------

def _probe_battery(supply_path: Path) -> Optional[dict]:
    """Read one /sys/class/power_supply/<name>/ entry.
    Returns None if the device is not a battery.
    """
    ptype = _sysfs_str(supply_path / "type")
    if ptype.upper() != "BATTERY":
        return None

    name = supply_path.name
    raw  = _read_supply_raw(supply_path)

    # -- Presence --
    present_raw    = raw.get("present", "1")
    battery_present = present_raw.strip() != "0"

    # -- Identification --
    manufacturer  = raw.get("manufacturer", "") or None
    model_name    = raw.get("model_name", "")   or None
    serial_number = raw.get("serial_number", "") or None
    technology    = raw.get("technology", "")   or None
    health        = raw.get("health", "")       or None
    status        = raw.get("status", "Unknown")
    capacity_level = raw.get("capacity_level", "") or None
    alarm         = raw.get("alarm", "") or None

    # -- Raw µ-unit fields --
    energy_now         = _sysfs_int(supply_path / "energy_now")
    energy_full        = _sysfs_int(supply_path / "energy_full")
    energy_full_design = _sysfs_int(supply_path / "energy_full_design")
    charge_now         = _sysfs_int(supply_path / "charge_now")
    charge_full        = _sysfs_int(supply_path / "charge_full")
    charge_full_design = _sysfs_int(supply_path / "charge_full_design")
    voltage_now        = _sysfs_int(supply_path / "voltage_now")   # µV
    current_now        = _sysfs_int(supply_path / "current_now")   # µA  (negative = discharging on some HW)
    power_now          = _sysfs_int(supply_path / "power_now")     # µW
    cycle_count        = _sysfs_int(supply_path / "cycle_count")
    capacity_percent   = _sysfs_int(supply_path / "capacity")      # 0-100

    # -- Derived capacity fields --
    # Prefer energy_ (µWh) if available; fall back to charge_ (µAh)
    _now    = energy_now    if energy_now    is not None else charge_now
    _full   = energy_full   if energy_full   is not None else charge_full
    _design = energy_full_design if energy_full_design is not None else charge_full_design
    _unit   = "mWh" if energy_full is not None else "mAh"

    def _to_milli(v: Optional[int]) -> Optional[int]:
        return round(v / 1000) if v is not None else None

    design_capacity_available = _to_milli(_design)
    full_capacity_available   = _to_milli(_full)

    # health_percent: how much of design capacity remains as full charge
    health_percent: Optional[float] = None
    if _design and _design > 0 and _full is not None:
        health_percent = round(100.0 * _full / _design, 1)

    # remaining_percent: current charge vs full
    remaining_percent: Optional[float] = None
    if _full and _full > 0 and _now is not None:
        remaining_percent = round(100.0 * _now / _full, 1)
    if remaining_percent is None and capacity_percent is not None:
        remaining_percent = float(capacity_percent)

    # estimated_runtime_minutes while discharging
    estimated_runtime_minutes: Optional[float] = None
    is_discharging = (status or "").lower() == "discharging"
    if is_discharging:
        if power_now and power_now > 0 and energy_now and energy_now > 0:
            estimated_runtime_minutes = round(energy_now / power_now * 60, 1)
        elif current_now and current_now != 0 and charge_now and charge_now > 0:
            _cur_abs = abs(current_now)
            if _cur_abs > 0:
                estimated_runtime_minutes = round(charge_now / _cur_abs * 60, 1)

    # battery_age_hint: try to extract from model or serial patterns, or manufacture date
    battery_age_hint: Optional[str] = None
    # Some batteries encode manufacture date in serial number e.g. "2019xxxx"
    if serial_number:
        m = re.search(r"(20\d{2})", serial_number)
        if m:
            battery_age_hint = f"manufacture year hint: {m.group(1)}"

    # -- Flags --
    flags: list[str] = []
    if not battery_present:
        flags.append("battery_not_present")
    if health and health.lower() not in ("good", "unknown", ""):
        flags.append(f"health_reported_as_{health.lower()}")
    if _full == 0:
        flags.append("full_capacity_zero")
    if capacity_percent == 0 and status in ("Not charging", "Unknown", "Discharging"):
        flags.append("capacity_zero")
    if status in ("Not charging", "Unknown") and not is_discharging:
        flags.append("not_charging_or_unknown_status")
    if cycle_count is not None and cycle_count > 500:
        flags.append(f"high_cycle_count_{cycle_count}")

    # -- Verdict --
    verdict = _battery_verdict(
        battery_present, health_percent, remaining_percent, _full, capacity_percent, status, flags
    )

    return {
        # Identity
        "name":                 name,
        "sysfs_path":           str(supply_path),
        "battery_present":      battery_present,
        "manufacturer":         manufacturer,
        "model_name":           model_name,
        "serial_number":        serial_number,
        "technology":           technology,
        "health":               health,
        "status":               status,
        "capacity_percent":     capacity_percent,
        "capacity_level":       capacity_level,
        "alarm":                alarm,
        # Raw µ-unit telemetry (None if not available)
        "energy_now":           energy_now,
        "energy_full":          energy_full,
        "energy_full_design":   energy_full_design,
        "charge_now":           charge_now,
        "charge_full":          charge_full,
        "charge_full_design":   charge_full_design,
        "voltage_now":          voltage_now,
        "current_now":          current_now,
        "power_now":            power_now,
        "cycle_count":          cycle_count,
        # Calculated
        "unit":                        _unit,
        "design_capacity_available":   design_capacity_available,
        "full_capacity_available":     full_capacity_available,
        "health_percent":              health_percent,
        "remaining_percent":           remaining_percent,
        "estimated_runtime_minutes":   estimated_runtime_minutes,
        "battery_age_hint":            battery_age_hint,
        # Assessment
        "flags":   flags,
        "verdict": verdict,
        # Raw sysfs snapshot
        "raw":     raw,
    }


def _battery_verdict(
    present: bool,
    health_percent: Optional[float],
    remaining_percent: Optional[float],
    full_raw: Optional[int],
    capacity_pct: Optional[int],
    status: str,
    flags: list[str],
) -> str:
    if not present:
        return "NOT_PRESENT"
    # Only claim DEAD when full capacity is explicitly reported as zero — not
    # when telemetry is simply absent.  Absence of capacity data → UNKNOWN.
    if "full_capacity_zero" in flags or full_raw == 0:
        return "DEAD"
    if health_percent is None:
        # No energy/charge telemetry — cannot compute health.  Do NOT claim
        # DEAD based on capacity_pct alone; that could be a driver artefact.
        return "UNKNOWN"
    if health_percent < 20.0:
        return "FAILING"
    if health_percent < 40.0:
        return "POOR"
    if health_percent < 70.0:
        return "WORN"
    return "GOOD"


# ---------------------------------------------------------------------------
# AC adapter probe
# ---------------------------------------------------------------------------

def _probe_ac(supply_path: Path) -> Optional[dict]:
    """Read one AC adapter entry.  Returns None if not a Mains/AC type."""
    ptype = _sysfs_str(supply_path / "type")
    if ptype.upper() not in ("MAINS", "USB"):
        return None
    name   = supply_path.name
    raw    = _read_supply_raw(supply_path)
    online = _sysfs_int(supply_path / "online")
    return {
        "name":         name,
        "sysfs_path":   str(supply_path),
        "ac_present":   True,
        "ac_online":    bool(online) if online is not None else None,
        "raw":          raw,
    }


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def _find_power_supplies() -> tuple[list[dict], list[dict]]:
    """Return (batteries, ac_adapters) by scanning /sys/class/power_supply/."""
    base = Path("/sys/class/power_supply")
    batteries: list[dict] = []
    ac_adapters: list[dict] = []
    if not base.exists():
        return batteries, ac_adapters
    for entry in sorted(base.iterdir()):
        if not entry.is_dir():
            continue
        ptype = _sysfs_str(entry / "type").upper()
        # Some drivers (older ACPI/embedded controllers) do not set a 'type'
        # file.  Fall back to name-prefix heuristics in that case.
        if not ptype:
            n = entry.name.upper()
            if n.startswith(("BAT",)):
                ptype = "BATTERY"
            elif n.startswith(("AC", "ADP", "MAINS", "ADPT")):
                ptype = "MAINS"
        if ptype == "BATTERY":
            b = _probe_battery(entry)
            if b:
                batteries.append(b)
        elif ptype in ("MAINS", "USB"):
            a = _probe_ac(entry)
            if a:
                ac_adapters.append(a)
    return batteries, ac_adapters


# ---------------------------------------------------------------------------
# Overall verdict
# ---------------------------------------------------------------------------

def _overall_verdict(batteries: list[dict]) -> str:
    if not batteries:
        return "NOT_PRESENT"
    worst = max(batteries, key=lambda b: _VERDICT_SEVERITY.get(b["verdict"], 0))
    return worst["verdict"]


# ---------------------------------------------------------------------------
# Interpretation + recommendations
# ---------------------------------------------------------------------------

_CUSTOMER_MSGS: dict[str, str] = {
    "GOOD":        "The laptop battery is in good health. It should provide normal battery life.",
    "WORN":        "The battery has aged and can hold less charge than when new. Expect reduced battery life.",
    "POOR":        "The battery is significantly degraded. Runtime will be short — mostly suitable for desk use on AC power.",
    "FAILING":     "The battery is failing and retains very little of its original capacity. Replace it soon.",
    "DEAD":        "The battery is effectively dead — it cannot store a meaningful charge. The laptop will only run on AC power.",
    "NOT_PRESENT": "No battery was detected. The laptop may be a desktop, or the battery is disconnected.",
    "UNKNOWN":     "Battery telemetry was insufficient to assess health. Physical inspection is recommended.",
}

_TECH_ACTIONS: dict[str, str] = {
    "GOOD":        "No battery action required.",
    "WORN":        "Note reduced capacity. Advise customer of shorter runtimes.",
    "POOR":        "Advise AC-only use. Recommend battery replacement if portability is required.",
    "FAILING":     "Recommend immediate battery replacement. Do not rely on battery power.",
    "DEAD":        "Remove or replace battery. Do not use on battery power.",
    "NOT_PRESENT": "Verify battery is physically present and connected.",
    "UNKNOWN":     "Manual inspection or live boot with battery tools recommended.",
}

_RECOMMENDED_ACTIONS: dict[str, list[str]] = {
    "GOOD":        ["No action required — battery is healthy."],
    "WORN":        [
        "Battery life will be reduced — expect shorter runtimes.",
        "Consider replacement if portability is important.",
    ],
    "POOR":        [
        "Use on AC power — battery runtime will be very short.",
        "Plan battery replacement before returning to customer.",
    ],
    "FAILING":     [
        "Replace the battery immediately.",
        "Do not rely on battery power for any use case.",
    ],
    "DEAD":        [
        "Replace the battery.",
        "If battery appears swollen or hot, handle with care — do not compress or puncture.",
        "Do not use on battery power.",
    ],
    "NOT_PRESENT": [
        "Verify battery is physically present and seated correctly.",
        "Run assessment again after reconnecting battery.",
    ],
    "UNKNOWN":     [
        "Physically test battery runtime or replace battery if portable use is required.",
        "Battery telemetry could not be read — manual inspection recommended.",
        "Try booting into a full Linux environment for additional battery tools.",
    ],
}


def _build_interpretation(
    overall_verdict: str,
    batteries: list[dict],
    ac_adapters: list[dict],
    confidence: str,
    limitations: list[str],
) -> dict:
    bat_count   = len(batteries)
    ac_online   = any(a.get("ac_online") for a in ac_adapters)
    best_health = None
    worst_health = None
    for b in batteries:
        hp = b.get("health_percent")
        if hp is not None:
            best_health  = hp if best_health  is None else max(best_health,  hp)
            worst_health = hp if worst_health is None else min(worst_health, hp)

    cust = _CUSTOMER_MSGS.get(overall_verdict, f"Battery verdict: {overall_verdict}.")
    # If UNKNOWN and any battery reports 'Not charging', add that context so
    # the customer summary is not generic.
    if overall_verdict == "UNKNOWN":
        not_charging = [b for b in batteries if (b.get("status") or "").lower() == "not charging"]
        if not_charging:
            names = ", ".join(b["name"] for b in not_charging)
            cust = (
                f"Battery {names} is detected but its health could not be measured "
                f"because capacity telemetry was not available. "
                f"The battery is reporting 'Not charging'. "
                f"This may indicate a worn or failed battery, a faulty charger, or a "
                f"driver limitation. Physical testing is recommended."
            )
    if ac_online and overall_verdict in ("DEAD", "FAILING", "POOR"):
        cust += " AC power is currently connected."

    tech_parts = [
        f"overall={overall_verdict}",
        f"batteries={bat_count}",
    ]
    for b in batteries:
        tech_parts.append(
            f"{b['name']}: verdict={b['verdict']} "
            f"health={b.get('health_percent')}% "
            f"remaining={b.get('remaining_percent')}% "
            f"status={b.get('status')}"
        )
    if ac_adapters:
        tech_parts.append(f"ac_online={ac_online}")

    recs = _RECOMMENDED_ACTIONS.get(overall_verdict, ["Assess battery manually."])

    return {
        "customer_summary":   cust,
        "technician_summary": "  ".join(tech_parts),
        "what_this_means": (
            "Battery health is assessed by comparing current full-charge capacity "
            "against the original design capacity from sysfs. "
            "This is a read-only passive assessment — no charge/discharge cycling "
            "was performed."
        ),
        "confidence":        confidence,
        "limitations":       limitations,
        "recommended_action": recs[0] if recs else "Assess battery manually.",
        "all_recommendations": recs,
    }


# ---------------------------------------------------------------------------
# Confidence + limitations
# ---------------------------------------------------------------------------

def _assess_confidence(batteries: list[dict], ac_adapters: list[dict]) -> tuple[str, list[str]]:
    limitations: list[str] = []

    if not batteries:
        limitations.append("no_battery_detected")
        return "unknown", limitations

    telemetry_present = any(
        b.get("health_percent") is not None
        for b in batteries
    )
    all_have_telemetry = all(
        b.get("health_percent") is not None
        for b in batteries
    )

    if not telemetry_present:
        # Battery detected but no energy_full / charge_full / design capacity
        # data could be read — health_percent cannot be computed.
        limitations.append("battery_capacity_telemetry_unavailable")
        conf = "low"
    elif all_have_telemetry:
        conf = "high"
    else:
        limitations.append("partial_battery_telemetry")
        conf = "medium"

    limitations.append("live_test_not_performed")
    limitations.append("rescuezilla_linux_reading_only")

    if not ac_adapters:
        limitations.append("ac_adapter_status_unavailable")

    for b in batteries:
        if b.get("cycle_count") is None:
            limitations.append(f"cycle_count_unavailable_{b['name']}")
        if b.get("current_now") is None and b.get("power_now") is None:
            limitations.append(f"runtime_estimation_unavailable_{b['name']}")

    return conf, limitations


# ---------------------------------------------------------------------------
# Safety block
# ---------------------------------------------------------------------------

_SAFETY = {
    "read_only":              True,
    "destructive":            False,
    "charge_test_performed":  False,
    "discharge_test_performed": False,
    "write_test_performed":   False,
}


# ---------------------------------------------------------------------------
# Console report
# ---------------------------------------------------------------------------

def _print_report(result: dict) -> None:
    w = 64
    print("\n" + "=" * w)
    print("  BATTERY HEALTH")
    print("=" * w)

    acs = result.get("ac_adapters") or []
    for a in acs:
        online = "ONLINE" if a.get("ac_online") else "offline/unknown"
        print(f"\n  AC adapter : {a['name']}  ({online})")

    batteries = result.get("batteries") or []
    if not batteries:
        print("\n  No battery detected.")
        print("  (Machine may be a desktop, or battery is disconnected.)")
    else:
        for b in batteries:
            print(f"\n  Battery   : {b['name']}  "
                  f"{b.get('manufacturer') or ''}  {b.get('model_name') or ''}")
            if b.get("technology"):
                print(f"  Technology : {b['technology']}")
            print(f"  Status    : {b['status']}")
            if b["capacity_percent"] is not None:
                print(f"  Charge    : {b['capacity_percent']}%")
            if b.get("health_percent") is not None:
                print(f"  Health    : {b['health_percent']}% of design capacity")
            if b.get("full_capacity_available") is not None:
                print(f"  Full cap  : {b['full_capacity_available']} {b['unit']} "
                      f"/ {b['design_capacity_available']} {b['unit']} (design)")
            if b.get("cycle_count") is not None:
                print(f"  Cycles    : {b['cycle_count']}")
            if b.get("estimated_runtime_minutes") is not None:
                print(f"  Est. runtime : {b['estimated_runtime_minutes']:.0f} min")
            print(f"\n  Verdict   : {b['verdict']}")
            if b.get("flags"):
                print(f"  Flags     : {', '.join(b['flags'])}")

    print()
    ov = result.get("overall_verdict", "UNKNOWN")
    print(f"  Overall verdict : {ov}")
    interp = result.get("interpretation") or {}
    if interp.get("customer_summary"):
        print(f"\n  {interp['customer_summary']}")
    for rec in (interp.get("all_recommendations") or []):
        print(f"  → {rec}")
    print("\n" + "=" * w + "\n")


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    parser = argparse.ArgumentParser(
        prog="m10_battery_health",
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--target", default="/mnt/windows",
        help="Path to mounted Windows installation (used for context only)",
    )
    parser.add_argument(
        "--json-only", action="store_true",
        help="Skip console report; write JSON log only",
    )
    args = parser.parse_args(argv)

    print("[m10] Reading power supply info from /sys/class/power_supply/ ...", flush=True)
    batteries, ac_adapters = _find_power_supplies()

    print(f"[m10] Found {len(batteries)} battery device(s), "
          f"{len(ac_adapters)} AC adapter(s)", flush=True)

    overall_verdict = _overall_verdict(batteries)
    confidence, limitations = _assess_confidence(batteries, ac_adapters)
    interpretation = _build_interpretation(
        overall_verdict, batteries, ac_adapters, confidence, limitations
    )

    result: dict = {
        "generated":       datetime.now(timezone.utc).isoformat(),
        "target":          args.target,
        "overall_verdict": overall_verdict,
        "confidence":      confidence,
        "limitations":     limitations,
        "interpretation":  interpretation,
        "safety":          _SAFETY,
        "batteries":       batteries,
        "ac_adapters":     ac_adapters,
    }

    if not args.json_only:
        _print_report(result)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = logs_dir / f"battery_health_{ts}.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[m10] Log written → {out}", flush=True)
    return 0
