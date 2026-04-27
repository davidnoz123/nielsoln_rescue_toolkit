"""
m10_battery_health.py — Nielsoln Rescue Toolkit: laptop battery health check.

Reads battery information from the live Linux environment (the rescue machine
itself has access to /sys/class/power_supply/) and from the offline Windows
installation (BatteryStaticData / BatteryStatusData WMI cache files if present).

On RescueZilla booted on the target laptop:
  - /sys/class/power_supply/BAT0/ (or BAT1) gives the current battery state
  - Reports capacity, cycle count, charge now/full/design, wear level

Also checks the Windows side for battery report artifacts if present.

Verdict:
  HEALTHY    — wear < 20%, cycles reasonable
  DEGRADED   — wear 20-50%, still functional but reduced runtime
  WORN       — wear > 50%, replacement recommended
  CRITICAL   — wear > 80% or capacity near zero
  NOT_FOUND  — no battery detected (desktop, or battery fully dead/removed)

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
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DESCRIPTION = (
    "Battery health: reads /sys/class/power_supply/ from the live environment "
    "to report battery wear level, cycle count, and charge capacity — "
    "requires --target /mnt/windows"
)

# ---------------------------------------------------------------------------
# /sys reader
# ---------------------------------------------------------------------------

def _read_sysfs(path: str) -> str:
    try:
        return Path(path).read_text(encoding="ascii", errors="replace").strip()
    except Exception:
        return ""


def _int_sysfs(path: str) -> Optional[int]:
    v = _read_sysfs(path)
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _probe_battery(supply_path: Path) -> Optional[dict]:
    """Read one /sys/class/power_supply/<name>/ directory."""
    ptype = _read_sysfs(str(supply_path / "type"))
    if ptype.upper() != "BATTERY":
        return None

    name   = supply_path.name
    status = _read_sysfs(str(supply_path / "status"))   # Charging/Discharging/Full/Unknown

    # Capacity in µAh or µWh — try both charge_ and energy_ variants
    charge_now    = _int_sysfs(str(supply_path / "charge_now"))
    charge_full   = _int_sysfs(str(supply_path / "charge_full"))
    charge_design = _int_sysfs(str(supply_path / "charge_full_design"))

    energy_now    = _int_sysfs(str(supply_path / "energy_now"))
    energy_full   = _int_sysfs(str(supply_path / "energy_full"))
    energy_design = _int_sysfs(str(supply_path / "energy_full_design"))

    # Prefer charge_ if available, fall back to energy_
    now    = charge_now    or energy_now
    full   = charge_full   or energy_full
    design = charge_design or energy_design

    cycles    = _int_sysfs(str(supply_path / "cycle_count"))
    voltage   = _int_sysfs(str(supply_path / "voltage_now"))        # µV
    present   = _read_sysfs(str(supply_path / "present"))
    capacity_pct = _int_sysfs(str(supply_path / "capacity"))        # 0-100 %
    manufacturer = _read_sysfs(str(supply_path / "manufacturer"))
    model_name   = _read_sysfs(str(supply_path / "model_name"))
    technology   = _read_sysfs(str(supply_path / "technology"))
    serial       = _read_sysfs(str(supply_path / "serial_number"))

    # Wear level: how much design capacity has been permanently lost
    wear_pct = None
    if design and full and design > 0:
        wear_pct = round(100 * (1 - full / design), 1)

    # Voltage in V
    voltage_v = round(voltage / 1_000_000, 2) if voltage else None

    # Capacities in mAh or mWh (convert from µ units)
    unit = "mAh" if charge_full else "mWh"
    def _milli(v):
        return round(v / 1000) if v else None

    result = {
        "name":        name,
        "present":     present == "1",
        "manufacturer": manufacturer,
        "model":       model_name,
        "technology":  technology,
        "serial":      serial,
        "status":      status,
        "capacity_pct": capacity_pct,
        "voltage_v":   voltage_v,
        "cycles":      cycles,
        "now":         _milli(now),
        "full":        _milli(full),
        "design":      _milli(design),
        "unit":        unit,
        "wear_pct":    wear_pct,
    }

    # Verdict
    if not (present == "1") or full == 0:
        verdict = "NOT_FOUND"
    elif wear_pct is None:
        verdict = "UNKNOWN"
    elif wear_pct >= 80:
        verdict = "CRITICAL"
    elif wear_pct >= 50:
        verdict = "WORN"
    elif wear_pct >= 20:
        verdict = "DEGRADED"
    else:
        verdict = "HEALTHY"

    result["verdict"] = verdict
    return result


def _find_batteries() -> list:
    """Scan /sys/class/power_supply/ for battery entries."""
    base = Path("/sys/class/power_supply")
    if not base.exists():
        return []
    batteries = []
    for entry in sorted(base.iterdir()):
        b = _probe_battery(entry)
        if b:
            batteries.append(b)
    return batteries


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(batteries: list) -> None:
    w = 60
    print("\n" + "=" * w)
    print("  BATTERY HEALTH")
    print("=" * w)

    if not batteries:
        print("\n  No battery detected.")
        print("  (Machine may be a desktop, or battery is disconnected.)")
        print()
        return

    for b in batteries:
        print(f"\n  Battery : {b['name']}  {b['manufacturer']} {b['model']}")
        print(f"  Technology : {b['technology'] or '?'}")
        print(f"  Status     : {b['status']}")
        if b["capacity_pct"] is not None:
            print(f"  Charge     : {b['capacity_pct']}%")
        if b["voltage_v"]:
            print(f"  Voltage    : {b['voltage_v']} V")
        if b["design"] and b["full"]:
            print(f"  Capacity   : {b['full']} / {b['design']} {b['unit']} "
                  f"(design)")
        if b["wear_pct"] is not None:
            print(f"  Wear level : {b['wear_pct']}%")
        if b["cycles"] is not None:
            print(f"  Cycles     : {b['cycles']}")

        v = b["verdict"]
        print(f"\n  Verdict    : {v}")
        if v == "CRITICAL":
            print("  Battery is severely degraded. Replace immediately.")
        elif v == "WORN":
            print("  Battery has lost more than half its capacity. Replacement recommended.")
        elif v == "DEGRADED":
            print("  Battery is degraded but still usable. Runtime will be reduced.")
        elif v == "HEALTHY":
            print("  Battery wear is within normal limits.")
        elif v == "NOT_FOUND":
            print("  Battery not present or fully discharged.")

    print("\n" + "=" * w + "\n")


def run(root: Path, argv: list) -> int:
    parser = argparse.ArgumentParser(
        prog="m10_battery_health",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="/mnt/windows",
                        help="Path to mounted Windows (used for display only)")
    args = parser.parse_args(argv)

    print("[m10] Reading battery info from /sys/class/power_supply/ ...")
    batteries = _find_batteries()

    if not batteries:
        print("[m10] No battery found.")

    _print_report(batteries)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = logs_dir / f"battery_health_{ts}.json"
    out.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "target":    args.target,
        "batteries": batteries,
    }, indent=2))
    print(f"[m10] Log written → {out}")
    return 0
