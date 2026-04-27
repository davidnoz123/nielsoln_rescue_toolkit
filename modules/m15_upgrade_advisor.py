"""
m15_upgrade_advisor.py — Nielsoln Rescue Toolkit: hardware upgrade advisor.

Synthesises data from previous module runs (hardware_profile, disk_health,
thermal_health) plus direct live reads to produce a prioritised upgrade
recommendation list with benefit estimates.

This module reads live hardware and module log files — not the mounted Windows
installation.  No --target argument is needed or accepted.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m15_upgrade_advisor

Output:
    Prints a prioritised recommendations table to stdout.
    Writes a JSON summary to <USB>/logs/upgrade_advisor_<timestamp>.json
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("upgrade_advisor")

DESCRIPTION = (
    "Upgrade advisor: synthesises hardware profile, disk health, and thermal "
    "data to produce prioritised upgrade recommendations (SSD, RAM, thermal "
    "service, battery, OS) with benefit ratings — live hardware, no --target"
)

# ---------------------------------------------------------------------------
# Benefit / urgency constants
# ---------------------------------------------------------------------------

_BENEFIT   = ("critical", "high", "medium", "low", "none")
_URGENCY   = ("immediate", "soon", "when_budget_allows", "optional", "not_needed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path: str | Path, default: str = "") -> str:
    try:
        return Path(path).read_text(errors="replace").strip()
    except Exception:
        return default


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as exc:
        return -1, str(exc)


def _latest_log(log_dir: Path, prefix: str) -> dict | None:
    """Return parsed JSON from the most recent log matching prefix_*.json."""
    if not log_dir.exists():
        return None
    matches = sorted(log_dir.glob(f"{prefix}_*.json"), reverse=True)
    if not matches:
        return None
    try:
        return json.loads(matches[0].read_text())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Data collection — live fallbacks when module logs are absent
# ---------------------------------------------------------------------------

def _get_ram_gib() -> float:
    """Total RAM in GiB from /proc/meminfo."""
    raw = _read("/proc/meminfo")
    m = re.search(r"MemTotal:\s+(\d+)\s+kB", raw)
    if m:
        return round(int(m.group(1)) / (1024 ** 2), 1)
    return 0.0


def _get_disk_type_and_model() -> tuple[str, str]:
    """Best-guess primary disk type (HDD/SSD/NVMe) and model from sysfs."""
    block = Path("/sys/block")
    if not block.exists():
        return "unknown", "unknown"
    for name in sorted(block.iterdir()):
        n = name.name
        if re.match(r"^(loop|ram|dm|sr|fd|nbd)", n):
            continue
        # Skip USB sticks (removable)
        if _read(name / "removable", "0") == "1":
            continue
        rotational = _read(name / "queue" / "rotational", "")
        model = _read(name / "device" / "model",
                      _read(name / "device" / "name", "unknown")).strip()
        if n.startswith("nvme"):
            return "NVMe SSD", model
        elif rotational == "0":
            return "SSD", model
        elif rotational == "1":
            return "HDD", model
    return "unknown", "unknown"


def _get_bios_year() -> int | None:
    """BIOS date year from DMI sysfs."""
    raw = _read("/sys/class/dmi/id/bios_date", "")
    # Format: MM/DD/YYYY or DD/MM/YYYY
    m = re.search(r"(\d{4})", raw)
    if m:
        y = int(m.group(1))
        if 1990 < y < 2100:
            return y
    return None


def _get_cpu_name() -> str:
    raw = _read("/proc/cpuinfo")
    m = re.search(r"model name\s*:\s*(.+)", raw)
    return m.group(1).strip() if m else "unknown"


def _get_battery_present() -> bool:
    """Check if any battery is present via /sys/class/power_supply."""
    ps = Path("/sys/class/power_supply")
    if not ps.exists():
        return False
    for entry in ps.iterdir():
        if _read(entry / "type", "").lower() == "battery":
            return True
    return False


def _get_battery_health_pct() -> int | None:
    """Return battery wear percentage (0=new, 100=dead) or None if unavailable."""
    ps = Path("/sys/class/power_supply")
    if not ps.exists():
        return None
    for entry in ps.iterdir():
        if _read(entry / "type", "").lower() != "battery":
            continue
        design = _read(entry / "energy_full_design", "")
        full   = _read(entry / "energy_full", "")
        if not design or not full:
            # Try charge_ variants
            design = _read(entry / "charge_full_design", "")
            full   = _read(entry / "charge_full", "")
        try:
            d, f = int(design), int(full)
            if d > 0:
                wear = max(0, round((1 - f / d) * 100))
                return wear
        except (ValueError, ZeroDivisionError):
            pass
    return None


# ---------------------------------------------------------------------------
# Assessment functions — each returns a recommendation dict
# ---------------------------------------------------------------------------

def _assess_storage(disk_log: dict | None) -> dict:
    """SSD upgrade recommendation."""
    rec = {
        "category": "Storage upgrade (HDD → SSD)",
        "benefit": "unknown",
        "urgency": "unknown",
        "evidence": [],
        "recommendation": "",
        "confidence": "medium",
    }

    # Pull from disk_health log if available
    disk_type = "unknown"
    clone_urgency = "none"
    smart_verdict = "unknown"
    model = "unknown"

    # disk_health log is a plain list of device dicts
    disk_devices = disk_log if isinstance(disk_log, list) else disk_log.get("devices", []) if disk_log else []

    if disk_devices:
        for dev in disk_devices:
            if dev.get("device", "").startswith("/dev/sd") or dev.get("device", "").startswith("/dev/nvme"):
                if _read(f"/sys/block/{Path(dev['device']).name}/removable", "0") != "1":
                    disk_type   = dev.get("type", "unknown")
                    clone_urgency = dev.get("clone_urgency", "none")
                    smart_verdict = dev.get("overall_verdict", "unknown")
                    model       = dev.get("model", "unknown")
                    break

    if disk_type == "unknown":
        disk_type, model = _get_disk_type_and_model()

    rec["evidence"].append(f"Primary disk: {model} ({disk_type})")
    if smart_verdict not in ("unknown", ""):
        rec["evidence"].append(f"SMART verdict: {smart_verdict}")

    if disk_type in ("NVMe SSD", "SSD"):
        rec["benefit"]        = "none"
        rec["urgency"]        = "not_needed"
        rec["recommendation"] = "Already running SSD — no storage upgrade needed."
        rec["confidence"]     = "high"
    elif disk_type == "HDD":
        if smart_verdict == "FAILING" or clone_urgency == "immediate":
            rec["benefit"]        = "critical"
            rec["urgency"]        = "immediate"
            rec["recommendation"] = (
                "HDD is FAILING — replace with SSD immediately before data loss. "
                "Clone to SSD now if any data can be saved."
            )
            rec["confidence"]     = "high"
        elif smart_verdict == "CAUTION" or clone_urgency == "soon":
            rec["benefit"]        = "high"
            rec["urgency"]        = "soon"
            rec["recommendation"] = (
                "HDD shows wear indicators. Replace with SSD: the machine will boot "
                "3–5× faster, run cooler, and be far more reliable.  Clone before "
                "the drive fails further."
            )
            rec["confidence"]     = "high"
        else:
            rec["benefit"]        = "high"
            rec["urgency"]        = "when_budget_allows"
            rec["recommendation"] = (
                "HDD detected — upgrading to a 2.5\" SATA SSD (e.g. 240–480 GB) is "
                "the single highest-impact upgrade for this machine."
            )
            rec["confidence"]     = "high"
    else:
        rec["benefit"]        = "unknown"
        rec["urgency"]        = "unknown"
        rec["recommendation"] = "Could not determine disk type. Run m05_disk_health first."
        rec["confidence"]     = "low"

    return rec


def _assess_ram(hw_log: dict | None) -> dict:
    rec = {
        "category": "RAM upgrade",
        "benefit": "unknown",
        "urgency": "unknown",
        "evidence": [],
        "recommendation": "",
        "confidence": "medium",
    }

    ram_gib = 0.0
    max_ram_gib = None

    if hw_log:
        ram_gib = hw_log.get("ram", {}).get("total_gib", 0.0)
        max_raw = hw_log.get("ram", {}).get("max_capacity_gib")
        if max_raw:
            try:
                max_ram_gib = float(max_raw)
            except (ValueError, TypeError):
                pass

    if not ram_gib:
        ram_gib = _get_ram_gib()

    rec["evidence"].append(f"Installed RAM: {ram_gib} GiB")
    if max_ram_gib:
        rec["evidence"].append(f"Max supported RAM: {max_ram_gib} GiB")

    if ram_gib <= 0:
        rec["benefit"]        = "unknown"
        rec["urgency"]        = "unknown"
        rec["recommendation"] = "Could not determine RAM — run m04_hardware_profile first."
        rec["confidence"]     = "low"
    elif ram_gib < 2:
        rec["benefit"]        = "high"
        rec["urgency"]        = "soon"
        rec["recommendation"] = (
            f"Only {ram_gib} GiB RAM — modern usage (browser, email) needs at least 4 GiB. "
            "Upgrade to maximum supported."
        )
        rec["confidence"]     = "high"
    elif ram_gib < 4:
        if max_ram_gib and max_ram_gib > ram_gib:
            rec["benefit"]        = "medium"
            rec["urgency"]        = "when_budget_allows"
            rec["recommendation"] = (
                f"{ram_gib} GiB RAM — usable but tight for Windows 10/11. "
                f"Board supports up to {max_ram_gib} GiB; upgrading would noticeably improve multitasking."
            )
            rec["confidence"]     = "high"
        else:
            rec["benefit"]        = "low"
            rec["urgency"]        = "optional"
            rec["recommendation"] = (
                f"{ram_gib} GiB RAM is at or near the board maximum. "
                "No RAM upgrade possible on this hardware."
            )
            rec["confidence"]     = "medium"
    else:
        rec["benefit"]        = "none"
        rec["urgency"]        = "not_needed"
        rec["recommendation"] = f"{ram_gib} GiB RAM — sufficient for typical use."
        rec["confidence"]     = "high"

    return rec


def _assess_thermal(thermal_log: dict | None) -> dict:
    rec = {
        "category": "Thermal service (clean + thermal paste)",
        "benefit": "unknown",
        "urgency": "unknown",
        "evidence": [],
        "recommendation": "",
        "confidence": "medium",
    }

    verdict = "unknown"
    if thermal_log:
        verdict = thermal_log.get("verdict", "unknown")
        for w in thermal_log.get("warnings", []):
            rec["evidence"].append(w)
        throttled = thermal_log.get("cpu_throttle", {}).get("throttled", False)
        if throttled:
            cur = thermal_log.get("cpu_throttle", {}).get("cur_mhz", "?")
            mx  = thermal_log.get("cpu_throttle", {}).get("max_mhz", "?")
            rec["evidence"].append(f"CPU throttled: {cur} MHz / {mx} MHz")

    bios_year = _get_bios_year()
    if bios_year:
        age = datetime.now().year - bios_year
        rec["evidence"].append(f"Machine age: ~{age} years (BIOS {bios_year})")

    if verdict == "CRITICAL":
        rec["benefit"]        = "critical"
        rec["urgency"]        = "immediate"
        rec["recommendation"] = (
            "Machine is critically overheating. Do not use until heatsink is cleaned "
            "and thermal paste is replaced. Risk of permanent CPU/GPU damage."
        )
        rec["confidence"]     = "high"
    elif verdict == "HOT":
        rec["benefit"]        = "high"
        rec["urgency"]        = "soon"
        rec["recommendation"] = (
            "Machine is running hot. Clean the heatsink and fan. "
            "Replace thermal paste (especially if 5+ years old)."
        )
        rec["confidence"]     = "high"
    elif verdict == "WARM":
        rec["benefit"]        = "medium"
        rec["urgency"]        = "when_budget_allows"
        rec["recommendation"] = (
            "Machine is warm at idle. A heatsink clean and fresh thermal paste would "
            "reduce temperatures, extend lifespan, and remove throttling."
        )
        rec["confidence"]     = "high"
    elif verdict == "HEALTHY":
        rec["benefit"]        = "low"
        rec["urgency"]        = "optional"
        rec["recommendation"] = "Temperatures are within normal range at idle."
        rec["confidence"]     = "medium"
    else:
        if bios_year and (datetime.now().year - bios_year) >= 8:
            rec["benefit"]        = "medium"
            rec["urgency"]        = "when_budget_allows"
            rec["recommendation"] = (
                "Machine is 8+ years old — thermal paste is likely dried out even if "
                "no sensor data is available.  Preventive clean recommended."
            )
            rec["confidence"]     = "low"
        else:
            rec["benefit"]        = "unknown"
            rec["urgency"]        = "unknown"
            rec["recommendation"] = "Run m09_thermal_health for thermal data."
            rec["confidence"]     = "low"

    return rec


def _assess_battery() -> dict:
    rec = {
        "category": "Battery replacement",
        "benefit": "unknown",
        "urgency": "unknown",
        "evidence": [],
        "recommendation": "",
        "confidence": "medium",
    }

    present = _get_battery_present()
    if not present:
        rec["benefit"]        = "none"
        rec["urgency"]        = "not_needed"
        rec["recommendation"] = "No battery detected (desktop or battery removed)."
        rec["confidence"]     = "high"
        return rec

    wear = _get_battery_health_pct()
    bios_year = _get_bios_year()

    if wear is not None:
        rec["evidence"].append(f"Battery wear: {wear}%")
    if bios_year:
        age = datetime.now().year - bios_year
        rec["evidence"].append(f"Machine age: ~{age} years")

    if wear is not None:
        if wear >= 70:
            rec["benefit"]        = "high"
            rec["urgency"]        = "soon"
            rec["recommendation"] = (
                f"Battery is {wear}% worn — capacity severely reduced. "
                "Replace battery or advise client laptop must stay plugged in."
            )
            rec["confidence"]     = "high"
        elif wear >= 40:
            rec["benefit"]        = "medium"
            rec["urgency"]        = "when_budget_allows"
            rec["recommendation"] = (
                f"Battery is {wear}% worn — noticeably reduced runtime. "
                "Replacement worthwhile if the machine is used away from power."
            )
            rec["confidence"]     = "high"
        else:
            rec["benefit"]        = "low"
            rec["urgency"]        = "optional"
            rec["recommendation"] = f"Battery wear at {wear}% — still reasonable capacity."
            rec["confidence"]     = "high"
    else:
        # No wear data — age-based guess
        if bios_year and (datetime.now().year - bios_year) >= 8:
            rec["benefit"]        = "medium"
            rec["urgency"]        = "when_budget_allows"
            rec["recommendation"] = (
                "Battery data unavailable, but machine is 8+ years old. "
                "Original battery is likely significantly degraded — test runtime and advise replacement if short."
            )
            rec["confidence"]     = "low"
        else:
            rec["recommendation"] = "Battery present but wear data unavailable. Run m10_battery_health for details."
            rec["confidence"]     = "low"

    return rec


def _assess_os(hw_log: dict | None) -> dict:
    rec = {
        "category": "Operating system upgrade",
        "benefit": "unknown",
        "urgency": "unknown",
        "evidence": [],
        "recommendation": "",
        "confidence": "medium",
    }

    # Check Windows version from DMI product name / BIOS date (rough proxy)
    # The real OS version comes from the mounted Windows target, not live hardware.
    # We note this limitation and recommend m02_detect / m03_triage data instead.
    bios_year = _get_bios_year()
    cpu = _get_cpu_name()
    ram_gib = _get_ram_gib()

    if bios_year:
        rec["evidence"].append(f"BIOS year: {bios_year}")
    rec["evidence"].append(f"CPU: {cpu}")
    rec["evidence"].append(f"RAM: {ram_gib} GiB")

    win11_capable = ram_gib >= 4  # Simplified — TPM/SecureBoot not checked offline

    rec["evidence"].append("Note: full OS compatibility check requires booted Windows environment")

    if bios_year and bios_year < 2012:
        rec["benefit"]        = "high"
        rec["urgency"]        = "soon"
        rec["recommendation"] = (
            "Machine is running a pre-2012 BIOS — likely Windows Vista/7/8, all now "
            "end-of-life and receiving no security updates. Upgrade to Windows 10 LTSC "
            "or Linux Mint for continued safe use. Windows 11 is unlikely to be "
            "supported on this hardware (no TPM 2.0, older CPU)."
        )
        rec["confidence"]     = "medium"
    elif not win11_capable:
        rec["benefit"]        = "medium"
        rec["urgency"]        = "when_budget_allows"
        rec["recommendation"] = (
            f"With {ram_gib} GiB RAM, Windows 11 is borderline. "
            "Windows 10 LTSC or Linux Mint are practical options for extended life."
        )
        rec["confidence"]     = "low"
    else:
        rec["benefit"]        = "medium"
        rec["urgency"]        = "when_budget_allows"
        rec["recommendation"] = (
            "Consider upgrading to Windows 10/11 or Linux Mint to maintain security support."
        )
        rec["confidence"]     = "low"

    return rec


def _assess_replace_vs_repair(hw_log: dict | None, recs: list[dict]) -> dict:
    """Overall verdict — replace vs repair."""
    rec = {
        "category": "Replace vs repair decision",
        "benefit": "informational",
        "urgency": "informational",
        "evidence": [],
        "recommendation": "",
        "confidence": "medium",
    }

    bios_year = _get_bios_year()
    ram_gib = _get_ram_gib()
    age = (datetime.now().year - bios_year) if bios_year else None

    if age:
        rec["evidence"].append(f"Machine age: ~{age} years")
    rec["evidence"].append(f"RAM: {ram_gib} GiB")

    # Count high/critical benefit items (excluding this one)
    critical_count = sum(1 for r in recs if r.get("benefit") in ("critical", "high"))
    total_cost_signal = critical_count

    if age and age >= 15:
        rec["recommendation"] = (
            f"Machine is ~{age} years old. Even with upgrades, longevity is limited. "
            "If the primary goal is reliable daily use, a modern refurbished laptop "
            f"(NZ$300–600) would be more cost-effective than investing in multiple upgrades."
        )
        rec["confidence"] = "medium"
    elif age and age >= 10:
        rec["recommendation"] = (
            f"Machine is ~{age} years old. An SSD upgrade and thermal service are "
            "worthwhile for extended life (2–4 more years). If {critical_count} major "
            "issues need fixing simultaneously, weigh cost against a refurbished replacement."
        )
        rec["confidence"] = "medium"
    else:
        rec["recommendation"] = (
            "Machine is young enough that targeted upgrades (SSD, thermal service) "
            "offer good value for money."
        )
        rec["confidence"] = "medium"

    return rec


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

_BENEFIT_ICON = {
    "critical": "!!!",
    "high":     " !! ",
    "medium":   " ~~ ",
    "low":      " -- ",
    "none":     " OK ",
    "unknown":  "  ? ",
    "informational": " >> ",
}

_URGENCY_LABEL = {
    "immediate":          "IMMEDIATE",
    "soon":               "Soon",
    "when_budget_allows": "When budget allows",
    "optional":           "Optional",
    "not_needed":         "Not needed",
    "unknown":            "Unknown",
    "informational":      "",
}


def _fmt_report(recs: list[dict]) -> str:
    lines = [
        "=" * 64,
        "  UPGRADE ADVISOR",
        "=" * 64,
    ]

    for r in recs:
        icon    = _BENEFIT_ICON.get(r["benefit"], "  ? ")
        urgency = _URGENCY_LABEL.get(r["urgency"], r["urgency"])
        conf    = r.get("confidence", "")
        lines.append(f"  [{icon}] {r['category']}")
        if urgency:
            lines.append(f"          Urgency    : {urgency}")
        lines.append(f"          Confidence : {conf}")
        for ev in r.get("evidence", []):
            lines.append(f"          Evidence   : {ev}")
        lines.append(f"          {r['recommendation']}")
        lines.append("")

    lines.append("=" * 64)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="bootstrap run m15_upgrade_advisor",
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--json-only", action="store_true",
        help="Suppress formatted report; only write JSON log"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _log.info("Running upgrade assessment …")

    log_dir = root / "logs"

    # Load previous module outputs (best-effort)
    hw_log      = _latest_log(log_dir, "hardware_profile")
    disk_log    = _latest_log(log_dir, "disk_health")
    thermal_log = _latest_log(log_dir, "thermal_health")

    if hw_log:
        _log.info("Using hardware_profile log: %s", sorted((log_dir).glob("hardware_profile_*.json"), reverse=True)[0].name)
    if disk_log:
        _log.info("Using disk_health log: %s", sorted((log_dir).glob("disk_health_*.json"), reverse=True)[0].name)
    if thermal_log:
        _log.info("Using thermal_health log: %s", sorted((log_dir).glob("thermal_health_*.json"), reverse=True)[0].name)

    # Build recommendations
    recs = [
        _assess_storage(disk_log),
        _assess_ram(hw_log),
        _assess_thermal(thermal_log),
        _assess_battery(),
        _assess_os(hw_log),
    ]
    recs.append(_assess_replace_vs_repair(hw_log, recs))

    # Sort: critical → high → medium → low → none → unknown → informational
    _order = {b: i for i, b in enumerate(_BENEFIT + ("informational",))}
    recs.sort(key=lambda r: _order.get(r["benefit"], 99))

    # Print
    if not args.json_only:
        print(_fmt_report(recs))

    # Write JSON log
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"upgrade_advisor_{timestamp}.json"
    log_path.write_text(json.dumps({
        "timestamp": timestamp,
        "recommendations": recs,
        "sources": {
            "hardware_profile": bool(hw_log),
            "disk_health":      bool(disk_log),
            "thermal_health":   bool(thermal_log),
        },
    }, indent=2))
    _log.info("Report written to %s", log_path)

    # Exit 1 if any critical finding
    return 1 if any(r["benefit"] == "critical" for r in recs) else 0
