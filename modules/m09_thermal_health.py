"""
m09_thermal_health.py — Nielsoln Rescue Toolkit: thermal health assessment.

Reads live hardware temperature sensors, fan data, and CPU throttling
indicators from /sys/class/hwmon, /sys/class/thermal, /proc/cpuinfo, and
optionally `sensors` (lm-sensors).  No --target argument is needed.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m09_thermal_health

Output:
    Prints a formatted report to stdout.
    Writes a JSON summary to <USB>/logs/thermal_health_<timestamp>.json
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("thermal_health")

DESCRIPTION = (
    "Thermal health: temperature sensors, fan data, CPU throttle state — "
    "detects overheating risk and recommends maintenance actions "
    "(live hardware — no --target needed)"
)

# ---------------------------------------------------------------------------
# Temperature thresholds (°C)
# ---------------------------------------------------------------------------

_CPU_WARN   = 75   # sustained idle warn
_CPU_CRIT   = 90   # critical / throttle risk
_GPU_WARN   = 80
_DISK_WARN  = 50
_DISK_CRIT  = 55
_GENERIC_WARN = 70
_GENERIC_CRIT = 85

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.returncode, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        return -1, f"command not found: {cmd[0]}"
    except Exception as exc:
        return -1, str(exc)


def _read(path: str | Path, default: str = "") -> str:
    try:
        return Path(path).read_text(errors="replace").strip()
    except Exception:
        return default


def _millideg_to_c(raw: str) -> float | None:
    """Convert a sysfs millidegree string to °C float, or None."""
    try:
        v = int(raw)
        # sysfs thermal zone temps are in millidegrees; hwmon may be too
        if v > 1000:
            return v / 1000.0
        return float(v)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# /sys/class/hwmon sensor collection
# ---------------------------------------------------------------------------

def _collect_hwmon() -> list[dict]:
    """Read all hwmon chips — temperatures and fan RPM."""
    results = []
    hwmon_root = Path("/sys/class/hwmon")
    if not hwmon_root.exists():
        return results

    for chip_dir in sorted(hwmon_root.iterdir()):
        chip_name = _read(chip_dir / "name", chip_dir.name)

        # --- temperatures ---
        for temp_input in sorted(chip_dir.glob("temp*_input")):
            label_file = temp_input.parent / temp_input.name.replace("_input", "_label")
            label = _read(label_file, "").strip() or temp_input.name.replace("_input", "")
            raw = _read(temp_input)
            temp_c = _millideg_to_c(raw)
            if temp_c is None:
                continue
            # Read optional crit/max
            crit_raw = _read(temp_input.parent / temp_input.name.replace("_input", "_crit"), "")
            max_raw  = _read(temp_input.parent / temp_input.name.replace("_input", "_max"), "")
            crit_c = _millideg_to_c(crit_raw)
            max_c  = _millideg_to_c(max_raw)
            results.append({
                "source": "hwmon",
                "chip":   chip_name,
                "label":  label,
                "kind":   "temperature",
                "value_c": round(temp_c, 1),
                "crit_c":  round(crit_c, 1) if crit_c is not None else None,
                "max_c":   round(max_c,  1) if max_c  is not None else None,
            })

        # --- fans ---
        for fan_input in sorted(chip_dir.glob("fan*_input")):
            label_file = fan_input.parent / fan_input.name.replace("_input", "_label")
            label = _read(label_file, "").strip() or fan_input.name.replace("_input", "")
            raw = _read(fan_input)
            try:
                rpm = int(raw)
            except ValueError:
                continue
            results.append({
                "source": "hwmon",
                "chip":   chip_name,
                "label":  label,
                "kind":   "fan",
                "rpm":    rpm,
            })

    return results


# ---------------------------------------------------------------------------
# /sys/class/thermal zone collection
# ---------------------------------------------------------------------------

def _collect_thermal_zones() -> list[dict]:
    thermal_root = Path("/sys/class/thermal")
    results = []
    if not thermal_root.exists():
        return results

    for zone in sorted(thermal_root.glob("thermal_zone*")):
        zone_type = _read(zone / "type", zone.name)
        temp_raw  = _read(zone / "temp", "")
        temp_c    = _millideg_to_c(temp_raw)
        if temp_c is None:
            continue
        policy = _read(zone / "policy", "")
        results.append({
            "source":  "thermal_zone",
            "zone":    zone.name,
            "type":    zone_type,
            "value_c": round(temp_c, 1),
            "policy":  policy,
        })

    return results


# ---------------------------------------------------------------------------
# CPU throttle / frequency scaling state
# ---------------------------------------------------------------------------

def _collect_cpu_throttle() -> dict:
    """Check cpufreq governor and any throttle flag in /proc/cpuinfo."""
    info: dict = {}

    # Governor for CPU0
    gov_path = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    info["governor"] = _read(gov_path, "unavailable")

    # Current vs max frequency
    cur_path = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
    max_path = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq")
    cur_khz = _read(cur_path, "")
    max_khz = _read(max_path, "")
    try:
        info["cur_mhz"] = round(int(cur_khz) / 1000)
        info["max_mhz"] = round(int(max_khz) / 1000)
        info["throttled"] = info["cur_mhz"] < (info["max_mhz"] * 0.7)
    except (ValueError, KeyError):
        info["throttled"] = False

    # Check /proc/cpuinfo for "cpu MHz"
    cpuinfo = _read("/proc/cpuinfo")
    freqs = re.findall(r"cpu MHz\s*:\s*([\d.]+)", cpuinfo)
    if freqs:
        mhz_vals = [float(f) for f in freqs]
        info["cpuinfo_mhz_min"] = round(min(mhz_vals))
        info["cpuinfo_mhz_max"] = round(max(mhz_vals))

    return info


# ---------------------------------------------------------------------------
# `sensors` command (lm-sensors) — best-effort supplement
# ---------------------------------------------------------------------------

def _collect_sensors_cmd() -> list[str]:
    """Run `sensors` and return raw output lines (empty if not available)."""
    rc, out = _run(["sensors"])
    if rc == 0 and out:
        return out.splitlines()
    return []


# ---------------------------------------------------------------------------
# Classify sensor readings into findings
# ---------------------------------------------------------------------------

def _classify_sensors(readings: list[dict]) -> list[dict]:
    """
    For each temperature reading, determine severity:
    ok / warn / critical.
    """
    findings = []
    for r in readings:
        if r.get("kind") != "temperature":
            continue
        temp = r["value_c"]
        label_lower = r.get("label", "").lower()
        chip_lower  = r.get("chip",  "").lower()

        # Pick thresholds based on context
        if any(k in label_lower or k in chip_lower for k in ("core", "cpu", "package")):
            warn, crit = _CPU_WARN, _CPU_CRIT
            category = "CPU"
        elif any(k in label_lower or k in chip_lower for k in ("gpu", "vga", "graphics")):
            warn, crit = _GPU_WARN, _GPU_CRIT
            category = "GPU"
        elif any(k in label_lower or k in chip_lower for k in ("disk", "drive", "hdd", "ssd")):
            warn, crit = _DISK_WARN, _DISK_CRIT
            category = "Disk"
        else:
            warn, crit = _GENERIC_WARN, _GENERIC_CRIT
            category = "Sensor"

        # Use device-reported crit threshold if present and tighter
        dev_crit = r.get("crit_c")
        if dev_crit is not None:
            crit = min(crit, dev_crit)
            warn = min(warn, crit - 10)

        if temp >= crit:
            severity = "critical"
        elif temp >= warn:
            severity = "warn"
        else:
            severity = "ok"

        findings.append({
            **r,
            "category": category,
            "severity": severity,
            "warn_threshold": warn,
            "crit_threshold": crit,
        })

    return findings


# ---------------------------------------------------------------------------
# Overall verdict
# ---------------------------------------------------------------------------

def _derive_verdict(findings: list[dict], fans: list[dict], throttle: dict) -> tuple[str, list[str], list[str]]:
    """
    Returns (verdict, warnings_list, recommendations_list).
    verdict: HEALTHY | WARM | HOT | CRITICAL
    """
    warnings: list[str] = []
    recs: list[str] = []

    critical_temps = [f for f in findings if f.get("severity") == "critical"]
    warn_temps     = [f for f in findings if f.get("severity") == "warn"]

    for f in critical_temps:
        warnings.append(
            f"{f['category']} sensor '{f['label']}' is critically hot: {f['value_c']}°C"
        )
    for f in warn_temps:
        warnings.append(
            f"{f['category']} sensor '{f['label']}' is elevated: {f['value_c']}°C"
        )

    # Fan analysis
    zero_rpm_fans = [f for f in fans if f.get("rpm", 1) == 0]
    for fan in zero_rpm_fans:
        warnings.append(f"Fan '{fan['label']}' reporting 0 RPM (may be stalled or disconnected)")

    if not fans:
        warnings.append("No fan data available — fan monitoring may not be supported by this hardware")

    # Throttle
    if throttle.get("throttled"):
        cur = throttle.get("cur_mhz", "?")
        mx  = throttle.get("max_mhz", "?")
        warnings.append(f"CPU is frequency-throttled: {cur} MHz / {mx} MHz max — possible thermal event")

    # Verdict
    if critical_temps:
        verdict = "CRITICAL"
        recs += [
            "Shut down immediately and allow the machine to cool.",
            "Clean CPU heatsink and fan — likely clogged with dust.",
            "Inspect and reseat CPU thermal paste (replace if cracked or dry).",
            "Do not run heavy workloads until serviced.",
        ]
    elif warn_temps or zero_rpm_fans:
        verdict = "HOT"
        recs += [
            "Clean CPU heatsink and fan vents — dust buildup is likely.",
            "Avoid heavy CPU/GPU loads until machine is serviced.",
            "Consider replacing thermal paste if machine is 5+ years old.",
        ]
    elif throttle.get("throttled"):
        verdict = "WARM"
        recs += [
            "CPU is throttling — system is managing heat but running below peak speed.",
            "Clean vents; thermal paste replacement may improve performance.",
        ]
    else:
        verdict = "HEALTHY"
        recs.append("No thermal concerns detected at idle.")

    return verdict, warnings, recs


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

_VERDICT_ICON = {
    "HEALTHY":  "OK ",
    "WARM":     "~~ ",
    "HOT":      "!! ",
    "CRITICAL": "!!!",
}


def _fmt_report(
    verdict: str,
    temp_findings: list[dict],
    fan_readings: list[dict],
    throttle: dict,
    warnings: list[str],
    recs: list[str],
    sensors_lines: list[str],
) -> str:
    icon = _VERDICT_ICON.get(verdict, "?  ")
    lines = [
        "=" * 58,
        "  THERMAL HEALTH ASSESSMENT",
        "=" * 58,
        f"  [{icon}] Overall verdict: {verdict}",
        "",
    ]

    # Temperatures
    if temp_findings:
        lines.append("  TEMPERATURES:")
        for f in sorted(temp_findings, key=lambda x: -x["value_c"]):
            flag = {"critical": " <-- CRITICAL", "warn": " <-- elevated", "ok": ""}.get(f["severity"], "")
            chip_label = f"{f['chip']} / {f['label']}" if f.get("chip") else f.get("label", "?")
            lines.append(f"    {chip_label:<38} {f['value_c']:>5.1f}°C{flag}")
    else:
        lines.append("  No temperature sensors detected.")
    lines.append("")

    # Fans
    if fan_readings:
        lines.append("  FANS:")
        for fan in fan_readings:
            rpm = fan.get("rpm", "?")
            chip_label = f"{fan['chip']} / {fan['label']}" if fan.get("chip") else fan.get("label", "?")
            flag = "  <-- STALLED?" if rpm == 0 else ""
            lines.append(f"    {chip_label:<38} {rpm:>6} RPM{flag}")
    else:
        lines.append("  No fan sensors detected.")
    lines.append("")

    # CPU throttle
    lines.append("  CPU FREQUENCY STATE:")
    if "cur_mhz" in throttle and "max_mhz" in throttle:
        gov = throttle.get("governor", "unknown")
        thr = " (THROTTLED)" if throttle.get("throttled") else ""
        lines.append(f"    Governor: {gov}")
        lines.append(f"    {throttle['cur_mhz']} MHz  /  {throttle['max_mhz']} MHz max{thr}")
    else:
        lines.append(f"    Governor: {throttle.get('governor', 'unavailable')}")
    if "cpuinfo_mhz_min" in throttle:
        lines.append(
            f"    /proc/cpuinfo MHz range: {throttle['cpuinfo_mhz_min']} – {throttle['cpuinfo_mhz_max']}"
        )
    lines.append("")

    # Warnings
    if warnings:
        lines.append("  FINDINGS:")
        for w in warnings:
            lines.append(f"    * {w}")
        lines.append("")

    # Recommendations
    lines.append("  RECOMMENDATIONS:")
    for r in recs:
        lines.append(f"    > {r}")
    lines.append("")

    # Raw `sensors` output (if available and useful)
    if sensors_lines:
        lines += ["  RAW `sensors` OUTPUT:", "  ----------------------"]
        lines += [f"    {ln}" for ln in sensors_lines[:40]]
        if len(sensors_lines) > 40:
            lines.append(f"    ... ({len(sensors_lines) - 40} more lines)")
        lines.append("")

    lines.append("=" * 58)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="bootstrap run m09_thermal_health",
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--json-only", action="store_true",
        help="Suppress formatted report; only write JSON log"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _log.info("Collecting thermal data …")

    # --- Collect ---
    hwmon_readings  = _collect_hwmon()
    thermal_zones   = _collect_thermal_zones()
    throttle        = _collect_cpu_throttle()
    sensors_lines   = _collect_sensors_cmd()

    # Merge temperature sources (prefer hwmon; use thermal zones as fallback)
    all_readings = hwmon_readings + [
        {
            "source": tz["source"],
            "chip":   tz["type"],
            "label":  tz["zone"],
            "kind":   "temperature",
            "value_c": tz["value_c"],
            "crit_c": None,
            "max_c":  None,
        }
        for tz in thermal_zones
        # Only include thermal zones not already covered by hwmon
        if not any(
            abs(r["value_c"] - tz["value_c"]) < 2
            for r in hwmon_readings
            if r.get("kind") == "temperature"
        )
    ]

    temp_findings = _classify_sensors(all_readings)
    fan_readings  = [r for r in hwmon_readings if r.get("kind") == "fan"]

    verdict, warnings, recs = _derive_verdict(temp_findings, fan_readings, throttle)

    # --- Report ---
    if not args.json_only:
        print(_fmt_report(verdict, temp_findings, fan_readings, throttle, warnings, recs, sensors_lines))

    # --- JSON log ---
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_dir = root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"thermal_health_{timestamp}.json"

    report = {
        "timestamp": timestamp,
        "verdict": verdict,
        "warnings": warnings,
        "recommendations": recs,
        "temperatures": temp_findings,
        "fans": fan_readings,
        "thermal_zones": thermal_zones,
        "cpu_throttle": throttle,
        "sensors_available": bool(sensors_lines),
    }
    log_path.write_text(json.dumps(report, indent=2))
    _log.info("Report written to %s", log_path)

    # Exit 1 if HOT or CRITICAL
    return 1 if verdict in ("HOT", "CRITICAL") else 0
