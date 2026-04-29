"""m09_thermal_health — Nielsoln Rescue Toolkit thermal analysis.

Phase 1 — passive thermal snapshot:
  Reads live sensors from /sys/class/hwmon, /sys/class/thermal,
  /proc/cpuinfo, and `sensors` (lm-sensors where available).

Phase 2 — short thermal response test (optional, default enabled):
  Applies light CPU load for --load-duration seconds (default 30),
  monitors temperature rise, detects throttling, then monitors cooldown.
  Stops immediately if temperature exceeds --max-temp (default 85 °C).

Verdicts:
  GOOD     — moderate idle, safe peak, quick recovery, no throttling
  FAIR     — warm but controlled, no emergency condition
  POOR     — rapid heat rise, high peak, slow recovery or throttling
  CRITICAL — unsafe peak temperature or emergency stop triggered
  UNKNOWN  — insufficient sensor data to classify
  SKIPPED  — load test skipped (--skip-load-test or no sensors)

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m09_thermal_health
    # Or:   bootstrap run m09_thermal_health -- --skip-load-test
    # Or:   bootstrap run m09_thermal_health -- --load-duration 20 --max-temp 80

Output:
    Prints a formatted report to stdout.
    Writes a JSON summary to <USB>/logs/thermal_health_<timestamp>.json
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

_log = logging.getLogger("thermal_health")

DESCRIPTION = (
    "Thermal analysis: passive sensor snapshot + short CPU load test — "
    "detects overheating, throttling, and cooling problems "
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

# Load-test thresholds
_LOAD_DEFAULT_DURATION_S  = 30    # seconds of CPU load
_LOAD_DEFAULT_MAX_TEMP    = 85.0  # emergency stop °C
_LOAD_POLL_INTERVAL_S     = 2.0   # temperature poll interval
_LOAD_COOLDOWN_S          = 60    # how long to monitor cooldown
_LOAD_RECOVERED_DELTA     = 5.0   # °C above idle = "recovered"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str]) -> tuple:
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


def _millideg_to_c(raw: str) -> Optional[float]:
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

def _collect_hwmon() -> List[dict]:
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

def _collect_thermal_zones() -> List[dict]:
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
# CPU frequency / throttle helpers
# ---------------------------------------------------------------------------

def _read_cur_cpu_mhz() -> Optional[int]:
    """Read current CPU0 frequency in MHz from sysfs."""
    cur = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "")
    try:
        return round(int(cur) / 1000)
    except (ValueError, TypeError):
        return None


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

def _collect_sensors_cmd() -> List[str]:
    """Run `sensors` and return raw output lines (empty if not available)."""
    rc, out = _run(["sensors"])
    if rc == 0 and out:
        return out.splitlines()
    return []


# ---------------------------------------------------------------------------
# CPU sensor helpers
# ---------------------------------------------------------------------------

def _is_cpu_sensor(r: dict) -> bool:
    label = (r.get("label") or "").lower()
    chip  = (r.get("chip")  or "").lower()
    return any(k in label or k in chip for k in ("core", "cpu", "package", "tdie", "tctl"))


def _peak_cpu_temp(readings: List[dict]) -> Optional[float]:
    """Return the highest CPU-category temperature from a list of sensor readings."""
    vals = [
        r["value_c"] for r in readings
        if r.get("kind") == "temperature" and _is_cpu_sensor(r)
    ]
    return max(vals) if vals else None


# ---------------------------------------------------------------------------
# Classify sensor readings into findings
# ---------------------------------------------------------------------------

def _classify_sensors(readings: List[dict]) -> List[dict]:
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
# Thermal response load test
# ---------------------------------------------------------------------------

def _load_worker(stop_event: threading.Event) -> None:
    """Burns CPU until stop_event is set.  Runs in a daemon thread."""
    while not stop_event.is_set():
        _ = sum(range(500_000))


def run_load_test(
    duration_s: int = _LOAD_DEFAULT_DURATION_S,
    max_safe_temp: float = _LOAD_DEFAULT_MAX_TEMP,
    poll_interval: float = _LOAD_POLL_INTERVAL_S,
) -> dict:
    """
    1. Measure idle baseline (3 seconds).
    2. Spin up load threads (one per logical CPU, capped at 8).
    3. Poll temperature every poll_interval seconds until duration_s reached
       or max_safe_temp exceeded.
    4. Stop load; monitor cooldown for _LOAD_COOLDOWN_S seconds.
    Return a dict describing the thermal response.
    """
    import os

    # --- idle baseline ---
    _log.info("Load test: measuring idle baseline …")
    wall_start = datetime.now(timezone.utc)  # for sample timestamps
    time.sleep(3)
    idle_readings = _collect_hwmon() + [
        {"kind": "temperature", "chip": tz["type"], "label": tz["zone"],
         "value_c": tz["value_c"]}
        for tz in _collect_thermal_zones()
    ]
    idle_temp = _peak_cpu_temp(idle_readings)
    freq_before = _read_cur_cpu_mhz()

    if idle_temp is None:
        return {
            "enabled": True,
            "skipped_reason": "no CPU temperature sensors found",
            "verdict": "UNKNOWN",
        }

    _log.info("Load test: idle CPU temp %.1f °C — starting %ds load …", idle_temp, duration_s)

    # --- start load threads ---
    n_threads = min(max(1, os.cpu_count() or 1), 8)
    stop_event = threading.Event()
    workers = [
        threading.Thread(target=_load_worker, args=(stop_event,), daemon=True)
        for _ in range(n_threads)
    ]
    for w in workers:
        w.start()

    samples: list = []
    start_ts        = time.monotonic()
    peak_temp       = idle_temp
    peak_ts         = start_ts
    emergency_stop  = False
    emergency_reason = ""
    freq_during_min: Optional[int] = None
    throttling_detected = False

    try:
        while True:
            elapsed = time.monotonic() - start_ts
            if elapsed >= duration_s:
                break
            time.sleep(poll_interval)

            readings = _collect_hwmon() + [
                {"kind": "temperature", "chip": tz["type"], "label": tz["zone"],
                 "value_c": tz["value_c"]}
                for tz in _collect_thermal_zones()
            ]
            cur_temp = _peak_cpu_temp(readings)
            cur_freq = _read_cur_cpu_mhz()

            if cur_temp is not None:
                elapsed_s = round(time.monotonic() - start_ts, 1)
                samples.append({
                    "elapsed_s": elapsed_s,
                    "timestamp": (wall_start + timedelta(seconds=elapsed_s)).isoformat(),
                    "cpu_temp":  cur_temp,
                    "cpu_freq":  cur_freq,
                    # legacy names kept for backward compat
                    "temp_c":   cur_temp,
                    "freq_mhz": cur_freq,
                })
                if cur_temp > peak_temp:
                    peak_temp = cur_temp
                    peak_ts   = time.monotonic()
                if cur_temp >= max_safe_temp:
                    emergency_stop   = True
                    emergency_reason = f"Temperature {cur_temp:.1f} °C >= safety limit {max_safe_temp:.1f} °C"
                    _log.warning("Load test: EMERGENCY STOP — %s", emergency_reason)
                    break

            if cur_freq is not None:
                if freq_during_min is None or cur_freq < freq_during_min:
                    freq_during_min = cur_freq

    finally:
        stop_event.set()
        for w in workers:
            w.join(timeout=5)

    duration_completed = round(time.monotonic() - start_ts, 1)
    time_to_peak       = round(peak_ts - start_ts, 1)
    temp_rise          = round(peak_temp - idle_temp, 1)

    # Throttling: did freq drop >20% from before?
    if freq_before and freq_during_min:
        throttling_detected = freq_during_min < (freq_before * 0.80)

    # --- cooldown monitoring ---
    _log.info("Load test: cooldown monitoring for %ds …", _LOAD_COOLDOWN_S)
    recovery_30s: Optional[float] = None
    recovery_60s: Optional[float] = None
    recovery_time_s: Optional[float] = None
    freq_after: Optional[int] = None
    cooldown_start = time.monotonic()

    for _ in range(int(_LOAD_COOLDOWN_S / poll_interval)):
        time.sleep(poll_interval)
        elapsed_cd = time.monotonic() - cooldown_start
        readings = _collect_hwmon() + [
            {"kind": "temperature", "chip": tz["type"], "label": tz["zone"],
             "value_c": tz["value_c"]}
            for tz in _collect_thermal_zones()
        ]
        cur_temp = _peak_cpu_temp(readings)
        if cur_temp is None:
            continue
        if elapsed_cd >= 28 and recovery_30s is None:
            recovery_30s = cur_temp
            freq_after   = _read_cur_cpu_mhz()
        if elapsed_cd >= 58 and recovery_60s is None:
            recovery_60s = cur_temp
        if recovery_time_s is None and cur_temp <= idle_temp + _LOAD_RECOVERED_DELTA:
            recovery_time_s = round(elapsed_cd, 1)

    return {
        "enabled":                True,
        "duration_requested_s":   duration_s,
        "duration_completed_s":   duration_completed,
        "n_load_threads":         n_threads,
        "emergency_stop":         emergency_stop,
        "emergency_stop_reason":  emergency_reason,
        "idle_temp_c":            round(idle_temp, 1),
        "peak_temp_c":            round(peak_temp, 1),
        "temp_rise_c":            temp_rise,
        "time_to_peak_s":         time_to_peak,
        "cpu_freq_before_mhz":    freq_before,
        "cpu_freq_during_min_mhz": freq_during_min,
        "cpu_freq_after_mhz":     freq_after,
        "throttling_detected":    throttling_detected,
        "recovery_temp_30s_c":    round(recovery_30s, 1) if recovery_30s is not None else None,
        "recovery_temp_60s_c":    round(recovery_60s, 1) if recovery_60s is not None else None,
        "recovery_time_s":        recovery_time_s,
        "samples":                samples,
    }


# ---------------------------------------------------------------------------
# Overall verdict
# ---------------------------------------------------------------------------

def _derive_verdict(
    findings: List[dict],
    fans: List[dict],
    throttle: dict,
    load_test: Optional[dict] = None,
) -> tuple:
    """
    Returns (verdict, warnings_list, recommendations_list).
    verdict: GOOD | FAIR | POOR | CRITICAL | UNKNOWN | SKIPPED
    """
    warnings: List[str] = []
    recs: List[str] = []

    critical_temps = [f for f in findings if f.get("severity") == "critical"]
    warn_temps     = [f for f in findings if f.get("severity") == "warn"]
    has_sensors    = bool(findings)

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

    # Throttle at idle
    if throttle.get("throttled"):
        cur = throttle.get("cur_mhz", "?")
        mx  = throttle.get("max_mhz", "?")
        warnings.append(f"CPU is frequency-throttled at idle: {cur} MHz / {mx} MHz max")

    # Load test analysis
    load_emergency   = load_test.get("emergency_stop")         if load_test else False
    load_throttled   = load_test.get("throttling_detected")    if load_test else False
    load_peak        = load_test.get("peak_temp_c")            if load_test else None
    load_rise        = load_test.get("temp_rise_c")            if load_test else None
    load_recovery    = load_test.get("recovery_time_s")        if load_test else None
    load_enabled     = (load_test or {}).get("enabled", False)

    if load_emergency:
        warnings.append(
            f"EMERGENCY STOP during load test: {load_test.get('emergency_stop_reason', '')} "
            f"(peak {load_peak}°C)"
        )
    if load_throttled:
        warnings.append(
            f"CPU throttling detected during load test: "
            f"{load_test.get('cpu_freq_during_min_mhz')} MHz min "
            f"(was {load_test.get('cpu_freq_before_mhz')} MHz before)"
        )
    if load_rise is not None and load_rise > 20:
        warnings.append(
            f"Rapid temperature rise under load: +{load_rise}°C in "
            f"{load_test.get('time_to_peak_s', '?')}s"
        )
    if load_recovery is not None and load_recovery > 45:
        warnings.append(
            f"Slow thermal recovery after load: {load_recovery}s to return within "
            f"{_LOAD_RECOVERED_DELTA}°C of idle"
        )

    # --- Determine verdict ---
    if not has_sensors:
        verdict = "UNKNOWN"
        recs.append("No thermal sensors detected. Install lm-sensors for better coverage.")
        return verdict, warnings, recs

    # CRITICAL: emergency stop, or critically hot sensor
    if load_emergency or critical_temps:
        verdict = "CRITICAL"
        recs += [
            "Shut down immediately and allow the machine to cool.",
            "Clean CPU heatsink and fan — likely clogged with dust.",
            "Inspect and reseat CPU thermal paste (replace if cracked or dry).",
            "Do not run heavy workloads until serviced.",
        ]
    # POOR: multiple warn indicators or severe throttling or very slow recovery
    elif (
        len(warn_temps) >= 2
        or (load_throttled and load_rise is not None and load_rise > 15)
        or (load_recovery is not None and load_recovery > 45)
        or zero_rpm_fans
    ):
        verdict = "POOR"
        recs += [
            "Clean CPU heatsink and fan vents — dust buildup is likely.",
            "Avoid heavy CPU/GPU loads until machine is serviced.",
            "Consider replacing thermal paste if machine is 5+ years old.",
        ]
    # FAIR: mild elevation, some throttling, moderate rise
    elif (
        warn_temps
        or throttle.get("throttled")
        or load_throttled
        or (load_rise is not None and load_rise > 10)
        or (load_recovery is not None and load_recovery > 20)
    ):
        verdict = "FAIR"
        recs += [
            "CPU is managing heat but running warm.",
            "Clean vents; thermal paste replacement may improve performance.",
        ]
    # SKIPPED: load test not run, passive snapshot looks OK
    elif not load_enabled:
        verdict = "SKIPPED"
        recs.append("Passive sensors OK at idle. Run without --skip-load-test for full assessment.")
    else:
        verdict = "GOOD"
        recs.append("No thermal concerns detected. Cooling appears healthy.")

    return verdict, warnings, recs


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

_VERDICT_ICON = {
    "GOOD":     "OK ",
    "FAIR":     "~~ ",
    "POOR":     "!! ",
    "CRITICAL": "!!!",
    "UNKNOWN":  "?  ",
    "SKIPPED":  "-- ",
    # Legacy names kept for backward compatibility
    "HEALTHY":  "OK ",
    "WARM":     "~~ ",
    "HOT":      "!! ",
}


def _fmt_report(
    verdict: str,
    temp_findings: List[dict],
    fan_readings: List[dict],
    throttle: dict,
    warnings: List[str],
    recs: List[str],
    sensors_lines: List[str],
    load_test: Optional[dict] = None,
) -> str:
    icon = _VERDICT_ICON.get(verdict, "?  ")
    lines = [
        "=" * 62,
        "  THERMAL ANALYSIS",
        "=" * 62,
        f"  [{icon}] Overall verdict: {verdict}",
        "",
    ]

    # Temperatures
    if temp_findings:
        lines.append("  IDLE TEMPERATURES:")
        for f in sorted(temp_findings, key=lambda x: -x["value_c"]):
            flag = {"critical": " <-- CRITICAL", "warn": " <-- elevated", "ok": ""}.get(f["severity"], "")
            chip_label = f"{f['chip']} / {f['label']}" if f.get("chip") else f.get("label", "?")
            lines.append(f"    {chip_label:<40} {f['value_c']:>5.1f}°C{flag}")
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
            lines.append(f"    {chip_label:<40} {rpm:>6} RPM{flag}")
    else:
        lines.append("  No fan sensors detected.")
    lines.append("")

    # CPU throttle
    lines.append("  CPU FREQUENCY (IDLE):")
    if "cur_mhz" in throttle and "max_mhz" in throttle:
        gov = throttle.get("governor", "unknown")
        thr = " (THROTTLED)" if throttle.get("throttled") else ""
        lines.append(f"    Governor : {gov}")
        lines.append(f"    Frequency: {throttle['cur_mhz']} MHz  /  {throttle['max_mhz']} MHz max{thr}")
    else:
        lines.append(f"    Governor: {throttle.get('governor', 'unavailable')}")
    if "cpuinfo_mhz_min" in throttle:
        lines.append(
            f"    /proc/cpuinfo: {throttle['cpuinfo_mhz_min']} – {throttle['cpuinfo_mhz_max']} MHz"
        )
    lines.append("")

    # Load test summary
    if load_test and load_test.get("enabled"):
        lt = load_test
        if lt.get("skipped_reason"):
            lines.append(f"  LOAD TEST: skipped — {lt['skipped_reason']}")
        else:
            lines.append("  THERMAL RESPONSE TEST:")
            lines.append(f"    Duration   : {lt.get('duration_completed_s', '?')}s "
                         f"(requested {lt.get('duration_requested_s', '?')}s)")
            lines.append(f"    Idle temp  : {lt.get('idle_temp_c', '?')}°C")
            lines.append(f"    Peak temp  : {lt.get('peak_temp_c', '?')}°C  "
                         f"(+{lt.get('temp_rise_c', '?')}°C in {lt.get('time_to_peak_s', '?')}s)")
            lines.append(f"    Freq before: {lt.get('cpu_freq_before_mhz', '?')} MHz  "
                         f"during min: {lt.get('cpu_freq_during_min_mhz', '?')} MHz")
            lines.append(f"    Throttling : {'YES' if lt.get('throttling_detected') else 'no'}")
            if lt.get('recovery_temp_30s_c') is not None:
                lines.append(f"    Recovery 30s: {lt['recovery_temp_30s_c']}°C  "
                             f"60s: {lt.get('recovery_temp_60s_c', '?')}°C")
            if lt.get('recovery_time_s') is not None:
                lines.append(f"    Recovered to idle+{_LOAD_RECOVERED_DELTA}°C in {lt['recovery_time_s']}s")
            if lt.get('emergency_stop'):
                lines.append(f"    !! EMERGENCY STOP: {lt.get('emergency_stop_reason', '')}")
        lines.append("")
    elif load_test and not load_test.get("enabled"):
        lines.append("  LOAD TEST: skipped (--skip-load-test)")
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

    # Raw `sensors` output
    if sensors_lines:
        lines += ["  RAW `sensors` OUTPUT:", "  " + "-" * 22]
        lines += [f"    {ln}" for ln in sensors_lines[:40]]
        if len(sensors_lines) > 40:
            lines.append(f"    ... ({len(sensors_lines) - 40} more lines)")
        lines.append("")

    lines.append("=" * 62)
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
    parser.add_argument(
        "--skip-load-test", action="store_true",
        help="Skip the CPU load test; passive snapshot only"
    )
    parser.add_argument(
        "--load-duration", type=int, default=_LOAD_DEFAULT_DURATION_S, metavar="SEC",
        help=f"CPU load test duration in seconds (default {_LOAD_DEFAULT_DURATION_S})"
    )
    parser.add_argument(
        "--max-temp", type=float, default=_LOAD_DEFAULT_MAX_TEMP, metavar="DEGC",
        help=f"Emergency stop temperature in °C (default {_LOAD_DEFAULT_MAX_TEMP})"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _log.info("Collecting thermal data …")

    # --- Phase 1: passive snapshot ---
    hwmon_readings  = _collect_hwmon()
    thermal_zones   = _collect_thermal_zones()
    throttle        = _collect_cpu_throttle()
    sensors_lines   = _collect_sensors_cmd()

    # Merge temperature sources (prefer hwmon; use thermal zones as fallback)
    all_readings = hwmon_readings + [
        {
            "source":  tz["source"],
            "chip":    tz["type"],
            "label":   tz["zone"],
            "kind":    "temperature",
            "value_c": tz["value_c"],
            "crit_c":  None,
            "max_c":   None,
        }
        for tz in thermal_zones
        if not any(
            abs(r["value_c"] - tz["value_c"]) < 2
            for r in hwmon_readings
            if r.get("kind") == "temperature"
        )
    ]

    temp_findings = _classify_sensors(all_readings)
    fan_readings  = [r for r in hwmon_readings if r.get("kind") == "fan"]

    # --- Phase 2: thermal response test ---
    if args.skip_load_test:
        load_test: Optional[dict] = {"enabled": False}
        _log.info("Load test skipped (--skip-load-test).")
    elif not temp_findings:
        load_test = {
            "enabled": True,
            "skipped_reason": "no CPU temperature sensors found",
            "verdict": "UNKNOWN",
        }
        _log.warning("Load test skipped — no temperature sensors detected.")
    else:
        _log.info(
            "Starting thermal response test (%ds, max temp %.1f°C) …",
            args.load_duration, args.max_temp,
        )
        load_test = run_load_test(
            duration_s=args.load_duration,
            max_safe_temp=args.max_temp,
        )

    verdict, warnings, recs = _derive_verdict(temp_findings, fan_readings, throttle, load_test)

    # ── Separate passive / response / overall verdicts ───────────────────────
    has_sensors = bool(temp_findings)
    critical_temps = [f for f in temp_findings if f.get("severity") == "critical"]
    warn_temps     = [f for f in temp_findings if f.get("severity") == "warn"]

    if not has_sensors:
        passive_verdict = "UNKNOWN"
    elif critical_temps:
        passive_verdict = "CRITICAL"
    elif len(warn_temps) >= 2 or [f for f in fan_readings if f.get("rpm", 1) == 0]:
        passive_verdict = "POOR"
    elif warn_temps or throttle.get("throttled"):
        passive_verdict = "FAIR"
    else:
        passive_verdict = "GOOD"

    lt_enabled = (load_test or {}).get("enabled", False)
    lt_skipped = (load_test or {}).get("skipped_reason")
    if not lt_enabled or not load_test:
        response_verdict    = "SKIPPED"
        response_confidence = "none"
    elif lt_skipped:
        response_verdict    = "UNKNOWN"
        response_confidence = "none"
    elif load_test.get("emergency_stop"):
        response_verdict    = "CRITICAL"
        response_confidence = "medium"
    elif (
        load_test.get("throttling_detected")
        and (load_test.get("temp_rise_c") or 0) > 15
    ) or (load_test.get("recovery_time_s") or 0) > 45:
        response_verdict    = "POOR"
        response_confidence = "high"
    elif (
        load_test.get("throttling_detected")
        or (load_test.get("temp_rise_c") or 0) > 10
        or (load_test.get("recovery_time_s") or 0) > 20
    ):
        response_verdict    = "FAIR"
        response_confidence = "high"
    else:
        response_verdict    = "GOOD"
        response_confidence = "high"

    _severity_rank = {"CRITICAL": 4, "POOR": 3, "FAIR": 2, "GOOD": 1,
                      "SKIPPED": 0, "UNKNOWN": 0}
    overall_thermal_verdict = (
        passive_verdict
        if _severity_rank.get(passive_verdict, 0) >= _severity_rank.get(response_verdict, 0)
        else response_verdict
    )
    # If overall was effectively UNKNOWN/SKIPPED, fall back to the combined verdict
    if overall_thermal_verdict in ("UNKNOWN", "SKIPPED"):
        overall_thermal_verdict = verdict

    # ── Limitations for this run ─────────────────────────────────────────────
    limitations: list[str] = []
    if not has_sensors:
        limitations.append("no_thermal_sensors_detected")
    if not fan_readings:
        limitations.append("no_fan_monitoring_available")
    if response_verdict in ("SKIPPED", "UNKNOWN"):
        limitations.append("load_test_not_performed")
    limitations.append("rescue_environment_readings_reflect_live_system_state")

    # ── Interpretation block ─────────────────────────────────────────────────
    _lt = load_test or {}
    _desc = {
        "GOOD":     "Thermal performance is healthy.",
        "FAIR":     "Mild thermal stress detected — cleaning may help.",
        "POOR":     "Significant thermal issues — service recommended.",
        "CRITICAL": "Critical overheating risk — immediate action required.",
        "UNKNOWN":  "Thermal status could not be determined (no sensors).",
        "SKIPPED":  "Passive thermal snapshot only — no load test performed.",
    }
    interpretation = {
        "customer_summary":   _desc.get(overall_thermal_verdict, f"Thermal verdict: {overall_thermal_verdict}."),
        "technician_summary": (
            f"passive={passive_verdict}  response={response_verdict}  "
            f"overall={overall_thermal_verdict}  "
            f"response_confidence={response_confidence}  "
            f"sensors={has_sensors}  "
            f"peak_c={(_lt.get('peak_temp_c') if _lt else None)}  "
            f"throttled={(_lt.get('throttling_detected') if _lt else None)}"
        ),
        "what_this_means": (
            "Thermal readings were taken from the running rescue environment, "
            "not from a Windows workload. Results reflect current hardware state."
        ),
        "confidence":        response_confidence if has_sensors else "none",
        "limitations":       limitations,
        "recommended_action": recs[0] if recs else "No action required.",
    }

    # --- Report ---
    if not args.json_only:
        print(_fmt_report(
            verdict, temp_findings, fan_readings, throttle,
            warnings, recs, sensors_lines, load_test,
        ))

    # --- JSON log ---
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_dir = root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"thermal_health_{timestamp}.json"

    # Promote time-series data to the top level for easy consumption
    _ts = _lt.get("samples", []) if _lt.get("enabled") and not _lt.get("skipped_reason") else []

    report = {
        "timestamp":                timestamp,
        "verdict":                  verdict,
        "passive_verdict":          passive_verdict,
        "response_verdict":         response_verdict,
        "overall_thermal_verdict":  overall_thermal_verdict,
        "response_confidence":      response_confidence,
        "limitations":              limitations,
        "interpretation":           interpretation,
        "warnings":                 warnings,        "recommendations":    recs,
        "temperatures":       temp_findings,
        "fans":               fan_readings,
        "thermal_zones":      thermal_zones,
        "cpu_throttle":       throttle,
        "sensors_available":  bool(sensors_lines),
        "sensors_raw":        sensors_lines,
        "time_series":        _ts,
        "thermal_response_test": load_test,
    }
    log_path.write_text(json.dumps(report, indent=2))
    _log.info("Report written to %s", log_path)

    # Exit 1 if POOR or CRITICAL (non-zero = needs attention)
    return 1 if verdict in ("POOR", "CRITICAL", "HOT") else 0
