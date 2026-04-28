"""
m28_cmos_health.py — Nielsoln Rescue Toolkit: CMOS / RTC battery health.

Checks whether the system's CMOS / real-time-clock battery is healthy by
comparing the hardware clock to the OS clock, looking for large time offsets,
and correlating with Windows System event log entries about time changes and
unexpected shutdowns.

A dead CMOS battery is one of the most common failures on old laptops:
  • System time resets to 1970 or BIOS default after every power cycle
  • BIOS settings (boot order, passwords) are lost
  • SSL certificates fail (time is wrong)
  • Windows can refuse to activate or update

This module needs --target for the event log scan but also reads live hardware
(hwclock / /sys/class/rtc) — no --target is required for the clock delta alone.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m28_cmos_health -- --target /mnt/windows

Output:
    Prints a formatted report to stdout.
    Writes JSON to <USB>/logs/cmos_health_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import struct
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

_log = logging.getLogger("m28_cmos_health")

DESCRIPTION = (
    "CMOS/RTC battery health: hardware clock vs system clock delta, Windows "
    "time-change events, and unexpected-shutdown events — requires --target "
    "/mnt/windows for event log scan; clock delta works without --target"
)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

_DELTA_WARN_SEC   = 120     # 2 minutes: possible drift
_DELTA_SUSPECT_SEC = 3600   # 1 hour: suspicious
_DELTA_DEAD_SEC   = 86400   # 1 day: likely dead battery

# If the RTC year is below this threshold the battery is dead regardless of
# the system-clock delta (live environments sync the system clock FROM the RTC
# at boot, so both clocks agree on the wrong year and the delta is 0).
_MIN_PLAUSIBLE_YEAR = 2020

# Windows EVTX EventIDs relevant to RTC / time / shutdown
_TIME_CHANGE_ID       = 4616   # Security: system time changed (requires audit)
_W32TM_CHANGE_ID      = 37     # System: W32tm time jump > threshold
_UNEXPECTED_SHUT_ID   = 6008   # System: unexpected previous shutdown
_DIRTY_SHUT_ID        = 41     # System: kernel power — unexpected reboot

# ---------------------------------------------------------------------------
# Bundled minimal evtx reader (xml-only, no python-evtx)
# Reads the raw XML embedded in EVTX records without any external libs.
# ---------------------------------------------------------------------------

_EVTX_MAGIC  = b"ElfFile\x00"
_CHUNK_MAGIC = b"ElfChnk\x00"


def _read_evtx_xml_records(evtx_path: Path):
    """
    Yield raw XML strings extracted from an EVTX file.
    Uses only stdlib — reads the binary file, finds chunk headers, extracts
    records.  Handles Vista-era EVTX format.
    """
    try:
        data = evtx_path.read_bytes()
    except (PermissionError, OSError) as exc:
        _log.warning("Cannot read %s: %s", evtx_path, exc)
        return

    if data[:8] != _EVTX_MAGIC:
        _log.warning("Not an EVTX file: %s", evtx_path)
        return

    # Locate chunks by scanning for chunk magic (ElfChnk\x00)
    pos = 0
    while True:
        idx = data.find(_CHUNK_MAGIC, pos)
        if idx == -1:
            break
        pos = idx + 1
        chunk = data[idx: idx + 65536]
        if len(chunk) < 512:
            continue
        # Records start at offset 0x200 in the chunk
        rec_off = 0x200
        while rec_off < len(chunk) - 4:
            # Each record: magic "**\x00\x00" then 4-byte size
            if chunk[rec_off: rec_off + 4] != b"\x2a\x2a\x00\x00":
                rec_off += 8
                continue
            if rec_off + 8 > len(chunk):
                break
            rec_size = struct.unpack_from("<I", chunk, rec_off + 4)[0]
            if rec_size < 24 or rec_off + rec_size > len(chunk):
                rec_off += 8
                continue
            rec_data = chunk[rec_off: rec_off + rec_size]
            # Find embedded XML (starts with "<Event xmlns")
            xml_start = rec_data.find(b"<Event ")
            if xml_start == -1:
                xml_start = rec_data.find(b"<Event\n")
            if xml_start != -1:
                raw_xml = rec_data[xml_start:]
                xml_end = raw_xml.find(b"</Event>")
                if xml_end != -1:
                    raw_xml = raw_xml[: xml_end + 8]
                try:
                    yield raw_xml.decode("utf-8", errors="replace")
                except Exception:
                    pass
            rec_off += rec_size


def _parse_event_id(xml: str) -> int | None:
    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
    if m:
        return int(m.group(1))
    return None


def _parse_event_time(xml: str) -> str:
    m = re.search(r'SystemTime="([^"]+)"', xml)
    return m.group(1) if m else ""


def _parse_event_data(xml: str) -> dict[str, str]:
    """Extract <Data Name="...">value</Data> pairs."""
    result = {}
    for m in re.finditer(r'<Data Name="([^"]+)"[^>]*>(.*?)</Data>', xml, re.DOTALL):
        result[m.group(1)] = m.group(2).strip()
    return result


# ---------------------------------------------------------------------------
# Clock delta measurement
# ---------------------------------------------------------------------------

def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.returncode, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        return -1, f"command not found: {cmd[0]}"
    except Exception as exc:
        return -1, str(exc)


def collect_clock_delta() -> dict:
    """
    Compare hardware RTC to system clock.
    Returns delta_sec (positive = RTC ahead of UTC) and method used.
    """
    now_utc = datetime.now(timezone.utc)

    # Try hwclock first
    rc, out = _run(["hwclock", "--utc", "--show"])
    if rc == 0 and out:
        # hwclock output: "2026-04-28 12:34:56.123456+00:00" or similar
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%a %d %b %Y %H:%M:%S %Z",
        ):
            try:
                hw_time = datetime.strptime(out.strip(), fmt)
                if hw_time.tzinfo is None:
                    hw_time = hw_time.replace(tzinfo=timezone.utc)
                return _build_clock_result("hwclock", hw_time, now_utc)
            except ValueError:
                continue

    # Fall back to /sys/class/rtc/rtc0/time + /date
    rtc_time = _read_path("/sys/class/rtc/rtc0/time")
    rtc_date = _read_path("/sys/class/rtc/rtc0/date")
    if rtc_time and rtc_date:
        try:
            hw_time = datetime.strptime(
                f"{rtc_date} {rtc_time}", "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            return _build_clock_result("sysfs_rtc", hw_time, now_utc)
        except ValueError:
            pass

    return {
        "method": "unavailable",
        "hw_time_utc": None,
        "sys_time_utc": now_utc.isoformat(),
        "delta_sec": None,
        "delta_abs_sec": None,
        "frozen_in_past": False,
        "frozen_year": None,
    }


def _build_clock_result(method: str, hw_time: datetime, now_utc: datetime) -> dict:
    """
    Build the clock-delta result dict, including the frozen-in-past check.

    On live rescue environments the system clock is synced FROM the RTC at
    boot — so if the battery is dead both clocks report the same wrong year
    and the delta is 0.  We detect this by comparing the RTC year against
    _MIN_PLAUSIBLE_YEAR rather than trusting the system clock.
    """
    delta = int((hw_time - now_utc).total_seconds())
    frozen = hw_time.year < _MIN_PLAUSIBLE_YEAR
    return {
        "method": method,
        "hw_time_utc": hw_time.isoformat(),
        "sys_time_utc": now_utc.isoformat(),
        "delta_sec": delta,
        "delta_abs_sec": abs(delta),
        "frozen_in_past": frozen,
        "frozen_year": hw_time.year if frozen else None,
    }


def _read_path(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Event log scan
# ---------------------------------------------------------------------------

def collect_time_events(target: Path) -> dict:
    """
    Scan System.evtx for time-change and unexpected-shutdown events.
    Returns counts and last occurrence timestamps.
    """
    system_evtx = target / "Windows" / "System32" / "winevt" / "Logs" / "System.evtx"
    if not system_evtx.exists():
        return {"available": False, "error": "System.evtx not found"}

    result: dict = {
        "available": True,
        "time_change_events": [],    # Event 37 (W32tm jumps)
        "unexpected_shutdowns": [],  # Event 6008
        "dirty_shutdowns": [],       # Event 41
    }

    for xml in _read_evtx_xml_records(system_evtx):
        eid = _parse_event_id(xml)
        if eid is None:
            continue
        ts = _parse_event_time(xml)
        data = _parse_event_data(xml)

        if eid == _W32TM_CHANGE_ID:
            result["time_change_events"].append({"time": ts, "data": data})
        elif eid == _UNEXPECTED_SHUT_ID:
            result["unexpected_shutdowns"].append({"time": ts, "data": data})
        elif eid == _DIRTY_SHUT_ID:
            result["dirty_shutdowns"].append({"time": ts, "data": data})

    # Keep only last 10 of each
    for key in ("time_change_events", "unexpected_shutdowns", "dirty_shutdowns"):
        result[key] = result[key][-10:]

    result["time_change_count"]    = len(result["time_change_events"])
    result["unexpected_shut_count"] = len(result["unexpected_shutdowns"])
    result["dirty_shut_count"]      = len(result["dirty_shutdowns"])
    return result


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def _derive_verdict(clock: dict, events: dict) -> str:
    # Frozen-in-past check: RTC year is implausibly old, so battery is dead
    # even if the delta vs system clock is 0 (live env syncs clock from RTC).
    if clock.get("frozen_in_past"):
        return "LIKELY_DEAD"

    delta = clock.get("delta_abs_sec")

    if delta is not None:
        if delta >= _DELTA_DEAD_SEC:
            return "LIKELY_DEAD"
        if delta >= _DELTA_SUSPECT_SEC:
            return "SUSPECT"

    # Frequent time-change corrections or unexpected shutdowns also suggest RTC issues
    if events.get("available"):
        tc  = events.get("time_change_count", 0)
        us  = events.get("unexpected_shut_count", 0)
        ds  = events.get("dirty_shut_count", 0)
        if tc >= 5 or (us + ds) >= 5:
            return "SUSPECT"

    if delta is not None and delta >= _DELTA_WARN_SEC:
        return "DRIFT"

    if delta is None and not events.get("available"):
        return "UNKNOWN"

    return "HEALTHY"


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def _fmt_report(report: dict) -> str:
    clock   = report["clock_delta"]
    events  = report["events"]
    verdict = report["verdict"]

    lines = [
        "=" * 56,
        "  CMOS / RTC BATTERY HEALTH",
        "=" * 56,
        f"  Verdict : {verdict}",
        "",
        "  Clock delta (hardware RTC vs system UTC):",
    ]

    if clock["method"] == "unavailable":
        lines.append("    hwclock / sysfs RTC not readable — cannot measure delta")
    else:
        lines += [
            f"    Method      : {clock['method']}",
            f"    HW time UTC : {clock['hw_time_utc']}",
            f"    Sys time UTC: {clock['sys_time_utc']}",
            f"    Delta       : {clock['delta_sec']:+d} seconds ({clock['delta_abs_sec']}s absolute)",
        ]
        if clock.get("frozen_in_past"):
            lines.append(
                f"    *** RTC reports year {clock['frozen_year']} — battery is DEAD. "
                f"System clock was synced from RTC at boot so delta shows 0. "
                f"Replace CR2032 CMOS battery. ***"
            )
        elif clock["delta_abs_sec"] >= _DELTA_DEAD_SEC:
            lines.append("    *** RTC is more than 1 day off — battery likely dead ***")
        elif clock["delta_abs_sec"] >= _DELTA_SUSPECT_SEC:
            lines.append("    *** RTC offset > 1 hour — battery suspect ***")
        elif clock["delta_abs_sec"] >= _DELTA_WARN_SEC:
            lines.append("    * RTC drift > 2 minutes — monitor")

    lines.append("")
    if events.get("available"):
        lines += [
            "  Windows System event log:",
            f"    Time-change corrections (Event 37) : {events['time_change_count']}",
            f"    Unexpected shutdowns (Event 6008)  : {events['unexpected_shut_count']}",
            f"    Dirty shutdowns (Event 41)         : {events['dirty_shut_count']}",
        ]
        if events["time_change_count"] >= 5:
            lines.append("    *** Repeated time corrections — RTC unreliable ***")
    else:
        lines.append("  System.evtx not available — event log scan skipped.")

    lines.append("=" * 56)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    ap = argparse.ArgumentParser(prog="m28_cmos_health", description=DESCRIPTION)
    ap.add_argument("--target", required=False, default=None,
                    help="Mount point of the Windows installation (for event log scan)")
    args = ap.parse_args(argv)

    if args.target:
        target = Path(args.target)
    else:
        try:
            from toolkit import find_windows_target
            target = find_windows_target()
        except Exception:
            target = None
        if target is not None:
            print(f"[m28] Auto-detected target: {target}", flush=True)

    print("[m28] Reading hardware clock delta ...", flush=True)
    clock = collect_clock_delta()
    if clock["method"] != "unavailable":
        print(f"[m28] Delta: {clock['delta_sec']:+d}s  "
              f"(method: {clock['method']})", flush=True)
    else:
        print("[m28] Could not read hardware clock", flush=True)

    events: dict = {"available": False, "error": "no --target provided"}
    if target and target.exists():
        print("[m28] Scanning System.evtx for time/shutdown events ...", flush=True)
        events = collect_time_events(target)
        print(f"[m28] Time changes: {events.get('time_change_count', 0)}  "
              f"Unexpected shutdowns: {events.get('unexpected_shut_count', 0)}  "
              f"Dirty shutdowns: {events.get('dirty_shut_count', 0)}", flush=True)

    verdict = _derive_verdict(clock, events)

    report = {
        "target":      str(target) if target else None,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "verdict":     verdict,
        "clock_delta": clock,
        "events":      events,
    }

    print()
    print(_fmt_report(report))

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = root / "logs" / f"cmos_health_{ts}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"[m28] Saved → {out_path}", flush=True)
    return 0
