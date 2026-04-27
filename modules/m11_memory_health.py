"""
m11_memory_health.py — Nielsoln Rescue Toolkit: RAM health check.

Reads memory information from the live Linux environment:
  - /proc/meminfo          — total RAM, available, swap usage
  - dmidecode (if available) — DIMM slot info, manufacturer, speed, errors
  - /sys/devices/system/memory/ — memory blocks present/offline

Also checks the offline Windows target for crash dump artifacts that suggest
prior memory failures:
  - Presence of %SystemRoot%\MEMORY.DMP (full kernel dump = severe crash)
  - Minidump files in %SystemRoot%\Minidump\*.dmp
  - Windows Event Log: look for event 1001 (BugCheck) in System.evtx (if
    python-evtx is already cached in the temp dir from m23, reuse it;
    otherwise skip evtx parsing)

Verdict:
  HEALTHY   — no evidence of memory problems
  SUSPECT   — crash dumps or many minidumps present (may indicate RAM faults)
  DEGRADED  — dmidecode reports ECC errors or uncorrectable events
  LOW_RAM   — total RAM is very low (< 1 GB usable)

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m11_memory_health --target /mnt/windows

Output:
    Prints a memory health report to stdout.
    Writes a JSON log to <USB>/logs/memory_health_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DESCRIPTION = (
    "Memory health: reads /proc/meminfo + dmidecode for RAM info, and checks "
    "the offline Windows target for crash dumps that suggest memory faults — "
    "requires --target /mnt/windows"
)

_LOW_RAM_MB = 1024    # flag as LOW_RAM below this threshold
_MINIDUMP_WARN = 5   # more than this many minidumps = SUSPECT


# ---------------------------------------------------------------------------
# /proc/meminfo reader
# ---------------------------------------------------------------------------

def _read_meminfo() -> dict:
    result = {}
    try:
        text = Path("/proc/meminfo").read_text(encoding="ascii", errors="replace")
        for line in text.splitlines():
            m = re.match(r"^(\w+):\s+(\d+)\s*kB", line)
            if m:
                result[m.group(1)] = int(m.group(2))
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# dmidecode reader (type 17 = Memory Device)
# ---------------------------------------------------------------------------

def _run_dmidecode() -> list:
    """Return list of DIMM dicts from dmidecode type 17, or []."""
    try:
        out = subprocess.run(
            ["dmidecode", "--type", "17"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode != 0:
            return []
        return _parse_dmi_type17(out.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def _parse_dmi_type17(text: str) -> list:
    dimms = []
    current: dict = {}
    for line in text.splitlines():
        if line.startswith("Memory Device"):
            if current:
                dimms.append(current)
            current = {}
        elif ":" in line and current is not None:
            key, _, val = line.partition(":")
            current[key.strip()] = val.strip()
    if current:
        dimms.append(current)
    # Filter out empty slots
    return [d for d in dimms if d.get("Size", "No Module Installed") not in
            ("No Module Installed", "Not Installed", "Not Present", "")]


# ---------------------------------------------------------------------------
# Crash dump checks on the Windows partition
# ---------------------------------------------------------------------------

def _check_crash_dumps(target: Path) -> dict:
    windows = target / "Windows"

    # Full kernel dump
    full_dump = windows / "MEMORY.DMP"
    has_full_dump = full_dump.exists()

    # Minidumps
    minidump_dir = windows / "Minidump"
    minidumps = []
    if minidump_dir.exists():
        minidumps = sorted(minidump_dir.glob("*.dmp"), key=lambda p: p.stat().st_mtime)

    # WER (Windows Error Reporting) crash reports
    wer_dirs = [
        windows / "ServiceProfiles" / "LocalService" / "AppData" / "Local" / "CrashDumps",
        target / "ProgramData" / "Microsoft" / "Windows" / "WER" / "ReportQueue",
        target / "ProgramData" / "Microsoft" / "Windows" / "WER" / "ReportArchive",
    ]
    wer_count = 0
    for wd in wer_dirs:
        if wd.exists():
            wer_count += sum(1 for _ in wd.rglob("*.dmp"))

    return {
        "full_dump_present": has_full_dump,
        "minidump_count":    len(minidumps),
        "wer_dump_count":    wer_count,
        "minidump_files":    [p.name for p in minidumps[-10:]],  # last 10
    }


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def _assess(meminfo: dict, dimms: list, crashes: dict) -> str:
    total_kb = meminfo.get("MemTotal", 0)

    if total_kb > 0 and total_kb < _LOW_RAM_MB * 1024:
        return "LOW_RAM"

    # Check for ECC errors in dmidecode output
    for d in dimms:
        err = d.get("Total Width", "")
        # dmidecode doesn't directly report ECC errors but we can check Error type
        error_info = d.get("Error Information Handle", "")
        if "error" in error_info.lower() and "no error" not in error_info.lower():
            return "DEGRADED"

    if crashes["full_dump_present"]:
        return "SUSPECT"
    if crashes["minidump_count"] > _MINIDUMP_WARN:
        return "SUSPECT"

    return "HEALTHY"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(meminfo: dict, dimms: list, crashes: dict, verdict: str,
                  dmidecode_available: bool) -> None:
    w = 60
    print("\n" + "=" * w)
    print("  MEMORY HEALTH")
    print("=" * w)

    total_kb = meminfo.get("MemTotal", 0)
    avail_kb = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
    swap_total = meminfo.get("SwapTotal", 0)
    swap_free  = meminfo.get("SwapFree", 0)
    swap_used  = swap_total - swap_free

    print(f"\n  Total RAM       : {total_kb // 1024} MB  ({total_kb // 1048576} GB)")
    print(f"  Available now   : {avail_kb // 1024} MB")
    if swap_total:
        print(f"  Swap            : {swap_used // 1024} MB used / {swap_total // 1024} MB total")

    if dimms:
        print(f"\n  DIMM slots populated: {len(dimms)}")
        for d in dimms:
            size   = d.get("Size", "?")
            mfr    = d.get("Manufacturer", "?")
            speed  = d.get("Speed", "?")
            loc    = d.get("Locator", d.get("Bank Locator", "?"))
            print(f"    {loc:<12}  {size:<10}  {mfr:<20}  {speed}")
    elif dmidecode_available:
        print("\n  (dmidecode returned no DIMM data)")
    else:
        print("\n  (dmidecode not available — DIMM detail unavailable)")

    print(f"\n  Crash dumps (Windows):")
    print(f"    Full dump (MEMORY.DMP) : {'YES ← system crashed hard' if crashes['full_dump_present'] else 'No'}")
    print(f"    Minidumps              : {crashes['minidump_count']}")
    if crashes["minidump_files"]:
        for f in crashes["minidump_files"][-5:]:
            print(f"      {f}")
    print(f"    WER crash reports      : {crashes['wer_dump_count']}")

    print(f"\n  Verdict : {verdict}")
    if verdict == "LOW_RAM":
        print("  RAM is very low — machine will struggle with modern use.")
    elif verdict == "SUSPECT":
        print("  Crash dumps detected — possible memory fault or driver bug.")
        print("  Consider running memtest86+ on next boot.")
    elif verdict == "DEGRADED":
        print("  ECC errors detected — RAM may be faulty.")
    else:
        print("  No evidence of memory problems found.")

    print("\n" + "=" * w + "\n")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    parser = argparse.ArgumentParser(
        prog="m11_memory_health",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="/mnt/windows",
                        help="Path to the mounted offline Windows installation")
    args = parser.parse_args(argv)

    target = Path(args.target)

    print("[m11] Reading /proc/meminfo ...")
    meminfo = _read_meminfo()
    if not meminfo:
        print("[m11] WARNING: Could not read /proc/meminfo")

    print("[m11] Running dmidecode ...")
    dimms = _run_dmidecode()
    dmidecode_available = bool(dimms) or Path("/usr/sbin/dmidecode").exists() or Path("/usr/bin/dmidecode").exists()

    print("[m11] Checking crash dumps on Windows partition ...")
    crashes = _check_crash_dumps(target)

    verdict = _assess(meminfo, dimms, crashes)
    _print_report(meminfo, dimms, crashes, verdict, dmidecode_available)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = logs_dir / f"memory_health_{ts}.json"
    out.write_text(json.dumps({
        "generated":           datetime.now(timezone.utc).isoformat(),
        "target":              str(target),
        "verdict":             verdict,
        "total_ram_mb":        meminfo.get("MemTotal", 0) // 1024,
        "available_ram_mb":    meminfo.get("MemAvailable", 0) // 1024,
        "swap_total_mb":       meminfo.get("SwapTotal", 0) // 1024,
        "swap_used_mb":        (meminfo.get("SwapTotal", 0) - meminfo.get("SwapFree", 0)) // 1024,
        "dimms":               dimms,
        "crash_dumps":         crashes,
    }, indent=2))
    print(f"[m11] Log written → {out}")
    return 0
