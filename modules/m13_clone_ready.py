"""
m13_clone_ready.py — Nielsoln Rescue Toolkit: assess whether the disk is ready to clone.

Reads the most-recent disk_health log (from m05) and assesses whether the source
disk is in a safe condition for imaging/cloning to a replacement drive.

Scoring factors:
  - SMART overall health (PASSED / FAILED)
  - Reallocated sectors (bad blocks remapped)
  - Pending sectors (unreadable blocks awaiting reallocation)
  - Uncorrectable sectors (read errors that cannot be recovered)
  - Power-on hours (age proxy)
  - Spin retry count (mechanical stress indicator)

Verdict:
  CLONE_NOW    — disk is failing; clone immediately before it gets worse
  CLONE_SOON   — disk has warnings; clone recommended within days
  CLONE_OK     — disk is healthy; clone or continue using
  CANNOT_ASSESS — no disk_health log found or SMART unavailable

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m13_clone_ready

Output:
    Prints a clone-readiness assessment to stdout.
    Writes a JSON log to <USB>/logs/clone_ready_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DESCRIPTION = (
    "Clone-readiness assessment: reads the most-recent disk_health log to determine "
    "whether the disk is safe to clone and how urgently cloning is recommended"
)

# ---------------------------------------------------------------------------
# SMART attribute IDs of interest
# ---------------------------------------------------------------------------

_REALLOCATED   = {"5"}   # Reallocated_Sector_Ct
_PENDING       = {"197"} # Current_Pending_Sector
_UNCORRECTABLE = {"198"} # Offline_Uncorrectable
_SPIN_RETRY    = {"10"}  # Spin_Retry_Count
_POWER_ON_HRS  = {"9"}   # Power_On_Hours

_HOURS_CAUTION  = 20_000   # ~8 years at 8h/day
_HOURS_CRITICAL = 40_000   # ~13 years continuous


def _latest(logs_dir: Path, glob: str) -> Optional[Path]:
    matches = sorted(logs_dir.glob(glob), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def _raw_int(raw_smart: dict, attr_ids: set) -> int:
    """Return the raw integer value for the first matching SMART attribute ID."""
    for attr_id in attr_ids:
        attr = raw_smart.get(str(attr_id)) or raw_smart.get(attr_id)
        if attr:
            raw = attr.get("raw", "0")
            # Raw may be "123 (text)" — extract leading integer
            try:
                return int(str(raw).split()[0])
            except (ValueError, IndexError):
                pass
    return 0


def _assess_drive(drive: dict) -> dict:
    """Return an assessment dict for a single drive."""
    model   = drive.get("model") or drive.get("device") or "Unknown disk"
    device  = drive.get("device", "")
    health  = drive.get("overall_health", "").upper()
    verdict_hint = (drive.get("overall_verdict") or drive.get("verdict") or "").upper()
    smart_available = drive.get("smart_available", True)
    raw_smart = drive.get("raw_smart") or {}

    issues  = []
    score   = 0   # 0=OK, 1=CAUTION, 2=CRITICAL

    if not smart_available:
        return {
            "device": device, "model": model,
            "verdict": "CANNOT_ASSESS",
            "reason":  "SMART data not available for this device",
            "issues": [],
        }

    # Health test result
    if health == "FAILED":
        issues.append("SMART self-test reports FAILED")
        score = max(score, 2)

    # Reallocated sectors
    reallocated = _raw_int(raw_smart, _REALLOCATED)
    if reallocated > 0:
        issues.append(f"Reallocated sectors: {reallocated}")
        score = max(score, 2 if reallocated >= 10 else 1)

    # Pending sectors
    pending = _raw_int(raw_smart, _PENDING)
    if pending > 0:
        issues.append(f"Pending (unreadable) sectors: {pending}")
        score = max(score, 2 if pending >= 5 else 1)

    # Uncorrectable sectors
    uncorrectable = _raw_int(raw_smart, _UNCORRECTABLE)
    if uncorrectable > 0:
        issues.append(f"Uncorrectable sectors: {uncorrectable}")
        score = max(score, 2)

    # Spin retry count
    spin_retry = _raw_int(raw_smart, _SPIN_RETRY)
    if spin_retry > 0:
        issues.append(f"Spin retry count: {spin_retry} (mechanical stress)")
        score = max(score, 1)

    # Power-on hours
    hours = _raw_int(raw_smart, _POWER_ON_HRS)
    if hours == 0:
        # Try info dict fallback
        info_hours = (drive.get("info") or {}).get("Power_On_Hours", "0")
        try:
            hours = int(str(info_hours).replace(",", "").split()[0])
        except (ValueError, IndexError):
            hours = 0
    if hours >= _HOURS_CRITICAL:
        issues.append(f"Power-on hours: {hours:,} (very old disk)")
        score = max(score, 2)
    elif hours >= _HOURS_CAUTION:
        issues.append(f"Power-on hours: {hours:,} (ageing disk)")
        score = max(score, 1)

    # Also respect clone_urgency from m05 if present
    clone_urgency = (drive.get("clone_urgency") or "").lower()
    if clone_urgency in ("critical", "high"):
        score = max(score, 2)
    elif clone_urgency in ("moderate", "medium"):
        score = max(score, 1)

    if score == 2:
        verdict = "CLONE_NOW"
    elif score == 1:
        verdict = "CLONE_SOON"
    else:
        verdict = "CLONE_OK"

    return {
        "device":  device,
        "model":   model,
        "verdict": verdict,
        "issues":  issues,
        "hours":   hours,
        "reallocated":   reallocated,
        "pending":       pending,
        "uncorrectable": uncorrectable,
        "spin_retry":    spin_retry,
    }


def _print_report(assessments: list, source_log: str) -> None:
    w = 60
    print("\n" + "=" * w)
    print("  CLONE READINESS ASSESSMENT")
    print(f"  Source: {source_log}")
    print("=" * w)

    for a in assessments:
        v = a["verdict"]
        model = a["model"]
        dev   = a["device"]
        print(f"\n  {dev}  {model}")
        print(f"  Verdict: {v}")
        if a["verdict"] == "CANNOT_ASSESS":
            print(f"  {a.get('reason','')}")
        else:
            if a["hours"]:
                print(f"  Power-on hours : {a['hours']:,}")
            for issue in a["issues"]:
                marker = "!!" if "Uncorrectable" in issue or "FAILED" in issue or "Reallocated" in issue else " !"
                print(f"  {marker} {issue}")
            if not a["issues"]:
                print("  No SMART problems found.")

        if v == "CLONE_NOW":
            print("\n  *** Clone or replace this disk IMMEDIATELY. ***")
            print("  *** Data loss risk is HIGH.                   ***")
        elif v == "CLONE_SOON":
            print("\n  Cloning to a new drive is recommended soon.")
        else:
            print("\n  Disk appears healthy enough to clone at any time.")

    print("\n" + "=" * w + "\n")


def run(root: Path, argv: list) -> int:
    parser = argparse.ArgumentParser(
        prog="m13_clone_ready",
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--target", default="/mnt/windows",
        help="Path to mounted Windows (used for display only)",
    )
    args = parser.parse_args(argv)

    logs_dir = root / "logs"
    matches  = sorted(logs_dir.glob("disk_health_*.json"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
    if not matches:
        print("ERROR: No disk_health log found. Run m05_disk_health first.")
        return 1

    source = matches[0]
    print(f"[m13] Reading {source.name} ...")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR: Cannot read log: {exc}")
        return 1

    drives = data if isinstance(data, list) else data.get("drives", data.get("disks", []))
    if not isinstance(drives, list) or not drives:
        print("ERROR: No drive data found in disk_health log.")
        return 1

    assessments = [_assess_drive(d) for d in drives]
    _print_report(assessments, source.name)

    ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = logs_dir / f"clone_ready_{ts}.json"
    out.write_text(json.dumps({
        "generated":  datetime.now(timezone.utc).isoformat(),
        "source_log": source.name,
        "assessments": assessments,
    }, indent=2))
    print(f"[m13] Log written → {out}")
    return 0
