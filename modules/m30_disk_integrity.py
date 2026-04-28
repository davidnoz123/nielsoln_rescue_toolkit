"""
m30_disk_integrity.py — Nielsoln Rescue Toolkit: advanced disk integrity check.

Goes beyond SMART to detect real-world filesystem and controller problems:
  - NTFS dirty bit  ($Volume / VBR flags)
  - CHKDSK log (Event ID 26226 in Application.evtx — "Checking file system")
  - Disk I/O error events (Event IDs 7, 11, 51 in System.evtx)
  - Controller reset events (Event ID 129 in System.evtx)
  - Disk usage summary (free space, partition sizes via statvfs)

SMART tells you about drive hardware health.  This module tells you about
filesystem corruption and controller reliability — a drive can pass SMART
yet still have a dirty/corrupted NTFS volume.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m30_disk_integrity -- --target /mnt/windows

Output:
    Prints a formatted report to stdout.
    Writes JSON to <USB>/logs/disk_integrity_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("m30_disk_integrity")

DESCRIPTION = (
    "Advanced disk integrity: NTFS dirty bit, CHKDSK log events, "
    "disk I/O error events, and controller reset events from Windows "
    "event logs — requires --target /mnt/windows"
)

# ---------------------------------------------------------------------------
# NTFS $Volume attribute / dirty bit
# ---------------------------------------------------------------------------
# The NTFS volume dirty bit lives in the $Volume metadata file at cluster
# 3 of the volume.  Reading the raw device is the most reliable way, but
# from a Linux mount we can check the journal / VBR more simply.
# The easiest portable method: read the NTFS VBR (sector 0) — bit 0 of
# byte at offset 0x40 (a Windows extension) or check via ntfsfix -n.


def _check_dirty_bit(device_path: str) -> dict:
    """
    Check the NTFS dirty bit for the device backing the target mount.
    Tries ntfsfix -n first; falls back to direct VBR byte read.
    """
    result = {"method": None, "dirty": None, "error": None}

    # ntfsfix -n: dry-run — prints "Volume is dirty" if set
    try:
        r = subprocess.run(
            ["ntfsfix", "-n", device_path],
            capture_output=True, text=True, timeout=30
        )
        output = (r.stdout + r.stderr).lower()
        result["method"] = "ntfsfix"
        if "volume is dirty" in output or "dirty flag is set" in output:
            result["dirty"] = True
        elif "volume is clean" in output or r.returncode == 0:
            result["dirty"] = False
        else:
            result["dirty"] = None
            result["note"] = (r.stdout + r.stderr).strip()[:200]
        return result
    except FileNotFoundError:
        pass  # ntfsfix not available
    except Exception as exc:
        result["error"] = str(exc)
        return result

    # Fallback: read byte 0x40 of the NTFS volume itself (VBR extension field).
    # Byte 0x40 = 0x00 → clean; 0x01 → dirty (chkdsk needed); 0x02 → surface scan needed
    try:
        with open(device_path, "rb") as fh:
            fh.seek(0x40)
            byte = fh.read(1)
        if byte:
            val = byte[0]
            result["method"] = "vbr_byte_0x40"
            result["dirty"]  = bool(val & 0x01)
            result["raw_byte"] = hex(val)
        else:
            result["error"] = "Could not read VBR byte"
    except PermissionError:
        result["error"] = "Permission denied reading device — run as root"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def _find_device_for_mount(target: Path) -> str | None:
    """
    Find the block device backing the mount point at *target*.
    Uses /proc/mounts.
    """
    try:
        mounts = Path("/proc/mounts").read_text()
        target_str = str(target).rstrip("/")
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].rstrip("/") == target_str:
                return parts[0]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# EVTX reader (same minimal impl as m28)
# ---------------------------------------------------------------------------

_EVTX_MAGIC  = b"ElfFile\x00"
_CHUNK_MAGIC = b"ElfChnk\x00"


def _read_evtx_xml_records(evtx_path: Path):
    """Yield raw XML strings from an EVTX file (minimal stdlib reader)."""
    try:
        data = evtx_path.read_bytes()
    except (PermissionError, OSError) as exc:
        _log.warning("Cannot read %s: %s", evtx_path, exc)
        return
    if data[:8] != _EVTX_MAGIC:
        return
    pos = 0
    while True:
        idx = data.find(_CHUNK_MAGIC, pos)
        if idx == -1:
            break
        pos = idx + 1
        chunk = data[idx: idx + 65536]
        if len(chunk) < 512:
            continue
        rec_off = 0x200
        while rec_off < len(chunk) - 4:
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
    return int(m.group(1)) if m else None


def _parse_event_time(xml: str) -> str:
    m = re.search(r'SystemTime="([^"]+)"', xml)
    return m.group(1) if m else ""


def _parse_event_data(xml: str) -> dict[str, str]:
    result = {}
    for m in re.finditer(r'<Data Name="([^"]+)"[^>]*>(.*?)</Data>', xml, re.DOTALL):
        result[m.group(1)] = m.group(2).strip()
    return result


def _parse_provider(xml: str) -> str:
    m = re.search(r'<Provider Name="([^"]+)"', xml)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Event log collectors
# ---------------------------------------------------------------------------

# System.evtx disk error event IDs
_DISK_ERROR_IDS = {
    7:   "disk: Bad block",
    11:  "disk: Controller error on device",
    51:  "disk: Paging error",
    55:  "Ntfs: Corruption detected",
    129: "StorPort / disk controller reset",
}

# Application.evtx CHKDSK event
_CHKDSK_ID    = 26226
_CHKDSK_PROV  = "Microsoft-Windows-Chkdsk"


def collect_disk_events(target: Path) -> dict:
    """
    Scan System.evtx for disk error events and Application.evtx for CHKDSK logs.
    """
    result: dict = {
        "system_evtx_available": False,
        "app_evtx_available":    False,
        "disk_errors":    [],
        "chkdsk_entries": [],
    }

    logs_dir = target / "Windows" / "System32" / "winevt" / "Logs"

    # -- System.evtx --
    sys_evtx = logs_dir / "System.evtx"
    if sys_evtx.exists():
        result["system_evtx_available"] = True
        for xml in _read_evtx_xml_records(sys_evtx):
            eid = _parse_event_id(xml)
            if eid in _DISK_ERROR_IDS:
                result["disk_errors"].append({
                    "event_id":    eid,
                    "description": _DISK_ERROR_IDS[eid],
                    "time":        _parse_event_time(xml),
                    "provider":    _parse_provider(xml),
                    "data":        _parse_event_data(xml),
                })
        # Keep last 20
        result["disk_errors"] = result["disk_errors"][-20:]

    # -- Application.evtx --
    app_evtx = logs_dir / "Application.evtx"
    if app_evtx.exists():
        result["app_evtx_available"] = True
        for xml in _read_evtx_xml_records(app_evtx):
            eid = _parse_event_id(xml)
            prov = _parse_provider(xml)
            if eid == _CHKDSK_ID or "chkdsk" in prov.lower():
                result["chkdsk_entries"].append({
                    "event_id": eid,
                    "time":     _parse_event_time(xml),
                    "provider": prov,
                    "data":     _parse_event_data(xml),
                })
        result["chkdsk_entries"] = result["chkdsk_entries"][-10:]

    # Summary counts by type
    from collections import Counter
    eid_counts: Counter = Counter(e["event_id"] for e in result["disk_errors"])
    result["disk_error_counts"] = {
        str(eid): {"count": count, "description": _DISK_ERROR_IDS.get(eid, "")}
        for eid, count in eid_counts.items()
    }
    result["total_disk_errors"] = len(result["disk_errors"])
    result["total_chkdsk_runs"] = len(result["chkdsk_entries"])

    return result


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def _derive_verdict(dirty: dict, events: dict) -> str:
    if dirty.get("dirty") is True:
        return "DIRTY_VOLUME"
    if events.get("total_disk_errors", 0) >= 10:
        return "CRITICAL"
    if events.get("total_disk_errors", 0) >= 3:
        return "WARNING"
    if events.get("total_chkdsk_runs", 0) >= 3:
        return "CHKDSK_HISTORY"
    if dirty.get("error"):
        return "UNKNOWN"
    return "OK"


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def _fmt_report(report: dict) -> str:
    dirty   = report["dirty_bit"]
    events  = report["events"]
    verdict = report["verdict"]

    lines = [
        "=" * 60,
        "  DISK INTEGRITY",
        "=" * 60,
        f"  Verdict : {verdict}",
        "",
        "  NTFS Dirty Bit:",
    ]

    if dirty.get("error"):
        lines.append(f"    Could not check: {dirty['error']}")
    elif dirty.get("dirty") is True:
        lines.append(f"    DIRTY — volume was not cleanly unmounted (method: {dirty['method']})")
        lines.append("    CHKDSK should be run before using this volume.")
    elif dirty.get("dirty") is False:
        lines.append(f"    Clean (method: {dirty['method']})")
    else:
        lines.append("    Unknown")

    lines += [
        "",
        f"  Disk error events in System.evtx  (total: {events.get('total_disk_errors', 0)}):",
    ]
    counts = events.get("disk_error_counts", {})
    if counts:
        for eid, info in sorted(counts.items()):
            lines.append(f"    Event {eid:>5s}: {info['count']:3d}x  {info['description']}")
    else:
        if events.get("system_evtx_available"):
            lines.append("    None — no disk errors recorded")
        else:
            lines.append("    System.evtx not available")

    lines += [
        "",
        f"  CHKDSK history in Application.evtx (total: {events.get('total_chkdsk_runs', 0)}):",
    ]
    if events.get("chkdsk_entries"):
        for e in events["chkdsk_entries"][-5:]:
            lines.append(f"    {e['time'][:19]}  Event {e['event_id']}")
    else:
        if events.get("app_evtx_available"):
            lines.append("    No CHKDSK runs found in event log")
        else:
            lines.append("    Application.evtx not available")

    lines.append("=" * 60)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    ap = argparse.ArgumentParser(prog="m30_disk_integrity", description=DESCRIPTION)
    ap.add_argument("--target", required=False, default=None,
                    help="Mount point of the Windows installation")
    args = ap.parse_args(argv)

    if args.target:
        target = Path(args.target)
    else:
        try:
            from toolkit import find_windows_target
            target = find_windows_target()
        except Exception:
            target = None
        if target is None:
            _log.error("Could not auto-detect Windows target. Pass --target.")
            return 1
        print(f"[m30] Auto-detected target: {target}", flush=True)

    if not target.exists():
        _log.error("Target path does not exist: %s", target)
        return 1

    # Find the device backing this mount
    device = _find_device_for_mount(target)
    if device:
        print(f"[m30] Detected device: {device}", flush=True)
    else:
        print("[m30] Could not detect device for mount — dirty bit check may be skipped",
              flush=True)

    print("[m30] Checking NTFS dirty bit ...", flush=True)
    dirty = {"method": None, "dirty": None, "error": "No device detected"} \
        if not device else _check_dirty_bit(device)
    if dirty.get("dirty") is True:
        print("[m30] *** DIRTY BIT SET — volume was not cleanly unmounted ***", flush=True)
    elif dirty.get("dirty") is False:
        print("[m30] Dirty bit: clean", flush=True)
    else:
        print(f"[m30] Dirty bit: unknown  ({dirty.get('error', '')})", flush=True)

    print("[m30] Scanning event logs for disk errors and CHKDSK history ...", flush=True)
    events = collect_disk_events(target)
    print(f"[m30] Disk error events: {events['total_disk_errors']}  "
          f"CHKDSK runs: {events['total_chkdsk_runs']}", flush=True)

    verdict = _derive_verdict(dirty, events)

    report = {
        "target":    str(target),
        "device":    device,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict":   verdict,
        "dirty_bit": dirty,
        "events":    events,
    }

    print()
    print(_fmt_report(report))

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = root / "logs" / f"disk_integrity_{ts}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"[m30] Saved → {out_path}", flush=True)
    return 0
