"""m40_time_integrity — Clock and timestamp trust analysis.

Collects:
  - Timezone configuration from SOFTWARE hive
  - NTP / W32Time service configuration
  - Event log time-change events (EventID 4616, System log)
  - CMOS battery health indicators (m28 log cross-reference)
  - Timestamp discontinuities in System event log
  - Live clock vs BIOS skew warning

Purpose:
  - Improve confidence in event timelines
  - Support CMOS battery diagnosis
  - Warn when log timing may be unreliable

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m40_time_integrity -- --target /mnt/windows

Output:
    logs/time_integrity_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

DESCRIPTION = (
    "Time integrity: timezone config, NTP service, time-change events, "
    "CMOS indicators, timestamp discontinuities"
)

# ---------------------------------------------------------------------------
# Minimal REGF hive parser (shared pattern)
# ---------------------------------------------------------------------------

_HIVE_BINS_OFFSET = 0x1000


class _RegHive:
    __slots__ = ("_data", "_root_offset")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._root_offset: int = struct.unpack_from("<I", data, 0x24)[0]

    def _cell(self, offset: int) -> Optional[memoryview]:
        if offset == 0xFFFFFFFF or offset < 0:
            return None
        file_off = _HIVE_BINS_OFFSET + offset
        if file_off + 4 > len(self._data):
            return None
        raw_size = struct.unpack_from("<i", self._data, file_off)[0]
        if raw_size >= 0:
            return None
        body_len = (-raw_size) - 4
        if body_len <= 0 or file_off + 4 + body_len > len(self._data):
            return None
        return memoryview(self._data)[file_off + 4: file_off + 4 + body_len]

    def _str_at(self, abs_offset: int, length: int, is_ascii: bool) -> str:
        if abs_offset + length > len(self._data):
            return ""
        raw = bytes(self._data[abs_offset: abs_offset + length])
        enc = "ascii" if is_ascii else "utf-16-le"
        return raw.decode(enc, errors="replace").rstrip("\x00")

    def _nk_info(self, offset: int) -> Optional[dict]:
        cell = self._cell(offset)
        if cell is None or len(cell) < 0x50 or bytes(cell[0:2]) != b"nk":
            return None
        flags           = struct.unpack_from("<H", cell, 2)[0]
        subkeys_offset  = struct.unpack_from("<I", cell, 0x1C)[0]
        values_count    = struct.unpack_from("<I", cell, 0x24)[0]
        values_list_off = struct.unpack_from("<I", cell, 0x28)[0]
        name_length     = struct.unpack_from("<H", cell, 0x48)[0]
        is_ascii        = bool(flags & 0x0020)
        abs_name_off    = _HIVE_BINS_OFFSET + offset + 4 + 0x4C
        name = self._str_at(abs_name_off, name_length, is_ascii)
        return {
            "name": name,
            "subkeys_offset": subkeys_offset,
            "values_count": values_count,
            "values_list_offset": values_list_off,
        }

    def _subkey_offsets(self, list_offset: int) -> List[int]:
        if list_offset == 0xFFFFFFFF:
            return []
        cell = self._cell(list_offset)
        if cell is None or len(cell) < 4:
            return []
        sig   = bytes(cell[0:2])
        count = struct.unpack_from("<H", cell, 2)[0]
        offsets: List[int] = []
        try:
            if sig in (b"lf", b"lh"):
                for i in range(count):
                    pos = 4 + i * 8
                    if pos + 4 > len(cell): break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"li":
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 > len(cell): break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"ri":
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 > len(cell): break
                    sub_off = struct.unpack_from("<I", cell, pos)[0]
                    offsets.extend(self._subkey_offsets(sub_off))
        except Exception:
            pass
        return offsets

    def _find_subkey_offset(self, parent_offset: int, name: str) -> Optional[int]:
        nk = self._nk_info(parent_offset)
        if nk is None:
            return None
        name_lower = name.lower()
        for sub_off in self._subkey_offsets(nk["subkeys_offset"]):
            sub_nk = self._nk_info(sub_off)
            if sub_nk and sub_nk["name"].lower() == name_lower:
                return sub_off
        return None

    def get_key_offset(self, path: str) -> Optional[int]:
        parts = [p for p in path.split("\\") if p]
        current = self._root_offset
        for part in parts:
            found = self._find_subkey_offset(current, part)
            if found is None:
                return None
            current = found
        return current

    def list_subkey_names(self, key_offset: int) -> List[str]:
        nk = self._nk_info(key_offset)
        if nk is None:
            return []
        names: List[str] = []
        for sub_off in self._subkey_offsets(nk["subkeys_offset"]):
            sub_nk = self._nk_info(sub_off)
            if sub_nk:
                names.append(sub_nk["name"])
        return names

    def list_values(self, key_offset: int) -> List[tuple]:
        nk = self._nk_info(key_offset)
        if nk is None or nk["values_count"] == 0 or nk["values_list_offset"] == 0xFFFFFFFF:
            return []
        vlist_cell = self._cell(nk["values_list_offset"])
        if vlist_cell is None:
            return []
        results: List[tuple] = []
        for i in range(nk["values_count"]):
            pos = i * 4
            if pos + 4 > len(vlist_cell): break
            try:
                vk_off = struct.unpack_from("<I", vlist_cell, pos)[0]
                val = self._read_vk(vk_off)
                if val is not None:
                    results.append(val)
            except Exception:
                pass
        return results

    def _read_vk(self, offset: int) -> Optional[tuple]:
        cell = self._cell(offset)
        if cell is None or len(cell) < 0x18 or bytes(cell[0:2]) != b"vk":
            return None
        name_length   = struct.unpack_from("<H", cell, 2)[0]
        data_size_raw = struct.unpack_from("<I", cell, 4)[0]
        data_offset   = struct.unpack_from("<I", cell, 8)[0]
        data_type     = struct.unpack_from("<I", cell, 12)[0]
        flags         = struct.unpack_from("<H", cell, 16)[0]
        is_ascii      = bool(flags & 0x0001)
        name = ""
        if name_length > 0:
            abs_name = _HIVE_BINS_OFFSET + offset + 4 + 0x14
            name = self._str_at(abs_name, name_length, is_ascii)
        inline      = bool(data_size_raw & 0x80000000)
        actual_size = data_size_raw & 0x7FFFFFFF
        try:
            if inline:
                raw = struct.pack("<I", data_offset)[:actual_size]
            else:
                data_cell = self._cell(data_offset)
                if data_cell is None:
                    return (name, data_type, None)
                raw = bytes(data_cell[:actual_size])
            return (name, data_type, _decode_value(data_type, raw))
        except Exception:
            return (name, data_type, None)


def _decode_value(data_type: int, raw: bytes) -> Any:
    if data_type in (1, 2):
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    if data_type == 4:
        return struct.unpack_from("<I", raw)[0] if len(raw) >= 4 else 0
    if data_type == 7:
        text = raw.decode("utf-16-le", errors="replace")
        return [s for s in text.split("\x00") if s]
    return raw.hex() if isinstance(raw, (bytes, bytearray)) else raw


def _open_hive(path: Path) -> Optional[_RegHive]:
    try:
        data = path.read_bytes()
        if len(data) < 0x1000 or data[:4] != b"regf":
            return None
        return _RegHive(data)
    except Exception:
        return None


def _values_dict(hive: _RegHive, key_offset: int) -> dict:
    return {n: d for n, _dt, d in hive.list_values(key_offset)}


# ---------------------------------------------------------------------------
# FILETIME helper
# ---------------------------------------------------------------------------

_FILETIME_EPOCH = 116444736000000000


def _filetime_to_iso(ft: int) -> Optional[str]:
    if ft == 0:
        return None
    try:
        us = (ft - _FILETIME_EPOCH) // 10
        dt = datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def _read_timezone(target: Path) -> dict:
    """Read timezone name and bias from SOFTWARE hive."""
    result: dict = {"timezone_key_name": None, "bias_minutes": None, "limitations": []}
    sw_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    hive = _open_hive(sw_path)
    if hive is None:
        result["limitations"].append("SOFTWARE hive not found")
        return result
    tz_off = hive.get_key_offset(
        "Microsoft\\Windows NT\\CurrentVersion\\Time Zones"
    )
    # Read current TZ from SYSTEM hive TimeZoneInformation
    sys_path = target / "Windows" / "System32" / "config" / "SYSTEM"
    sys_hive = _open_hive(sys_path)
    if sys_hive:
        for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
            off = sys_hive.get_key_offset(
                f"{cs}\\Control\\TimeZoneInformation"
            )
            if off:
                vals = _values_dict(sys_hive, off)
                result["timezone_key_name"]  = vals.get("TimeZoneKeyName") or vals.get("StandardName")
                bias_raw = vals.get("Bias")
                if isinstance(bias_raw, int):
                    # Bias is stored as signed int32 (minutes west of UTC)
                    if bias_raw > 0x7FFFFFFF:
                        bias_raw = bias_raw - 0x100000000
                    result["bias_minutes"] = bias_raw
                break
    return result


def _read_ntp_config(target: Path) -> dict:
    """Read W32Time NTP configuration from SYSTEM hive."""
    result: dict = {
        "w32tm_service_start": None,
        "ntp_server": None,
        "ntp_type": None,
        "limitations": [],
    }
    sys_path = target / "Windows" / "System32" / "config" / "SYSTEM"
    hive = _open_hive(sys_path)
    if hive is None:
        result["limitations"].append("SYSTEM hive not found")
        return result
    for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
        svc_off = hive.get_key_offset(f"{cs}\\Services\\W32Time")
        if svc_off:
            svc_vals = _values_dict(hive, svc_off)
            result["w32tm_service_start"] = svc_vals.get("Start")

        ntp_off = hive.get_key_offset(
            f"{cs}\\Services\\W32Time\\Parameters"
        )
        if ntp_off:
            ntp_vals = _values_dict(hive, ntp_off)
            result["ntp_server"] = ntp_vals.get("NtpServer")
            result["ntp_type"]   = ntp_vals.get("Type")
            break
    return result


# ---------------------------------------------------------------------------
# EVT log parsing — minimal, for EventID 4616 (time change)
# ---------------------------------------------------------------------------

# Windows .evt (legacy) record signature
_EVT_RECORD_SIG = 0x4C664C65  # "eLfL"


def _read_evt_time_changes(log_path: Path) -> List[dict]:
    """Scan a legacy Windows .evt file for EventID 4616 (system time changed)."""
    events: List[dict] = []
    try:
        data = log_path.read_bytes()
    except OSError:
        return events
    offset = 4  # skip file header magic
    limit  = len(data) - 56
    while offset < limit:
        try:
            rec_len = struct.unpack_from("<I", data, offset)[0]
            sig     = struct.unpack_from("<I", data, offset + 4)[0]
            if sig != _EVT_RECORD_SIG or rec_len < 56 or rec_len > 0x10000:
                offset += 4
                continue
            event_id_full = struct.unpack_from("<I", data, offset + 8)[0]
            event_id      = event_id_full & 0xFFFF
            time_gen      = struct.unpack_from("<I", data, offset + 16)[0]
            if event_id == 4616 or event_id == 520:  # 520 = Vista-era equivalent
                dt = datetime.fromtimestamp(time_gen, tz=timezone.utc)
                events.append({
                    "event_id":  event_id,
                    "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                })
            offset += max(rec_len, 4)
        except struct.error:
            break
    return events


def _find_system_evt(target: Path) -> Optional[Path]:
    candidates = [
        target / "Windows" / "System32" / "winevt" / "Logs" / "System.evtx",
        target / "Windows" / "System32" / "config" / "SysEvent.Evt",
        target / "Windows" / "System32" / "config" / "sysevent.evt",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _detect_timestamp_anomalies(log_path: Path) -> List[str]:
    """Heuristic: look for very large time gaps in the system event log."""
    anomalies: List[str] = []
    try:
        data = log_path.read_bytes()
    except OSError:
        return anomalies
    timestamps: List[int] = []
    offset = 4
    limit  = len(data) - 56
    while offset < limit:
        try:
            rec_len = struct.unpack_from("<I", data, offset)[0]
            sig     = struct.unpack_from("<I", data, offset + 4)[0]
            if sig != _EVT_RECORD_SIG or rec_len < 56 or rec_len > 0x10000:
                offset += 4
                continue
            time_gen = struct.unpack_from("<I", data, offset + 16)[0]
            timestamps.append(time_gen)
            offset += max(rec_len, 4)
        except struct.error:
            break

    if len(timestamps) < 2:
        return anomalies

    timestamps.sort()
    prev = timestamps[0]
    for ts in timestamps[1:]:
        gap_days = (ts - prev) / 86400
        if gap_days > 365:
            d1 = datetime.fromtimestamp(prev, tz=timezone.utc).strftime("%Y-%m-%d")
            d2 = datetime.fromtimestamp(ts,   tz=timezone.utc).strftime("%Y-%m-%d")
            anomalies.append(
                f"Gap of {gap_days:.0f} days in event log: {d1} → {d2}"
            )
        prev = ts
    return anomalies


def _check_cmos_log(root: Path) -> Optional[dict]:
    """Look for an existing m28_cmos_health log and summarise CMOS state."""
    logs_dir = root / "logs"
    if not logs_dir.is_dir():
        return None
    cmos_logs = sorted(logs_dir.glob("cmos_health_*.json"), reverse=True)
    if not cmos_logs:
        return None
    try:
        data = json.loads(cmos_logs[0].read_text(encoding="utf-8"))
        return {
            "verdict":        data.get("verdict"),
            "battery_ok":     data.get("battery_ok"),
            "clock_drift_s":  data.get("clock_drift_seconds"),
            "log_file":       cmos_logs[0].name,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path, root: Path) -> dict:
    limitations: List[str] = []

    tz_info  = _read_timezone(target)
    ntp_info = _read_ntp_config(target)
    limitations.extend(tz_info.pop("limitations", []))
    limitations.extend(ntp_info.pop("limitations", []))

    # Time-change events
    time_changes: List[dict] = []
    evt_path = _find_system_evt(target)
    if evt_path:
        if evt_path.suffix.lower() == ".evt":
            time_changes = _read_evt_time_changes(evt_path)
            anomalies    = _detect_timestamp_anomalies(evt_path)
        else:
            limitations.append(
                f"Event log is EVTX format ({evt_path.name}) — only legacy .evt parsing supported; "
                "time-change events not extracted"
            )
            anomalies = []
    else:
        limitations.append("System event log not found")
        anomalies = []

    cmos = _check_cmos_log(root)

    # Derive verdict
    flags: List[str] = []
    if len(time_changes) > 3:
        flags.append(f"frequent_time_changes ({len(time_changes)} events)")
    if anomalies:
        flags.extend(anomalies)
    if cmos and cmos.get("verdict") in ("DEAD", "POOR"):
        flags.append(f"cmos_battery_{cmos['verdict'].lower()}")
    if ntp_info.get("ntp_type") in ("NoSync", None):
        flags.append("ntp_not_configured")

    if any("cmos_battery_dead" in f or "gap" in f.lower() for f in flags):
        verdict = "UNRELIABLE"
    elif flags:
        verdict = "WARNING"
    else:
        verdict = "OK"

    return {
        "scan_status":     "ok",
        "verdict":         verdict,
        "timezone":        tz_info,
        "ntp_config":      ntp_info,
        "time_change_events": time_changes,
        "timestamp_anomalies": anomalies,
        "cmos_summary":    cmos,
        "flags":           flags,
        "limitations":     limitations,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== TIME INTEGRITY ANALYSIS ===")
    print(f"Verdict  : {data.get('verdict', '?')}")

    tz = data.get("timezone", {})
    print(f"Timezone : {tz.get('timezone_key_name', 'unknown')}  "
          f"(bias {tz.get('bias_minutes', '?')} min from UTC)")

    ntp = data.get("ntp_config", {})
    print(f"NTP      : type={ntp.get('ntp_type', '?')}  server={ntp.get('ntp_server', '?')}")

    tc = data.get("time_change_events", [])
    if tc:
        print(f"\nTime-change events ({len(tc)}):")
        for e in tc[:10]:
            print(f"  {e['timestamp']}  EventID {e['event_id']}")

    anoms = data.get("timestamp_anomalies", [])
    if anoms:
        print(f"\nTimestamp anomalies:")
        for a in anoms:
            print(f"  {a}")

    cmos = data.get("cmos_summary")
    if cmos:
        print(f"\nCMOS (from m28 log): verdict={cmos.get('verdict')}  "
              f"drift={cmos.get('clock_drift_s')} s")

    flags = data.get("flags", [])
    if flags:
        print(f"\nFlags:")
        for f in flags:
            print(f"  - {f}")

    limits = data.get("limitations", [])
    if limits:
        print("\nLimitations:")
        for lim in limits:
            print(f"  - {lim}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    from toolkit import find_windows_target  # noqa: PLC0415

    parser = argparse.ArgumentParser(prog="m40_time_integrity", description=DESCRIPTION)
    parser.add_argument("--target", default="")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m40] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    print(f"[m40] Analysing time integrity in {target_path} ...")
    data = analyse(target_path, root)

    from datetime import datetime as _dt, timezone as _tz
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"time_integrity_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m40] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
