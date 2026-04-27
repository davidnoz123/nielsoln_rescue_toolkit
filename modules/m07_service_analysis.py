"""
m07_service_analysis.py — Nielsoln Rescue Toolkit: offline Windows service analysis.

Reads HKLM\\SYSTEM\\CurrentControlSet\\Services from the offline SYSTEM hive and
produces a categorised report of every registered service/driver.  Flags:

  SUSPICIOUS  — unusual image path (not system32/syswow64/program files), or
                known-bad patterns (temp dirs, user profile paths, base64-looking
                names, double-extension tricks)
  THIRD_PARTY — legitimate but non-Microsoft service
  DRIVER      — kernel/filesystem/boot driver
  DISABLED    — start type 4 (disabled)
  DELETED     — ImagePath present but file absent from the target disk

Helps answer:
  - What is running / starts at boot on this machine?
  - Are there malware-installed services?
  - What third-party software has a resident service?

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m07_service_analysis --target /mnt/windows

Output:
    Prints a flagged service table to stdout.
    Writes a JSON log to <USB>/logs/service_analysis_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

DESCRIPTION = (
    "Service analysis: reads offline Windows SYSTEM hive to list all registered "
    "services/drivers with start type, image path, and flags (suspicious, "
    "third-party, driver, disabled, deleted) — requires --target /mnt/windows"
)

# ---------------------------------------------------------------------------
# Pure-Python REGF hive parser (same implementation as m06)
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
        subkeys_count   = struct.unpack_from("<I", cell, 0x14)[0]
        subkeys_offset  = struct.unpack_from("<I", cell, 0x1C)[0]
        values_count    = struct.unpack_from("<I", cell, 0x24)[0]
        values_list_off = struct.unpack_from("<I", cell, 0x28)[0]
        name_length     = struct.unpack_from("<H", cell, 0x48)[0]
        is_ascii        = bool(flags & 0x0020)
        abs_name_off    = _HIVE_BINS_OFFSET + offset + 4 + 0x4C
        name = self._str_at(abs_name_off, name_length, is_ascii)
        return {
            "name": name,
            "subkeys_count": subkeys_count,
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

    def get_subkey_offset(self, key_offset: int, name: str) -> Optional[int]:
        return self._find_subkey_offset(key_offset, name)

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
        if name_length > 0:
            abs_name = _HIVE_BINS_OFFSET + offset + 4 + 0x14
            name = self._str_at(abs_name, name_length, is_ascii)
        else:
            name = ""
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
            return (name, data_type, self._decode_value(data_type, raw))
        except Exception:
            return (name, data_type, None)

    @staticmethod
    def _decode_value(data_type: int, raw: bytes):
        if data_type in (1, 2):
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if data_type == 4:
            return struct.unpack_from("<I", raw)[0] if len(raw) >= 4 else 0
        if data_type == 5:
            return struct.unpack_from(">I", raw)[0] if len(raw) >= 4 else 0
        if data_type == 11:
            return struct.unpack_from("<Q", raw)[0] if len(raw) >= 8 else 0
        if data_type == 7:
            text = raw.decode("utf-16-le", errors="replace")
            return [s for s in text.split("\x00") if s]
        return raw.hex()


def _open_hive(path: Path) -> Optional[_RegHive]:
    try:
        data = path.read_bytes()
        if len(data) < 0x1000 or data[:4] != b"regf":
            return None
        return _RegHive(data)
    except Exception:
        return None


def _values_dict(hive: _RegHive, key_offset: int) -> dict:
    return {name: data for name, _dtype, data in hive.list_values(key_offset)}


# ---------------------------------------------------------------------------
# Service start-type and type constants
# ---------------------------------------------------------------------------

_START_NAMES = {
    0: "BOOT",
    1: "SYSTEM",
    2: "AUTO",
    3: "DEMAND",
    4: "DISABLED",
}

_TYPE_NAMES = {
    0x01: "KERNEL_DRIVER",
    0x02: "FS_DRIVER",
    0x04: "ADAPTER",
    0x08: "RECOGNIZER",
    0x10: "OWN_PROCESS",
    0x20: "SHARE_PROCESS",
    0x50: "OWN_PROCESS_INTERACTIVE",
    0x60: "SHARE_PROCESS_INTERACTIVE",
    0x110: "OWN_PROCESS",
    0x120: "SHARE_PROCESS",
}

_DRIVER_TYPES = {0x01, 0x02, 0x04, 0x08}

# Paths that are considered "safe" locations for service binaries
_SAFE_PATH_PATTERNS = [
    re.compile(r, re.IGNORECASE) for r in [
        r"\\windows\\system32\\",
        r"\\windows\\syswow64\\",
        r"\\windows\\sysnative\\",
        r"\\windows\\servicing\\",
        r"\\program files\\",
        r"\\program files \(x86\)\\",
        r"\\windows\\microsoft\.net\\",
        r"\\windows\\winsxs\\",
        r"%systemroot%",
        r"%windir%",
        r"%programfiles%",
        r"system32\\svchost\.exe",
    ]
]

# Patterns that are always suspicious regardless of location
_SUSPICIOUS_PATTERNS = [
    re.compile(r, re.IGNORECASE) for r in [
        r"\\temp\\",
        r"\\tmp\\",
        r"\\appdata\\",
        r"\\users\\.*\\appdata\\",
        r"\\desktop\\",
        r"\\downloads\\",
        r"\\recycler\\",
        r"\$recycle\.bin",
        # double extension tricks
        r"\.(txt|doc|jpg|pdf|mp3|zip)\.(exe|dll|scr|bat|cmd|ps1)",
        # purely numeric or random-looking short names in non-system paths
    ]
]


def _classify_image_path(raw_path: str, target: Path) -> dict:
    """Return a classification dict for an ImagePath value."""
    if not raw_path:
        return {"resolved": "", "safe": True, "exists": None, "suspicious_reason": None}

    # Strip svchost -k group suffix and service= args
    path = raw_path.strip().strip('"')
    # Extract just the exe path from "C:\path\to\svc.exe -arg1 -arg2"
    # Handle paths with or without quotes
    if raw_path.startswith('"'):
        m = re.match(r'"([^"]+)"', raw_path)
        exe_path = m.group(1) if m else path
    else:
        # First token that looks like a path
        m = re.match(r'([A-Za-z]:\\[^\s]+\.(?:exe|dll|sys|com))', raw_path, re.IGNORECASE)
        if m:
            exe_path = m.group(1)
        else:
            exe_path = raw_path.split()[0] if raw_path.split() else raw_path

    # Expand common env vars for existence checking
    resolved = exe_path
    resolved_lower = resolved.lower()

    # Check suspicious patterns first
    suspicious_reason = None
    for pat in _SUSPICIOUS_PATTERNS:
        if pat.search(resolved_lower):
            suspicious_reason = f"path matches suspicious pattern: {pat.pattern}"
            break

    # Check if it's in a safe location
    safe = any(p.search(resolved_lower) for p in _SAFE_PATH_PATTERNS)

    # Check file existence on target (expand %systemroot% → target/Windows)
    exists = None
    try:
        check = resolved
        check = re.sub(r'%systemroot%', str(target / "Windows"), check, flags=re.IGNORECASE)
        check = re.sub(r'%windir%', str(target / "Windows"), check, flags=re.IGNORECASE)
        check = re.sub(r'%programfiles%', str(target / "Program Files"), check, flags=re.IGNORECASE)
        # Convert Windows path separators and make it relative to target
        if re.match(r'[A-Za-z]:\\', check):
            # Strip drive letter, make relative to target
            rel = re.sub(r'^[A-Za-z]:\\', '', check).replace("\\", "/")
            candidate = target / rel
            exists = candidate.exists()
        elif check.startswith("\\"):
            rel = check.lstrip("\\").replace("\\", "/")
            candidate = target / rel
            exists = candidate.exists()
    except Exception:
        pass

    return {
        "resolved": exe_path,
        "safe": safe,
        "exists": exists,
        "suspicious_reason": suspicious_reason,
    }


# ---------------------------------------------------------------------------
# Determine CurrentControlSet number
# ---------------------------------------------------------------------------

def _get_current_control_set(hive: _RegHive) -> str:
    """Return e.g. 'ControlSet001' by reading Select\\Current."""
    try:
        off = hive.get_key_offset("Select")
        if off is None:
            return "ControlSet001"
        vals = _values_dict(hive, off)
        current = vals.get("Current", 1)
        return f"ControlSet{int(current):03d}"
    except Exception:
        return "ControlSet001"


# ---------------------------------------------------------------------------
# Main parse logic
# ---------------------------------------------------------------------------

def _parse_services(hive: _RegHive, target: Path) -> List[dict]:
    ccs = _get_current_control_set(hive)
    services_path = f"{ccs}\\Services"
    services_off = hive.get_key_offset(services_path)
    if services_off is None:
        raise RuntimeError(f"Key not found in hive: {services_path}")

    service_names = hive.list_subkey_names(services_off)
    results = []

    for svc_name in service_names:
        svc_off = hive.get_subkey_offset(services_off, svc_name)
        if svc_off is None:
            continue
        vals = _values_dict(hive, svc_off)

        start       = vals.get("Start")
        svc_type    = vals.get("Type")
        image_path  = vals.get("ImagePath") or ""
        display     = vals.get("DisplayName") or svc_name
        description = vals.get("Description") or ""
        error_ctrl  = vals.get("ErrorControl")
        object_name = vals.get("ObjectName") or ""  # logon account

        start_name  = _START_NAMES.get(start, str(start) if start is not None else "?")
        type_name   = _TYPE_NAMES.get(svc_type, str(svc_type) if svc_type is not None else "?")
        is_driver   = svc_type in _DRIVER_TYPES if svc_type is not None else False
        is_disabled = (start == 4)

        path_info   = _classify_image_path(image_path, target)

        flags = []
        if path_info["suspicious_reason"]:
            flags.append("SUSPICIOUS")
        elif not path_info["safe"] and image_path and not is_driver:
            flags.append("SUSPICIOUS")
        if is_driver:
            flags.append("DRIVER")
        if is_disabled:
            flags.append("DISABLED")
        if path_info["exists"] is False:
            flags.append("DELETED")
        # Third-party heuristic: non-driver, non-disabled, image path exists but
        # not in a Windows system directory
        if (not is_driver and not is_disabled
                and image_path
                and not path_info["safe"]
                and "SUSPICIOUS" not in flags):
            flags.append("THIRD_PARTY")

        results.append({
            "name":         svc_name,
            "display_name": display if isinstance(display, str) else svc_name,
            "start":        start_name,
            "type":         type_name,
            "image_path":   image_path,
            "resolved_path": path_info["resolved"],
            "path_exists":  path_info["exists"],
            "object_name":  object_name,
            "flags":        flags,
            "suspicious_reason": path_info["suspicious_reason"],
        })

    return results


# ---------------------------------------------------------------------------
# Summary + display
# ---------------------------------------------------------------------------

def _summarise(services: List[dict]) -> dict:
    total       = len(services)
    suspicious  = [s for s in services if "SUSPICIOUS" in s["flags"]]
    third_party = [s for s in services if "THIRD_PARTY" in s["flags"]]
    deleted     = [s for s in services if "DELETED" in s["flags"]]
    auto_start  = [s for s in services if s["start"] in ("AUTO", "BOOT", "SYSTEM")
                   and "DRIVER" not in s["flags"] and "DISABLED" not in s["flags"]]

    verdict = "CLEAN"
    if suspicious:
        verdict = "SUSPICIOUS" if len(suspicious) >= 3 else "REVIEW"
    elif deleted:
        verdict = "REVIEW"

    return {
        "verdict":          verdict,
        "total":            total,
        "suspicious_count": len(suspicious),
        "third_party_count": len(third_party),
        "deleted_count":    len(deleted),
        "auto_start_services": len(auto_start),
        "suspicious":       suspicious,
        "third_party":      third_party,
        "deleted":          deleted,
        "auto_start":       auto_start,
    }


def _print_report(services: List[dict], summary: dict, verbose: bool = False) -> None:
    v = summary["verdict"]
    width = 60
    print("\n" + "=" * width)
    print(f"  SERVICE ANALYSIS — {v}")
    print("=" * width)
    print(f"  Total services/drivers : {summary['total']}")
    print(f"  Auto-start services    : {summary['auto_start_services']}")
    print(f"  Third-party services   : {summary['third_party_count']}")
    print(f"  Suspicious             : {summary['suspicious_count']}")
    print(f"  Deleted (path missing) : {summary['deleted_count']}")

    if summary["suspicious"]:
        print(f"\n{'--- SUSPICIOUS ' + '-'*45}")
        for s in summary["suspicious"]:
            reason = s.get("suspicious_reason") or "path not in safe system directory"
            print(f"  {s['name']:<30}  {s['start']:<9}  {s['image_path']}")
            print(f"    ^ {reason}")

    if summary["deleted"]:
        print(f"\n{'--- DELETED (binary missing) ' + '-'*31}")
        for s in summary["deleted"]:
            print(f"  {s['name']:<30}  {s['start']:<9}  {s['image_path']}")

    if verbose or summary["third_party_count"] > 0:
        print(f"\n{'--- THIRD-PARTY AUTO-START ' + '-'*33}")
        shown = [s for s in summary["third_party"] if s["start"] in ("AUTO", "BOOT", "SYSTEM")]
        if shown:
            for s in shown:
                dn = s["display_name"]
                print(f"  {s['name']:<30}  {s['start']:<9}  {dn}")
        else:
            print("  (none)")

    print()


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    """
    run(root, argv) — module entry point called by bootstrap.

    root : Path to the USB root (for writing logs)
    argv : list of string args, e.g. ["--target", "/mnt/windows"]
    """
    parser = argparse.ArgumentParser(
        prog="m07_service_analysis",
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--target", required=True,
        help="Path to the mounted offline Windows installation, e.g. /mnt/windows",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show all third-party services, not just auto-start ones",
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Print summary only (no per-service detail)",
    )
    args = parser.parse_args(argv)

    target = Path(args.target)
    hive_path = target / "Windows" / "System32" / "config" / "SYSTEM"

    if not hive_path.exists():
        print(f"ERROR: SYSTEM hive not found at {hive_path}")
        return 1

    print(f"[m07] Opening SYSTEM hive: {hive_path} ({hive_path.stat().st_size // 1024} KB)")
    hive = _open_hive(hive_path)
    if hive is None:
        print("ERROR: Failed to parse SYSTEM hive (not a valid REGF file?)")
        return 1

    print("[m07] Parsing services ...")
    try:
        services = _parse_services(hive, target)
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 1

    print(f"[m07] {len(services)} service/driver entries found.")
    summary = _summarise(services)

    if not args.summary:
        _print_report(services, summary, verbose=args.verbose)
    else:
        print(f"\nVerdict: {summary['verdict']}  "
              f"(suspicious={summary['suspicious_count']}, "
              f"third_party={summary['third_party_count']}, "
              f"deleted={summary['deleted_count']})")

    # Write JSON log
    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"service_analysis_{ts}.json"
    log_path.write_text(json.dumps({
        "generated":    datetime.now(timezone.utc).isoformat(),
        "target":       str(target),
        "hive":         str(hive_path),
        "summary":      {k: v for k, v in summary.items()
                         if k not in ("suspicious", "third_party", "deleted", "auto_start")},
        "services":     services,
    }, indent=2))
    print(f"[m07] Log written → {log_path}")
    return 0
