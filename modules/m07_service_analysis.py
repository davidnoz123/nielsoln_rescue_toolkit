"""
m07_service_analysis.py — Nielsoln Rescue Toolkit: offline Windows service analysis.

Reads HKLM\\SYSTEM\\CurrentControlSet\\Services from the offline SYSTEM hive and
produces a rich categorised report of every registered service/driver.

Collected per-service:
  SERVICE_FULL_CONFIG   — all registry values decoded (Start, Type, ErrorControl,
                          Group, Tag, DependOnService, DependOnGroup, ObjectName,
                          Description, DelayedAutoStart, FailureActions,
                          RequiredPrivileges, ServiceSidType, LaunchProtected)
  SERVICE_DLL_DETAILS   — Parameters\\ServiceDll / ServiceMain / ServiceDllUnloadOnStop
  SVCHOST_GROUPS        — which svchost -k group the service belongs to (from SOFTWARE)
  SERVICE_FILE_EVIDENCE — resolved path, size, mtime, SHA256, PE version strings,
                          location classification, unquoted path risk
  SERVICE_EVENT_HISTORY — SCM event counts + recent examples from System.evtx

Risk flags (extends v1 set):
  SUSPICIOUS                — unusual image path or known-bad pattern
  THIRD_PARTY               — non-Microsoft service outside system dirs
  DRIVER                    — kernel / filesystem / boot driver
  DISABLED                  — start type 4
  DELETED / MISSING_BINARY  — ImagePath present but file absent
  MISSING_SERVICE_DLL       — Parameters\\ServiceDll absent from disk
  UNQUOTED_PATH             — unquoted path with spaces (privilege escalation risk)
  AUTO_START_WRITABLE_LOCATION — auto-start from user-writable directory
  HAS_FAILURE_EVENTS        — SCM failure events in System.evtx
  SVCHOST_NO_GROUP          — svchost-hosted but group not in SOFTWARE mapping
  PARSE_ERROR               — corrupt registry entry, skipped

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m07_service_analysis --target /mnt/windows

Output:
    Prints a flagged service table to stdout.
    Writes logs/service_analysis_<timestamp>.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DESCRIPTION = (
    "Service analysis: reads offline SYSTEM hive for full service configuration, "
    "file evidence, ServiceDll details, svchost group mapping, and SCM event history"
)

# ---------------------------------------------------------------------------
# Pure-Python REGF hive parser (same core as m06)
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
        if data_type == 3:
            return raw  # REG_BINARY — return raw bytes for caller to decode
        if data_type == 4:
            return struct.unpack_from("<I", raw)[0] if len(raw) >= 4 else 0
        if data_type == 5:
            return struct.unpack_from(">I", raw)[0] if len(raw) >= 4 else 0
        if data_type == 7:
            text = raw.decode("utf-16-le", errors="replace")
            return [s for s in text.split("\x00") if s]
        if data_type == 11:
            return struct.unpack_from("<Q", raw)[0] if len(raw) >= 8 else 0
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
    return {name: data for name, _dtype, data in hive.list_values(key_offset)}


# ---------------------------------------------------------------------------
# Service registry constants
# ---------------------------------------------------------------------------

_START_NAMES = {0: "BOOT", 1: "SYSTEM", 2: "AUTO", 3: "DEMAND", 4: "DISABLED"}

# Legacy type name table (v1 compat — used for the "type" string field)
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

# Bit-flag decoding for config.type_flags
_SERVICE_TYPE_FLAGS: Dict[int, str] = {
    0x001: "KERNEL_DRIVER",
    0x002: "FILE_SYSTEM_DRIVER",
    0x004: "ADAPTER",
    0x008: "RECOGNIZER_DRIVER",
    0x010: "WIN32_OWN_PROCESS",
    0x020: "WIN32_SHARE_PROCESS",
    0x100: "INTERACTIVE_PROCESS",
}

_DRIVER_TYPES = {0x01, 0x02, 0x04, 0x08}

_ERROR_CONTROL_NAMES = {0: "IGNORE", 1: "NORMAL", 2: "SEVERE", 3: "CRITICAL"}

_FAILURE_ACTION_TYPE_NAMES = {0: "NONE", 1: "RESTART", 2: "REBOOT", 3: "RUN_COMMAND"}

_SERVICE_SID_TYPE_NAMES = {0: "NONE", 1: "UNRESTRICTED", 3: "RESTRICTED"}

_LAUNCH_PROTECTED_NAMES = {
    0: "NONE",
    1: "PPL_WINDOWS_LIGHT",
    2: "PPL_ANTIMALWARE_LIGHT",
    3: "PPL_WINDOWS",
}

# Safe locations for service binaries
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

# Patterns that are always suspicious
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
        r"\.(txt|doc|jpg|pdf|mp3|zip)\.(exe|dll|scr|bat|cmd|ps1)$",
    ]
]

# SCM event IDs of interest in System.evtx
_SCM_EVENT_IDS = {
    7000: "service_failed_start",
    7001: "dependency_failed_start",
    7002: "dependency_group_failed",
    7003: "dependency_nonexistent",
    7009: "timeout_connect",
    7011: "timeout_transaction",
    7023: "terminated_with_error",
    7024: "terminated_service_error",
    7031: "terminated_unexpectedly",
    7032: "corrective_action_attempted",
    7034: "terminated_unexpectedly",
    7045: "new_service_installed",
}
_SCM_ERROR_IDS = {7000, 7001, 7002, 7003, 7009, 7011, 7023, 7024, 7031, 7032, 7034}

_EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# ---------------------------------------------------------------------------
# Control set context
# ---------------------------------------------------------------------------

def _get_control_set_context(hive: _RegHive) -> dict:
    """Resolve the active control set and return context metadata."""
    try:
        sel_off = hive.get_key_offset("Select")
        if sel_off is None:
            return {
                "active": "ControlSet001",
                "available": [],
                "current_value": None,
                "last_known_good": None,
                "failed_boot_count": None,
                "fallback_used": True,
                "error": "Select key not found",
            }
        vals = _values_dict(hive, sel_off)
        current_val     = vals.get("Current")
        last_known_good = vals.get("LastKnownGood")
        failed_val      = vals.get("Failed")

        active = f"ControlSet{int(current_val or 1):03d}"

        # Enumerate available ControlSetNNN keys
        available: List[str] = []
        for name in hive.list_subkey_names(hive._root_offset):
            if re.match(r"^ControlSet\d{3}$", name, re.IGNORECASE):
                available.append(name)
        available.sort()

        # Verify the selected set exists; fall back if not
        fallback_used = False
        if active not in available and available:
            active = available[0]
            fallback_used = True

        return {
            "active":            active,
            "available":         available,
            "current_value":     current_val,
            "last_known_good":   last_known_good,
            "failed_boot_count": failed_val,
            "fallback_used":     fallback_used,
        }
    except Exception as exc:
        return {
            "active": "ControlSet001",
            "available": [],
            "current_value": None,
            "last_known_good": None,
            "failed_boot_count": None,
            "fallback_used": True,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# FailureActions REG_BINARY decoder
# ---------------------------------------------------------------------------

def _parse_failure_actions(raw) -> Optional[dict]:
    """Decode the FailureActions REG_BINARY value.

    Layout: DWORD dwResetPeriod, DWORD (reserved), DWORD (reserved),
            DWORD cActions, ACTION[cActions] {DWORD Type; DWORD Delay_ms}
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            raw = bytes.fromhex(raw)
        except ValueError:
            return None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 16:
        return None
    try:
        reset_period = struct.unpack_from("<I", raw, 0)[0]
        c_actions    = struct.unpack_from("<I", raw, 12)[0]
        actions = []
        for i in range(min(c_actions, 8)):
            off = 16 + i * 8
            if off + 8 > len(raw):
                break
            atype    = struct.unpack_from("<I", raw, off)[0]
            delay_ms = struct.unpack_from("<I", raw, off + 4)[0]
            actions.append({
                "type":     _FAILURE_ACTION_TYPE_NAMES.get(atype, str(atype)),
                "delay_ms": delay_ms,
            })
        return {"reset_period_sec": reset_period, "actions": actions}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _expand_win_path(path_str: str, target: Path) -> str:
    """Expand common Windows env vars to target-relative absolute strings."""
    p = path_str.strip().strip('"')
    p = re.sub(r"%systemroot%",           str(target / "Windows"),              p, flags=re.IGNORECASE)
    p = re.sub(r"%windir%",               str(target / "Windows"),              p, flags=re.IGNORECASE)
    p = re.sub(r"%programfiles%",         str(target / "Program Files"),        p, flags=re.IGNORECASE)
    p = re.sub(r"%programfiles\(x86\)%",  str(target / "Program Files (x86)"),  p, flags=re.IGNORECASE)
    p = re.sub(r"%systemdrive%",          str(target),                          p, flags=re.IGNORECASE)
    return p


def _extract_exe_from_image_path(image_path: str) -> str:
    """Extract the bare executable path (without args) from an ImagePath value."""
    if not image_path:
        return ""
    s = image_path.strip()
    if s.startswith('"'):
        m = re.match(r'"([^"]+)"', s)
        return m.group(1) if m else s.strip('"')
    m = re.match(r'([A-Za-z]:\\[^\s]+\.(?:exe|dll|sys|com))', s, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.match(r'(%[^%]+%\\[^\s]+\.(?:exe|dll|sys|com))', s, re.IGNORECASE)
    if m:
        return m.group(1)
    tokens = s.split()
    return tokens[0] if tokens else s


def _check_unquoted_path(image_path: str) -> bool:
    """Return True if image_path is unquoted and contains spaces (priv-esc risk)."""
    if not image_path:
        return False
    s = image_path.strip()
    if s.startswith('"'):
        return False
    if " " not in s:
        return False
    # svchost -k pattern is not a real unquoted path risk
    if re.search(r"svchost\.exe\s+-k\s+\w+", s, re.IGNORECASE):
        return False
    # Use .*? (non-greedy) to capture the full path up to the extension,
    # including any directory components that contain spaces.
    m = re.match(r'([A-Za-z]:\\.*?\.(?:exe|dll|sys|com))', s, re.IGNORECASE)
    if m:
        return " " in m.group(1)
    # Fallback: check if the first whitespace-delimited token has spaces (unlikely)
    return " " in s.split()[0] if s.split() else False


def _win_path_to_local(win_path: str, target: Path) -> Optional[Path]:
    """Convert a Windows path (drive-letter or env-expanded) to a Path under target."""
    p = _expand_win_path(win_path, target)
    m = re.match(r'[A-Za-z]:\\(.*)', p)
    if m:
        rel = m.group(1).replace("\\", "/")
        return target / rel
    if p.startswith("\\"):
        rel = p.lstrip("\\").replace("\\", "/")
        return target / rel
    return None


# ---------------------------------------------------------------------------
# PE version string reader (best-effort scan-based, no external deps)
# ---------------------------------------------------------------------------

_PE_VERSION_KEYS = [
    "CompanyName", "ProductName", "FileVersion", "ProductVersion",
    "InternalName", "OriginalFilename", "FileDescription",
]
_PE_MAX_SCAN = 8 * 1024 * 1024


def _parse_pe_version_strings(data: bytes) -> dict:
    """Scan PE bytes for VS_VERSION_INFO String entries.  Best-effort; {} on failure."""
    result: dict = {}
    try:
        for key in _PE_VERSION_KEYS:
            encoded = (key + "\x00").encode("utf-16-le")
            pos = 0
            while True:
                p = data.find(encoded, pos)
                if p < 0:
                    break
                if p < 6:
                    pos = p + 2
                    continue
                hdr       = p - 6
                w_len     = struct.unpack_from("<H", data, hdr)[0]
                w_val_len = struct.unpack_from("<H", data, hdr + 2)[0]
                w_type    = struct.unpack_from("<H", data, hdr + 4)[0]
                if w_type not in (0, 1) or w_len < 8 or w_val_len > 512 or w_len > 4096:
                    pos = p + 2
                    continue
                after_key = p + len(encoded)
                aligned   = hdr + (((after_key - hdr) + 3) & ~3)
                val_bytes = w_val_len * 2
                val_end   = aligned + val_bytes
                if val_end > len(data) or val_bytes == 0:
                    pos = p + 2
                    continue
                value = data[aligned:val_end].decode("utf-16-le", errors="replace").rstrip("\x00")
                if value and 1 <= len(value) <= 200:
                    result[key] = value
                    break
                pos = p + 2
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# File evidence
# ---------------------------------------------------------------------------

_LOCATION_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("system32",      re.compile(r"\\windows\\system32\\",  re.IGNORECASE)),
    ("syswow64",      re.compile(r"\\windows\\syswow64\\",  re.IGNORECASE)),
    ("winsxs",        re.compile(r"\\windows\\winsxs\\",    re.IGNORECASE)),
    ("windows",       re.compile(r"\\windows\\",            re.IGNORECASE)),
    ("program_files", re.compile(r"\\program files",        re.IGNORECASE)),
    ("appdata",       re.compile(r"\\appdata\\",            re.IGNORECASE)),
    ("users",         re.compile(r"\\users\\",              re.IGNORECASE)),
    ("temp",          re.compile(r"\\te?mp\\",              re.IGNORECASE)),
]
_SHA256_MAX = 50 * 1024 * 1024


def _classify_location(path_str: str) -> str:
    for label, pat in _LOCATION_PATTERNS:
        if pat.search(path_str):
            return label
    return "other"


def _get_file_evidence(win_exe_path: str, target: Path) -> dict:
    """Collect file-system evidence for a service binary path (read-only)."""
    base: dict = {
        "win_path":           win_exe_path,
        "exists":             None,
        "size_bytes":         None,
        "modified":           None,
        "sha256":             None,
        "location":           _classify_location(win_exe_path),
        "suspicious_location": False,
        "version_info":       {},
        "error":              None,
    }
    if not win_exe_path:
        return base

    local = _win_path_to_local(win_exe_path, target)
    if local is None:
        base["error"] = "could not resolve path"
        return base

    try:
        if not local.exists():
            base["exists"] = False
            return base
        base["exists"] = True
        st = local.stat()
        base["size_bytes"] = st.st_size
        base["modified"]   = datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
    except Exception as exc:
        base["error"] = str(exc)
        return base

    # SHA256 (skip very large files)
    try:
        if st.st_size <= _SHA256_MAX:
            h = hashlib.sha256()
            with local.open("rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            base["sha256"] = h.hexdigest()
    except Exception:
        pass

    # PE version strings
    try:
        suffix = local.suffix.lower()
        if suffix in (".exe", ".dll", ".sys") and st.st_size <= _PE_MAX_SCAN:
            raw = local.read_bytes()
            if raw[:2] == b"MZ":
                base["version_info"] = _parse_pe_version_strings(raw)
    except Exception:
        pass

    # Suspicious location flag
    for pat in _SUSPICIOUS_PATTERNS:
        if pat.search(win_exe_path.lower()):
            base["suspicious_location"] = True
            break

    return base


# ---------------------------------------------------------------------------
# ServiceDll details (Parameters subkey)
# ---------------------------------------------------------------------------

def _get_service_dll_details(
    hive: _RegHive, svc_off: int, target: Path
) -> Optional[dict]:
    """Read Parameters\\ServiceDll and related values.  Returns None if absent."""
    try:
        params_off = hive.get_subkey_offset(svc_off, "Parameters")
        if params_off is None:
            return None
        vals      = _values_dict(hive, params_off)
        dll_path  = vals.get("ServiceDll", "")
        if not dll_path:
            return None
        main_func     = vals.get("ServiceMain")
        unload_on_stop = vals.get("ServiceDllUnloadOnStop")
        exe_path  = _extract_exe_from_image_path(str(dll_path))
        evidence  = _get_file_evidence(exe_path, target)
        return {
            "ServiceDll":                  dll_path,
            "ServiceMain":                 main_func,
            "ServiceDllUnloadOnStop":      bool(unload_on_stop) if unload_on_stop is not None else None,
            "resolved_path":               exe_path,
            "file_evidence":               evidence,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Svchost group mapping (SOFTWARE hive)
# ---------------------------------------------------------------------------

def _get_svchost_groups(target: Path) -> Dict[str, List[str]]:
    """Return {group_name: [service_names]} from offline SOFTWARE hive.

    Key: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost
    Each value is REG_MULTI_SZ listing service names in that group.
    """
    groups: Dict[str, List[str]] = {}
    soft_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    if not soft_path.exists():
        return groups
    hive = _open_hive(soft_path)
    if hive is None:
        return groups
    try:
        key_off = hive.get_key_offset(
            r"Microsoft\Windows NT\CurrentVersion\Svchost"
        )
        if key_off is None:
            return groups
        for name, dtype, data in hive.list_values(key_off):
            if isinstance(data, list):
                groups[name] = [s.lower() for s in data if s]
            elif isinstance(data, str) and data:
                groups[name] = [s.lower() for s in data.split() if s]
    except Exception:
        pass
    return groups


def _build_svc_to_group(groups: Dict[str, List[str]]) -> Dict[str, str]:
    """Invert group→services to service_name→group_name (all lower-case)."""
    result: Dict[str, str] = {}
    for group, services in groups.items():
        for svc in services:
            result[svc.lower()] = group
    return result


# ---------------------------------------------------------------------------
# SCM event history from System.evtx
# ---------------------------------------------------------------------------

def _ensure_evtx() -> bool:
    """Load python-evtx from m23's bundled wheel if not already importable."""
    try:
        import Evtx.Evtx  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        m23_path = Path(__file__).parent / "m23_logon_audit.py"
        if not m23_path.exists():
            return False
        spec = importlib.util.spec_from_file_location("_m23_loader_m07", m23_path)
        m23  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m23)
        return m23._ensure_evtx()
    except Exception:
        return False


def _evtx_data_named(event_data, name: str) -> str:
    ns = _EVTX_NS
    for el in event_data.findall(f"{{{ns}}}Data"):
        if el.get("Name", "") == name:
            return (el.text or "").strip()
    return ""


def _load_service_events(target: Path) -> Dict[str, dict]:
    """Parse System.evtx for SCM events.

    Returns {service_name_lower: {event_counts: {eid_str: count},
                                   recent_events: [{event_id, timestamp, category}, ...]}}
    """
    results: Dict[str, dict] = {}
    evtx_path = (
        target / "Windows" / "System32" / "winevt" / "Logs" / "System.evtx"
    )
    if not evtx_path.exists():
        return results
    if not _ensure_evtx():
        return results
    try:
        import Evtx.Evtx as evtx
        with evtx.Evtx(str(evtx_path)) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                    ns   = _EVTX_NS
                    sys_el = root.find(f"{{{ns}}}System")
                    if sys_el is None:
                        continue
                    eid_el = sys_el.find(f"{{{ns}}}EventID")
                    if eid_el is None:
                        continue
                    eid = int(eid_el.text or 0)
                    if eid not in _SCM_EVENT_IDS:
                        continue
                    ts_el = sys_el.find(f"{{{ns}}}TimeCreated")
                    ts = ts_el.get("SystemTime", "") if ts_el is not None else ""
                    evt_data = root.find(f"{{{ns}}}EventData")
                    if evt_data is None:
                        continue
                    # Service name: try named params then first unnamed Data element
                    svc_name = _evtx_data_named(evt_data, "param1")
                    if not svc_name:
                        svc_name = _evtx_data_named(evt_data, "ServiceName")
                    if not svc_name:
                        els = list(evt_data)
                        if els:
                            svc_name = (els[0].text or "").strip()
                    if not svc_name:
                        continue
                    key = svc_name.lower()
                    if key not in results:
                        results[key] = {"event_counts": {}, "recent_events": []}
                    ec      = results[key]["event_counts"]
                    eid_str = str(eid)
                    ec[eid_str] = ec.get(eid_str, 0) + 1
                    if len(results[key]["recent_events"]) < 5:
                        results[key]["recent_events"].append({
                            "event_id":  eid,
                            "timestamp": ts,
                            "category":  _SCM_EVENT_IDS[eid],
                        })
                except Exception:
                    continue
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# Full service configuration decoder
# ---------------------------------------------------------------------------

def _decode_type_flags(type_val: Optional[int]) -> List[str]:
    if type_val is None:
        return []
    return [name for bit, name in sorted(_SERVICE_TYPE_FLAGS.items()) if type_val & bit]


def _build_full_config(vals: dict) -> dict:
    """Build SERVICE_FULL_CONFIG dict from raw registry values dict."""
    start_raw = vals.get("Start")
    type_raw  = vals.get("Type")
    ec_raw    = vals.get("ErrorControl")
    sid_raw   = vals.get("ServiceSidType")
    lp_raw    = vals.get("LaunchProtected")
    return {
        "start_raw":            start_raw,
        "start_name":           _START_NAMES.get(start_raw, str(start_raw) if start_raw is not None else None),
        "type_raw":             type_raw,
        "type_flags":           _decode_type_flags(type_raw),
        "error_control_raw":    ec_raw,
        "error_control":        _ERROR_CONTROL_NAMES.get(ec_raw, str(ec_raw) if ec_raw is not None else None),
        "group":                vals.get("Group"),
        "tag":                  vals.get("Tag"),
        "depend_on_service":    vals.get("DependOnService") or [],
        "depend_on_group":      vals.get("DependOnGroup")   or [],
        "object_name":          vals.get("ObjectName"),
        "description":          vals.get("Description"),
        "delayed_auto_start":   bool(vals.get("DelayedAutostart") or vals.get("DelayedAutoStart")),
        "failure_actions":      _parse_failure_actions(vals.get("FailureActions")),
        "failure_command":      vals.get("FailureCommand"),
        "required_privileges":  vals.get("RequiredPrivileges") or [],
        "service_sid_type_raw": sid_raw,
        "service_sid_type":     _SERVICE_SID_TYPE_NAMES.get(sid_raw, str(sid_raw) if sid_raw is not None else None),
        "launch_protected_raw": lp_raw,
        "launch_protected":     _LAUNCH_PROTECTED_NAMES.get(lp_raw, str(lp_raw) if lp_raw is not None else None),
    }


# ---------------------------------------------------------------------------
# Image-path classification (v1 logic preserved + unquoted_path_risk added)
# ---------------------------------------------------------------------------

def _classify_image_path(raw_path: str, target: Path) -> dict:
    """Return a classification dict for an ImagePath value."""
    if not raw_path:
        return {
            "resolved": "", "safe": True, "exists": None,
            "suspicious_reason": None, "unquoted_path_risk": False,
        }

    exe_path      = _extract_exe_from_image_path(raw_path)
    exe_lower     = exe_path.lower()

    suspicious_reason = None
    for pat in _SUSPICIOUS_PATTERNS:
        if pat.search(exe_lower):
            suspicious_reason = f"path matches suspicious pattern: {pat.pattern}"
            break

    safe     = any(p.search(exe_lower) for p in _SAFE_PATH_PATTERNS)
    unquoted = _check_unquoted_path(raw_path)

    exists = None
    try:
        local = _win_path_to_local(exe_path, target)
        if local is not None:
            exists = local.exists()
    except Exception:
        pass

    return {
        "resolved":          exe_path,
        "safe":              safe,
        "exists":            exists,
        "suspicious_reason": suspicious_reason,
        "unquoted_path_risk": unquoted,
    }


# ---------------------------------------------------------------------------
# Risk flag builder
# ---------------------------------------------------------------------------

def _build_flags(
    path_info:     dict,
    config:        dict,
    dll:           Optional[dict],
    type_raw:      Optional[int],
    svchost_group: Optional[str],
    event_history: Optional[dict],
    image_path:    str,
) -> List[str]:
    flags: List[str] = []
    is_driver   = bool(type_raw is not None and (type_raw & 0x0F) in {1, 2, 4, 8})
    is_disabled = (config.get("start_name") == "DISABLED")
    is_auto     = config.get("start_name") in ("AUTO", "BOOT", "SYSTEM")

    # Suspicious path
    if path_info.get("suspicious_reason") or path_info.get("suspicious_location"):
        flags.append("SUSPICIOUS")
    elif image_path and not path_info.get("safe") and not is_driver:
        flags.append("SUSPICIOUS")

    # Missing binary
    if path_info.get("exists") is False and image_path:
        flags.append("MISSING_BINARY")
        flags.append("DELETED")  # v1 compat

    # Unquoted path
    if path_info.get("unquoted_path_risk"):
        flags.append("UNQUOTED_PATH")

    # Missing ServiceDll
    if dll is not None and dll["file_evidence"].get("exists") is False:
        flags.append("MISSING_SERVICE_DLL")

    # Auto-start from user-writable location
    loc = path_info.get("location", "")
    if is_auto and loc in ("users", "appdata", "temp") and not is_disabled:
        if "SUSPICIOUS" not in flags:
            flags.append("SUSPICIOUS")
        flags.append("AUTO_START_WRITABLE_LOCATION")

    # Disabled
    if is_disabled:
        flags.append("DISABLED")

    # Driver
    if is_driver:
        flags.append("DRIVER")

    # SCM failure events
    if event_history and any(
        int(eid) in _SCM_ERROR_IDS for eid in event_history.get("event_counts", {})
    ):
        flags.append("HAS_FAILURE_EVENTS")

    # Svchost without group mapping
    if image_path and re.search(r"svchost\.exe", image_path, re.IGNORECASE):
        if svchost_group is None:
            flags.append("SVCHOST_NO_GROUP")

    # Third-party
    if (not is_driver and not is_disabled and image_path
            and not path_info.get("safe") and "SUSPICIOUS" not in flags):
        flags.append("THIRD_PARTY")

    return flags


# ---------------------------------------------------------------------------
# Single service parser
# ---------------------------------------------------------------------------

def _parse_one_service(
    hive:          _RegHive,
    svc_off:       int,
    svc_name:      str,
    target:        Path,
    svc_to_group:  Dict[str, str],
    service_events: Dict[str, dict],
) -> dict:
    vals = _values_dict(hive, svc_off)

    start_raw  = vals.get("Start")
    type_raw   = vals.get("Type")
    image_path = vals.get("ImagePath") or ""
    display    = vals.get("DisplayName") or svc_name
    if not isinstance(display, str):
        display = svc_name

    # Full config
    config = _build_full_config(vals)

    # Path classification (v1 compat fields)
    path_info = _classify_image_path(image_path, target)

    # File evidence for the main executable
    exe_path = _extract_exe_from_image_path(image_path)
    file_evidence = _get_file_evidence(exe_path, target) if exe_path else {
        "win_path": "", "exists": None, "size_bytes": None, "modified": None,
        "sha256": None, "location": "unknown", "suspicious_location": False,
        "version_info": {}, "error": None,
    }

    # ServiceDll details
    dll_details = _get_service_dll_details(hive, svc_off, target)

    # Svchost group
    svchost_group: Optional[str] = svc_to_group.get(svc_name.lower())

    # SCM event history
    event_history = service_events.get(svc_name.lower())

    # Risk flags
    flags = _build_flags(
        path_info, config, dll_details, type_raw,
        svchost_group, event_history, image_path,
    )

    # v1 "type" string field
    type_name = _TYPE_NAMES.get(type_raw, str(type_raw) if type_raw is not None else "?")

    return {
        # --- Preserved v1 fields ---
        "name":              svc_name,
        "display_name":      display,
        "start":             config["start_name"] or "?",
        "type":              type_name,
        "image_path":        image_path,
        "resolved_path":     path_info["resolved"],
        "path_exists":       path_info["exists"],
        "object_name":       vals.get("ObjectName") or "",
        "flags":             flags,
        "suspicious_reason": path_info["suspicious_reason"],
        # --- New v2 fields ---
        "config":            config,
        "file_evidence":     file_evidence,
        "dll_details":       dll_details,
        "svchost_group":     svchost_group,
        "event_history":     event_history,
        "unquoted_path_risk": path_info["unquoted_path_risk"],
    }


# ---------------------------------------------------------------------------
# Main parse loop
# ---------------------------------------------------------------------------

def _parse_services(
    hive:           _RegHive,
    target:         Path,
    svc_to_group:   Dict[str, str],
    service_events: Dict[str, dict],
    ccs:            str,
) -> List[dict]:
    services_path = f"{ccs}\\Services"
    services_off  = hive.get_key_offset(services_path)
    if services_off is None:
        raise RuntimeError(f"Key not found in hive: {services_path}")

    results: List[dict] = []
    for svc_name in hive.list_subkey_names(services_off):
        svc_off = hive.get_subkey_offset(services_off, svc_name)
        if svc_off is None:
            continue
        try:
            results.append(
                _parse_one_service(hive, svc_off, svc_name, target,
                                   svc_to_group, service_events)
            )
        except Exception:
            results.append({
                "name": svc_name, "display_name": svc_name,
                "start": "?", "type": "?", "image_path": "",
                "resolved_path": "", "path_exists": None, "object_name": "",
                "flags": ["PARSE_ERROR"], "suspicious_reason": None,
                "config": {}, "file_evidence": {}, "dll_details": None,
                "svchost_group": None, "event_history": None,
                "unquoted_path_risk": False,
            })
    return results


# ---------------------------------------------------------------------------
# Summary (v2 extended — all v1 fields preserved)
# ---------------------------------------------------------------------------

def _summarise(services: List[dict]) -> dict:
    total       = len(services)
    suspicious  = [s for s in services if "SUSPICIOUS"           in s["flags"]]
    third_party = [s for s in services if "THIRD_PARTY"          in s["flags"]]
    deleted     = [s for s in services if "DELETED"              in s["flags"]]
    missing_bin = [s for s in services if "MISSING_BINARY"       in s["flags"]]
    missing_dll = [s for s in services if "MISSING_SERVICE_DLL"  in s["flags"]]
    unquoted    = [s for s in services if "UNQUOTED_PATH"        in s["flags"]]
    has_events  = [s for s in services if "HAS_FAILURE_EVENTS"   in s["flags"]]
    disabled    = [s for s in services if "DISABLED"             in s["flags"]]
    boot_drvr   = [s for s in services if s["start"] == "BOOT"   and "DRIVER" in s["flags"]]
    sys_drvr    = [s for s in services if s["start"] == "SYSTEM" and "DRIVER" in s["flags"]]
    auto_start  = [s for s in services
                   if s["start"] in ("AUTO", "BOOT", "SYSTEM")
                   and "DRIVER" not in s["flags"]
                   and "DISABLED" not in s["flags"]]
    svc_hosted  = [s for s in services
                   if s.get("image_path") and
                   re.search(r"svchost\.exe", s.get("image_path", ""), re.IGNORECASE)]

    verdict = "CLEAN"
    if suspicious:
        verdict = "SUSPICIOUS" if len(suspicious) >= 3 else "REVIEW"
    elif missing_bin or unquoted:
        verdict = "REVIEW"
    elif deleted:
        verdict = "REVIEW"

    return {
        # --- v1 preserved ---
        "verdict":                verdict,
        "total":                  total,
        "suspicious_count":       len(suspicious),
        "third_party_count":      len(third_party),
        "deleted_count":          len(deleted),
        "auto_start_services":    len(auto_start),
        # --- v2 extended ---
        "boot_drivers":           len(boot_drvr),
        "system_drivers":         len(sys_drvr),
        "disabled_count":         len(disabled),
        "missing_binaries":       len(missing_bin),
        "missing_service_dlls":   len(missing_dll),
        "unquoted_path_risks":    len(unquoted),
        "failure_event_count":    len(has_events),
        "svchost_hosted_count":   len(svc_hosted),
        # --- internal lists (stripped before JSON output) ---
        "_suspicious":   suspicious,
        "_third_party":  third_party,
        "_deleted":      deleted,
        "_unquoted":     unquoted,
        "_missing_dll":  missing_dll,
        "_has_events":   has_events,
        "_auto_start":   auto_start,
    }


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def _print_report(services: List[dict], summary: dict, verbose: bool = False) -> None:
    v     = summary["verdict"]
    width = 70
    print("\n" + "=" * width)
    print(f"  SERVICE ANALYSIS — {v}")
    print("=" * width)
    print(f"  Total services/drivers  : {summary['total']}")
    print(f"  Auto-start services     : {summary['auto_start_services']}")
    print(f"  Boot drivers            : {summary['boot_drivers']}")
    print(f"  System drivers          : {summary['system_drivers']}")
    print(f"  Disabled                : {summary['disabled_count']}")
    print(f"  Third-party             : {summary['third_party_count']}")
    print(f"  Suspicious              : {summary['suspicious_count']}")
    print(f"  Missing binary          : {summary['missing_binaries']}")
    print(f"  Missing ServiceDll      : {summary['missing_service_dlls']}")
    print(f"  Unquoted path risks     : {summary['unquoted_path_risks']}")
    print(f"  SCM failure events      : {summary['failure_event_count']}")
    print(f"  Svchost-hosted          : {summary['svchost_hosted_count']}")

    if summary["_suspicious"]:
        print(f"\n--- SUSPICIOUS {'─' * 54}")
        for s in summary["_suspicious"]:
            reason = s.get("suspicious_reason") or "path not in safe system directory"
            print(f"  {s['name']:<32}  {s['start']:<8}  {s['image_path'][:48]}")
            print(f"    ^ {reason}")
            if s.get("event_history"):
                counts = s["event_history"].get("event_counts", {})
                if counts:
                    print(f"    Events: {counts}")

    if summary["_deleted"]:
        print(f"\n--- MISSING BINARY {'─' * 50}")
        for s in summary["_deleted"]:
            print(f"  {s['name']:<32}  {s['start']:<8}  {s['image_path'][:48]}")

    if summary["_unquoted"]:
        print(f"\n--- UNQUOTED PATH RISK {'─' * 46}")
        for s in summary["_unquoted"]:
            print(f"  {s['name']:<32}  {s['image_path'][:58]}")

    if summary["_missing_dll"]:
        print(f"\n--- MISSING ServiceDll {'─' * 46}")
        for s in summary["_missing_dll"]:
            dll = s.get("dll_details") or {}
            print(f"  {s['name']:<32}  {dll.get('ServiceDll', '?')[:48]}")

    if summary["_has_events"]:
        print(f"\n--- SCM FAILURE EVENTS {'─' * 46}")
        for s in summary["_has_events"]:
            counts = s.get("event_history", {}).get("event_counts", {})
            print(f"  {s['name']:<32}  {counts}")

    if verbose or summary["third_party_count"] > 0:
        auto_tp = [s for s in summary["_third_party"]
                   if s["start"] in ("AUTO", "BOOT", "SYSTEM")]
        if auto_tp:
            print(f"\n--- THIRD-PARTY AUTO-START {'─' * 42}")
            for s in auto_tp:
                print(f"  {s['name']:<32}  {s['start']:<8}  {s['display_name']}")

    print()


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    """Bootstrap entry point.

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
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all third-party services")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only")
    parser.add_argument("--no-events", action="store_true",
                        help="Skip System.evtx event correlation (faster)")
    args = parser.parse_args(argv)

    target    = Path(args.target)
    hive_path = target / "Windows" / "System32" / "config" / "SYSTEM"

    if not hive_path.exists():
        print(f"ERROR: SYSTEM hive not found at {hive_path}")
        return 1

    print(f"[m07] Opening SYSTEM hive: {hive_path} "
          f"({hive_path.stat().st_size // 1024} KB)")
    hive = _open_hive(hive_path)
    if hive is None:
        print("ERROR: Failed to parse SYSTEM hive (not a valid REGF file?)")
        return 1

    # Control set context
    ccs_context = _get_control_set_context(hive)
    ccs = ccs_context["active"]
    print(f"[m07] Active control set: {ccs} "
          f"(available: {ccs_context.get('available', [])})")
    if ccs_context.get("fallback_used"):
        print("[m07] WARNING: fallback control set used — "
              "Select key missing or corrupt")

    # Svchost groups from SOFTWARE hive
    print("[m07] Loading svchost group mapping ...")
    svchost_groups = _get_svchost_groups(target)
    svc_to_group   = _build_svc_to_group(svchost_groups)
    print(f"[m07] {len(svchost_groups)} svchost groups, "
          f"{len(svc_to_group)} service→group mappings")

    # SCM event history from System.evtx
    service_events: Dict[str, dict] = {}
    if not args.no_events:
        print("[m07] Loading SCM events from System.evtx ...")
        service_events = _load_service_events(target)
        total_evts = sum(
            sum(ec.values())
            for ec in (v["event_counts"] for v in service_events.values())
        )
        print(f"[m07] {len(service_events)} services with SCM events "
              f"({total_evts} total records)")

    # Parse all services
    print("[m07] Parsing services ...")
    try:
        services = _parse_services(hive, target, svc_to_group, service_events, ccs)
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
              f"missing={summary['missing_binaries']}, "
              f"unquoted={summary['unquoted_path_risks']})")

    # Write JSON log (strip internal list fields from summary)
    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"service_analysis_{ts}.json"
    summary_out = {k: v for k, v in summary.items() if not k.startswith("_")}
    log_path.write_text(json.dumps({
        "generated":           datetime.now(timezone.utc).isoformat(),
        "target":              str(target),
        "hive":                str(hive_path),
        "control_set_context": ccs_context,
        "svchost_groups":      svchost_groups,
        "summary":             summary_out,
        "services":            services,
    }, indent=2, default=str))
    print(f"[m07] Log written → {log_path}")
    return 0
