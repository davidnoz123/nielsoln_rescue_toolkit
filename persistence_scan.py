r"""
persistence_scan.py — Nielsoln Rescue Toolkit: offline Windows persistence mechanism scanner.

Scans a mounted, read-only Windows filesystem for all common persistence mechanisms:
  - Startup folders (system-wide and per-user)
  - Scheduled tasks (modern XML format and legacy .job binary)
  - Auto-start services (from the offline SYSTEM registry hive)
  - Registry autoruns (Run, RunOnce, Winlogon, IFEO, policy scripts, BHOs, etc.)

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap.py persist --target /mnt/windows [--summary]

Output:
  Default  : JSON lines to logs/persist_<timestamp>.jsonl (one Finding per line)
  --summary: also print a sorted human-readable summary to stdout

Safety: Read-only. Never modifies, deletes, quarantines, or follows symlink loops.
"""

import dataclasses
import json
import logging
import os
import re
import struct
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

_log = logging.getLogger("persist")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Finding:
    type: str                  # startup | task | service | registry | info | error
    source: str                # file path or registry key path where found
    command: str               # the executable or full command string
    user: Optional[str]        # associated username, or None for system-wide
    score: int                 # 0–100 risk score
    risk: str                  # low | medium | high
    reasons: List[str]         # human-readable score explanations

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


def _info(source: str, message: str) -> Finding:
    """Create a non-threat informational finding."""
    return Finding(
        type="info", source=source, command="", user=None,
        score=0, risk="low", reasons=[message],
    )


def _error_finding(source: str, message: str) -> Finding:
    """Create an error finding (subsystem unavailable, partial data, etc.)."""
    return Finding(
        type="error", source=source, command="", user=None,
        score=0, risk="low", reasons=[f"scan error: {message}"],
    )


# ---------------------------------------------------------------------------
# Risk scorer
# ---------------------------------------------------------------------------

# Executables that indicate scripting, interpretation, or indirect execution
_RISKY_EXE_STEMS = {
    "powershell", "pwsh", "wscript", "cscript", "mshta", "msiexec",
    "regsvr32", "rundll32", "cmd", "regasm", "regsvcs", "installutil",
    "certutil", "bitsadmin", "wmic", "odbcconf", "pcalua",
    "bash", "wsl", "schtasks", "at", "forfiles",
}

# Extensions that are inherently executable / risky as persistence targets
_SUSPICIOUS_EXTS = {
    ".scr", ".pif", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".bat", ".cmd", ".ps1", ".psm1",
}

# Path substrings that indicate user-writable locations
_WRITABLE_PATH_HINTS = [
    "\\appdata\\", "\\temp\\", "\\tmp\\",
    "\\downloads\\", "\\desktop\\", "\\public\\",
    "\\recycle", "\\$recycle",
]

# Path prefixes considered safe (system-managed)
_SAFE_PATH_PREFIXES = [
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\",
]

_PROG_FILES_HINTS = [
    "c:\\program files\\",
    "c:\\program files (x86)\\",
]

# String fragments suggesting encoded or obfuscated commands
_OBFUSCATION_HINTS = [
    "-encodedcommand", "-enc ", " -e ", "frombase64string",
    "iex(", "invoke-expression", "downloadstring(",
    "hidden", "char(", "[convert]::",
]


def _extract_exe_path(command: str) -> str:
    """Extract the executable path from a command string (handles quoted paths)."""
    cmd = command.strip()
    if not cmd:
        return ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    return (cmd.split()[0] if cmd.split() else cmd)


def _score_command(
    command: str,
    base: int,
    target_root: Optional[Path] = None,
) -> tuple:
    """Return (score, reasons) for *command*, starting from *base*.

    Every risk adjustment produces a human-readable entry in reasons so the
    report is self-explanatory.
    """
    score = base
    reasons: List[str] = []

    if not command:
        return max(0, score), reasons

    cmd_lower = command.lower().replace("/", "\\")
    exe_path = _extract_exe_path(command)
    exe_lower = exe_path.lower().replace("/", "\\")
    exe_name = os.path.basename(exe_lower)
    exe_stem = os.path.splitext(exe_name)[0]
    exe_ext  = os.path.splitext(exe_name)[1]

    # ---- Risk increases ----

    if exe_stem in _RISKY_EXE_STEMS or exe_name in {s + ".exe" for s in _RISKY_EXE_STEMS}:
        score += 25
        reasons.append(f"uses scripting/execution proxy: {exe_name}")

    if exe_ext in _SUSPICIOUS_EXTS:
        score += 15
        reasons.append(f"suspicious file extension: {exe_ext}")

    for hint in _OBFUSCATION_HINTS:
        if hint in cmd_lower:
            score += 30
            reasons.append(f"possible obfuscated/encoded command (contains '{hint.strip()}')")
            break

    for hint in _WRITABLE_PATH_HINTS:
        if hint in cmd_lower:
            score += 20
            reasons.append(f"executes from user-writable location ({hint.strip(chr(92))})")
            break

    # Double extension (e.g., invoice.pdf.exe)
    parts = exe_name.split(".")
    if len(parts) >= 3 and parts[-1] in ("exe", "dll", "scr", "bat", "cmd"):
        score += 15
        reasons.append(f"double file extension (possible spoofing): {exe_name}")

    # Target file not present on disk
    if target_root is not None and "\\" in exe_lower and not exe_lower.startswith("\\\\"):
        # Strip drive letter and make relative to target root
        rel = re.sub(r"^[a-z]:\\", "", exe_lower).lstrip("\\")
        candidate = target_root / rel
        if not candidate.exists():
            score += 15
            reasons.append(f"target file not found on disk: {exe_path}")

    # ---- Risk decreases ----

    for safe in _SAFE_PATH_PREFIXES:
        if exe_lower.startswith(safe):
            score -= 20
            reasons.append(f"runs from system directory ({safe.rstrip(chr(92))})")
            break
    else:
        for pf in _PROG_FILES_HINTS:
            if pf in exe_lower:
                score -= 10
                reasons.append("runs from Program Files")
                break

    score = max(0, min(100, score))
    if not reasons:
        reasons.append("no specific risk indicators found")
    return score, reasons


def _risk_level(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _make_finding(
    ftype: str,
    source: str,
    command: str,
    base: int,
    user: Optional[str] = None,
    extra_reasons: Optional[List[str]] = None,
    target_root: Optional[Path] = None,
) -> Finding:
    """Build a Finding, computing score from command content."""
    score, reasons = _score_command(command, base, target_root=target_root)
    if extra_reasons:
        reasons = list(extra_reasons) + reasons
    return Finding(
        type=ftype,
        source=source,
        command=command,
        user=user,
        score=score,
        risk=_risk_level(score),
        reasons=reasons,
    )


# ---------------------------------------------------------------------------
# Registry hive parser (REGF format, pure Python stdlib, read-only)
# ---------------------------------------------------------------------------

# Hive bins data region starts at this file offset in every REGF file.
_HIVE_BINS_OFFSET = 0x1000


class _RegHive:
    """Minimal read-only parser for Windows NT registry hive files (REGF format).

    Supports:
      - Key navigation by backslash-separated path from root
      - Value enumeration (name, type, decoded data)
      - Subkey name enumeration
      - Subkey list types: lf, lh, li, ri

    All methods are exception-safe and never modify the underlying data.
    """

    __slots__ = ("_data", "_root_offset")

    def __init__(self, data: bytes) -> None:
        self._data = data
        # Root cell offset is stored at header byte 0x24 (relative to hive bins).
        self._root_offset: int = struct.unpack_from("<I", data, 0x24)[0]

    # ------------------------------------------------------------------
    # Low-level cell access
    # ------------------------------------------------------------------

    def _cell(self, offset: int) -> Optional[memoryview]:
        """Return a memoryview of the cell body at hive-relative *offset*.

        The cell body starts after the 4-byte size prefix.  Returns None if
        the offset is invalid, the cell is free (positive size), or the data
        is truncated.
        """
        if offset == 0xFFFFFFFF or offset < 0:
            return None
        file_off = _HIVE_BINS_OFFSET + offset
        if file_off + 4 > len(self._data):
            return None
        raw_size = struct.unpack_from("<i", self._data, file_off)[0]
        if raw_size >= 0:        # free cell — skip
            return None
        body_len = (-raw_size) - 4
        if body_len <= 0 or file_off + 4 + body_len > len(self._data):
            return None
        return memoryview(self._data)[file_off + 4: file_off + 4 + body_len]

    def _str_at(self, abs_offset: int, length: int, is_ascii: bool) -> str:
        """Decode a string from an absolute file offset."""
        if abs_offset + length > len(self._data):
            return ""
        raw = bytes(self._data[abs_offset: abs_offset + length])
        enc = "ascii" if is_ascii else "utf-16-le"
        return raw.decode(enc, errors="replace").rstrip("\x00")

    # ------------------------------------------------------------------
    # Named key (nk) cell
    # ------------------------------------------------------------------

    def _nk_info(self, offset: int) -> Optional[dict]:
        """Parse a named key cell.  Returns a dict or None."""
        cell = self._cell(offset)
        if cell is None or len(cell) < 0x50 or bytes(cell[0:2]) != b"nk":
            return None
        flags           = struct.unpack_from("<H", cell, 2)[0]
        subkeys_count   = struct.unpack_from("<I", cell, 0x18)[0]
        subkeys_offset  = struct.unpack_from("<I", cell, 0x20)[0]
        values_count    = struct.unpack_from("<I", cell, 0x28)[0]
        values_list_off = struct.unpack_from("<I", cell, 0x2C)[0]
        name_length     = struct.unpack_from("<H", cell, 0x4C)[0]
        is_ascii        = bool(flags & 0x0020)
        # Name bytes follow the fixed 0x50-byte header; account for the 4-byte
        # size prefix that precedes the cell body in the file.
        abs_name_off = _HIVE_BINS_OFFSET + offset + 4 + 0x50
        name = self._str_at(abs_name_off, name_length, is_ascii)
        return {
            "name": name,
            "subkeys_count": subkeys_count,
            "subkeys_offset": subkeys_offset,
            "values_count": values_count,
            "values_list_offset": values_list_off,
        }

    # ------------------------------------------------------------------
    # Subkey list traversal (lf / lh / li / ri)
    # ------------------------------------------------------------------

    def _subkey_offsets(self, list_offset: int) -> List[int]:
        """Return all nk cell offsets listed in a subkey list cell."""
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
                # Each record: key_offset (4 bytes) + hash/hint (4 bytes)
                for i in range(count):
                    pos = 4 + i * 8
                    if pos + 4 > len(cell):
                        break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"li":
                # Each record: key_offset (4 bytes)
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 > len(cell):
                        break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"ri":
                # Index root: each entry points to another subkey list
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 > len(cell):
                        break
                    sub_off = struct.unpack_from("<I", cell, pos)[0]
                    offsets.extend(self._subkey_offsets(sub_off))
        except Exception:
            pass
        return offsets

    def _find_subkey_offset(self, parent_offset: int, name: str) -> Optional[int]:
        """Return the cell offset of a direct child key matching *name* (case-insensitive)."""
        nk = self._nk_info(parent_offset)
        if nk is None:
            return None
        name_lower = name.lower()
        for sub_off in self._subkey_offsets(nk["subkeys_offset"]):
            sub_nk = self._nk_info(sub_off)
            if sub_nk and sub_nk["name"].lower() == name_lower:
                return sub_off
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_key_offset(self, path: str) -> Optional[int]:
        """Navigate to a key by backslash-separated path from the hive root.

        Returns the cell offset, or None if any component is not found.
        """
        parts = [p for p in path.split("\\") if p]
        current = self._root_offset
        for part in parts:
            found = self._find_subkey_offset(current, part)
            if found is None:
                return None
            current = found
        return current

    def list_subkey_names(self, key_offset: int) -> List[str]:
        """Return names of all direct child keys of *key_offset*."""
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
        """Return offset of a named direct child key, or None."""
        return self._find_subkey_offset(key_offset, name)

    def list_values(self, key_offset: int) -> List[tuple]:
        """Return list of (name, data_type, decoded_value) for all values in key."""
        nk = self._nk_info(key_offset)
        if nk is None or nk["values_count"] == 0:
            return []
        if nk["values_list_offset"] == 0xFFFFFFFF:
            return []
        vlist_cell = self._cell(nk["values_list_offset"])
        if vlist_cell is None:
            return []
        results: List[tuple] = []
        for i in range(nk["values_count"]):
            pos = i * 4
            if pos + 4 > len(vlist_cell):
                break
            try:
                vk_off = struct.unpack_from("<I", vlist_cell, pos)[0]
                val = self._read_vk(vk_off)
                if val is not None:
                    results.append(val)
            except Exception:
                pass
        return results

    def _read_vk(self, offset: int) -> Optional[tuple]:
        """Parse a value key (vk) cell.  Returns (name, type, decoded_value) or None."""
        cell = self._cell(offset)
        if cell is None or len(cell) < 0x18 or bytes(cell[0:2]) != b"vk":
            return None
        name_length  = struct.unpack_from("<H", cell, 2)[0]
        data_size_raw = struct.unpack_from("<I", cell, 4)[0]
        data_offset  = struct.unpack_from("<I", cell, 8)[0]
        data_type    = struct.unpack_from("<I", cell, 12)[0]
        flags        = struct.unpack_from("<H", cell, 16)[0]

        # flags bit 0: name is ASCII; otherwise UTF-16-LE
        is_ascii = bool(flags & 0x0001)
        if name_length > 0:
            abs_name = _HIVE_BINS_OFFSET + offset + 4 + 0x18
            name = self._str_at(abs_name, name_length, is_ascii)
        else:
            name = ""   # the default value "(Default)"

        # data_size_raw bit 31 set means data is stored inline in the data_offset field
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
        """Decode registry value bytes into a Python-native type."""
        if data_type in (1, 2):    # REG_SZ, REG_EXPAND_SZ
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if data_type == 4:         # REG_DWORD_LE
            return struct.unpack_from("<I", raw)[0] if len(raw) >= 4 else 0
        if data_type == 5:         # REG_DWORD_BE
            return struct.unpack_from(">I", raw)[0] if len(raw) >= 4 else 0
        if data_type == 11:        # REG_QWORD
            return struct.unpack_from("<Q", raw)[0] if len(raw) >= 8 else 0
        if data_type == 7:         # REG_MULTI_SZ
            text = raw.decode("utf-16-le", errors="replace")
            return [s for s in text.split("\x00") if s]
        return raw                 # REG_BINARY or unknown: return raw bytes


def _open_hive(path: Path) -> Optional[_RegHive]:
    """Open a registry hive file.  Returns None on any error (missing, corrupt, etc.)."""
    try:
        data = path.read_bytes()
        if len(data) < 0x1000 or data[:4] != b"regf":
            return None
        return _RegHive(data)
    except Exception:
        return None


def _hive_values_at(hive: _RegHive, path: str) -> List[tuple]:
    """Return values at *path* in *hive*, or [] if the path does not exist."""
    try:
        off = hive.get_key_offset(path)
        if off is None:
            return []
        return hive.list_values(off)
    except Exception:
        return []


def _hive_subkey_names(hive: _RegHive, path: str) -> List[str]:
    """Return direct subkey names at *path* in *hive*, or []."""
    try:
        off = hive.get_key_offset(path)
        if off is None:
            return []
        return hive.list_subkey_names(off)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# 1. Startup folder scanner
# ---------------------------------------------------------------------------

# Extensions that represent executable or launchable files in startup folders
_STARTUP_EXTS = {
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf",
    ".hta", ".ps1", ".pif", ".scr", ".com", ".lnk", ".url",
}

# Base risk for items found in startup folders — their presence is the signal
_BASE_STARTUP = 40

# System-wide startup paths relative to the Windows root
_SYSTEM_STARTUP_RELPATHS = [
    "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",   # Vista+
    "Documents and Settings\\All Users\\Start Menu\\Programs\\Startup", # XP
]


def _scan_one_startup_dir(
    startup_dir: Path,
    user: Optional[str],
    target_root: Optional[Path],
) -> List[Finding]:
    """Produce a Finding for each executable/script/shortcut in *startup_dir*."""
    findings: List[Finding] = []
    try:
        for entry in startup_dir.iterdir():
            if not entry.is_file():
                continue
            ext = entry.suffix.lower()
            if ext not in _STARTUP_EXTS:
                continue
            command = str(entry)
            extra: List[str] = [f"found in startup folder: {startup_dir}"]
            if ext == ".lnk":
                resolved = _resolve_lnk(entry)
                if resolved:
                    command = resolved
                else:
                    extra.append("shortcut target could not be resolved")
            findings.append(_make_finding(
                "startup", str(entry), command, _BASE_STARTUP,
                user=user, extra_reasons=extra, target_root=target_root,
            ))
    except (PermissionError, OSError) as exc:
        findings.append(_error_finding(str(startup_dir), f"could not read startup folder: {exc}"))
    return findings


def scan_startup_folders(target: Path) -> List[Finding]:
    """Scan all system-wide and per-user startup folders."""
    findings: List[Finding] = []

    # System-wide startup
    for rel in _SYSTEM_STARTUP_RELPATHS:
        d = target / rel
        if d.is_dir():
            found = _scan_one_startup_dir(d, user=None, target_root=target)
            if not found:
                findings.append(_info(str(d), "startup folder is empty"))
            else:
                findings.extend(found)

    # Per-user startup (Vista+: Users\<user>\AppData\Roaming\…  XP: …\Start Menu\…)
    for users_base in ["Users", "Documents and Settings"]:
        users_path = target / users_base
        if not users_path.is_dir():
            continue
        try:
            for entry in users_path.iterdir():
                if not entry.is_dir():
                    continue
                username = entry.name
                # Vista+
                startup = (entry / "AppData" / "Roaming" / "Microsoft"
                           / "Windows" / "Start Menu" / "Programs" / "Startup")
                if not startup.is_dir():
                    # XP
                    startup = entry / "Start Menu" / "Programs" / "Startup"
                if startup.is_dir():
                    found = _scan_one_startup_dir(startup, user=username, target_root=target)
                    if not found:
                        findings.append(_info(str(startup), f"startup folder for {username!r} is empty"))
                    else:
                        findings.extend(found)
        except PermissionError:
            pass

    return findings


# ---- LNK (shortcut) target resolver ----

def _resolve_lnk(lnk_path: Path) -> Optional[str]:
    """Extract the target path string from a .lnk shortcut file.

    Implements just enough of the MS-SHLLINK format to get the local base path.
    Read-only.  Returns None on any parse error.
    """
    try:
        data = lnk_path.read_bytes()
        # Header: 4-byte header size (always 0x4C), then GUID, then LinkFlags at 0x14
        if len(data) < 0x4C or data[:4] != b"\x4c\x00\x00\x00":
            return None
        link_flags = struct.unpack_from("<I", data, 0x14)[0]
        has_target_idlist = bool(link_flags & 0x0001)
        has_link_info     = bool(link_flags & 0x0002)

        pos = 0x4C  # first optional section

        if has_target_idlist:
            if pos + 2 > len(data):
                return None
            idlist_size = struct.unpack_from("<H", data, pos)[0]
            pos += 2 + idlist_size

        if has_link_info:
            if pos + 4 > len(data):
                return None
            li_size = struct.unpack_from("<I", data, pos)[0]
            if pos + li_size > len(data):
                return None
            li = data[pos: pos + li_size]
            if len(li) < 0x20:
                return None
            # LocalBasePathOffset at li+0x1C  (ANSI string from start of LinkInfo)
            lbp_off = struct.unpack_from("<I", li, 0x1C)[0]
            if lbp_off and lbp_off < li_size:
                raw = li[lbp_off:]
                end = raw.find(b"\x00")
                if end >= 0:
                    return raw[:end].decode("ascii", errors="replace")
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 2. Scheduled task scanner
# ---------------------------------------------------------------------------

_BASE_TASK = 35


def _parse_task_xml(xml_path: Path) -> Optional[tuple]:
    """Parse a Windows Task Scheduler XML file.

    Returns (full_command, arguments, user_id) or None if parsing fails or
    the file is not a task XML.
    """
    try:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()
        # Determine namespace prefix
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        def _find(el, *tags):
            for tag in tags:
                child = el.find(f"{ns}{tag}")
                if child is not None:
                    return child
            return None

        actions = _find(root, "Actions")
        if actions is None:
            return None

        exec_el = _find(actions, "Exec")
        if exec_el is not None:
            cmd_el  = _find(exec_el, "Command")
            args_el = _find(exec_el, "Arguments")
            user_el = root.find(f".//{ns}UserId")
            cmd  = (cmd_el.text  or "").strip() if cmd_el  is not None else ""
            args = (args_el.text or "").strip() if args_el is not None else ""
            user = (user_el.text or "").strip() if user_el is not None else None
            full = f"{cmd} {args}".strip() if args else cmd
            return (full, args, user)

        # COM handler (e.g. shell extensions used as tasks)
        com_el = _find(actions, "ComHandler")
        if com_el is not None:
            clsid_el = _find(com_el, "ClassId")
            data_el  = _find(com_el, "Data")
            clsid = (clsid_el.text or "").strip() if clsid_el is not None else ""
            data  = (data_el.text  or "").strip() if data_el  is not None else ""
            return (f"COM:{clsid}", data, None)

        return None
    except Exception:
        return None


def _parse_job_file(job_path: Path) -> Optional[str]:
    """Extract the command from a legacy Windows Task Scheduler .job file.

    The .job binary format (MS-TSCH §2.4) starts with a 68-byte fixed section
    followed by variable-length strings encoded as UTF-16-LE with 2-byte
    character-count prefixes.  We extract the application name and parameters.
    Returns the command string, or None on parse failure.
    """
    try:
        data = job_path.read_bytes()
        if len(data) < 0x44:
            return None
        pos = 0x44                          # variable-length section starts here
        if pos + 2 > len(data):
            return None
        pos += 2                            # skip Running Instance Count (2 bytes)

        def _read_wstr(at: int) -> tuple:  # returns (string, new_pos)
            if at + 2 > len(data):
                return ("", at)
            char_count = struct.unpack_from("<H", data, at)[0]
            at += 2
            byte_count = char_count * 2
            if at + byte_count > len(data):
                return ("", at)
            s = data[at: at + byte_count].decode("utf-16-le", errors="replace").rstrip("\x00")
            return (s, at + byte_count)

        app_name, pos = _read_wstr(pos)
        params,   pos = _read_wstr(pos)
        full = f"{app_name} {params}".strip() if params else app_name
        return full or None
    except Exception:
        return None


def scan_scheduled_tasks(target: Path) -> List[Finding]:
    """Scan modern XML tasks (Vista+) and legacy .job tasks (XP)."""
    findings: List[Finding] = []

    # Modern tasks: Windows\System32\Tasks\ (Vista+)
    modern_root = target / "Windows" / "System32" / "Tasks"
    if modern_root.is_dir():
        parsed_count = 0
        for dirpath, _dirs, files in os.walk(str(modern_root), followlinks=False):
            for fname in files:
                task_path = Path(dirpath) / fname
                try:
                    result = _parse_task_xml(task_path)
                except Exception:
                    result = None
                rel_label = str(task_path.relative_to(modern_root))
                if result:
                    parsed_count += 1
                    full_cmd, _args, task_user = result
                    findings.append(_make_finding(
                        "task", str(task_path), full_cmd, _BASE_TASK,
                        user=task_user,
                        extra_reasons=[f"scheduled task: {rel_label}"],
                        target_root=target,
                    ))
                elif task_path.stat().st_size > 0:
                    # Not parseable but present — report it
                    findings.append(_make_finding(
                        "task", str(task_path), str(task_path), _BASE_TASK + 5,
                        extra_reasons=[f"scheduled task file could not be parsed: {rel_label}"],
                        target_root=target,
                    ))
        if parsed_count == 0:
            findings.append(_info(
                str(modern_root),
                "Windows\\System32\\Tasks exists but contained no parseable task XML files",
            ))
    else:
        findings.append(_info(
            str(target / "Windows" / "System32" / "Tasks"),
            "Windows\\System32\\Tasks not found (pre-Vista or tasks folder was cleared)",
        ))

    # Legacy tasks: Windows\Tasks\*.job (XP / 2003)
    legacy_root = target / "Windows" / "Tasks"
    if legacy_root.is_dir():
        for job_file in legacy_root.glob("*.job"):
            cmd = _parse_job_file(job_file)
            if cmd:
                findings.append(_make_finding(
                    "task", str(job_file), cmd, _BASE_TASK,
                    extra_reasons=["legacy .job scheduled task"],
                    target_root=target,
                ))
            else:
                findings.append(_make_finding(
                    "task", str(job_file), str(job_file), _BASE_TASK + 5,
                    extra_reasons=["legacy .job task: command could not be parsed"],
                    target_root=target,
                ))

    return findings


# ---------------------------------------------------------------------------
# 3. Service scanner (from offline SYSTEM registry hive)
# ---------------------------------------------------------------------------

_BASE_SERVICE = 20

_SVC_START_LABELS = {0: "BOOT", 1: "SYSTEM", 2: "AUTO", 3: "DEMAND", 4: "DISABLED"}

_SVC_TYPE_LABELS = {
    0x01: "KERNEL_DRIVER",
    0x02: "FILE_SYSTEM_DRIVER",
    0x10: "OWN_PROCESS",
    0x20: "SHARE_PROCESS",
    0x110: "INTERACTIVE_OWN_PROCESS",
    0x120: "INTERACTIVE_SHARE_PROCESS",
}

# Kernel/FS drivers are expected to start at boot; give them a slight score reduction
_DRIVER_TYPES = {0x01, 0x02}


def _get_current_control_set_name(hive: _RegHive) -> Optional[str]:
    """Return the name of the active control set (e.g. 'ControlSet001')."""
    try:
        select_off = hive.get_key_offset("Select")
        if select_off is not None:
            for name, _dtype, val in hive.list_values(select_off):
                if name.lower() == "current" and isinstance(val, int):
                    return f"ControlSet{val:03d}"
    except Exception:
        pass
    for candidate in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        if hive.get_key_offset(candidate) is not None:
            return candidate
    return None


def scan_services(target: Path) -> List[Finding]:
    """Scan auto-start services from the offline SYSTEM registry hive."""
    findings: List[Finding] = []
    hive_path = target / "Windows" / "System32" / "config" / "SYSTEM"
    if not hive_path.exists():
        findings.append(_info(str(hive_path), "SYSTEM hive not found — services cannot be scanned"))
        return findings

    hive = _open_hive(hive_path)
    if hive is None:
        findings.append(_error_finding(
            str(hive_path), "could not parse SYSTEM hive (corrupt or unsupported format)"))
        return findings

    ccs = _get_current_control_set_name(hive)
    if ccs is None:
        findings.append(_error_finding(
            str(hive_path), "could not determine CurrentControlSet in SYSTEM hive"))
        return findings

    services_rel = f"{ccs}\\Services"
    services_offset = hive.get_key_offset(services_rel)
    if services_offset is None:
        findings.append(_error_finding(
            str(hive_path), f"Services key not found at {services_rel}"))
        return findings

    service_names = hive.list_subkey_names(services_offset)
    scanned = 0
    for svc_name in service_names:
        try:
            svc_off = hive.get_subkey_offset(services_offset, svc_name)
            if svc_off is None:
                continue
            vals = {n: v for n, _t, v in hive.list_values(svc_off)}
            start = vals.get("Start")
            if not isinstance(start, int) or start > 2:
                continue  # DEMAND(3) or DISABLED(4) — not auto-start

            svc_type    = vals.get("Type", 0)
            image_path  = vals.get("ImagePath") or ""
            display     = vals.get("DisplayName") or svc_name
            start_label = _SVC_START_LABELS.get(start, str(start))
            type_label  = _SVC_TYPE_LABELS.get(svc_type, f"type=0x{svc_type:02x}")

            if not isinstance(image_path, str):
                image_path = ""

            # Expand common abbreviated paths used in ImagePath values
            command = image_path
            lp = image_path.lower()
            if lp.startswith("\\systemroot\\"):
                command = "C:\\Windows\\" + image_path[len("\\SystemRoot\\"):]
            elif lp.startswith("system32\\"):
                command = "C:\\Windows\\" + image_path
            elif lp.startswith("\\??\\"):
                command = image_path[4:]

            extra = [
                f"service: {svc_name} ({display})",
                f"start type: {start_label}",
                f"service type: {type_label}",
            ]
            if start in (0, 1):
                extra.append("boot/system-level start — higher privilege than normal auto-start")

            base = _BASE_SERVICE + (10 if start in (0, 1) else 0)
            if svc_type in _DRIVER_TYPES:
                base = max(0, base - 10)    # drivers are expected at boot

            findings.append(_make_finding(
                "service",
                f"SYSTEM\\{services_rel}\\{svc_name}",
                command,
                base,
                extra_reasons=extra,
                target_root=target,
            ))
            scanned += 1
        except Exception:
            pass

    if scanned == 0:
        findings.append(_info(
            str(hive_path),
            f"no auto-start services (Start ≤ 2) found in {services_rel}",
        ))
    return findings


# ---------------------------------------------------------------------------
# 4. Registry autorun scanner
# ---------------------------------------------------------------------------

# (key_path, extraction_mode, base_score)
# Modes:
#   "values"       — each string value is a command
#   "winlogon"     — only specific well-known value names (Userinit, Shell, …)
#   "ifeo"         — each subkey's "Debugger" value (hijack technique)
#   "subkeys_clsid"— each subkey name is a CLSID (BHO detection)
#   "subkeys_spe"  — each subkey is a monitored process (SilentProcessExit)

_SOFTWARE_AUTORUN_PATHS = [
    ("Microsoft\\Windows\\CurrentVersion\\Run",                         "values",       40),
    ("Microsoft\\Windows\\CurrentVersion\\RunOnce",                     "values",       40),
    ("Microsoft\\Windows\\CurrentVersion\\RunServices",                 "values",       40),
    ("Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",             "values",       40),
    ("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",            "values",       40),
    ("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",        "values",       40),
    ("Microsoft\\Windows NT\\CurrentVersion\\Winlogon",                 "winlogon",     55),
    ("Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "ifeo",     65),
    ("Policies\\Microsoft\\Windows\\System\\Scripts\\Logon",            "values",       50),
    ("Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff",           "values",       50),
    ("Policies\\Microsoft\\Windows\\System\\Scripts\\Startup",          "values",       55),
    ("Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown",         "values",       55),
    ("Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "subkeys_clsid", 50),
    ("Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",        "subkeys_spe",  50),
]

_NTUSER_AUTORUN_PATHS = [
    ("Software\\Microsoft\\Windows\\CurrentVersion\\Run",              "values",   40),
    ("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",          "values",   40),
    ("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",      "winlogon", 55),
    ("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "values", 45),
]

# Winlogon values that can be replaced with malicious payloads
_WINLOGON_WATCHED = {"userinit", "shell", "taskman", "appsetup"}


def _extract_values_as_findings(
    hive: _RegHive,
    hive_label: str,
    key_path: str,
    base: int,
    user: Optional[str],
    target_root: Optional[Path],
) -> List[Finding]:
    """Enumerate all string values at key_path and return one Finding per entry."""
    findings: List[Finding] = []
    key_off = hive.get_key_offset(key_path)
    if key_off is None:
        return findings
    source = f"{hive_label}\\{key_path}"
    for name, _dtype, val in hive.list_values(key_off):
        if not isinstance(val, str) or not val.strip():
            continue
        findings.append(_make_finding(
            "registry", source, val.strip(), base,
            user=user,
            extra_reasons=[f"registry autorun: {source} [{name or '(Default)'}]"],
            target_root=target_root,
        ))
    return findings


def _extract_winlogon_findings(
    hive: _RegHive,
    hive_label: str,
    key_path: str,
    base: int,
    user: Optional[str],
    target_root: Optional[Path],
) -> List[Finding]:
    """Extract Winlogon-specific autorun values (Userinit, Shell, TaskMan)."""
    findings: List[Finding] = []
    key_off = hive.get_key_offset(key_path)
    if key_off is None:
        return findings
    source = f"{hive_label}\\{key_path}"
    for name, _dtype, val in hive.list_values(key_off):
        if name.lower() not in _WINLOGON_WATCHED:
            continue
        if not isinstance(val, str) or not val.strip():
            continue
        findings.append(_make_finding(
            "registry", source, val.strip(), base,
            user=user,
            extra_reasons=[f"Winlogon autorun: {source} [{name}]"],
            target_root=target_root,
        ))
    return findings


def _extract_ifeo_findings(
    hive: _RegHive,
    hive_label: str,
    key_path: str,
    target_root: Optional[Path],
) -> List[Finding]:
    """Extract Image File Execution Options Debugger values.

    IFEO Debugger is a classic hijack technique: any process with a matching
    executable name launches the Debugger command instead of the real binary.
    """
    findings: List[Finding] = []
    key_off = hive.get_key_offset(key_path)
    if key_off is None:
        return findings
    source = f"{hive_label}\\{key_path}"
    for exe_name in hive.list_subkey_names(key_off):
        sub_off = hive.get_subkey_offset(key_off, exe_name)
        if sub_off is None:
            continue
        for name, _dtype, val in hive.list_values(sub_off):
            if name.lower() != "debugger":
                continue
            if not isinstance(val, str) or not val.strip():
                continue
            findings.append(_make_finding(
                "registry", f"{source}\\{exe_name}", val.strip(), 65,
                extra_reasons=[
                    f"IFEO debugger hijack: launches when {exe_name!r} is executed",
                    "Image File Execution Options 'Debugger' intercepts any launch of the target process",
                ],
                target_root=target_root,
            ))
    return findings


def _extract_bho_findings(
    hive: _RegHive,
    hive_label: str,
    key_path: str,
    target_root: Optional[Path],
) -> List[Finding]:
    """Extract Browser Helper Object CLSIDs (Internet Explorer persistence)."""
    findings: List[Finding] = []
    key_off = hive.get_key_offset(key_path)
    if key_off is None:
        return findings
    source = f"{hive_label}\\{key_path}"
    for clsid in hive.list_subkey_names(key_off):
        findings.append(_make_finding(
            "registry", f"{source}\\{clsid}",
            f"BHO CLSID: {clsid}", 45,
            extra_reasons=[
                f"Browser Helper Object: {clsid}",
                "BHOs load automatically into Internet Explorer at launch",
            ],
            target_root=target_root,
        ))
    return findings


def _extract_spe_findings(
    hive: _RegHive,
    hive_label: str,
    key_path: str,
    target_root: Optional[Path],
) -> List[Finding]:
    """Extract SilentProcessExit monitor entries (persistence via process monitoring)."""
    findings: List[Finding] = []
    key_off = hive.get_key_offset(key_path)
    if key_off is None:
        return findings
    source = f"{hive_label}\\{key_path}"
    for proc_name in hive.list_subkey_names(key_off):
        sub_off = hive.get_subkey_offset(key_off, proc_name)
        if sub_off is None:
            continue
        vals = {n.lower(): v for n, _t, v in hive.list_values(sub_off)}
        monitor_process = vals.get("monitorprocess", "")
        if isinstance(monitor_process, str) and monitor_process.strip():
            findings.append(_make_finding(
                "registry", f"{source}\\{proc_name}",
                monitor_process.strip(), 50,
                extra_reasons=[
                    f"SilentProcessExit monitor for: {proc_name}",
                    "MonitorProcess is launched whenever the watched process exits — a persistence technique",
                ],
                target_root=target_root,
            ))
        else:
            findings.append(_make_finding(
                "registry", f"{source}\\{proc_name}",
                f"monitored process: {proc_name}", 40,
                extra_reasons=[
                    f"SilentProcessExit entry: {proc_name} (no MonitorProcess value found)",
                ],
                target_root=target_root,
            ))
    return findings


def scan_registry_autoruns(target: Path) -> List[Finding]:
    """Scan SOFTWARE and per-user NTUSER.DAT hives for autorun entries."""
    findings: List[Finding] = []

    # ---- HKLM: SOFTWARE hive ----
    sw_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    if sw_path.exists():
        hive = _open_hive(sw_path)
        if hive is None:
            findings.append(_error_finding(
                str(sw_path), "could not parse SOFTWARE hive (corrupt or unsupported format)"))
        else:
            label = "HKLM\\SOFTWARE"
            for key_path, mode, base in _SOFTWARE_AUTORUN_PATHS:
                try:
                    if mode == "values":
                        findings.extend(_extract_values_as_findings(
                            hive, label, key_path, base, None, target))
                    elif mode == "winlogon":
                        findings.extend(_extract_winlogon_findings(
                            hive, label, key_path, base, None, target))
                    elif mode == "ifeo":
                        findings.extend(_extract_ifeo_findings(
                            hive, label, key_path, target))
                    elif mode == "subkeys_clsid":
                        findings.extend(_extract_bho_findings(
                            hive, label, key_path, target))
                    elif mode == "subkeys_spe":
                        findings.extend(_extract_spe_findings(
                            hive, label, key_path, target))
                except Exception as exc:
                    findings.append(_error_finding(f"{label}\\{key_path}", str(exc)))
    else:
        findings.append(_info(
            str(sw_path),
            "SOFTWARE hive not found — registry autoruns could not be scanned",
        ))

    # ---- HKU: Per-user NTUSER.DAT hives ----
    for users_base in ["Users", "Documents and Settings"]:
        users_path = target / users_base
        if not users_path.is_dir():
            continue
        try:
            for entry in users_path.iterdir():
                if not entry.is_dir():
                    continue
                username = entry.name
                ntuser = entry / "NTUSER.DAT"
                if not ntuser.exists():
                    continue
                hive = _open_hive(ntuser)
                if hive is None:
                    findings.append(_error_finding(
                        str(ntuser),
                        f"could not parse NTUSER.DAT for {username!r}"))
                    continue
                label = f"HKU\\{username}"
                for key_path, mode, base in _NTUSER_AUTORUN_PATHS:
                    try:
                        if mode == "values":
                            findings.extend(_extract_values_as_findings(
                                hive, label, key_path, base, username, target))
                        elif mode == "winlogon":
                            findings.extend(_extract_winlogon_findings(
                                hive, label, key_path, base, username, target))
                    except Exception as exc:
                        findings.append(_error_finding(f"{label}\\{key_path}", str(exc)))
        except PermissionError:
            pass

    return findings


# ---------------------------------------------------------------------------
# 5. Main entry point
# ---------------------------------------------------------------------------

def run_persistence_scan(
    root: Path,
    target: Path,
    summary: bool = False,
    no_startup: bool = False,
    no_tasks: bool = False,
    no_services: bool = False,
    no_registry: bool = False,
) -> int:
    """Scan an offline Windows installation for persistence mechanisms.

    Writes all findings as JSON lines to logs/persist_<timestamp>.jsonl.
    Optionally prints a human-readable sorted summary.

    Exit codes:
        0  completed; no actionable findings
        1  completed; at least one high-risk finding
        2  target does not exist
        3  completed; findings present (medium/low only)
    """
    if not target.exists():
        _log.error("Target does not exist: %s", target)
        print(f"ERROR: Target does not exist: {target}")
        return 2

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_path = logs_dir / f"persist_{timestamp}.jsonl"

    print(f"\n=== NIELSOLN PERSISTENCE SCAN ===")
    print(f"  Target  : {target}")
    print(f"  Output  : {output_path}")
    print()

    all_findings: List[Finding] = []

    def _run_phase(label: str, fn, *args) -> None:
        print(f"  [{label:18s}] scanning …", end=" ", flush=True)
        try:
            found = fn(*args)
            real  = [f for f in found if f.type not in ("info", "error")]
            other = [f for f in found if f.type in ("info", "error")]
            print(f"{len(real)} finding(s), {len(other)} info/error(s)")
            _log.info("Phase %s: %d findings, %d info/errors", label, len(real), len(other))
            all_findings.extend(found)
        except Exception as exc:
            print(f"FAILED ({exc})")
            _log.exception("Phase %s failed unexpectedly", label)
            all_findings.append(_error_finding(label, str(exc)))

    if not no_startup:
        _run_phase("startup folders", scan_startup_folders, target)
    if not no_tasks:
        _run_phase("scheduled tasks", scan_scheduled_tasks, target)
    if not no_services:
        _run_phase("services",        scan_services,        target)
    if not no_registry:
        _run_phase("registry autoruns", scan_registry_autoruns, target)

    # Write JSON lines output
    with output_path.open("w", encoding="utf-8") as fh:
        for finding in all_findings:
            fh.write(finding.to_json() + "\n")

    # Partition findings
    real_findings  = [f for f in all_findings if f.type not in ("info", "error")]
    error_findings = [f for f in all_findings if f.type == "error"]
    high   = [f for f in real_findings if f.risk == "high"]
    medium = [f for f in real_findings if f.risk == "medium"]
    low    = [f for f in real_findings if f.risk == "low"]

    print()
    print("=" * 50)
    print("PERSISTENCE SCAN SUMMARY")
    print(f"  Date     : {timestamp}")
    print(f"  Target   : {target}")
    print(f"  Findings : {len(real_findings)} total"
          f"  ({len(high)} high  {len(medium)} medium  {len(low)} low)")
    print(f"  Errors   : {len(error_findings)}")
    print(f"  Output   : {output_path}")
    print("=" * 50)

    if summary and real_findings:
        _print_summary(real_findings)

    _log.info(
        "Persistence scan complete: %d findings (%d high, %d medium, %d low), %d errors",
        len(real_findings), len(high), len(medium), len(low), len(error_findings),
    )

    if high:
        return 1
    if real_findings:
        return 3
    return 0


def _print_summary(findings: List[Finding]) -> None:
    """Print a sorted, human-readable summary of all real findings."""
    sorted_f = sorted(findings, key=lambda f: (-f.score, f.type, f.source))
    print()
    print(f"FINDINGS — sorted by risk score ({len(sorted_f)} total)")
    print("-" * 80)
    for i, f in enumerate(sorted_f, 1):
        risk_tag = f"[{f.risk.upper():6s}]"
        print(f"[{i:03d}] {risk_tag} score={f.score:3d}  type={f.type}")
        print(f"       source  : {f.source}")
        print(f"       command : {f.command or '(none)'}")
        if f.user:
            print(f"       user    : {f.user}")
        for reason in f.reasons:
            print(f"       reason  : {reason}")
        print()
