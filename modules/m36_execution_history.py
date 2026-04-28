"""m36_execution_history — Offline Windows application execution history analysis.

Collects:
  - Prefetch files from Windows\\Prefetch\\*.pf (run count, last run times, volume serials)
  - RunMRU from NTUSER.DAT (commands typed into Run dialog)
  - RecentDocs from NTUSER.DAT (recently opened documents)
  - TypedPaths from NTUSER.DAT (Explorer address bar history)
  - LNK shortcuts from %AppData%\\Microsoft\\Windows\\Recent\\

Flags suspicious executables: paths in Temp/AppData/Downloads, LOLBins,
encoded command usage.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m36_execution_history -- --target /mnt/windows

Output:
    logs/execution_history_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DESCRIPTION = (
    "Execution history: Prefetch entries, RunMRU, RecentDocs, LNK shortcuts — "
    "what ran recently and what was opened"
)

# ---------------------------------------------------------------------------
# Minimal REGF hive parser (same engine as m07, m33)
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
            abs_name_off = _HIVE_BINS_OFFSET + offset + 4 + 20
            name = self._str_at(abs_name_off, name_length, is_ascii)
        data = self._read_value_data(data_size_raw, data_offset, data_type)
        return (name, data_type, data)

    def _read_value_data(self, size_raw: int, offset: int, dtype: int) -> Any:
        inline = bool(size_raw & 0x80000000)
        size   = size_raw & 0x7FFFFFFF
        if inline:
            raw = struct.pack("<I", offset)[:size] if size <= 4 else b""
        else:
            cell = self._cell(offset)
            if cell is None:
                return None
            raw = bytes(cell[:size])
        if dtype == 1:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if dtype == 2:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if dtype == 4:
            return struct.unpack_from("<I", raw)[0] if len(raw) >= 4 else None
        if dtype == 11:
            return struct.unpack_from("<Q", raw)[0] if len(raw) >= 8 else None
        if dtype == 7:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00").split("\x00")
        return raw.hex()

    def get_value(self, key_offset: int, value_name: str) -> Any:
        vn_lower = value_name.lower()
        for name, dtype, data in self.list_values(key_offset):
            if name.lower() == vn_lower:
                return data
        return None


# ---------------------------------------------------------------------------
# FILETIME helper
# ---------------------------------------------------------------------------

_EPOCH_DELTA = 116444736000000000


def _filetime_to_iso(ft: int) -> Optional[str]:
    if ft == 0:
        return None
    try:
        epoch_sec = (ft - _EPOCH_DELTA) / 10_000_000
        return datetime.fromtimestamp(epoch_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Prefetch parser
# Supports format versions 17 (XP), 23 (Vista/7), 26 (8.1)
# ---------------------------------------------------------------------------

_PF_MAGIC = b"SCCA"

# Vista/7 Prefetch: version 23
# Offset 0x00: version (DWORD), 0x04: magic "SCCA"
# Offset 0x0C: exe name (60 UTF-16LE chars)
# Offset 0x4C: hash (DWORD)
# Offset 0x98: run count (DWORD)
# Offset 0x80: last run time (FILETIME x8 for v26, x1 for v17/23)

def _parse_prefetch_file(path: Path) -> Optional[dict]:
    try:
        data = path.read_bytes()
        if len(data) < 0xA0:
            return None
        version = struct.unpack_from("<I", data, 0)[0]
        magic   = data[4:8]
        if magic != _PF_MAGIC:
            return None
        if version not in (17, 23, 26, 30):
            return None

        # Executable name: offset 0x10, 60 UTF-16LE chars (versions 17/23/26)
        exe_raw = data[0x10:0x10 + 60 * 2]
        exe_name = exe_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if not exe_name:
            exe_name = path.stem  # fallback to filename

        # Hash
        pf_hash = struct.unpack_from("<I", data, 0x4C)[0]

        # Offsets differ by version
        if version in (17, 23):
            run_count_off   = 0x90
            last_run_off    = 0x78
            last_run_count  = 1
        elif version == 26:
            run_count_off   = 0xD0
            last_run_off    = 0x80
            last_run_count  = 8
        else:  # 30 (Win10) — best-effort
            run_count_off   = 0xD0
            last_run_off    = 0x80
            last_run_count  = 8

        if run_count_off + 4 > len(data):
            return None

        run_count = struct.unpack_from("<I", data, run_count_off)[0]

        last_run_times = []
        for i in range(last_run_count):
            off = last_run_off + i * 8
            if off + 8 > len(data):
                break
            ft = struct.unpack_from("<Q", data, off)[0]
            if ft == 0:
                break
            iso = _filetime_to_iso(ft)
            if iso:
                last_run_times.append(iso)

        return {
            "exe_name":       exe_name,
            "pf_file":        path.name,
            "pf_hash":        f"{pf_hash:08X}",
            "version":        version,
            "run_count":      run_count,
            "last_run_times": last_run_times,
            "last_run":       last_run_times[0] if last_run_times else None,
        }
    except Exception:
        return None


def _load_prefetch(target: Path) -> Tuple[List[dict], List[str]]:
    limitations: List[str] = []
    prefetch_dir = target / "Windows" / "Prefetch"
    if not prefetch_dir.is_dir():
        limitations.append("Windows\\Prefetch directory not found or not accessible")
        return [], limitations

    entries: List[dict] = []
    for pf_file in sorted(prefetch_dir.glob("*.pf")):
        entry = _parse_prefetch_file(pf_file)
        if entry:
            entries.append(entry)

    if not entries:
        limitations.append("No readable Prefetch files found")
    else:
        # Sort by last_run descending (most recent first)
        entries.sort(key=lambda e: e.get("last_run") or "", reverse=True)

    return entries, limitations


# ---------------------------------------------------------------------------
# RunMRU from NTUSER.DAT
# HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
# ---------------------------------------------------------------------------

def _load_run_mru(hive: _RegHive) -> List[str]:
    off = hive.get_key_offset(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
    )
    if off is None:
        return []
    mru_order = hive.get_value(off, "MRUList") or ""
    results: List[str] = []
    for ch in str(mru_order):
        val = hive.get_value(off, ch)
        if val:
            # Strip trailing \1 MRU marker
            results.append(str(val).rstrip("\x01").rstrip("\\1"))
    return results


# ---------------------------------------------------------------------------
# TypedPaths from NTUSER.DAT
# HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
# ---------------------------------------------------------------------------

def _load_typed_paths(hive: _RegHive) -> List[str]:
    off = hive.get_key_offset(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"
    )
    if off is None:
        return []
    results: List[str] = []
    for name, dtype, data in hive.list_values(off):
        if data:
            results.append(str(data))
    return results


# ---------------------------------------------------------------------------
# RecentDocs from NTUSER.DAT — extract filenames from binary blobs
# HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
# ---------------------------------------------------------------------------

def _load_recent_docs(hive: _RegHive) -> List[str]:
    off = hive.get_key_offset(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
    )
    if off is None:
        return []
    results: List[str] = []
    # The MRUListEx value has the order; each named value (0, 1, 2...) is a binary blob
    # The filename is at offset 0 as null-terminated UTF-16LE
    for name, dtype, data in hive.list_values(off):
        if name in ("MRUListEx",):
            continue
        if not isinstance(data, str) and data:
            # binary blob — try to extract filename
            if isinstance(data, str):
                results.append(data)
            else:
                # data is hex string from _read_value_data fallback
                try:
                    raw = bytes.fromhex(str(data))
                    # filename starts at offset 0 as null-terminated UTF-16LE
                    null_pos = raw.find(b"\x00\x00")
                    if null_pos > 0 and null_pos % 2 == 0:
                        fname = raw[:null_pos + 2].decode("utf-16-le", errors="replace").rstrip("\x00")
                        if fname:
                            results.append(fname)
                except Exception:
                    pass
        elif isinstance(data, str) and data:
            results.append(data)
    return results[:50]  # cap


# ---------------------------------------------------------------------------
# LNK shortcuts from Recent directory
# ---------------------------------------------------------------------------

def _read_lnk_target(lnk_path: Path) -> Optional[str]:
    """Extract the target path from a .lnk file (minimal parser)."""
    try:
        data = lnk_path.read_bytes()
        if len(data) < 0x4C or data[:4] != b"\x4C\x00\x00\x00":
            return None
        link_flags = struct.unpack_from("<I", data, 0x14)[0]
        has_link_target_idlist = bool(link_flags & 0x0001)
        offset = 0x4C
        if has_link_target_idlist:
            if offset + 2 > len(data):
                return None
            idlist_size = struct.unpack_from("<H", data, offset)[0]
            offset += 2 + idlist_size
        # Now at LinkInfo header
        if offset + 4 > len(data):
            return None
        li_size = struct.unpack_from("<I", data, offset)[0]
        if li_size < 0x1C or offset + li_size > len(data):
            return None
        local_base_offset = struct.unpack_from("<I", data, offset + 0x10)[0]
        if local_base_offset == 0:
            return None
        abs_path_off = offset + local_base_offset
        end = data.find(b"\x00", abs_path_off)
        if end < 0:
            return None
        return data[abs_path_off:end].decode("ascii", errors="replace")
    except Exception:
        return None


def _load_lnk_shortcuts(target: Path, users_dir: Path) -> Tuple[List[dict], List[str]]:
    limitations: List[str] = []
    results: List[dict] = []

    # Walk each user's Recent folder
    if not users_dir.is_dir():
        limitations.append("Users directory not found; LNK shortcuts unavailable")
        return results, limitations

    for user_dir in sorted(users_dir.iterdir()):
        if not user_dir.is_dir():
            continue
        recent_dir = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
        if not recent_dir.is_dir():
            continue
        for lnk in sorted(recent_dir.glob("*.lnk")):
            try:
                mtime = datetime.fromtimestamp(lnk.stat().st_mtime, tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except OSError:
                mtime = ""
            target_path = _read_lnk_target(lnk)
            results.append({
                "user":         user_dir.name,
                "lnk_file":     lnk.name,
                "target":       target_path or "",
                "modified_utc": mtime,
            })

    results.sort(key=lambda r: r.get("modified_utc") or "", reverse=True)
    return results, limitations


# ---------------------------------------------------------------------------
# Suspicious flag computation for prefetch entries
# ---------------------------------------------------------------------------

_SUSPICIOUS_DIRS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\", r"\\downloads\\",
    r"\\public\\", r"\\users\\all users\\",
]

_LOLBINS_EXE = {
    "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
}


def _flag_prefetch(entry: dict) -> List[str]:
    flags: List[str] = []
    exe = entry.get("exe_name", "").lower()
    if exe in _LOLBINS_EXE:
        flags.append("lolbin")
    for pat in _SUSPICIOUS_DIRS:
        if re.search(pat, exe):
            flags.append("suspicious_path")
            break
    return flags


# ---------------------------------------------------------------------------
# Load NTUSER.DAT for a user
# ---------------------------------------------------------------------------

def _find_ntuser_hives(target: Path) -> List[Tuple[str, Path]]:
    """Return [(username, ntuser_path), ...] for all found NTUSER.DAT files."""
    results: List[Tuple[str, Path]] = []
    users_dir = target / "Users"
    if not users_dir.is_dir():
        return results
    for user_dir in sorted(users_dir.iterdir()):
        if not user_dir.is_dir():
            continue
        ntuser = user_dir / "NTUSER.DAT"
        if ntuser.exists():
            results.append((user_dir.name, ntuser))
    return results


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    limitations: List[str] = []

    # Prefetch
    prefetch_entries, pf_lim = _load_prefetch(target)
    limitations.extend(pf_lim)

    # Add flags to prefetch entries
    for entry in prefetch_entries:
        entry["flags"] = _flag_prefetch(entry)

    # Per-user registry data
    run_mru_by_user: Dict[str, List[str]] = {}
    typed_paths_by_user: Dict[str, List[str]] = {}
    recent_docs_by_user: Dict[str, List[str]] = {}

    ntuser_hives = _find_ntuser_hives(target)
    if not ntuser_hives:
        limitations.append("No NTUSER.DAT files found; per-user execution history unavailable")
    else:
        for username, ntuser_path in ntuser_hives:
            try:
                data = ntuser_path.read_bytes()
                if data[:4] != b"regf":
                    limitations.append(f"NTUSER.DAT for {username}: invalid signature, skipped")
                    continue
                hive = _RegHive(data)
                run_mru = _load_run_mru(hive)
                if run_mru:
                    run_mru_by_user[username] = run_mru
                typed = _load_typed_paths(hive)
                if typed:
                    typed_paths_by_user[username] = typed
                recent = _load_recent_docs(hive)
                if recent:
                    recent_docs_by_user[username] = recent
            except Exception as exc:
                limitations.append(f"NTUSER.DAT for {username}: read error — {exc}")

    # LNK shortcuts
    lnk_shortcuts, lnk_lim = _load_lnk_shortcuts(target, target / "Users")
    limitations.extend(lnk_lim)

    # Flagged prefetch entries
    flagged_pf = [e for e in prefetch_entries if e.get("flags")]

    summary = {
        "prefetch_count":      len(prefetch_entries),
        "flagged_prefetch":    len(flagged_pf),
        "users_with_run_mru":  list(run_mru_by_user.keys()),
        "lnk_shortcut_count":  len(lnk_shortcuts),
    }

    verdict = "OK"
    if any("lolbin" in e.get("flags", []) for e in prefetch_entries):
        verdict = "WARNING"
    if any("suspicious_path" in e.get("flags", []) for e in prefetch_entries):
        verdict = "WARNING"

    return {
        "scan_status":       "ok",
        "verdict":           verdict,
        "summary":           summary,
        "prefetch_entries":  prefetch_entries,
        "flagged_prefetch":  flagged_pf,
        "run_mru":           run_mru_by_user,
        "typed_paths":       typed_paths_by_user,
        "recent_docs":       recent_docs_by_user,
        "lnk_shortcuts":     lnk_shortcuts[:100],  # cap at 100
        "limitations":       limitations,
    }


# ---------------------------------------------------------------------------
# Report printing
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== EXECUTION HISTORY ===")
    print(f"Verdict   : {data.get('verdict', '?')}")
    s = data.get("summary", {})
    print(f"Prefetch  : {s.get('prefetch_count', 0)} entries, "
          f"{s.get('flagged_prefetch', 0)} flagged")
    print(f"LNK files : {s.get('lnk_shortcut_count', 0)}")

    flagged = data.get("flagged_prefetch", [])
    if flagged:
        print(f"\nFlagged executables ({len(flagged)}):")
        for e in flagged:
            flags = ", ".join(e.get("flags", []))
            last  = e.get("last_run", "?")
            count = e.get("run_count", "?")
            print(f"  {e.get('exe_name', '?'):40}  runs={count}  last={last}  [{flags}]")

    recent = data.get("prefetch_entries", [])[:10]
    if recent:
        print("\nRecent prefetch (top 10 by last run):")
        for e in recent:
            last  = e.get("last_run", "?")
            count = e.get("run_count", "?")
            print(f"  {e.get('exe_name', '?'):40}  runs={count}  last={last}")

    for user, mru in data.get("run_mru", {}).items():
        if mru:
            print(f"\nRunMRU [{user}]:")
            for entry in mru:
                print(f"  {entry}")

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

    parser = argparse.ArgumentParser(
        prog="m36_execution_history",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="",
                        help="Path to mounted Windows partition (auto-detect if omitted)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m36] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    import time
    from datetime import datetime as _dt, timezone as _tz

    print(f"[m36] Analysing execution history in {target_path} ...")
    data = analyse(target_path)
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"execution_history_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m36] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
