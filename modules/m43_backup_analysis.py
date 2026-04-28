"""m43_backup_analysis — Backup and data safety analysis.

Detects:
  - System Restore / Volume Shadow Copy service configuration
  - Restore point directories (System Volume Information)
  - Backup software installations (SOFTWARE hive Uninstall scan)
  - Cloud sync apps (Dropbox, OneDrive, Google Drive, etc.)
  - Backup folder names in user directories
  - External drive history (MountedDevices from SYSTEM hive)
  - Recent backup evidence (file mtimes in backup folders)
  - No-backup risk assessment

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m43_backup_analysis -- --target /mnt/windows

Output:
    logs/backup_analysis_<timestamp>.json
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
    "Backup analysis: System Restore config, restore points, backup software, "
    "cloud sync apps, backup folders, external drive history, no-backup risk"
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
    return {n: d for n, _t, d in hive.list_values(key_offset)}


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

# Backup / cloud sync software keywords
_BACKUP_SOFTWARE_KEYWORDS = [
    "acronis", "macrium", "paragon", "norton ghost", "ghost",
    "backup exec", "arcserve", "veeam", "cobian", "easeus",
    "aomei", "todo backup", "backup4all", "genie backup",
    "ntbackup", "windows backup",
]

_CLOUD_SYNC_KEYWORDS = [
    "dropbox", "onedrive", "googledrive", "google drive", "google backup",
    "mega", "sugarsync", "box.com", "box sync", "icloud",
    "carbonite", "backblaze", "crashplan", "idrive",
]

_BACKUP_FOLDER_NAMES = {
    "backup", "backups", "my backup", "system restore",
    "old files", "archive", "archives", "old documents",
}


def _check_system_restore(target: Path) -> dict:
    """Check System Restore / VSS service configuration."""
    result: dict = {
        "sr_service_start": None,
        "vss_service_start": None,
        "restore_point_dirs": [],
        "sr_data_dir_present": False,
    }
    sys_path = target / "Windows" / "System32" / "config" / "SYSTEM"
    hive = _open_hive(sys_path)
    if hive:
        for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
            sr_off = hive.get_key_offset(f"{cs}\\Services\\srservice")
            if sr_off is None:
                sr_off = hive.get_key_offset(f"{cs}\\Services\\SystemRestore")
            if sr_off:
                vals = _values_dict(hive, sr_off)
                result["sr_service_start"] = vals.get("Start")

            vss_off = hive.get_key_offset(f"{cs}\\Services\\VSS")
            if vss_off:
                vals = _values_dict(hive, vss_off)
                result["vss_service_start"] = vals.get("Start")
            break

    # Check for restore point directories
    svi = target / "System Volume Information"
    if svi.exists():
        result["sr_data_dir_present"] = True
        try:
            rp_dirs = [d.name for d in svi.iterdir()
                       if d.is_dir() and d.name.startswith("_restore")]
            result["restore_point_dirs"] = rp_dirs[:10]
        except (PermissionError, OSError):
            result["restore_point_dirs"] = ["<access denied>"]

    return result


def _find_backup_software(target: Path) -> List[dict]:
    """Scan Uninstall key for backup/cloud software."""
    found: List[dict] = []
    sw_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    hive = _open_hive(sw_path)
    if hive is None:
        return found

    for arch_path in (
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ):
        off = hive.get_key_offset(arch_path)
        if off is None:
            continue
        for sub_name in hive.list_subkey_names(off):
            sub_off = hive.get_subkey_offset(off, sub_name)
            if sub_off is None:
                continue
            vals    = _values_dict(hive, sub_off)
            name    = str(vals.get("DisplayName") or sub_name).lower()
            version = str(vals.get("DisplayVersion") or "")

            category = None
            for kw in _BACKUP_SOFTWARE_KEYWORDS:
                if kw in name:
                    category = "backup"
                    break
            if category is None:
                for kw in _CLOUD_SYNC_KEYWORDS:
                    if kw in name:
                        category = "cloud_sync"
                        break
            if category:
                found.append({
                    "name":     str(vals.get("DisplayName") or sub_name),
                    "version":  version,
                    "category": category,
                })
    return found


def _find_backup_folders(target: Path) -> List[dict]:
    """Check Users directories for backup-named folders."""
    results: List[dict] = []
    users_dir = target / "Users"
    if not users_dir.is_dir():
        return results
    for user_dir in sorted(users_dir.iterdir()):
        if not user_dir.is_dir():
            continue
        for folder in user_dir.iterdir():
            if not folder.is_dir():
                continue
            if folder.name.lower() in _BACKUP_FOLDER_NAMES:
                try:
                    mtime = datetime.fromtimestamp(
                        folder.stat().st_mtime, tz=timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                except OSError:
                    mtime = None
                results.append({
                    "path":  str(folder),
                    "user":  user_dir.name,
                    "mtime": mtime,
                })
    return results


def _count_external_drives(target: Path) -> int:
    """Count MountedDevices entries for external drives (USB mass storage)."""
    sys_path = target / "Windows" / "System32" / "config" / "SYSTEM"
    hive = _open_hive(sys_path)
    if hive is None:
        return 0
    md_off = hive.get_key_offset("MountedDevices")
    if md_off is None:
        return 0
    # External drives typically appear as DosDevices\E:, F:, G:, etc.
    count = 0
    for val_name, _dtype, _data in hive.list_values(md_off):
        if re.match(r"\\DosDevices\\[D-Z]:", val_name, re.IGNORECASE):
            count += 1
    return count


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    limitations: List[str] = []

    sr_info       = _check_system_restore(target)
    backup_sw     = _find_backup_software(target)
    backup_folders = _find_backup_folders(target)
    ext_drives    = _count_external_drives(target)

    # Classify risk
    has_backup     = bool(backup_sw or sr_info.get("restore_point_dirs") or backup_folders)
    has_cloud      = any(s["category"] == "cloud_sync" for s in backup_sw)
    has_local_bkp  = any(s["category"] == "backup" for s in backup_sw)
    has_rp         = bool(sr_info.get("restore_point_dirs"))

    # SR service start type: 2=Auto, 3=Manual, 4=Disabled
    sr_start = sr_info.get("sr_service_start")
    sr_disabled = (sr_start == 4)

    if not has_backup:
        verdict = "WARNING"
        risk_label = "no_backup_detected"
    elif sr_disabled and not has_cloud and not has_local_bkp:
        verdict = "WARNING"
        risk_label = "system_restore_disabled_no_other_backup"
    else:
        verdict = "OK"
        risk_label = None

    return {
        "scan_status":            "ok",
        "verdict":                verdict,
        "no_backup_risk":         not has_backup,
        "no_backup_risk_label":   risk_label,
        "system_restore":         sr_info,
        "backup_software":        backup_sw,
        "cloud_sync_detected":    has_cloud,
        "local_backup_detected":  has_local_bkp,
        "restore_points_present": has_rp,
        "backup_folders":         backup_folders,
        "external_drive_letters_ever_mounted": ext_drives,
        "limitations":            limitations,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== BACKUP ANALYSIS ===")
    print(f"Verdict  : {data.get('verdict', '?')}")

    if data.get("no_backup_risk"):
        print(f"\n[!] NO BACKUP DETECTED — risk label: {data.get('no_backup_risk_label')}")

    sr = data.get("system_restore", {})
    start_map = {2: "Automatic", 3: "Manual", 4: "Disabled", None: "unknown"}
    sr_start_label = start_map.get(sr.get("sr_service_start"), str(sr.get("sr_service_start")))
    rp_count = len(sr.get("restore_point_dirs", []))
    print(f"\nSystem Restore:")
    print(f"  Service start    : {sr_start_label}")
    print(f"  SVI dir present  : {sr.get('sr_data_dir_present')}")
    print(f"  Restore point dirs : {rp_count}")

    sw = data.get("backup_software", [])
    if sw:
        print(f"\nBackup/cloud software ({len(sw)}):")
        for s in sw:
            print(f"  [{s['category']:12}]  {s['name']}  {s['version']}")
    else:
        print("\nNo backup or cloud sync software found in registry")

    bkp_folders = data.get("backup_folders", [])
    if bkp_folders:
        print(f"\nBackup-named folders ({len(bkp_folders)}):")
        for f in bkp_folders:
            print(f"  {f['user']:20}  {f['path']}")

    print(f"\nExternal drive letters ever mounted: {data.get('external_drive_letters_ever_mounted', 0)}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    from toolkit import find_windows_target  # noqa: PLC0415

    parser = argparse.ArgumentParser(prog="m43_backup_analysis", description=DESCRIPTION)
    parser.add_argument("--target", default="")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m43] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    print(f"[m43] Analysing backup configuration in {target_path} ...")
    data = analyse(target_path)

    from datetime import datetime as _dt, timezone as _tz
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"backup_analysis_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m43] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
