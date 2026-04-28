"""m42_registry_health — Registry hive health and anomaly analysis.

Checks:
  - Hive availability (SYSTEM, SOFTWARE, SAM, SECURITY, all NTUSER.DAT files)
  - Hive parse errors (truncated, bad magic, unreadable cells)
  - Orphaned service/driver ImagePath references (file missing on disk)
  - Pending file rename operations (SYSTEM hive)
  - Autorun anomalies not already flagged elsewhere (Winlogon shell/userinit overrides,
    AppInit_DLLs, Image File Execution Options debugger hijacks)
  - AppInit_DLLs presence

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m42_registry_health -- --target /mnt/windows

Output:
    logs/registry_health_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import struct
import time
from pathlib import Path
from typing import Any, List, Optional

DESCRIPTION = (
    "Registry health: hive availability, parse errors, orphaned service ImagePaths, "
    "pending renames, Winlogon/AppInit/IFEO hijacks"
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


def _open_hive_checked(path: Path) -> tuple:
    """Return (hive_or_None, error_str_or_None)."""
    if not path.exists():
        return None, "not_found"
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, f"read_error: {exc}"
    if len(data) < 0x1000:
        return None, "truncated"
    if data[:4] != b"regf":
        return None, f"bad_magic: {data[:4].hex()}"
    try:
        hive = _RegHive(data)
        # Quick sanity: try to access root
        nk = hive._nk_info(hive._root_offset)
        if nk is None:
            return None, "root_nk_unreadable"
        return hive, None
    except Exception as exc:
        return None, f"parse_error: {exc}"


def _values_dict(hive: _RegHive, key_offset: int) -> dict:
    return {n: d for n, _t, d in hive.list_values(key_offset)}


# ---------------------------------------------------------------------------
# Hive availability check
# ---------------------------------------------------------------------------

def _check_hive_availability(target: Path) -> List[dict]:
    results: List[dict] = []
    config_dir = target / "Windows" / "System32" / "config"
    system_hives = [
        ("SYSTEM",   config_dir / "SYSTEM"),
        ("SOFTWARE", config_dir / "SOFTWARE"),
        ("SAM",      config_dir / "SAM"),
        ("SECURITY", config_dir / "SECURITY"),
    ]
    for name, path in system_hives:
        hive, err = _open_hive_checked(path)
        results.append({
            "hive":      name,
            "path":      str(path),
            "available": hive is not None,
            "error":     err,
        })

    # NTUSER.DAT for each user
    users_dir = target / "Users"
    if users_dir.is_dir():
        for user_dir in sorted(users_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            ntuser = user_dir / "NTUSER.DAT"
            if not ntuser.exists():
                ntuser = user_dir / "ntuser.dat"
            hive, err = _open_hive_checked(ntuser)
            results.append({
                "hive":      f"NTUSER.DAT ({user_dir.name})",
                "path":      str(ntuser),
                "available": hive is not None,
                "error":     err,
            })
    return results


# ---------------------------------------------------------------------------
# Orphaned services
# ---------------------------------------------------------------------------

def _check_orphaned_services(target: Path) -> List[dict]:
    """Find services whose ImagePath points to a file that doesn't exist."""
    orphaned: List[dict] = []
    sys_path = target / "Windows" / "System32" / "config" / "SYSTEM"
    hive, err = _open_hive_checked(sys_path)
    if hive is None:
        return orphaned

    for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
        svc_key = hive.get_key_offset(f"{cs}\\Services")
        if svc_key is None:
            continue
        for svc_name in hive.list_subkey_names(svc_key):
            svc_off = hive.get_subkey_offset(svc_key, svc_name)
            if svc_off is None:
                continue
            vals = _values_dict(hive, svc_off)
            image = str(vals.get("ImagePath") or "").strip()
            if not image:
                continue
            # Normalise: strip leading \??\, SystemRoot, etc.
            cleaned = image.replace("\\??\\", "").replace(
                "%SystemRoot%", str(target / "Windows")
            ).replace("\\SystemRoot\\", str(target / "Windows") + "/")
            # Strip kernel driver prefix (\\Driver\\ etc.)
            if cleaned.startswith("\\"):
                cleaned = cleaned.lstrip("\\")
                # Could be "System32\drivers\foo.sys" → check under Windows
                probe = target / "Windows" / cleaned
                if not probe.exists():
                    probe = target / cleaned
            else:
                probe = Path(cleaned)
                if not probe.is_absolute():
                    probe = target / cleaned

            if not probe.exists():
                orphaned.append({
                    "service":    svc_name,
                    "image_path": image,
                    "resolved":   str(probe),
                })
        break  # only check first found ControlSet
    return orphaned


# ---------------------------------------------------------------------------
# Autorun / hijack checks
# ---------------------------------------------------------------------------

def _check_autorun_anomalies(target: Path) -> List[dict]:
    anomalies: List[dict] = []
    sw_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    hive, err = _open_hive_checked(sw_path)

    if hive:
        # Winlogon Shell and Userinit
        wl_off = hive.get_key_offset(
            "Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        )
        if wl_off:
            vals = _values_dict(hive, wl_off)
            shell    = str(vals.get("Shell") or "")
            userinit = str(vals.get("Userinit") or "")
            if shell and shell.lower() not in ("explorer.exe", ""):
                anomalies.append({
                    "type":  "winlogon_shell_override",
                    "key":   "Winlogon\\Shell",
                    "value": shell,
                })
            if userinit and "userinit.exe" in userinit.lower():
                # Flag if extra entries appended
                parts = [p.strip() for p in userinit.split(",") if p.strip()]
                if len(parts) > 1:
                    anomalies.append({
                        "type":  "winlogon_userinit_extra",
                        "key":   "Winlogon\\Userinit",
                        "value": userinit,
                    })

        # AppInit_DLLs
        appinit_off = hive.get_key_offset(
            "Microsoft\\Windows NT\\CurrentVersion\\Windows"
        )
        if appinit_off:
            vals = _values_dict(hive, appinit_off)
            appinit = str(vals.get("AppInit_DLLs") or "").strip()
            if appinit:
                anomalies.append({
                    "type":  "appinit_dlls",
                    "key":   "Windows\\AppInit_DLLs",
                    "value": appinit,
                })

        # Image File Execution Options (debugger hijacks)
        ifeo_off = hive.get_key_offset(
            "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        )
        if ifeo_off:
            for exe_name in hive.list_subkey_names(ifeo_off):
                exe_off = hive.get_subkey_offset(ifeo_off, exe_name)
                if exe_off is None:
                    continue
                vals = _values_dict(hive, exe_off)
                debugger = str(vals.get("Debugger") or "").strip()
                if debugger:
                    anomalies.append({
                        "type":    "ifeo_debugger_hijack",
                        "target":  exe_name,
                        "debugger": debugger,
                    })

    return anomalies


# ---------------------------------------------------------------------------
# Pending rename operations
# ---------------------------------------------------------------------------

def _check_pending_renames(target: Path) -> List[str]:
    sys_path = target / "Windows" / "System32" / "config" / "SYSTEM"
    hive, _ = _open_hive_checked(sys_path)
    if hive is None:
        return []
    for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
        off = hive.get_key_offset(
            f"{cs}\\Control\\Session Manager"
        )
        if off:
            vals = _values_dict(hive, off)
            pfrops = vals.get("PendingFileRenameOperations")
            if pfrops:
                if isinstance(pfrops, list):
                    return pfrops[:40]
                if isinstance(pfrops, str):
                    return [pfrops[:200]]
            break
    return []


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    limitations: List[str] = []

    hive_status       = _check_hive_availability(target)
    orphaned_services = _check_orphaned_services(target)
    autorun_anomalies = _check_autorun_anomalies(target)
    pending_renames   = _check_pending_renames(target)

    parse_errors = [h for h in hive_status if h["error"] and h["error"] != "not_found"]
    missing_hives = [h for h in hive_status if h["error"] == "not_found"]

    flags: List[str] = []
    if parse_errors:
        flags.append(f"{len(parse_errors)} hive parse errors")
    if orphaned_services:
        flags.append(f"{len(orphaned_services)} orphaned service ImagePaths")
    if autorun_anomalies:
        flags.append(f"{len(autorun_anomalies)} autorun anomalies")
    if pending_renames:
        flags.append(f"{len(pending_renames)} pending rename operations")

    if any("ifeo_debugger_hijack" in a.get("type", "") for a in autorun_anomalies):
        verdict = "SUSPICIOUS"
    elif any("appinit_dlls" in a.get("type", "") for a in autorun_anomalies):
        verdict = "SUSPICIOUS"
    elif flags:
        verdict = "WARNING"
    else:
        verdict = "OK"

    return {
        "scan_status":        "ok",
        "verdict":            verdict,
        "hive_status":        hive_status,
        "parse_errors":       parse_errors,
        "orphaned_services":  orphaned_services[:50],
        "autorun_anomalies":  autorun_anomalies,
        "pending_renames":    pending_renames[:20],
        "flags":              flags,
        "limitations":        limitations,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== REGISTRY HEALTH ANALYSIS ===")
    print(f"Verdict  : {data.get('verdict', '?')}")

    hive_status = data.get("hive_status", [])
    ok    = sum(1 for h in hive_status if h["available"])
    total = len(hive_status)
    print(f"Hives    : {ok}/{total} available")
    for h in hive_status:
        if not h["available"]:
            print(f"  MISSING/ERROR: {h['hive']}  — {h['error']}")

    orphans = data.get("orphaned_services", [])
    if orphans:
        print(f"\nOrphaned service ImagePaths ({len(orphans)}):")
        for s in orphans[:20]:
            print(f"  {s['service']:30}  {s['image_path'][:80]}")

    autoruns = data.get("autorun_anomalies", [])
    if autoruns:
        print(f"\nAutorun anomalies ({len(autoruns)}):")
        for a in autoruns:
            t = a.get("type", "?")
            if t == "ifeo_debugger_hijack":
                print(f"  [IFEO hijack] {a.get('target', '?')}  →  {a.get('debugger', '?')}")
            elif t == "appinit_dlls":
                print(f"  [AppInit_DLLs]  {a.get('value', '?')[:80]}")
            elif t == "winlogon_shell_override":
                print(f"  [Winlogon Shell]  {a.get('value', '?')[:80]}")
            else:
                print(f"  [{t}]  {a.get('value', a.get('key', '?'))[:80]}")

    renames = data.get("pending_renames", [])
    if renames:
        print(f"\nPending rename operations: {len(renames)} entries")
        for r in renames[:5]:
            print(f"  {r[:100]}")

    flags = data.get("flags", [])
    if flags:
        print("\nFlags:")
        for f in flags:
            print(f"  - {f}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    from toolkit import find_windows_target  # noqa: PLC0415

    parser = argparse.ArgumentParser(prog="m42_registry_health", description=DESCRIPTION)
    parser.add_argument("--target", default="")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m42] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    print(f"[m42] Analysing registry health in {target_path} ...")
    data = analyse(target_path)

    from datetime import datetime as _dt, timezone as _tz
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"registry_health_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m42] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
