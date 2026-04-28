"""m35_windows_update_analysis — Offline Windows Update and patch-state analysis.

Reads:
  - SOFTWARE hive: installed hotfixes / QFEs, Windows Update config, CBS packages
  - SYSTEM hive: PendingFileRenameOperations (pending reboot indicator)
  - Windows\\WindowsUpdate.log (first / last lines)

Produces a JSON report with installed patches, pending reboot state,
last update activity, and any limitations encountered.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m35_windows_update_analysis -- --target /mnt/windows

Output:
    logs/windows_update_analysis_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DESCRIPTION = (
    "Windows Update analysis: installed hotfixes, CBS packages, pending reboot "
    "state, and last update activity from offline registry hives"
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
        if dtype == 1:   # REG_SZ
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if dtype == 2:   # REG_EXPAND_SZ
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if dtype == 4:   # REG_DWORD
            return struct.unpack_from("<I", raw)[0] if len(raw) >= 4 else None
        if dtype == 11:  # REG_QWORD
            return struct.unpack_from("<Q", raw)[0] if len(raw) >= 8 else None
        if dtype == 7:   # REG_MULTI_SZ
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00").split("\x00")
        return raw.hex()

    def get_value(self, key_offset: int, value_name: str) -> Any:
        vn_lower = value_name.lower()
        for name, dtype, data in self.list_values(key_offset):
            if name.lower() == vn_lower:
                return data
        return None


# ---------------------------------------------------------------------------
# FILETIME helpers
# ---------------------------------------------------------------------------

_EPOCH_DELTA = 116444736000000000  # 100ns ticks between 1601-01-01 and 1970-01-01


def _filetime_to_iso(ft: int) -> Optional[str]:
    if ft == 0:
        return None
    try:
        epoch_sec = (ft - _EPOCH_DELTA) / 10_000_000
        return datetime.fromtimestamp(epoch_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Installed hotfixes from SOFTWARE hive
# Methods:
#   1. Microsoft\Updates\<product>\<kb>  (XP/Vista era)
#   2. Microsoft\Windows NT\CurrentVersion\Hotfix\<kb>
#   3. Microsoft\Windows\CurrentVersion\Uninstall\<kb>  (MSU-style)
# ---------------------------------------------------------------------------

def _load_hotfixes(hive: _RegHive) -> Tuple[List[dict], List[str]]:
    hotfixes: List[dict] = []
    limitations: List[str] = []
    seen: set = set()

    # Method 1: Microsoft\Updates (Vista style)
    upd_off = hive.get_key_offset("Microsoft\\Updates")
    if upd_off is not None:
        for product in hive.list_subkey_names(upd_off):
            prod_off = hive.get_subkey_offset(upd_off, product)
            if prod_off is None:
                continue
            for kb_name in hive.list_subkey_names(prod_off):
                if kb_name.upper() in seen:
                    continue
                seen.add(kb_name.upper())
                kb_off = hive.get_subkey_offset(prod_off, kb_name)
                desc = hive.get_value(kb_off, "Description") if kb_off else ""
                date = hive.get_value(kb_off, "InstalledDate") if kb_off else ""
                hotfixes.append({
                    "kb":          kb_name,
                    "description": desc or "",
                    "install_date": date or "",
                    "source":      "Updates",
                })
    else:
        limitations.append("Microsoft\\Updates key not found (Vista-era QFE list unavailable)")

    # Method 2: Hotfix subkey (older style)
    hf_off = hive.get_key_offset("Microsoft\\Windows NT\\CurrentVersion\\Hotfix")
    if hf_off is not None:
        for kb_name in hive.list_subkey_names(hf_off):
            if kb_name.upper() in seen:
                continue
            seen.add(kb_name.upper())
            kb_off = hive.get_subkey_offset(hf_off, kb_name)
            desc   = hive.get_value(kb_off, "Fix Description") if kb_off else ""
            hotfixes.append({
                "kb":          kb_name,
                "description": desc or "",
                "install_date": "",
                "source":      "Hotfix",
            })

    # Method 3: Uninstall key for KB/security updates
    uninst_off = hive.get_key_offset("Microsoft\\Windows\\CurrentVersion\\Uninstall")
    if uninst_off is not None:
        for kb_name in hive.list_subkey_names(uninst_off):
            if not (kb_name.upper().startswith("KB") or "SECURITY UPDATE" in kb_name.upper()
                    or "UPDATE FOR WINDOWS" in kb_name.upper()):
                continue
            if kb_name.upper() in seen:
                continue
            seen.add(kb_name.upper())
            kb_off   = hive.get_subkey_offset(uninst_off, kb_name)
            disp     = hive.get_value(kb_off, "DisplayName") if kb_off else ""
            date     = hive.get_value(kb_off, "InstallDate") if kb_off else ""
            hotfixes.append({
                "kb":          kb_name,
                "description": disp or "",
                "install_date": date or "",
                "source":      "Uninstall",
            })

    # Sort by KB name
    hotfixes.sort(key=lambda h: h["kb"])
    return hotfixes, limitations


# ---------------------------------------------------------------------------
# CBS (Component Based Servicing) packages — Vista and later
# SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages
# ---------------------------------------------------------------------------

def _load_cbs_summary(hive: _RegHive) -> Tuple[dict, List[str]]:
    limitations: List[str] = []
    cbs_off = hive.get_key_offset(
        "Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"
    )
    if cbs_off is None:
        limitations.append(
            "CBS Packages key not found; servicing package metadata unavailable"
        )
        return {"total": 0, "installed": 0, "staged": 0, "superseded": 0}, limitations

    total = installed = staged = superseded = 0
    for pkg_name in hive.list_subkey_names(cbs_off):
        total += 1
        pkg_off = hive.get_subkey_offset(cbs_off, pkg_name)
        if pkg_off is None:
            continue
        state = hive.get_value(pkg_off, "CurrentState")
        # CurrentState values: 0=absent, 16=staged, 32=staged, 48=installed
        if isinstance(state, int):
            if state == 112 or state == 48:
                installed += 1
            elif state == 16 or state == 32:
                staged += 1
            elif state == 64:
                superseded += 1

    return {
        "total": total,
        "installed": installed,
        "staged": staged,
        "superseded": superseded,
    }, limitations


# ---------------------------------------------------------------------------
# Pending reboot check via SYSTEM hive
# HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations
# ---------------------------------------------------------------------------

def _check_pending_reboot(system_hive_path: Path) -> Tuple[dict, List[str]]:
    limitations: List[str] = []
    result = {
        "pending_file_rename_operations": False,
        "windows_update_pending_reboot": False,
        "pending_details": [],
    }
    if not system_hive_path.exists():
        limitations.append("SYSTEM hive not found; pending reboot check skipped")
        return result, limitations

    try:
        data = system_hive_path.read_bytes()
        if data[:4] != b"regf":
            limitations.append("SYSTEM hive has invalid signature; pending reboot check skipped")
            return result, limitations
        hive = _RegHive(data)
        # Try CurrentControlSet (may be ControlSet001 or ControlSet002)
        for cs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
            smgr_off = hive.get_key_offset(
                f"{cs}\\Control\\Session Manager"
            )
            if smgr_off is None:
                continue
            pfr = hive.get_value(smgr_off, "PendingFileRenameOperations")
            if pfr:
                result["pending_file_rename_operations"] = True
                if isinstance(pfr, list):
                    result["pending_details"] = pfr[:20]  # cap list
                break

        # Windows Update pending reboot — SYSTEM\CurrentControlSet\Services\wuauserv
        # Not reliable from SYSTEM alone; noted as limitation
        limitations.append(
            "Windows Update AutoUpdate pending-reboot flag requires SOFTWARE hive "
            "(WindowsUpdate\\Auto Update\\RebootRequired) — checked separately"
        )
    except Exception as exc:
        limitations.append(f"SYSTEM hive read error: {exc}")

    return result, limitations


# ---------------------------------------------------------------------------
# Windows Update pending reboot from SOFTWARE hive
# SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired
# ---------------------------------------------------------------------------

def _check_wu_pending_reboot(hive: _RegHive) -> bool:
    off = hive.get_key_offset(
        "Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired"
    )
    return off is not None


# ---------------------------------------------------------------------------
# WindowsUpdate.log summary
# ---------------------------------------------------------------------------

def _read_wu_log(target: Path) -> Tuple[dict, List[str]]:
    limitations: List[str] = []
    log_path = target / "Windows" / "WindowsUpdate.log"
    if not log_path.exists():
        limitations.append("WindowsUpdate.log not found")
        return {"available": False}, limitations

    try:
        # Read first and last chunk
        size = log_path.stat().st_size
        with log_path.open("rb") as f:
            head_raw = f.read(4096)
            if size > 4096:
                f.seek(max(0, size - 4096))
                tail_raw = f.read(4096)
            else:
                tail_raw = b""

        head = head_raw.decode("utf-8", errors="replace")
        tail = (tail_raw or head_raw).decode("utf-8", errors="replace")

        first_lines = [l.rstrip() for l in head.splitlines()[:5] if l.strip()]
        last_lines  = [l.rstrip() for l in tail.splitlines()[-10:] if l.strip()]

        # Extract last date from last lines
        last_date = ""
        import re
        date_pat = re.compile(r"\d{4}-\d{2}-\d{2}")
        for line in reversed(last_lines):
            m = date_pat.search(line)
            if m:
                last_date = m.group(0)
                break

        return {
            "available": True,
            "size_bytes": size,
            "first_lines": first_lines,
            "last_lines": last_lines,
            "last_activity_date": last_date,
        }, limitations
    except Exception as exc:
        limitations.append(f"WindowsUpdate.log read error: {exc}")
        return {"available": False}, limitations


# ---------------------------------------------------------------------------
# Windows Update config from SOFTWARE hive
# ---------------------------------------------------------------------------

def _load_wu_config(hive: _RegHive) -> dict:
    config: dict = {}
    au_off = hive.get_key_offset(
        "Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update"
    )
    if au_off is None:
        return config
    for name, dtype, data in hive.list_values(au_off):
        config[name] = data
    return config


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    limitations: List[str] = []

    sw_hive_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    sys_hive_path = target / "Windows" / "System32" / "config" / "SYSTEM"

    hotfixes: List[dict] = []
    cbs_summary: dict = {}
    wu_config: dict = {}
    wu_reboot = False

    if not sw_hive_path.exists():
        limitations.append("SOFTWARE hive not found; registry-based update data unavailable")
    else:
        try:
            sw_data = sw_hive_path.read_bytes()
            if sw_data[:4] != b"regf":
                limitations.append("SOFTWARE hive has invalid signature")
            else:
                sw_hive = _RegHive(sw_data)
                hf, lim = _load_hotfixes(sw_hive)
                hotfixes = hf
                limitations.extend(lim)

                cbs, lim2 = _load_cbs_summary(sw_hive)
                cbs_summary = cbs
                limitations.extend(lim2)

                wu_config = _load_wu_config(sw_hive)
                wu_reboot = _check_wu_pending_reboot(sw_hive)
        except Exception as exc:
            limitations.append(f"SOFTWARE hive parse error: {exc}")

    pending, sys_lim = _check_pending_reboot(sys_hive_path)
    limitations.extend(sys_lim)
    if wu_reboot:
        pending["windows_update_pending_reboot"] = True

    wu_log, log_lim = _read_wu_log(target)
    limitations.extend(log_lim)

    summary = {
        "hotfix_count": len(hotfixes),
        "cbs_packages": cbs_summary,
        "pending_reboot": (
            pending.get("pending_file_rename_operations", False)
            or pending.get("windows_update_pending_reboot", False)
        ),
    }

    verdict = "OK"
    if summary["pending_reboot"]:
        verdict = "WARNING"

    return {
        "scan_status": "ok",
        "verdict": verdict,
        "summary": summary,
        "hotfixes": hotfixes,
        "windows_update_config": wu_config,
        "pending_reboot": pending,
        "windows_update_log": wu_log,
        "cbs_packages": cbs_summary,
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Report printing
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== WINDOWS UPDATE ANALYSIS ===")
    print(f"Verdict      : {data.get('verdict', '?')}")
    s = data.get("summary", {})
    print(f"Hotfixes     : {s.get('hotfix_count', 0)} installed")
    cbs = s.get("cbs_packages", {})
    if cbs:
        print(f"CBS Packages : {cbs.get('total', 0)} total, {cbs.get('installed', 0)} installed")
    if s.get("pending_reboot"):
        print("!! PENDING REBOOT DETECTED !!")

    wu_log = data.get("windows_update_log", {})
    if wu_log.get("available"):
        print(f"WU Log       : {wu_log.get('size_bytes', 0):,} bytes, "
              f"last activity: {wu_log.get('last_activity_date', 'unknown')}")

    hotfixes = data.get("hotfixes", [])
    if hotfixes:
        print(f"\nInstalled hotfixes ({len(hotfixes)}):")
        for h in hotfixes[-20:]:  # show last 20
            kb = h.get("kb", "?")
            desc = h.get("description", "")[:60]
            date = h.get("install_date", "")
            print(f"  {kb:20}  {date:12}  {desc}")
        if len(hotfixes) > 20:
            print(f"  ... and {len(hotfixes) - 20} more")

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
        prog="m35_windows_update_analysis",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="",
                        help="Path to mounted Windows partition (auto-detect if omitted)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only, not full hotfix list")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m35] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    import time
    from datetime import datetime as _dt, timezone as _tz

    print(f"[m35] Analysing Windows Update state in {target_path} ...")
    data = analyse(target_path)
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"windows_update_analysis_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m35] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
