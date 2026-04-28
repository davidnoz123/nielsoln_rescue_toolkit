"""m46_recent_change_analysis — Timeline of recent changes to a Windows installation.

Correlates multiple sources to identify what changed before a reported problem:
  - Installed software (SOFTWARE hive Uninstall key — InstallDate field)
  - Driver packages (DriverStore/FileRepository folder modification times)
  - Scheduled tasks (Windows/System32/Tasks mtime)
  - Prefetch files (Windows/Prefetch mtime as execution indicator)
  - Windows Update log (last activity date from WindowsUpdate.log)
  - OEM INF files (Windows/inf/oem*.inf mtime)

The output is a unified timeline sorted newest-first.
Full URLs and private user data are not collected.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m46_recent_change_analysis -- --target /mnt/windows

Output:
    logs/recent_change_analysis_<timestamp>.json
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
    "Recent change analysis: unified timeline of software installs, driver changes, "
    "task modifications, and Windows Update activity"
)

# ---------------------------------------------------------------------------
# Minimal REGF hive parser (shared pattern — see m33/m35/m36/m37)
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
    return {name: data for name, _dtype, data in hive.list_values(key_offset)}


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def _parse_install_date(raw: str) -> Optional[str]:
    """Convert YYYYMMDD install date string to YYYY-MM-DD.  Returns None if invalid."""
    s = raw.strip()
    if re.match(r"^\d{8}$", s):
        return f"{s[:4]}-{s[4:6]}-{s[6:8]}"
    return None


def _mtime_to_iso(path: Path) -> Optional[str]:
    try:
        ts = path.stat().st_mtime
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return None


def _mtime_date(path: Path) -> Optional[str]:
    iso = _mtime_to_iso(path)
    return iso[:10] if iso else None


# ---------------------------------------------------------------------------
# Data collectors
# ---------------------------------------------------------------------------

def _collect_software_installs(target: Path) -> List[dict]:
    """Read Uninstall key from SOFTWARE hive for named + dated installs."""
    items: List[dict] = []
    sw_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    hive = _open_hive(sw_path)
    if hive is None:
        return items
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
            vals       = _values_dict(hive, sub_off)
            name       = vals.get("DisplayName") or sub_name
            inst_date  = _parse_install_date(str(vals.get("InstallDate") or ""))
            publisher  = vals.get("Publisher") or None
            version    = vals.get("DisplayVersion") or None
            if not inst_date:
                continue  # skip undated entries — noise
            items.append({
                "date":        inst_date,
                "source":      "software_install",
                "description": name,
                "publisher":   publisher,
                "version":     version,
            })
    return items


def _collect_driver_changes(target: Path) -> List[dict]:
    """Return driver package entries using FileRepository folder mtimes as install date proxy."""
    items: List[dict] = []
    filerepository = target / "Windows" / "System32" / "DriverStore" / "FileRepository"
    if not filerepository.is_dir():
        return items
    for folder in filerepository.iterdir():
        if not folder.is_dir():
            continue
        date_iso = _mtime_date(folder)
        if not date_iso:
            continue
        # Try to get a readable name from the first INF file
        inf_files = list(folder.glob("*.inf"))
        description = inf_files[0].stem if inf_files else folder.name
        items.append({
            "date":        date_iso,
            "source":      "driver_package",
            "description": description,
            "folder":      folder.name,
        })
    return items


def _collect_task_changes(target: Path) -> List[dict]:
    """Return scheduled task XML file changes by mtime."""
    items: List[dict] = []
    tasks_dir = target / "Windows" / "System32" / "Tasks"
    if not tasks_dir.is_dir():
        return items
    for task_file in tasks_dir.rglob("*"):
        if not task_file.is_file():
            continue
        date_iso = _mtime_date(task_file)
        if not date_iso:
            continue
        items.append({
            "date":        date_iso,
            "source":      "scheduled_task",
            "description": task_file.name,
            "path":        str(task_file.relative_to(tasks_dir)),
        })
    return items


def _collect_oem_inf_changes(target: Path) -> List[dict]:
    """Return oem*.inf file mtimes from Windows/inf/ as driver-install indicators."""
    items: List[dict] = []
    inf_dir = target / "Windows" / "inf"
    if not inf_dir.is_dir():
        return items
    for inf_file in sorted(inf_dir.glob("oem*.inf")):
        date_iso = _mtime_date(inf_file)
        if not date_iso:
            continue
        items.append({
            "date":        date_iso,
            "source":      "oem_inf",
            "description": inf_file.name,
        })
    return items


_WU_LOG_DATE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}"  # "YYYY-MM-DD HH:MM:SS" format (Vista WU log)
    r"|(\d{4}/\d{2}/\d{2})"                        # "YYYY/MM/DD" format
)


def _collect_wu_log_activity(target: Path) -> List[dict]:
    """Extract the most recent dated activity lines from WindowsUpdate.log."""
    items: List[dict] = []
    wu_log = target / "Windows" / "WindowsUpdate.log"
    if not wu_log.exists():
        return items
    try:
        # Read the last 50 KB — most recent entries
        size = wu_log.stat().st_size
        offset = max(0, size - 51200)
        with wu_log.open("rb") as fh:
            fh.seek(offset)
            raw = fh.read(51200)
        try:
            text = raw.decode("utf-16-le", errors="replace")
        except Exception:
            text = raw.decode("latin-1", errors="replace")

        dates_seen: set = set()
        for line in text.splitlines():
            m = _WU_LOG_DATE_RE.search(line)
            if m:
                date_str = (m.group(1) or m.group(2) or "").replace("/", "-")
                if date_str and date_str not in dates_seen:
                    dates_seen.add(date_str)
                    # Grab a brief description from the line
                    desc = line.strip()[:120]
                    items.append({
                        "date":        date_str,
                        "source":      "windows_update_log",
                        "description": desc,
                    })
        # Deduplicate to last occurrence per date
        by_date: dict = {}
        for item in items:
            by_date[item["date"]] = item
        items = list(by_date.values())
    except Exception:
        pass
    return items


# ---------------------------------------------------------------------------
# Timeline construction
# ---------------------------------------------------------------------------

def _is_within_days(date_str: str, days: int, anchor_date: str) -> bool:
    """Return True if date_str is within `days` days before anchor_date."""
    try:
        d1 = datetime.strptime(date_str[:10], "%Y-%m-%d")
        d2 = datetime.strptime(anchor_date[:10], "%Y-%m-%d")
        return 0 <= (d2 - d1).days <= days
    except ValueError:
        return False


def analyse(target: Path, days: int = 90) -> dict:
    limitations: List[str] = []
    timeline: List[dict] = []

    sw_items   = _collect_software_installs(target)
    drv_items  = _collect_driver_changes(target)
    task_items = _collect_task_changes(target)
    inf_items  = _collect_oem_inf_changes(target)
    wu_items   = _collect_wu_log_activity(target)

    timeline.extend(sw_items)
    timeline.extend(drv_items)
    timeline.extend(task_items)
    timeline.extend(inf_items)
    timeline.extend(wu_items)

    if not sw_items:
        limitations.append("No dated software installs found (SOFTWARE hive missing or no InstallDate fields)")
    if not drv_items:
        limitations.append("DriverStore/FileRepository not found")
    if not task_items:
        limitations.append("Windows/System32/Tasks not found")

    # Sort newest first
    def _sort_key(e: dict) -> str:
        return e.get("date") or ""

    timeline.sort(key=_sort_key, reverse=True)

    # Determine anchor date: most recent entry, or today
    if timeline:
        anchor_date = timeline[0].get("date", "")
    else:
        anchor_date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

    # Tag entries within the window
    for entry in timeline:
        entry["within_window"] = _is_within_days(entry.get("date", ""), days, anchor_date)

    recent_count = sum(1 for e in timeline if e.get("within_window"))
    verdicts = {
        "NO_CHANGES":      recent_count == 0,
        "CHANGES_FOUND":   0 < recent_count <= 10,
        "RECENT_ACTIVITY": recent_count > 10,
    }
    verdict = next(k for k, v in verdicts.items() if v)

    # Breakdown by source
    sources: dict = {}
    for entry in timeline:
        src = entry.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1

    return {
        "scan_status":     "ok",
        "verdict":         verdict,
        "window_days":     days,
        "anchor_date":     anchor_date,
        "summary": {
            "total_entries":       len(timeline),
            "entries_in_window":   recent_count,
            "entries_by_source":   sources,
        },
        "timeline":        timeline,
        "limitations":     limitations,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(data: dict, max_entries: int = 50) -> None:
    print("\n=== RECENT CHANGE ANALYSIS ===")
    print(f"Verdict  : {data.get('verdict', '?')}")
    s = data.get("summary", {})
    print(f"Window   : {data.get('window_days')} days before {data.get('anchor_date')}")
    print(f"Total    : {s.get('total_entries', 0)} entries  "
          f"({s.get('entries_in_window', 0)} within window)")

    src_counts = s.get("entries_by_source", {})
    if src_counts:
        parts = ", ".join(f"{k}: {v}" for k, v in sorted(src_counts.items()))
        print(f"Sources  : {parts}")

    recent = [e for e in data.get("timeline", []) if e.get("within_window")]
    if recent:
        print(f"\nRecent changes (newest first, showing up to {max_entries}):")
        for entry in recent[:max_entries]:
            src  = entry.get("source", "?")[:20]
            desc = (entry.get("description") or "")[:80]
            pub  = entry.get("publisher")
            ver  = entry.get("version")
            extra = ""
            if pub:
                extra += f"  [{pub}]"
            if ver:
                extra += f"  v{ver}"
            print(f"  {entry.get('date', '?')}  {src:22}  {desc}{extra}")
    else:
        print("\nNo recent changes found within the window.")

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
        prog="m46_recent_change_analysis",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="",
                        help="Mounted Windows partition path (auto-detect if omitted)")
    parser.add_argument("--days", type=int, default=90,
                        help="Window size in days for 'recent' classification (default: 90)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m46] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    print(f"[m46] Analysing recent changes in {target_path} (window: {args.days} days) ...")
    data = analyse(target_path, days=args.days)

    from datetime import datetime as _dt, timezone as _tz
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"recent_change_analysis_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m46] Log written: {out_path}")

    return 0 if data.get("verdict") != "RECENT_ACTIVITY" else 1
