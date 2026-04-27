"""
m06_software_inventory.py — Nielsoln Rescue Toolkit: offline Windows software inventory.

Reads the installed-software registry keys from the offline Windows SOFTWARE hive
(HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall and the WOW6432Node
equivalent) plus common per-user NTUSER.DAT hives.

Categorises each application and flags legacy, duplicate, suspicious, or unnecessary
entries to feed BLOAT_DETECTION, SYSTEM_LIFESPAN, and client report generation.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m06_software_inventory --target /mnt/windows

Output:
    Prints a categorised inventory table to stdout.
    Writes a JSON log to <USB>/logs/software_inventory_<timestamp>.json
"""

from __future__ import annotations

import json
import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

_log = logging.getLogger("software_inventory")

DESCRIPTION = (
    "Software inventory: reads offline Windows registry (Uninstall keys) to list "
    "installed applications with version, publisher, install date, category, and "
    "flags (legacy, suspicious, bloat) — requires --target /mnt/windows"
)

# ---------------------------------------------------------------------------
# Registry hive parser — same pure-Python REGF implementation as m01
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
                    if pos + 4 > len(cell):
                        break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"li":
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 > len(cell):
                        break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"ri":
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


def _values_dict(hive: _RegHive, path: str) -> dict:
    """Return {name: value} dict for all values at path."""
    try:
        off = hive.get_key_offset(path)
        if off is None:
            return {}
        return {name: data for name, _dtype, data in hive.list_values(off)}
    except Exception:
        return {}


def _subkey_names(hive: _RegHive, path: str) -> List[str]:
    try:
        off = hive.get_key_offset(path)
        if off is None:
            return []
        return hive.list_subkey_names(off)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Categorisation
# ---------------------------------------------------------------------------

_CATEGORY_RULES: list[tuple[str, list[str]]] = [
    # (category, list of lowercase keywords matched against name+publisher)
    ("Security",     ["antivirus", "antimalware", "anti-virus", "kaspersky", "norton",
                      "mcafee", "avast", "avira", "bitdefender", "eset", "malwarebytes",
                      "webroot", "sophos", "defender", "firewall", "spybot"]),
    ("Browser",      ["chrome", "firefox", "internet explorer", "edge", "opera", "safari",
                      "brave", "vivaldi", "waterfox", "seamonkey"]),
    ("Office",       ["microsoft office", "word", "excel", "powerpoint", "outlook",
                      "onenote", "access", "libreoffice", "openoffice", "wps office",
                      "wordperfect", "lotus"]),
    ("Driver",       ["driver", "chipset", "realtek", "intel(r) hd", "nvidia", "amd catalyst",
                      "ati catalyst", "broadcom", "marvell", "synaptics", "alps",
                      "ricoh", "conexant", "via technologies", "elantech"]),
    ("OS Component", ["microsoft .net", "visual c++", "visual basic runtime", "windows",
                      "directx", "update", "kb", "hotfix", "service pack", "wga",
                      "silverlight", "msxml", "vc_redist", "vcredist", "redistributable"]),
    ("Vendor Tool",  ["asus", "hp ", "dell ", "lenovo", "acer", "toshiba", "sony vaio",
                      "fujitsu", "samsung", "recovery", "assist", "support center",
                      "control center", "launch manager", "quick launch"]),
    ("Java/Runtime", ["java ", "jre ", "jdk ", "oracle java", "sun java"]),
    ("Media",        ["vlc", "itunes", "quicktime", "winamp", "real player", "windows media",
                      "media player", "k-lite", "codec", "divx", "xvid", "adobe flash",
                      "shockwave", "silverlight"]),
    ("Productivity", ["adobe reader", "acrobat", "foxit", "pdf", "notepad", "paint",
                      "7-zip", "winrar", "winzip", "putty", "teamviewer", "zoom",
                      "skype", "dropbox", "evernote", "lastpass"]),
    ("Game",         ["steam", "game", "games", "origin", "uplay", "battlenet",
                      "epic games", "directplay"]),
    ("Toolbar/BHO",  ["toolbar", "ask.com", "ask toolbar", "babylon", "conduit",
                      "delta search", "search protect", "sweetpacks", "mywebsearch"]),
]

_SUSPICIOUS_KEYWORDS = [
    "toolbar", "ask toolbar", "babylon", "conduit", "delta search",
    "sweetpacks", "mywebsearch", "search protect", "coupon", "savings",
    "weatherbug", "bonzi", "gator", "hotbar", "istart", "surf canyon",
]

_LEGACY_PUBLISHERS = [
    "macromedia", "sun microsystems", "netscape", "real networks", "broderbund",
    "corel", "borland", "lotus", "wordperfect",
]

# Apps with a known install year before this are flagged legacy
_LEGACY_YEAR_THRESHOLD = 2014

# Bloat patterns — vendor-bundled junk common on consumer laptops
_BLOAT_KEYWORDS = [
    "toolbar", "trial", "demo", "ask.com", "bing bar", "google toolbar",
    "mcafee security scan", "adobe air", "autoupdate", "auto-update",
    "coupon printer", "wild tangent", "wildtangent", "roxio", "cyberlink",
    "power2go", "powercinema", "powerdirector", "muvee", "corel videostudio",
    "netflix", "music studio", "photo studio",
]


def _categorise(name: str, publisher: str) -> str:
    combined = (name + " " + publisher).lower()
    for category, keywords in _CATEGORY_RULES:
        if any(kw in combined for kw in keywords):
            return category
    return "Other"


def _flags(name: str, publisher: str, install_year: Optional[int]) -> List[str]:
    flags: List[str] = []
    combined = (name + " " + publisher).lower()
    if any(kw in combined for kw in _SUSPICIOUS_KEYWORDS):
        flags.append("suspicious")
    if any(kw in combined for kw in _BLOAT_KEYWORDS):
        flags.append("bloat")
    if any(kw in combined for kw in [kw for _, kws in _CATEGORY_RULES[:1] for kw in kws]):
        pass  # security tools not flagged legacy
    if any(kw in publisher.lower() for kw in _LEGACY_PUBLISHERS):
        flags.append("legacy-publisher")
    if install_year is not None and install_year < _LEGACY_YEAR_THRESHOLD:
        flags.append("legacy-install-date")
    return flags


# ---------------------------------------------------------------------------
# Uninstall key reader
# ---------------------------------------------------------------------------

def _parse_install_date(raw: str) -> Optional[int]:
    """Parse YYYYMMDD string → year int, or None."""
    if raw and len(raw) == 8 and raw.isdigit():
        try:
            return int(raw[:4])
        except ValueError:
            pass
    return None


def _read_uninstall_key(hive: _RegHive, base_path: str, subkey: str, scope: str) -> Optional[dict]:
    """Read one subkey under an Uninstall key and return a software entry dict."""
    full_path = f"{base_path}\\{subkey}"
    vals = _values_dict(hive, full_path)
    if not vals:
        return None

    name      = str(vals.get("DisplayName", "")).strip()
    if not name:
        return None  # skip component-only entries with no display name

    version   = str(vals.get("DisplayVersion", "")).strip()
    publisher = str(vals.get("Publisher", "")).strip()
    inst_date = str(vals.get("InstallDate", "")).strip()
    inst_loc  = str(vals.get("InstallLocation", "")).strip()
    uninstall = str(vals.get("UninstallString", "")).strip()
    sys_comp  = vals.get("SystemComponent", 0)
    quiet_ui  = vals.get("NoRemove", 0)    # 1 = hidden from Add/Remove Programs
    est_size  = vals.get("EstimatedSize", None)

    # Skip purely internal Windows/system components
    if sys_comp == 1:
        return None

    install_year = _parse_install_date(inst_date)
    category     = _categorise(name, publisher)
    entry_flags  = _flags(name, publisher, install_year)

    entry: dict = {
        "name":           name,
        "version":        version or None,
        "publisher":      publisher or None,
        "install_date":   inst_date or None,
        "install_year":   install_year,
        "category":       category,
        "flags":          entry_flags,
        "scope":          scope,
        "size_kb":        int(est_size) if isinstance(est_size, int) else None,
        "uninstall_key":  subkey,
    }
    return entry


def _read_uninstall_hive(hive: _RegHive, base_path: str, scope: str) -> List[dict]:
    """Read all entries from one Uninstall key path."""
    entries = []
    subkeys = _subkey_names(hive, base_path)
    for sk in subkeys:
        entry = _read_uninstall_key(hive, base_path, sk, scope)
        if entry:
            entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Hive locations
# ---------------------------------------------------------------------------

_SW_HIVE_RELPATHS = [
    "Windows/System32/config/SOFTWARE",
    "WINDOWS/System32/config/SOFTWARE",
]

_UNINSTALL_PATHS = [
    "Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
]

_USER_HIVE_GLOB = [
    "Users/*/NTUSER.DAT",
    "Documents and Settings/*/NTUSER.DAT",
]

_USER_UNINSTALL_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"


def _collect_system_software(target: Path) -> List[dict]:
    entries = []
    hive_path: Optional[Path] = None
    for rel in _SW_HIVE_RELPATHS:
        p = target / rel
        if p.exists():
            hive_path = p
            break
    if not hive_path:
        _log.warning("SOFTWARE hive not found under %s", target)
        return entries

    hive = _open_hive(hive_path)
    if not hive:
        _log.warning("Could not parse SOFTWARE hive at %s", hive_path)
        return entries

    _log.info("Reading system SOFTWARE hive …")
    for up in _UNINSTALL_PATHS:
        scope = "HKLM (32-bit)" if "Wow6432Node" in up else "HKLM"
        batch = _read_uninstall_hive(hive, up, scope)
        _log.info("  %s: %d entries", up, len(batch))
        entries.extend(batch)

    return entries


def _collect_user_software(target: Path) -> List[dict]:
    entries = []
    ntuser_paths: List[Path] = []
    for glob_pat in _USER_HIVE_GLOB:
        ntuser_paths.extend(sorted(target.glob(glob_pat)))

    for ntuser in ntuser_paths:
        username = ntuser.parent.name
        hive = _open_hive(ntuser)
        if not hive:
            continue
        _log.info("Reading NTUSER.DAT for user '%s' …", username)
        batch = _read_uninstall_hive(hive, _USER_UNINSTALL_PATH, f"HKCU ({username})")
        _log.info("  %d entries", len(batch))
        entries.extend(batch)

    return entries


# ---------------------------------------------------------------------------
# De-duplication
# ---------------------------------------------------------------------------

def _deduplicate(entries: List[dict]) -> List[dict]:
    """Remove true duplicates (same name+version appearing in both HKLM and WOW)."""
    seen: dict[str, str] = {}   # normalised_name → scope
    result = []
    for e in entries:
        key = re.sub(r"\s+", " ", (e["name"] + (e["version"] or "")).lower().strip())
        if key in seen:
            e["flags"] = e["flags"] + ["duplicate"]
        else:
            seen[key] = e["scope"]
        result.append(e)
    return result


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

_CAT_ORDER = [
    "Office", "Browser", "Security", "Productivity", "Media", "Game",
    "Java/Runtime", "Driver", "Vendor Tool", "OS Component",
    "Toolbar/BHO", "Other",
]


def _fmt_report(entries: List[dict], summary: dict) -> str:
    lines = [
        "=" * 70,
        "  SOFTWARE INVENTORY",
        "=" * 70,
        f"  Total entries : {summary['total']}",
        f"  Flagged       : {summary['flagged']} "
        f"({summary['suspicious']} suspicious, {summary['bloat']} bloat, "
        f"{summary['legacy']} legacy)",
        "",
    ]

    # Group by category
    by_cat: dict[str, List[dict]] = {}
    for e in entries:
        by_cat.setdefault(e["category"], []).append(e)

    for cat in _CAT_ORDER:
        if cat not in by_cat:
            continue
        cat_entries = sorted(by_cat[cat], key=lambda x: x["name"].lower())
        lines.append(f"  [{cat}]  ({len(cat_entries)} items)")
        for e in cat_entries:
            flag_str = f"  [{', '.join(e['flags'])}]" if e["flags"] else ""
            ver_str  = f" v{e['version']}" if e.get("version") else ""
            pub_str  = f" — {e['publisher']}" if e.get("publisher") else ""
            yr_str   = f" ({e['install_year']})" if e.get("install_year") else ""
            lines.append(f"    {e['name']}{ver_str}{pub_str}{yr_str}{flag_str}")
        lines.append("")

    # Any categories not in the ordered list
    for cat, cat_entries in sorted(by_cat.items()):
        if cat in _CAT_ORDER:
            continue
        lines.append(f"  [{cat}]  ({len(cat_entries)} items)")
        for e in sorted(cat_entries, key=lambda x: x["name"].lower()):
            flag_str = f"  [{', '.join(e['flags'])}]" if e["flags"] else ""
            ver_str  = f" v{e['version']}" if e.get("version") else ""
            lines.append(f"    {e['name']}{ver_str}{flag_str}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="bootstrap run m06_software_inventory",
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--target", required=True, metavar="PATH",
        help="Mount point of the offline Windows installation (e.g. /mnt/windows)"
    )
    parser.add_argument(
        "--no-user-hives", action="store_true",
        help="Skip per-user NTUSER.DAT hives"
    )
    parser.add_argument(
        "--flagged-only", action="store_true",
        help="Only show entries that have at least one flag"
    )
    parser.add_argument(
        "--json-only", action="store_true",
        help="Suppress formatted report; only write JSON log"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    target = Path(args.target)
    if not target.exists():
        _log.error("Target path does not exist: %s", target)
        return 2

    _log.info("Scanning software inventory from %s …", target)

    entries: List[dict] = []
    entries.extend(_collect_system_software(target))
    if not args.no_user_hives:
        entries.extend(_collect_user_software(target))

    entries = _deduplicate(entries)

    if args.flagged_only:
        entries = [e for e in entries if e["flags"]]

    # Summary stats
    summary = {
        "total":      len(entries),
        "flagged":    sum(1 for e in entries if e["flags"]),
        "suspicious": sum(1 for e in entries if "suspicious" in e["flags"]),
        "bloat":      sum(1 for e in entries if "bloat" in e["flags"]),
        "legacy":     sum(1 for e in entries if any(
            f.startswith("legacy") for f in e["flags"]
        )),
        "by_category": {},
    }
    for e in entries:
        summary["by_category"][e["category"]] = (
            summary["by_category"].get(e["category"], 0) + 1
        )

    if not args.json_only:
        print(_fmt_report(entries, summary))

    # Write JSON log
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_dir = root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"software_inventory_{timestamp}.json"
    log_path.write_text(json.dumps({
        "timestamp": timestamp,
        "target":    str(target),
        "summary":   summary,
        "entries":   entries,
    }, indent=2, default=str))
    _log.info("Report written to %s", log_path)

    return 0
