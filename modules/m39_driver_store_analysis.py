"""m39_driver_store_analysis — DriverStore and installed driver package analysis.

Walks Windows/System32/DriverStore/FileRepository and Windows/inf to collect:
  - Driver packages (INF file, provider, class, version, date)
  - Duplicate packages (same base INF name, multiple versions)
  - Old or very-old driver packages (pre-2007, pre-2004)
  - OEM INF files in Windows/inf/

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m39_driver_store_analysis -- --target /mnt/windows

Output:
    logs/driver_store_analysis_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DESCRIPTION = (
    "Driver store analysis: FileRepository packages, versions, duplicates, "
    "old drivers, OEM INF inventory"
)

# ---------------------------------------------------------------------------
# INF file parser — [Version] section only
# ---------------------------------------------------------------------------

def _read_inf_text(path: Path) -> str:
    """Read INF file trying UTF-16-LE, then UTF-8, then latin-1."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def _parse_inf_version(text: str) -> dict:
    """Return key/value dict from the [Version] section of an INF file."""
    result: dict = {}
    in_version = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        line = re.sub(r"\s*;.*$", "", line)  # strip inline comments
        low = line.lower()
        if low == "[version]":
            in_version = True
            continue
        if in_version and line.startswith("["):
            break
        if in_version and "=" in line:
            key, _, val = line.partition("=")
            result[key.strip().lower()] = val.strip()
    return result


def _parse_driver_ver(driverver: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse 'MM/DD/YYYY[,version]' → (ISO-date, version).  Returns (None, None) if unparseable."""
    parts = [p.strip() for p in driverver.split(",", 1)]
    date_iso: Optional[str] = None
    version:  Optional[str] = None
    if parts:
        m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})$", parts[0])
        if m:
            date_iso = f"{m.group(3)}-{int(m.group(1)):02d}-{int(m.group(2)):02d}"
    if len(parts) >= 2:
        version = parts[1]
    return date_iso, version


def _base_inf_name(folder_name: str) -> str:
    """Extract base INF name from FileRepository folder name.
    'acpitime.inf_amd64_abc123' → 'acpitime.inf'
    'oem5.inf_x86_ab12' → 'oem5.inf'
    """
    m = re.match(r"^(.+?\.inf)(?:_|$)", folder_name.lower())
    return m.group(1) if m else folder_name.lower()


def _resolve_provider(raw: str, strings_map: dict) -> str:
    """Expand %Token% references using the [Strings] section map."""
    m = re.match(r"^%(.+)%$", raw.strip())
    if m:
        key = m.group(1).lower()
        return strings_map.get(key, raw)
    return raw


def _parse_inf_strings(text: str) -> dict:
    """Return key→value dict from the [Strings] section."""
    result: dict = {}
    in_strings = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        line = re.sub(r"\s*;.*$", "", line)
        low = line.lower()
        if low == "[strings]":
            in_strings = True
            continue
        if in_strings and line.startswith("["):
            break
        if in_strings and "=" in line:
            key, _, val = line.partition("=")
            result[key.strip().lower()] = val.strip().strip('"')
    return result


def _age_flag(date_iso: Optional[str]) -> Optional[str]:
    if not date_iso:
        return None
    try:
        year = int(date_iso[:4])
        if year < 2004:
            return "very_old"
        if year < 2007:
            return "old"
    except (ValueError, IndexError):
        pass
    return None


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    limitations: List[str] = []
    packages:    List[dict] = []
    by_base:     Dict[str, List[dict]] = defaultdict(list)

    filerepository = target / "Windows" / "System32" / "DriverStore" / "FileRepository"
    if not filerepository.is_dir():
        limitations.append("DriverStore/FileRepository not found")
        return {
            "scan_status": "ok",
            "verdict":     "UNKNOWN",
            "summary":     {},
            "packages":    [],
            "duplicates":  [],
            "oem_infs":    [],
            "limitations": limitations,
        }

    for folder in sorted(filerepository.iterdir()):
        if not folder.is_dir():
            continue
        folder_name = folder.name
        base_inf    = _base_inf_name(folder_name)

        # Find the INF file — prefer the one whose name matches the base
        inf_files = list(folder.glob("*.inf"))
        inf_file: Optional[Path] = None
        for f in inf_files:
            if f.name.lower() == base_inf:
                inf_file = f
                break
        if inf_file is None and inf_files:
            inf_file = inf_files[0]

        if inf_file is None:
            entry: dict = {
                "folder":         folder_name,
                "base_inf":       base_inf,
                "inf_file":       None,
                "provider":       None,
                "class":          None,
                "driver_date":    None,
                "driver_version": None,
                "flags":          ["no_inf_file"],
            }
            packages.append(entry)
            by_base[base_inf].append(entry)
            continue

        try:
            inf_text = _read_inf_text(inf_file)
            ver      = _parse_inf_version(inf_text)
            strings  = _parse_inf_strings(inf_text)
        except Exception as exc:
            limitations.append(f"INF parse error {folder_name}: {exc}")
            ver     = {}
            strings = {}

        driver_date, driver_version = _parse_driver_ver(ver.get("driverver", ""))
        raw_provider = ver.get("provider", "")
        provider     = _resolve_provider(raw_provider, strings) if raw_provider else None
        drv_class    = ver.get("class") or None

        flags: List[str] = []
        age = _age_flag(driver_date)
        if age:
            flags.append(age)

        entry = {
            "folder":         folder_name,
            "base_inf":       base_inf,
            "inf_file":       inf_file.name,
            "provider":       provider,
            "class":          drv_class,
            "driver_date":    driver_date,
            "driver_version": driver_version,
            "flags":          flags,
        }
        packages.append(entry)
        by_base[base_inf].append(entry)

    # Detect duplicates
    duplicates: List[dict] = []
    for base, entries in by_base.items():
        if len(entries) > 1:
            duplicates.append({
                "base_inf": base,
                "count":    len(entries),
                "versions": [e.get("driver_version") for e in entries],
                "dates":    [e.get("driver_date") for e in entries],
            })
            for e in entries:
                if "duplicate" not in e["flags"]:
                    e["flags"].append("duplicate")

    # OEM INFs in Windows/inf/
    oem_infs: List[dict] = []
    system_inf_dir = target / "Windows" / "inf"
    if system_inf_dir.is_dir():
        for inf_path in sorted(system_inf_dir.glob("oem*.inf")):
            try:
                inf_text = _read_inf_text(inf_path)
                ver      = _parse_inf_version(inf_text)
                strings  = _parse_inf_strings(inf_text)
                ddate, dver = _parse_driver_ver(ver.get("driverver", ""))
                raw_prov = ver.get("provider", "")
                oem_infs.append({
                    "file":           inf_path.name,
                    "provider":       _resolve_provider(raw_prov, strings) if raw_prov else None,
                    "class":          ver.get("class") or None,
                    "driver_date":    ddate,
                    "driver_version": dver,
                })
            except Exception:
                pass

    old_count  = sum(1 for p in packages if any(f in ("old", "very_old") for f in p["flags"]))
    dup_count  = len(duplicates)

    verdict = "OK"
    if dup_count > 5 or old_count > 10:
        verdict = "WARNING"

    summary = {
        "total_packages":     len(packages),
        "duplicate_groups":   dup_count,
        "old_driver_packages": old_count,
        "oem_inf_files":      len(oem_infs),
    }

    return {
        "scan_status": "ok",
        "verdict":     verdict,
        "summary":     summary,
        "packages":    packages,
        "duplicates":  duplicates,
        "oem_infs":    oem_infs,
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== DRIVER STORE ANALYSIS ===")
    print(f"Verdict  : {data.get('verdict', '?')}")
    s = data.get("summary", {})
    print(
        f"Packages : {s.get('total_packages', 0)} total | "
        f"{s.get('duplicate_groups', 0)} duplicate groups | "
        f"{s.get('old_driver_packages', 0)} old"
    )
    print(f"OEM INFs : {s.get('oem_inf_files', 0)} in Windows/inf/")

    dups = data.get("duplicates", [])
    if dups:
        print(f"\nDuplicate driver groups ({len(dups)}):")
        for d in dups[:20]:
            dates = ", ".join(v for v in (d.get("dates") or []) if v)
            print(f"  {d['base_inf']:50}  {d['count']} copies  [{dates}]")

    old_pkgs = [
        p for p in data.get("packages", [])
        if any(f in ("old", "very_old") for f in p.get("flags", []))
    ]
    if old_pkgs:
        print(f"\nOld driver packages ({min(len(old_pkgs), 20)} of {len(old_pkgs)}):")
        for p in old_pkgs[:20]:
            flags = ",".join(p.get("flags", []))
            prov  = (p.get("provider") or "?")[:30]
            print(f"  {p['base_inf']:40}  {p.get('driver_date', '?')}  {prov}  [{flags}]")

    limits = data.get("limitations", [])
    if limits:
        print("\nLimitations:")
        for lim in limits[:10]:
            print(f"  - {lim}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    from toolkit import find_windows_target  # noqa: PLC0415

    parser = argparse.ArgumentParser(
        prog="m39_driver_store_analysis",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="",
                        help="Mounted Windows partition path (auto-detect if omitted)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only, skip full package listing")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m39] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    print(f"[m39] Analysing DriverStore in {target_path} ...")
    data = analyse(target_path)

    from datetime import datetime as _dt, timezone as _tz
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"driver_store_analysis_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m39] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
