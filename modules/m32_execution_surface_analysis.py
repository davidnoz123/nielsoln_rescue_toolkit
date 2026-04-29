"""
m32_execution_surface_analysis.py — Nielsoln Rescue Toolkit: execution surface analysis.

Correlates service executables (from m07) against ClamAV scan coverage (m18) and
system integrity findings (m31) to determine whether each executable is:
  - scanned by ClamAV or outside scan scope
  - trusted / in a safe system location
  - associated with known integrity anomalies
  - a risk-scored execution surface entry point

Produces a per-service risk table with flags and actionable recommendations.

Safety: read-only; reads existing log files only; does not modify target.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m32_execution_surface_analysis -- --target /mnt/windows

Output:
    Prints a risk-ranked execution surface report to stdout.
    Writes logs/execution_surface_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DESCRIPTION = (
    "Execution surface analysis: correlates service executables against ClamAV "
    "scan coverage and system integrity findings to identify unscanned, untrusted, "
    "or suspicious execution targets with risk scoring — requires prior m07, m18, m31 logs"
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Windows paths that are considered safe system locations
_SAFE_PREFIXES = [
    r"\windows\system32\\",
    r"\windows\syswow64\\",
    r"\windows\sysnative\\",
    r"\windows\servicing\\",
    r"\windows\winsxs\\",
    r"\windows\microsoft.net\\",
    r"\program files\\",
    r"\program files (x86)\\",
]

# Windows paths that are intrinsically suspicious for service executables
_SUSPICIOUS_PATTERNS = [
    re.compile(r"\\te?mp\\", re.IGNORECASE),
    re.compile(r"\\appdata\\", re.IGNORECASE),
    re.compile(r"\\desktop\\", re.IGNORECASE),
    re.compile(r"\\downloads?\\", re.IGNORECASE),
    re.compile(r"\\recycler\\", re.IGNORECASE),
    re.compile(r"\\\$recycle\.bin", re.IGNORECASE),
    re.compile(r"\\users\\[^\\]+\\(?!appdata\\local\\programs)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Log-finding helpers
# ---------------------------------------------------------------------------

def _latest(logs_dir: Path, glob: str) -> Optional[Path]:
    """Return the most recently modified file matching glob, or None."""
    matches = sorted(logs_dir.glob(glob), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Log loaders
# ---------------------------------------------------------------------------

def _load_service_log(logs_dir: Path) -> Tuple[Optional[dict], Optional[str]]:
    """Load the latest service_analysis log.  Returns (data, filename)."""
    p = _latest(logs_dir, "service_analysis_*.json")
    if not p:
        return None, None
    d = _read_json(p)
    return (d, p.name) if d else (None, p.name)


def _load_clamav_log(logs_dir: Path) -> Tuple[Optional[dict], Optional[str]]:
    """Load the latest clamav_scan log.  Returns (data, filename)."""
    p = _latest(logs_dir, "clamav_scan_*.json")
    if not p:
        return None, None
    d = _read_json(p)
    return (d, p.name) if d else (None, p.name)


def _load_integrity_log(logs_dir: Path) -> Tuple[Optional[dict], Optional[str]]:
    """Load the latest system_integrity log.  Returns (data, filename)."""
    p = _latest(logs_dir, "system_integrity_*.json")
    if not p:
        return None, None
    d = _read_json(p)
    return (d, p.name) if d else (None, p.name)


# ---------------------------------------------------------------------------
# Windows → Linux path normalisation
# ---------------------------------------------------------------------------

def _win_to_linux(win_path: str, target: Path) -> Optional[str]:
    """Convert a Windows absolute path to a Linux path under target.

    Handles:
      C:\\Windows\\... → {target}/Windows/...
      \\SystemRoot\\... → {target}/Windows/...
      \\Windows\\... → {target}/Windows/...
      \\??\\C:\\... → strips \\??\\ prefix, then normal drive-letter handling

    Always returns forward-slash paths (safe on both Linux and Windows test envs).
    """
    if not win_path:
        return None
    p = win_path.strip().strip('"')

    # Strip NT kernel namespace prefixes (simple string check — no re.sub with paths)
    for ns in ("\\\\?\\", "\\\\.\\" ):
        if p.startswith(ns):
            p = p[len(ns):]
            break

    # Canonical Linux-style base paths (always forward-slash, no os.sep ambiguity)
    win_base    = target.as_posix() + "/Windows"
    target_base = target.as_posix()

    # Expand env vars using plain startswith (avoids re.sub replacement string issues)
    pl = p.lower()
    for env in ("%systemroot%", "%windir%"):
        if pl.startswith(env):
            rest = p[len(env):].lstrip("\\/")
            return (win_base + "/" + rest.replace("\\", "/")) if rest else win_base

    if pl.startswith("%systemdrive%"):
        rest = p[len("%systemdrive%"):].lstrip("\\/")
        return (target_base + "/" + rest.replace("\\", "/")) if rest else target_base

    # \\SystemRoot\... notation
    m = re.match(r"\\SystemRoot\\(.*)", p, re.IGNORECASE)
    if m:
        rel = m.group(1).replace("\\", "/")
        return win_base + "/" + rel

    # Drive-letter path: X:\rest
    m = re.match(r"[A-Za-z]:\\(.*)", p)
    if m:
        rel = m.group(1).replace("\\", "/")
        return target_base + "/" + rel

    # Already a Linux-style absolute path
    if p.startswith("/"):
        return p

    # Absolute-ish path starting with single backslash
    if p.startswith("\\"):
        rel = p.lstrip("\\").replace("\\", "/")
        return target_base + "/" + rel

    return None


def _win_path_lower(win_path: str) -> str:
    """Return the Windows path normalised to lowercase with forward slashes."""
    return win_path.replace("\\", "/").lower()


def _relpath_under_windows(win_path: str) -> Optional[str]:
    """Return the portion of a Windows path relative to the Windows directory.

    e.g. C:\\Windows\\System32\\ntdll.dll → System32/ntdll.dll
         C:\\Program Files\\Foo\\bar.exe  → None  (not under Windows)
    """
    norm = win_path.replace("\\", "/")
    m = re.search(r"/[Ww]indows/(.*)", norm)
    if m:
        return m.group(1)
    return None


# ---------------------------------------------------------------------------
# ClamAV scan coverage check
# ---------------------------------------------------------------------------

def _build_scan_index(clamav_data: Optional[dict]) -> dict:
    """Extract normalised structures from clamav log for fast lookups.

    Returns dict with:
      scanned_dirs  — set of lowercase Linux path strings that were scanned
      perm_denied   — set of lowercase Linux paths (permission denied)
      size_skipped  — set of lowercase Linux paths (size-limited)
      has_clamav    — bool: was clamav actually run (not just analyze_only/no_clamav)
      scan_status   — raw scan_status string
    """
    if not clamav_data:
        return {
            "scanned_dirs": set(), "perm_denied": set(),
            "size_skipped": set(), "has_clamav": False, "scan_status": "no_data",
        }
    scope  = clamav_data.get("scan_scope") or {}
    gaps   = clamav_data.get("scan_gaps")  or {}
    status = clamav_data.get("scan_status", "unknown")
    has_clamav = status not in ("no_clamav", "analyze_only", "unknown")

    scanned = {p.rstrip("/").lower() for p in (scope.get("paths_scanned") or [])}
    perm    = {p.rstrip("/").lower() for p in (gaps.get("permission_denied") or [])}
    size    = {p.rstrip("/").lower() for p in (gaps.get("size_limited_files") or [])}
    return {
        "scanned_dirs": scanned,
        "perm_denied":  perm,
        "size_skipped": size,
        "has_clamav":   has_clamav,
        "scan_status":  status,
    }


def _was_path_scanned(linux_path: Optional[str], scan_index: dict) -> str:
    """Return scan coverage status for a single absolute Linux path.

    Returns one of:
      "scanned"           — path is under a scanned directory
      "permission_denied" — path or parent was denied
      "size_skipped"      — file was too large for ClamAV
      "out_of_scope"      — scanned, but this file's dir was not included
      "no_scan_data"      — no clamav log available
      "no_clamav"         — clamav not installed / not run
    """
    if not scan_index.get("has_clamav"):
        status = scan_index.get("scan_status", "no_data")
        return "no_clamav" if status in ("no_clamav",) else "no_scan_data"

    if not linux_path:
        return "no_scan_data"

    lp = linux_path.rstrip("/").lower()

    # Check permission denied (exact file or parent dir)
    for denied in scan_index["perm_denied"]:
        if lp == denied or lp.startswith(denied + "/"):
            return "permission_denied"

    # Check size-skipped (exact file match)
    if lp in scan_index["size_skipped"]:
        return "size_skipped"

    # Check if any scanned directory covers this file
    lp_dir = lp.rsplit("/", 1)[0] if "/" in lp else lp
    for scanned in scan_index["scanned_dirs"]:
        if lp_dir == scanned or lp_dir.startswith(scanned + "/"):
            return "scanned"
        # Also accept if the scanned path is the file itself
        if lp == scanned:
            return "scanned"

    return "out_of_scope"


# ---------------------------------------------------------------------------
# Integrity correlation
# ---------------------------------------------------------------------------

def _build_integrity_index(integrity_data: Optional[dict]) -> dict:
    """Build fast lookup sets from m31 integrity log.

    Returns dict with:
      anomalous_relpaths — set of lowercase Windows-relative paths (e.g. system32/ntdll.dll)
      anomalous_details  — {relpath_lower: anomaly_entry_dict}
      missing_relpaths   — set of lowercase Windows-relative paths
    """
    if not integrity_data:
        return {"anomalous_relpaths": set(), "anomalous_details": {}, "missing_relpaths": set()}

    anomalous_raw = integrity_data.get("anomalous_files") or []
    missing_raw   = integrity_data.get("missing_files")   or []

    anomalous_relpaths: set = set()
    anomalous_details:  dict = {}
    for entry in anomalous_raw:
        path = entry.get("path", "")
        if path:
            key = path.replace("\\", "/").lower()
            anomalous_relpaths.add(key)
            anomalous_details[key] = entry

    missing_relpaths: set = set()
    for entry in missing_raw:
        path = entry.get("path", "") if isinstance(entry, dict) else str(entry)
        if path:
            missing_relpaths.add(path.replace("\\", "/").lower())

    return {
        "anomalous_relpaths": anomalous_relpaths,
        "anomalous_details":  anomalous_details,
        "missing_relpaths":   missing_relpaths,
    }


def _integrity_status(win_path: str, integrity_index: dict) -> dict:
    """Return integrity correlation for a Windows executable path.

    The win_path should be relative to the Windows directory
    (e.g. System32/ntdll.dll) — obtained from _relpath_under_windows().

    Returns:
      {in_protected_list, anomalies, missing, anomaly_details}
    """
    if not win_path:
        return {"in_protected_list": False, "anomalies": [], "missing": False, "anomaly_details": None}

    rel = win_path.replace("\\", "/").lower()

    in_anomalous = rel in integrity_index["anomalous_relpaths"]
    in_missing   = rel in integrity_index["missing_relpaths"]
    details      = integrity_index["anomalous_details"].get(rel)
    anomalies    = details.get("anomalies", []) if details else []

    return {
        "in_protected_list": in_anomalous or in_missing,
        "anomalies":         anomalies,
        "missing":           in_missing,
        "anomaly_details":   details,
    }


# ---------------------------------------------------------------------------
# Suspicious location check
# ---------------------------------------------------------------------------

def _is_suspicious_location(win_path: str) -> bool:
    """Return True if the Windows path is in an intrinsically suspicious location."""
    if not win_path:
        return False
    for pat in _SUSPICIOUS_PATTERNS:
        if pat.search(win_path):
            return True
    return False


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _score_risk(
    start: str,
    scan_result: str,
    file_exists: Optional[bool],
    integrity: dict,
    location_suspicious: bool,
    m07_flags: List[str],
    is_svchost: bool,
    dll_scan_result: str,
) -> str:
    """Return a risk level: LOW / MEDIUM / HIGH / CRITICAL."""

    auto_starts = {"AUTO", "BOOT", "SYSTEM"}
    is_autostart = start in auto_starts

    # Base risk
    risk = "MEDIUM" if is_autostart else "LOW"

    # Escalate: executable missing
    if file_exists is False:
        if is_autostart:
            return "CRITICAL"
        risk = "HIGH"

    # Escalate: not scanned at all + autostart
    not_scanned = scan_result in ("out_of_scope", "no_scan_data", "no_clamav")
    if not_scanned and is_autostart:
        risk = "HIGH"

    # Escalate: integrity anomaly
    if integrity.get("anomalies"):
        risk = _max_risk(risk, "HIGH")

    # Escalate: suspicious location
    if location_suspicious:
        risk = _max_risk(risk, "HIGH")

    # Escalate: m07 marked SUSPICIOUS
    if "SUSPICIOUS" in m07_flags:
        risk = _max_risk(risk, "HIGH")

    # CRITICAL conditions
    if (not_scanned and location_suspicious) or \
       (not_scanned and "SUSPICIOUS" in m07_flags) or \
       (not_scanned and integrity.get("anomalies")) or \
       (is_svchost and dll_scan_result in ("out_of_scope", "no_scan_data") and is_autostart):
        return "CRITICAL"

    if "SUSPICIOUS" in m07_flags and location_suspicious:
        return "CRITICAL"

    return risk


def _max_risk(r1: str, r2: str) -> str:
    return r1 if _RISK_ORDER.get(r1, 99) <= _RISK_ORDER.get(r2, 99) else r2


# ---------------------------------------------------------------------------
# Flag computation
# ---------------------------------------------------------------------------

def _compute_flags(
    start: str,
    scan_result: str,
    dll_scan_result: str,
    file_exists: Optional[bool],
    location_suspicious: bool,
    integrity: dict,
    m07_flags: List[str],
    is_svchost: bool,
    risk: str,
) -> List[str]:
    """Return list of flag strings for a service entry."""
    flags: List[str] = []

    if scan_result in ("out_of_scope", "no_scan_data", "no_clamav"):
        flags.append("executable_not_scanned")

    if file_exists is False:
        flags.append("executable_missing")

    if location_suspicious:
        flags.append("executable_untrusted")

    if "SUSPICIOUS" in m07_flags or "UNQUOTED_PATH" in m07_flags:
        flags.append("suspicious_path")

    if is_svchost and dll_scan_result in ("out_of_scope", "no_scan_data", "no_clamav"):
        flags.append("svchost_dll_unchecked")

    if integrity.get("anomalies"):
        flags.append("system_file_anomaly")

    if risk in ("HIGH", "CRITICAL") and start in ("AUTO", "BOOT", "SYSTEM"):
        flags.append("high_risk_autostart")

    return flags


# ---------------------------------------------------------------------------
# Per-service analysis
# ---------------------------------------------------------------------------

def _analyse_service(
    svc: dict,
    target: Path,
    scan_index: dict,
    integrity_index: dict,
) -> dict:
    """Analyse one service entry from m07 log.

    Returns a per-service analysis dict.
    """
    name          = svc.get("name", "")
    display_name  = svc.get("display_name", name)
    start         = svc.get("start", "?")
    image_path    = svc.get("image_path", "")
    resolved_path = svc.get("resolved_path", "")
    m07_flags     = svc.get("flags") or []
    svchost_group = svc.get("svchost_group")
    dll_details   = svc.get("dll_details")

    # Primary executable evidence from m07 file_evidence
    fe = svc.get("file_evidence") or {}
    file_exists   = fe.get("exists")
    location_susp = fe.get("suspicious_location", False) or _is_suspicious_location(resolved_path or image_path)

    # Determine the effective executable for scanning correlation
    # For svchost services, the real code is in the ServiceDll
    is_svchost = bool(svchost_group or (
        image_path and re.search(r"svchost\.exe", image_path, re.IGNORECASE)
    ))

    # Convert resolved Windows path to Linux path for scan lookup
    primary_win   = resolved_path or image_path
    primary_linux = _win_to_linux(primary_win, target)
    scan_result   = _was_path_scanned(primary_linux, scan_index)

    # ServiceDll scan coverage (svchost services)
    dll_win_path   = None
    dll_linux_path = None
    dll_scan_result = "not_applicable"
    if is_svchost and dll_details:
        dll_win_path   = dll_details.get("resolved_path") or dll_details.get("ServiceDll", "")
        dll_linux_path = _win_to_linux(dll_win_path, target)
        dll_scan_result = _was_path_scanned(dll_linux_path, scan_index)
        dll_fe = dll_details.get("file_evidence") or {}
        if file_exists is None:
            file_exists = dll_fe.get("exists")
        if not location_susp:
            location_susp = dll_fe.get("suspicious_location", False) or _is_suspicious_location(dll_win_path or "")

    # Integrity correlation — use relpath under Windows dir
    win_rel = _relpath_under_windows(primary_win)
    integrity = _integrity_status(win_rel or primary_win, integrity_index)

    # Risk and flags
    risk = _score_risk(
        start, scan_result, file_exists,
        integrity, location_susp, m07_flags,
        is_svchost, dll_scan_result,
    )
    flags = _compute_flags(
        start, scan_result, dll_scan_result,
        file_exists, location_susp, integrity,
        m07_flags, is_svchost, risk,
    )

    result: dict = {
        "name":                 name,
        "display_name":         display_name,
        "start_type":           start,
        "start_type_int":       svc.get("config", {}).get("start_raw"),
        "image_path_raw":       image_path,
        "image_path_resolved":  primary_win,
        "is_svchost":           is_svchost,
        "svchost_group":        svchost_group,
        "scan_result":          scan_result,
        "integrity_status":     {
            "exists":            file_exists,
            "anomalies":         integrity.get("anomalies", []),
            "in_protected_list": integrity.get("in_protected_list", False),
            "missing":           integrity.get("missing", False),
        },
        "location_suspicious":  location_susp,
        "risk":                 risk,
        "flags":                flags,
    }

    # Parse ImagePath into executable + arguments
    _raw_ip = image_path or ""
    if _raw_ip.startswith('"'):
        _eq      = _raw_ip.find('"', 1)
        _cmd_exe  = _raw_ip[1:_eq]  if _eq != -1 else _raw_ip.strip('"')
        _cmd_args = _raw_ip[_eq + 1:].strip() if _eq != -1 else ""
    else:
        _m_ip = re.match(
            r"(.*?\.(?:exe|sys|dll|bat|cmd|com|scr|pif))\s*(.*)",
            _raw_ip, re.IGNORECASE,
        )
        if _m_ip:
            _cmd_exe, _cmd_args = _m_ip.group(1), _m_ip.group(2).strip()
        else:
            _parts    = _raw_ip.split(None, 1)
            _cmd_exe  = _parts[0] if _parts else _raw_ip
            _cmd_args = _parts[1].strip() if len(_parts) > 1 else ""
    result["command_parsed_executable"] = _cmd_exe or None
    result["command_parsed_arguments"]  = _cmd_args or None

    # Add service_dll block if relevant
    if is_svchost:
        result["service_dll"] = {
            "path":        dll_win_path,
            "scan_result": dll_scan_result,
        }

    return result


# ---------------------------------------------------------------------------
# Summary and recommendations
# ---------------------------------------------------------------------------

def _compute_summary(services_analysed: List[dict]) -> dict:
    total       = len(services_analysed)
    not_scanned = sum(1 for s in services_analysed if "executable_not_scanned" in s["flags"])
    untrusted   = sum(1 for s in services_analysed if "executable_untrusted"   in s["flags"])
    high_risk   = sum(1 for s in services_analysed if s["risk"] in ("HIGH",))
    critical    = sum(1 for s in services_analysed if s["risk"] == "CRITICAL")
    return {
        "total_services":      total,
        "executables_analysed": total,
        "not_scanned":         not_scanned,
        "untrusted":           untrusted,
        "high_risk":           high_risk,
        "critical_risk":       critical,
    }


def _compute_risk_distribution(services_analysed: List[dict]) -> dict:
    dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for s in services_analysed:
        dist[s["risk"]] = dist.get(s["risk"], 0) + 1
    return dist


def _compute_recommendations(summary: dict, services_analysed: List[dict]) -> List[str]:
    recs: List[str] = []

    if summary["critical_risk"] > 0:
        recs.append(
            f"{summary['critical_risk']} service(s) are CRITICAL risk — review immediately: "
            + ", ".join(s["name"] for s in services_analysed if s["risk"] == "CRITICAL")[:120]
        )

    if summary["not_scanned"] > 0:
        recs.append(
            f"{summary['not_scanned']} service executable(s) were not scanned by ClamAV — "
            "run m18 with --thorough or broaden scan scope"
        )

    if summary["untrusted"] > 0:
        recs.append(
            f"{summary['untrusted']} service(s) have executables in suspicious locations "
            "(temp, appdata, user dirs) — investigate manually"
        )

    svchost_unchecked = [s for s in services_analysed if "svchost_dll_unchecked" in s["flags"]]
    if svchost_unchecked:
        recs.append(
            f"{len(svchost_unchecked)} svchost-hosted service DLL(s) were not scanned — "
            "these are common persistence targets; verify: "
            + ", ".join(s["name"] for s in svchost_unchecked)[:100]
        )

    anomaly_services = [s for s in services_analysed if "system_file_anomaly" in s["flags"]]
    if anomaly_services:
        recs.append(
            f"{len(anomaly_services)} service executable(s) match files flagged by m31 integrity audit "
            "— correlate anomaly types for tampering indicators: "
            + ", ".join(s["name"] for s in anomaly_services)[:100]
        )

    missing = [s for s in services_analysed if "executable_missing" in s["flags"]]
    if missing:
        recs.append(
            f"{len(missing)} service(s) reference missing executables — "
            "could indicate deletion after installation: "
            + ", ".join(s["name"] for s in missing)[:100]
        )

    return recs


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

_W = 72

def _print_report(result: dict) -> None:
    summary = result.get("summary", {})
    dist    = result.get("risk_distribution", {})
    svc_list = result.get("services_analysed", [])

    print("\n" + "=" * _W)
    print("  EXECUTION SURFACE ANALYSIS")
    print(f"  Target  : {result.get('target', '?')}")
    print(f"  Report  : {result.get('generated', '?')}")
    print("=" * _W)
    print(f"  Services analysed : {summary.get('total_services', 0)}")
    print(f"  Not scanned       : {summary.get('not_scanned', 0)}")
    print(f"  Untrusted path    : {summary.get('untrusted', 0)}")
    print(f"  High risk         : {summary.get('high_risk', 0)}")
    print(f"  CRITICAL risk     : {summary.get('critical_risk', 0)}")
    print(f"  Risk distribution : CRITICAL={dist.get('CRITICAL',0)}  HIGH={dist.get('HIGH',0)}"
          f"  MEDIUM={dist.get('MEDIUM',0)}  LOW={dist.get('LOW',0)}")

    # CRITICAL entries
    critical = [s for s in svc_list if s["risk"] == "CRITICAL"]
    if critical:
        print(f"\n  {'— CRITICAL ' + '─' * 58}")
        for s in critical:
            print(f"  {s['name']:<32}  {s['start_type']:<8}  "
                  f"scan={s['scan_result']}")
            if s["flags"]:
                print(f"    flags: {', '.join(s['flags'])}")
            if s.get("image_path_resolved"):
                print(f"    path : {s['image_path_resolved'][:65]}")

    # HIGH entries
    high = [s for s in svc_list if s["risk"] == "HIGH"]
    if high:
        print(f"\n  {'— HIGH RISK ' + '─' * 57}")
        for s in high:
            print(f"  {s['name']:<32}  {s['start_type']:<8}  "
                  f"scan={s['scan_result']}")
            if s["flags"]:
                print(f"    flags: {', '.join(s['flags'])}")

    recs = result.get("recommendations", [])
    if recs:
        print(f"\n  {'— RECOMMENDATIONS ' + '─' * 50}")
        for rec in recs:
            # Wrap at ~68 chars
            words = rec.split()
            line = ""
            for w in words:
                if len(line) + len(w) + 1 > 68:
                    print(f"  → {line}")
                    line = w
                else:
                    line = (line + " " + w).strip()
            if line:
                print(f"  → {line}")

    print("\n" + "=" * _W + "\n")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    """Entry point called by bootstrap.py run <module>."""
    parser = argparse.ArgumentParser(
        prog="m32_execution_surface_analysis",
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--target", default="/mnt/windows",
        help="Path to the mounted offline Windows installation",
    )
    parser.add_argument(
        "--service-log",
        help="Override path to service_analysis_*.json (default: latest in logs/)",
    )
    parser.add_argument(
        "--clamav-log",
        help="Override path to clamav_scan_*.json (default: latest in logs/)",
    )
    parser.add_argument(
        "--integrity-log",
        help="Override path to system_integrity_*.json (default: latest in logs/)",
    )
    parser.add_argument(
        "--min-risk", default="LOW",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum risk level to include in output (default: LOW)",
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Print summary section only (no per-service table)",
    )
    args = parser.parse_args(argv)

    target   = Path(args.target)
    logs_dir = root / "logs"
    logs_dir.mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # Load logs
    # ------------------------------------------------------------------
    if args.service_log:
        svc_data = _read_json(Path(args.service_log))
        svc_file = Path(args.service_log).name
    else:
        svc_data, svc_file = _load_service_log(logs_dir)

    if args.clamav_log:
        clamav_data = _read_json(Path(args.clamav_log))
        clamav_file = Path(args.clamav_log).name
    else:
        clamav_data, clamav_file = _load_clamav_log(logs_dir)

    if args.integrity_log:
        integrity_data = _read_json(Path(args.integrity_log))
        integrity_file = Path(args.integrity_log).name
    else:
        integrity_data, integrity_file = _load_integrity_log(logs_dir)

    # Warn if any source is missing (analysis still proceeds with limited info)
    if not svc_data:
        print("WARNING: no service_analysis log found — run m07 first for best results")
        print("  Execution surface analysis requires service data to be useful.")
        # Write minimal output and exit gracefully
        ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "target":    str(target),
            "source_logs": {
                "service_analysis": svc_file,
                "clamav_scan":      clamav_file,
                "system_integrity": integrity_file,
            },
            "error": "no_service_log",
            "services_analysed": [],
            "summary": _compute_summary([]),
            "risk_distribution": _compute_risk_distribution([]),
            "recommendations": ["Run m07 service analysis first, then re-run m32"],
        }
        out_path = logs_dir / f"execution_surface_{ts}.json"
        out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"  Log: {out_path}")
        return 1

    if not clamav_data:
        print("WARNING: no clamav_scan log found — run m18 for scan coverage data")
    if not integrity_data:
        print("WARNING: no system_integrity log found — run m31 for integrity correlation")

    # ------------------------------------------------------------------
    # Build correlation indices
    # ------------------------------------------------------------------
    scan_index      = _build_scan_index(clamav_data)
    integrity_index = _build_integrity_index(integrity_data)

    # ------------------------------------------------------------------
    # Analyse each service
    # ------------------------------------------------------------------
    services_raw = svc_data.get("services") or []
    services_analysed: List[dict] = []
    min_order = _RISK_ORDER.get(args.min_risk, 3)

    for svc in services_raw:
        entry = _analyse_service(svc, target, scan_index, integrity_index)
        if _RISK_ORDER.get(entry["risk"], 99) <= min_order:
            services_analysed.append(entry)

    # Sort by risk (worst first), then alphabetically
    services_analysed.sort(
        key=lambda s: (_RISK_ORDER.get(s["risk"], 99), s["name"].lower())
    )

    summary          = _compute_summary(services_analysed)
    risk_dist        = _compute_risk_distribution(services_analysed)
    recommendations  = _compute_recommendations(summary, services_analysed)

    # ------------------------------------------------------------------
    # Assemble output
    # ------------------------------------------------------------------
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    result = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "target":    str(target),
        "source_logs": {
            "service_analysis": svc_file,
            "clamav_scan":      clamav_file,
            "system_integrity": integrity_file,
        },
        "services_analysed":  services_analysed,
        "summary":            summary,
        "risk_distribution":  risk_dist,
        "recommendations":    recommendations,
    }

    # ------------------------------------------------------------------
    # Print report
    # ------------------------------------------------------------------
    if not args.summary:
        _print_report(result)
    else:
        s = result["summary"]
        print(f"Execution Surface: total={s['total_services']} "
              f"not_scanned={s['not_scanned']} "
              f"untrusted={s['untrusted']} "
              f"high={s['high_risk']} "
              f"critical={s['critical_risk']}")

    # ------------------------------------------------------------------
    # Write log
    # ------------------------------------------------------------------
    out_path = logs_dir / f"execution_surface_{ts}.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"  Log written: {out_path.name}")

    return 0


# ---------------------------------------------------------------------------
# REPL guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    sys.exit(run(Path("."), sys.argv[1:]))
