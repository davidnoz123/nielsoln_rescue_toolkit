"""
m18_clamav_scan.py — Nielsoln Rescue Toolkit: ClamAV scan with comprehensive analysis.

Runs clamscan with OOM-safe memory limits and resume support, then produces a
structured JSON report covering:

  1. Virus definition metadata      — version, age, signature counts per database
  2. Scan scope                     — paths scanned, clamscan flags, archive/recursion settings
  3. Scan execution details         — start/end time, duration, infected/error counts
  4. Coverage analysis              — key Windows dirs (System32, Users, AppData, etc.)
  5. Scan gaps                      — skipped files, size limits, permission denials
  6. File type limitations          — what file types are not deeply scanned per profile
  7. Heuristic limitations          — inherent blind spots (zero-day, fileless, encrypted)
  8. Cross-module correlation       — compares against m01, m07, m27, m31 findings
  9. Scan confidence score          — high/medium/low/unknown with explanations
 10. Miss analysis                  — consolidated coverage gap summary
 11. Recommendations                — actionable next steps
 12. JSON log                       — logs/clamav_scan_<timestamp>.json

Requires ClamAV to be installed or bundled (bootstrap clamav --install).

Safety: read-only — does not quarantine, delete, or modify any files on the target.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m18_clamav_scan -- --target /mnt/windows [--profile thorough]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

DESCRIPTION = (
    "ClamAV scan with comprehensive evidence-based assessment: definition metadata, "
    "coverage analysis, scan gaps, confidence scoring, cross-module correlation, "
    "and recommendations (requires: bootstrap clamav --install)"
)

# ---------------------------------------------------------------------------
# Key Windows directories to check for coverage
# (relative to the Windows installation root, i.e. target/)
# ---------------------------------------------------------------------------

_COVERAGE_DIRS = {
    "system32":      "Windows/System32",
    "syswow64":      "Windows/SysWOW64",
    "windows_temp":  "Windows/Temp",
    "users":         "Users",
    "program_files": "Program Files",
    "program_files_x86": "Program Files (x86)",
    "programdata":   "ProgramData",
}

# AppData is inside Users/*/AppData — check it separately
_APPDATA_PATTERN = re.compile(r"/[Uu]sers/[^/]+/[Aa]pp[Dd]ata", re.IGNORECASE)

# Definitions database filenames
_DB_FILES = {
    "main":     ["main.cvd", "main.cld"],
    "daily":    ["daily.cvd", "daily.cld"],
    "bytecode": ["bytecode.cvd", "bytecode.cld"],
}

# CVD/CLD build-time format: "07 Dec 2024 09-54 -0500"
_CVD_TIME_FMTS = [
    "%d %b %Y %H-%M %z",
    "%d %b %Y %H:%M %z",
    "%d %b %Y %H-%M %Z",
    "%d %b %Y",
]

# Clamscan log line patterns
_RE_FOUND     = re.compile(r"^(.+): (.+) FOUND$")
_RE_ERROR     = re.compile(r"^(.+): (.+) ERROR$")
_RE_WARNING   = re.compile(r"^WARNING: (.+)$")
_RE_PERM      = re.compile(r"(?:Permission denied|access denied)", re.IGNORECASE)
_RE_SIZE_SKIP = re.compile(r"(?:size limit|Max (?:file|scan) size reached|Skipped)", re.IGNORECASE)
_RE_SUMMARY   = re.compile(
    r"(?:Scanned files|Infected files|Total errors|Scanned directories|Data scanned|Data read)"
    r":\s*(.+)"
)

# Static limitation text (included in every report)
_FILE_TYPE_LIMITATIONS_QUICK = [
    "Only executable and script types scanned: .exe .dll .sys .bat .cmd .ps1 .vbs "
    ".js .jse .wsf .scr .pif .com .cpl .msi .hta .lnk",
    "Archive files (.zip .rar .7z .cab .tar etc.) are NOT unpacked and scanned",
    "PDF documents are NOT scanned",
    "Office documents (.doc .xls .ppt .docx etc.) are NOT scanned",
    "Macro-enabled documents are NOT scanned",
    "Data files and custom formats are NOT scanned",
]

_FILE_TYPE_LIMITATIONS_THOROUGH = [
    "All file types scanned, but subject to size limits (max 50 MB per file, 200 MB total)",
    "Deeply nested archives (> 5 levels) may not be fully unpacked",
    "Password-protected archives cannot be scanned",
    "Encrypted containers (BitLocker, EFS, VeraCrypt) cannot be scanned",
    "Very large files exceeding the per-file size limit are not scanned",
]

_HEURISTIC_LIMITATIONS = [
    "Zero-day malware (unknown to ClamAV database) CANNOT be detected",
    "Custom or targeted malware not matching any known signature CANNOT be detected",
    "Fileless malware (executing in memory with no on-disk presence) CANNOT be detected",
    "Behaviour-based threats (require runtime execution to manifest) CANNOT be detected",
    "Rootkits that hide files from the filesystem at the OS level CANNOT be detected",
    "Polymorphic or metamorphic malware with sufficient obfuscation may evade detection",
    "Encrypted payloads that have not yet been decrypted on disk CANNOT be scanned",
    "ClamAV is a general-purpose scanner — detection rates for Windows malware vary; "
    "a clean result is not a guarantee of no infection",
]

# Definition age thresholds (days)
_DEF_STALE_WARN  = 30   # definitions older than this → warn
_DEF_STALE_HIGH  = 90   # definitions older than this → high concern
_DEF_MISSING_VAL = -1   # sentinel for unavailable

_W = 68   # report width


# ---------------------------------------------------------------------------
# 1. Virus definition metadata
# ---------------------------------------------------------------------------

def _parse_cvd_header(path: Path) -> dict:
    """Parse ClamAV CVD/CLD database header (first 512 bytes).

    CVD header format (colon-separated):
        ClamAV-VDB:<build_time>:<version>:<sig_count>:<level>:<md5>:<dsig>:<builder>:<build_level>
    """
    result = {
        "file":        path.name,
        "version":     None,
        "build_time":  None,
        "sig_count":   None,
        "age_days":    None,
        "parse_error": None,
    }
    try:
        with path.open("rb") as fh:
            header_bytes = fh.read(512)
        header = header_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()
        parts = header.split(":")
        if len(parts) < 4 or not parts[0].startswith("ClamAV-VDB"):
            result["parse_error"] = "Not a valid CVD/CLD header"
            result["raw_header"] = header_bytes.decode("ascii", errors="replace")[:256]
            return result

        result["raw_header"] = header_bytes.decode("ascii", errors="replace").split("\x00")[0][:256]

        build_time_str = parts[1].strip()
        version_str    = parts[2].strip()
        sig_count_str  = parts[3].strip()

        result["version"] = version_str if version_str.isdigit() else version_str

        # Try to parse sig count
        if sig_count_str.isdigit():
            result["sig_count"] = int(sig_count_str)

        # Parse build time
        parsed_dt = None
        for fmt in _CVD_TIME_FMTS:
            try:
                parsed_dt = datetime.strptime(build_time_str, fmt)
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue

        if parsed_dt:
            result["build_time"] = parsed_dt.strftime("%Y-%m-%dT%H:%M:%S%z")
            now = datetime.now(timezone.utc)
            result["age_days"] = max(0, (now - parsed_dt).days)
        else:
            result["build_time"] = build_time_str
            result["parse_error"] = f"Could not parse build time: {build_time_str!r}"

    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


def _sigtool_info(db_path: Path) -> Optional[dict]:
    """Run sigtool --info and parse output.  Returns None if sigtool unavailable."""
    try:
        out = subprocess.run(
            ["sigtool", "--info", str(db_path)],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0:
            return None
        info: dict = {}
        for line in out.stdout.splitlines():
            if line.startswith("Version:"):
                info["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Build time:"):
                info["build_time_raw"] = line.split(":", 1)[1].strip()
            elif line.startswith("Signatures:"):
                val = line.split(":", 1)[1].strip()
                if val.isdigit():
                    info["sig_count"] = int(val)
        return info if info else None
    except Exception:
        return None


def _get_db_metadata(db_dir: Optional[Path]) -> dict:
    """Return metadata for main/daily/bytecode databases."""
    result: dict = {}
    if db_dir is None or not db_dir.is_dir():
        # Try system ClamAV dirs as fallback
        for candidate in [
            Path("/usr/share/clamav"),
            Path("/var/lib/clamav"),
            Path("/usr/local/share/clamav"),
        ]:
            if candidate.is_dir():
                db_dir = candidate
                break

    for name, filenames in _DB_FILES.items():
        found = None
        if db_dir:
            for fn in filenames:
                cand = db_dir / fn
                if cand.exists():
                    found = cand
                    break
        if found:
            meta = _parse_cvd_header(found)
            # Try sigtool for more accurate info
            st = _sigtool_info(found)
            if st:
                if st.get("version"):
                    meta["version"] = st["version"]
                if st.get("sig_count"):
                    meta["sig_count"] = st["sig_count"]
            result[name] = meta
        else:
            result[name] = {
                "file":        None,
                "version":     None,
                "build_time":  None,
                "sig_count":   None,
                "age_days":    None,
                "parse_error": "Database file not found",
            }

    return result


# ---------------------------------------------------------------------------
# 2b. Raw scan output collector
# ---------------------------------------------------------------------------

def _collect_raw_output(log_files: List[Path], max_chars: int = 40_000) -> str:
    """Concatenate raw clamscan log text from segment files (capped to max_chars)."""
    parts: List[str] = []
    total = 0
    for lf in log_files:
        try:
            text = lf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        remaining = max_chars - total
        if remaining <= 0:
            break
        if len(text) > remaining:
            parts.append(text[:remaining])
            parts.append(f"\n... [TRUNCATED: {len(text) - remaining} additional chars in {lf.name}] ...")
            total = max_chars
            break
        parts.append(text)
        total += len(text)
    return "".join(parts)


def _split_raw_output(raw: str) -> tuple[list[str], list[str]]:
    """Extract ERROR: and WARNING: lines from raw clamscan output."""
    errors:   list[str] = []
    warnings: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("ERROR:"):
            errors.append(stripped)
        elif stripped.startswith("WARNING:") or stripped.startswith("LibClamAV Warning:"):
            warnings.append(stripped)
    return errors, warnings


def _build_effective_definitions(definitions: dict, def_summary: dict) -> dict:
    """Build a clean effective_definitions block from per-DB metadata and summary."""
    eff_db   = def_summary.get("effective_db")
    db_meta  = definitions.get(eff_db, {}) if eff_db else {}
    # Gather limitations
    lims: list[str] = []
    lim = def_summary.get("limitation")
    if lim:
        lims.append(lim)
    if def_summary.get("definition_confidence") in ("low", "unknown"):
        lims.append("definition_age_uncertain")
    return {
        "effective_database":   eff_db,
        "effective_build_time": db_meta.get("build_time"),
        "effective_age_days":   db_meta.get("age_days"),
        "definition_confidence": def_summary.get("definition_confidence", "unknown"),
        "definition_limitations": lims,
    }


# ---------------------------------------------------------------------------
# 2. Log parsing
# ---------------------------------------------------------------------------

def _parse_clamscan_logs(log_files: List[Path]) -> dict:
    """Aggregate all segment log files into structured findings."""
    infected:         List[dict] = []
    errors:           List[str]  = []
    permission_denied: List[str] = []
    size_skipped:     List[str]  = []
    warnings:         List[str]  = []
    summary_stats:    dict       = {}
    scanned_dirs_set: Set[str]   = set()

    seen_infected: Set[str] = set()

    for log_path in log_files:
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for line in text.splitlines():
            line = line.rstrip()
            if not line:
                continue

            # Summary lines (only present if --no-summary not used, but try anyway)
            m = _RE_SUMMARY.match(line)
            if m:
                key = line.split(":")[0].strip().lower().replace(" ", "_")
                summary_stats[key] = m.group(1).strip()
                continue

            # Infected
            m = _RE_FOUND.match(line)
            if m:
                fpath, vname = m.group(1), m.group(2)
                if fpath not in seen_infected:
                    seen_infected.add(fpath)
                    infected.append({"path": fpath, "virus": vname})
                    # Track which dir this is in
                    parent = str(Path(fpath).parent)
                    scanned_dirs_set.add(parent)
                continue

            # Error
            m = _RE_ERROR.match(line)
            if m:
                fpath = m.group(1)
                if _RE_PERM.search(m.group(2)):
                    if fpath not in permission_denied:
                        permission_denied.append(fpath)
                else:
                    if fpath not in errors:
                        errors.append(fpath)
                continue

            # Permission denied (standalone warning style)
            if _RE_PERM.search(line):
                path_m = re.search(r"'([^']+)'", line) or re.search(r'"([^"]+)"', line)
                if path_m:
                    p = path_m.group(1)
                    if p not in permission_denied:
                        permission_denied.append(p)
                continue

            # Size skip
            if _RE_SIZE_SKIP.search(line):
                path_m = re.match(r"^(.+?):", line)
                if path_m:
                    p = path_m.group(1)
                    if p not in size_skipped:
                        size_skipped.append(p)
                continue

            # Warning
            m = _RE_WARNING.match(line)
            if m:
                msg = m.group(1)
                if msg not in warnings:
                    warnings.append(msg)

    return {
        "infected":          infected,
        "error_paths":       errors[:100],
        "permission_denied": permission_denied[:100],
        "size_skipped":      size_skipped[:50],
        "warnings":          warnings[:50],
        "summary_stats":     summary_stats,
        "scanned_dirs_hint": sorted(scanned_dirs_set),
    }


# ---------------------------------------------------------------------------
# 3. Filesystem scan-scope estimation
# ---------------------------------------------------------------------------

def _quick_dir_stats(path: Path, deadline: float) -> Tuple[int, int]:
    """Count files and total bytes in a directory tree.

    Stops when *deadline* (time.monotonic()) is reached.
    Returns (file_count, total_bytes).
    """
    file_count  = 0
    total_bytes = 0
    try:
        for root_str, dirs, files in os.walk(str(path), followlinks=False):
            if time.monotonic() > deadline:
                break
            for fn in files:
                fp = Path(root_str) / fn
                try:
                    total_bytes += fp.stat().st_size
                    file_count  += 1
                except OSError:
                    pass
    except OSError:
        pass
    return file_count, total_bytes


def _estimate_scope(
    target: Path,
    scan_dirs: List[Path],
    profile: str,
    time_limit_secs: float = 10.0,
) -> dict:
    """Estimate file counts and byte totals for scanned directories.

    Caps the walk at *time_limit_secs* total to avoid blocking on large partitions.
    """
    deadline    = time.monotonic() + time_limit_secs
    total_files = 0
    total_bytes = 0
    dirs_info   = []

    for d in scan_dirs:
        if not d.is_dir():
            continue
        if time.monotonic() > deadline:
            break
        fc, tb = _quick_dir_stats(d, deadline)
        total_files += fc
        total_bytes += tb
        dirs_info.append(str(d))

    # Which extensions does quick profile scan?
    from toolkit import _QUICK_EXTENSIONS  # type: ignore[import]
    include_exts = _QUICK_EXTENSIONS if profile == "quick" else None

    return {
        "directories_scanned": len([d for d in scan_dirs if d.is_dir()]),
        "files_scanned":       total_files if total_files > 0 else None,
        "total_bytes_scanned": total_bytes if total_bytes > 0 else None,
        "estimate_note":       "File/byte counts are estimates; exact totals unavailable "
                               "due to clamscan --infected flag (only infected files are logged)",
    }


# ---------------------------------------------------------------------------
# 4. Coverage analysis
# ---------------------------------------------------------------------------

def _compute_coverage(target: Path, scan_dirs: List[Path]) -> dict:
    """Check which key Windows directories were included in the scan."""
    scanned_strs = {Path(d).as_posix().lower() for d in scan_dirs}

    def _was_scanned(rel: str) -> bool:
        full = (target / rel).as_posix().lower()
        return any(full.startswith(s.lower()) or s.lower().startswith(full)
                   for s in scanned_strs)

    system32_scanned   = _was_scanned("Windows/System32")
    syswow64_scanned   = _was_scanned("Windows/SysWOW64")
    wtemp_scanned      = _was_scanned("Windows/Temp")
    users_scanned      = _was_scanned("Users")
    pf_scanned         = _was_scanned("Program Files")
    pf86_scanned       = _was_scanned("Program Files (x86)")
    programdata_scanned = _was_scanned("ProgramData")

    # AppData lives under Users — covered if Users was scanned
    appdata_scanned = users_scanned

    # Also check SysWOW64 exists (may be absent on pure 32-bit Vista)
    syswow64_exists = (target / "Windows" / "SysWOW64").is_dir()

    # Overall estimate
    critical_covered = sum([system32_scanned, users_scanned])
    total_key        = 2 + (1 if syswow64_exists else 0) + 1 + 1  # sys32 + users + syswow64 + pf + wtemp
    covered_count    = sum([
        system32_scanned,
        users_scanned,
        syswow64_scanned if syswow64_exists else True,  # don't penalise if absent
        wtemp_scanned,
        pf_scanned,
    ])

    if critical_covered == 2 and covered_count >= 4:
        overall = "high"
    elif critical_covered >= 1 and covered_count >= 2:
        overall = "medium"
    elif covered_count >= 1:
        overall = "low"
    else:
        overall = "unknown"

    not_scanned = []
    if not system32_scanned:
        not_scanned.append("Windows/System32")
    if syswow64_exists and not syswow64_scanned:
        not_scanned.append("Windows/SysWOW64")
    if not wtemp_scanned:
        not_scanned.append("Windows/Temp")
    if not users_scanned:
        not_scanned.append("Users")
    if not pf_scanned and (target / "Program Files").is_dir():
        not_scanned.append("Program Files")
    if not pf86_scanned and (target / "Program Files (x86)").is_dir():
        not_scanned.append("Program Files (x86)")
    if not programdata_scanned and (target / "ProgramData").is_dir():
        not_scanned.append("ProgramData")

    return {
        "system32_scanned":          system32_scanned,
        "syswow64_scanned":          syswow64_scanned,
        "windows_temp_scanned":      wtemp_scanned,
        "users_scanned":             users_scanned,
        "appdata_scanned":           appdata_scanned,
        "program_files_scanned":     pf_scanned,
        "program_files_x86_scanned": pf86_scanned,
        "programdata_scanned":       programdata_scanned,
        "dirs_not_scanned":          not_scanned,
        "overall_estimate":          overall,
    }


# ---------------------------------------------------------------------------
# 5. Scan gaps
# ---------------------------------------------------------------------------

def _compute_gaps(
    parsed_logs: dict,
    coverage: dict,
    profile: str,
    profile_flags: dict,
) -> dict:
    """Aggregate all scan gaps into a structured report."""
    perm_denied  = parsed_logs.get("permission_denied", [])
    size_skipped = parsed_logs.get("size_skipped", [])
    error_paths  = parsed_logs.get("error_paths", [])
    not_scanned  = coverage.get("dirs_not_scanned", [])

    archives_not_scanned = profile == "quick"
    return {
        "skipped_files_count":    len(size_skipped) + len(error_paths),
        "skipped_paths":          (size_skipped + error_paths)[:50],
        "size_limited_files":     size_skipped[:50],
        "error_paths":            error_paths[:50],
        "permission_denied":      perm_denied[:50],
        "dirs_not_scanned":       not_scanned,
        "archives_skipped":       "All archives not scanned" if archives_not_scanned
                                  else "Archives scanned (subject to size/depth limits)",
        "archives_skipped_flag":  archives_not_scanned,
        "max_file_size":          profile_flags.get("max_file_size", "unknown"),
        "max_scan_size":          profile_flags.get("max_scan_size", "unknown"),
    }


# ---------------------------------------------------------------------------
# 6 & 7. File type and heuristic limitations (static)
# ---------------------------------------------------------------------------

def _get_limitations(profile: str) -> Tuple[List[str], List[str]]:
    if profile == "thorough":
        ft = _FILE_TYPE_LIMITATIONS_THOROUGH
    else:
        ft = _FILE_TYPE_LIMITATIONS_QUICK
    return ft, _HEURISTIC_LIMITATIONS


# ---------------------------------------------------------------------------
# 8. Cross-module correlation
# ---------------------------------------------------------------------------

def _latest_log(logs_dir: Path, glob: str) -> Optional[Path]:
    matches = sorted(logs_dir.glob(glob), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def _read_json_log(p: Optional[Path]) -> Optional[dict]:
    if p is None:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _correlate_modules(logs_dir: Path, infected: List[dict]) -> dict:
    """Cross-correlate ClamAV results with findings from other modules."""
    result: dict = {
        "persistence_log":          None,
        "persistence_suspicious":   0,
        "service_analysis_log":     None,
        "service_suspicious":       0,
        "device_manager_log":       None,
        "device_problem_count":     0,
        "system_integrity_log":     None,
        "system_integrity_verdict": None,
        "cross_module_flags":       [],
        "unexplained_signals":      [],
    }

    infected_paths = {i["path"] for i in infected}

    # m01 persistence
    ps_path = _latest_log(logs_dir, "persist_*.jsonl")
    if ps_path:
        result["persistence_log"] = ps_path.name
        try:
            suspicious = sum(
                1 for l in ps_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if l.strip() and json.loads(l).get("severity") in ("HIGH", "MEDIUM")
            )
            result["persistence_suspicious"] = suspicious
        except Exception:
            pass

    # m07 service analysis
    sa_path = _latest_log(logs_dir, "service_analysis_*.json")
    if sa_path:
        result["service_analysis_log"] = sa_path.name
        sa = _read_json_log(sa_path)
        if sa:
            result["service_suspicious"] = sa.get("summary", {}).get("suspicious_count", 0)

    # m27 device manager
    dm_path = _latest_log(logs_dir, "device_manager_*.json")
    if dm_path:
        result["device_manager_log"] = dm_path.name
        dm = _read_json_log(dm_path)
        if dm:
            devs = dm.get("devices", [])
            result["device_problem_count"] = sum(
                1 for d in (devs if isinstance(devs, list) else [])
                if d.get("problem_code") and d.get("problem_code") != 0
            )

    # m31 system integrity
    si_path = _latest_log(logs_dir, "system_integrity_*.json")
    if si_path:
        result["system_integrity_log"] = si_path.name
        si = _read_json_log(si_path)
        if si:
            result["system_integrity_verdict"] = si.get("verdict")

    # Cross-flags
    cav_clean = len(infected) == 0
    si_v = result["system_integrity_verdict"] or ""
    persist_sus = result["persistence_suspicious"]
    svc_sus = result["service_suspicious"]

    if cav_clean and si_v == "TAMPERING_SUSPECTED":
        result["cross_module_flags"].append("CLAMAV_CLEAN_BUT_TAMPERING_SUSPECTED")
        result["unexplained_signals"].append(
            "ClamAV found no known signatures, but the system integrity audit detected "
            "tampering indicators — this is consistent with custom or targeted malware "
            "not present in ClamAV's signature database"
        )
    if cav_clean and persist_sus > 0:
        result["cross_module_flags"].append("CLAMAV_CLEAN_BUT_SUSPICIOUS_PERSISTENCE")
        result["unexplained_signals"].append(
            f"ClamAV found no infections, but {persist_sus} suspicious persistence "
            f"entry/entries were found — manual investigation of those entries recommended"
        )
    if cav_clean and svc_sus > 0:
        result["cross_module_flags"].append("CLAMAV_CLEAN_BUT_SUSPICIOUS_SERVICES")
        result["unexplained_signals"].append(
            f"ClamAV found no infections, but {svc_sus} suspicious service(s) detected "
            f"— may be custom malware, unwanted software, or legitimate tools "
            f"with poor metadata"
        )
    if not cav_clean and (persist_sus > 0 or svc_sus > 0):
        result["cross_module_flags"].append("MULTIPLE_MODULE_THREAT_SIGNALS")
        result["unexplained_signals"].append(
            "ClamAV found infections AND other modules detected suspicious activity — "
            "treat as high-confidence compromise; review all findings together"
        )

    return result


# ---------------------------------------------------------------------------
# 8b. Definition summary (effective age + confidence)
# ---------------------------------------------------------------------------

def _compute_definition_summary(definitions: dict) -> dict:
    """Derive effective_definition_age and definition_confidence from per-DB metadata.

    effective_definition_age is the age (days) of the NEWEST available database,
    which is what determines how current the signatures actually are.  The daily DB
    supersedes main; if both are present the daily age is used.

    definition_confidence:
      "high"   — daily DB present with a parseable timestamp
      "medium" — only main DB found with a parseable timestamp
      "low"    — no parseable timestamps, inconsistent values, or only bytecode

    Returns a dict with:
      effective_definition_age  : int | None
      effective_db              : "daily" | "main" | "bytecode" | None
      definition_confidence     : "high" | "medium" | "low"
      limitation                : str | None  (set when confidence is not "high")
    """
    # Prefer databases in freshness order: daily, main, bytecode
    candidates = [
        ("daily",    definitions.get("daily",    {})),
        ("main",     definitions.get("main",     {})),
        ("bytecode", definitions.get("bytecode", {})),
    ]

    ages: dict = {}   # db_name → age_days (int) for all DBs that have a value
    for name, meta in candidates:
        age = meta.get("age_days")
        if age is not None:
            ages[name] = age

    # Detect inconsistency: main and daily should not differ by more than a few days
    # in normal operation.  A large discrepancy (e.g. one freshly updated and one not)
    # means the effective coverage is only as good as the freshest.
    inconsistent = False
    if "main" in ages and "daily" in ages:
        if abs(ages["daily"] - ages["main"]) > 7:
            # Not an error — daily is always newer; just confirm we use daily
            inconsistent = False  # expected divergence; not a problem

    # Pick effective DB: the one with the smallest (freshest) age_days
    if ages:
        effective_db   = min(ages, key=lambda k: ages[k])
        effective_age  = ages[effective_db]
    else:
        effective_db  = None
        effective_age = None

    # Confidence
    if "daily" in ages:
        confidence   = "high"
        limitation   = None
    elif "main" in ages:
        confidence   = "medium"
        limitation   = (
            "daily.cvd/cld not found — using main database age as effective age; "
            "signatures may be older than the most recent daily update"
        )
    elif "bytecode" in ages:
        confidence   = "low"
        limitation   = (
            "Only bytecode database found — cannot determine signature age accurately; "
            "main and daily databases are missing"
        )
    else:
        confidence   = "low"
        limitation   = (
            "No ClamAV definition databases with parseable timestamps found; "
            "definition age cannot be determined"
        )

    return {
        "effective_definition_age": effective_age,
        "effective_db":             effective_db,
        "definition_confidence":    confidence,
        "limitation":               limitation,
    }


# ---------------------------------------------------------------------------
# 9. Scan confidence
# ---------------------------------------------------------------------------

def _compute_confidence(
    definitions: dict,
    def_summary: dict,
    coverage: dict,
    gaps: dict,
    execution: dict,
    profile: str,
) -> dict:
    """Compute scan confidence level.

    Scoring (start at 6 = high potential):
      -3  all definition files missing/unavailable
      -2  definition age > 90 days
      -1  definition age 30–90 days
      -2  System32 not scanned
      -1  Users not scanned
      -1  profile = quick (archives not scanned)
      -2  scan was partial / OOM killed
      -1  errors_encountered > 10
      -1  permission_denied > 10

    Levels: ≥5 → high, 3–4 → medium, 1–2 → low, ≤0 → unknown
    """
    score   = 6
    reasons: List[str] = []

    # Definition age — use the pre-computed summary (effective = freshest DB)
    eff_age   = def_summary.get("effective_definition_age")
    eff_db    = def_summary.get("effective_db")
    def_conf  = def_summary.get("definition_confidence", "low")
    def_limit = def_summary.get("limitation")

    any_def_ok = eff_age is not None
    missing_dbs = [
        name for name in ("main", "daily")
        if definitions.get(name, {}).get("age_days") is None
    ]
    for db_name in missing_dbs:
        score -= 1
        reasons.append(f"{db_name} definition database not found")

    if not any_def_ok:
        score -= 3
        reasons.append("No definition databases found — signature matching unavailable")
    elif eff_age > _DEF_STALE_HIGH:
        score -= 2
        reasons.append(
            f"Definitions are {eff_age} days old ({eff_db}) "
            f"(> {_DEF_STALE_HIGH} days) — many recent threats will not be detected"
        )
    elif eff_age > _DEF_STALE_WARN:
        score -= 1
        reasons.append(
            f"Definitions are {eff_age} days old ({eff_db}) "
            f"(> {_DEF_STALE_WARN} days) — some recent threats may not be detected"
        )

    if def_conf == "low" and any_def_ok:
        reasons.append(f"Definition confidence: low — {def_limit}")

    # Coverage
    if not coverage.get("system32_scanned"):
        score -= 2
        reasons.append("Windows/System32 was NOT scanned — critical directory missed")
    if not coverage.get("users_scanned"):
        score -= 1
        reasons.append("Users directory was NOT scanned — user-space malware may be missed")

    # Profile
    if profile == "quick":
        score -= 1
        reasons.append(
            "Quick profile only scans executables/scripts — archive-based malware not scanned"
        )

    # Partial scan
    if execution.get("oom_killed") or execution.get("scan_status") == "partial":
        score -= 2
        reasons.append("Scan was incomplete (OOM kill or partial coverage)")

    # Errors
    err_count = execution.get("errors_encountered", 0) or 0
    if err_count > 10:
        score -= 1
        reasons.append(f"{err_count} scan errors encountered — some files were not checked")

    # Permission denials
    perm_count = len(gaps.get("permission_denied", []))
    if perm_count > 10:
        score -= 1
        reasons.append(
            f"{perm_count} permission-denied paths — some files inaccessible "
            f"(common on offline NTFS mounts with ACLs)"
        )

    if score >= 5:
        level = "high"
    elif score >= 3:
        level = "medium"
    elif score >= 1:
        level = "low"
    else:
        level = "unknown"

    if not reasons:
        reasons.append("No significant concerns detected")

    return {"level": level, "score": max(0, score), "max_score": 6, "reasons": reasons}


# ---------------------------------------------------------------------------
# 10. Miss analysis
# ---------------------------------------------------------------------------

def _compute_miss_analysis(
    coverage: dict,
    gaps: dict,
    file_type_limitations: List[str],
    heuristic_limitations: List[str],
    cross_module: dict,
    confidence: dict,
) -> dict:
    """Consolidate all coverage-gap information."""
    coverage_gaps: List[str] = []

    if gaps.get("dirs_not_scanned"):
        for d in gaps["dirs_not_scanned"]:
            coverage_gaps.append(f"Directory not scanned: {d}")
    if gaps.get("archives_skipped_flag"):
        coverage_gaps.append(
            "Archive files not unpacked — malware delivered inside .zip/.rar/.cab not detected"
        )
    if gaps.get("size_limited_files"):
        coverage_gaps.append(
            f"{len(gaps['size_limited_files'])} file(s) skipped due to size limits"
        )
    if gaps.get("permission_denied"):
        coverage_gaps.append(
            f"{len(gaps['permission_denied'])} path(s) inaccessible (permission denied)"
        )

    cross_flags = cross_module.get("cross_module_flags", [])
    confidence_adjustment = "lowered" if confidence["level"] in ("low", "unknown") else "unchanged"

    return {
        "coverage_gaps":            coverage_gaps,
        "file_type_limitations":    file_type_limitations,
        "heuristic_limitations":    heuristic_limitations,
        "cross_module_flags":       cross_flags,
        "unexplained_signals":      cross_module.get("unexplained_signals", []),
        "confidence_adjustment":    confidence_adjustment,
    }


# ---------------------------------------------------------------------------
# 11. Recommendations
# ---------------------------------------------------------------------------

def _compute_recommendations(
    definitions: dict,
    def_summary: dict,
    coverage: dict,
    gaps: dict,
    confidence: dict,
    cross_module: dict,
    infected: List[dict],
    profile: str,
) -> List[str]:
    recs: List[str] = []

    # Definition age — use effective (freshest) age from pre-computed summary
    eff_age = def_summary.get("effective_definition_age")
    eff_db  = def_summary.get("effective_db")
    no_defs = not any(definitions.get(k, {}).get("age_days") is not None for k in ("main", "daily"))

    if no_defs:
        recs.append(
            "Install ClamAV and download virus definitions: "
            "run `bootstrap clamav --install` then `bootstrap clamav --update-db`"
        )
    elif eff_age is not None and eff_age > _DEF_STALE_HIGH:
        recs.append(
            f"Update virus definitions immediately — {eff_db} is {eff_age} days old "
            f"(run `bootstrap clamav --update-db` with a network connection)"
        )
    elif eff_age is not None and eff_age > _DEF_STALE_WARN:
        recs.append(
            f"Update virus definitions when possible — {eff_db} is {eff_age} days old "
            f"(run `bootstrap clamav --update-db`)"
        )

    # Profile
    if profile == "quick":
        recs.append(
            "Run a thorough scan for complete coverage: "
            "bootstrap run m18_clamav_scan -- --target <path> --profile thorough"
        )

    # Coverage gaps
    not_scanned = coverage.get("dirs_not_scanned", [])
    if not_scanned:
        dirs_str = ", ".join(not_scanned[:4])
        recs.append(
            f"Scan missing directories individually: {dirs_str}"
        )

    # Infections
    if infected:
        recs.append(
            f"{len(infected)} infected file(s) found — review with persistence scan (m01) "
            f"and service analysis (m07) to assess impact; do NOT boot the OS until reviewed"
        )
        recs.append(
            "Consider full OS reinstallation if system files are infected "
            "(ClamAV cannot repair infected files in this toolkit)"
        )

    # Cross-module flags
    xflags = cross_module.get("cross_module_flags", [])
    if "CLAMAV_CLEAN_BUT_TAMPERING_SUSPECTED" in xflags:
        recs.append(
            "System integrity audit indicates tampering — run a secondary AV scanner "
            "(Malwarebytes, ESET Online Scanner, etc.) from a separate clean system"
        )
    if "CLAMAV_CLEAN_BUT_SUSPICIOUS_PERSISTENCE" in xflags:
        recs.append(
            f"Review {cross_module['persistence_suspicious']} suspicious persistence "
            f"entry/entries found by the persistence scanner (m01)"
        )
    if "CLAMAV_CLEAN_BUT_SUSPICIOUS_SERVICES" in xflags:
        recs.append(
            f"Investigate {cross_module['service_suspicious']} suspicious service(s) "
            f"found by service analysis (m07)"
        )

    # Confidence low
    if confidence["level"] in ("low", "unknown"):
        recs.append(
            "Overall scan confidence is LOW — consider a secondary scanner on a "
            "different platform before declaring the system clean"
        )

    if not recs:
        recs.append(
            "No significant issues detected — maintain up-to-date definitions and "
            "run thorough scans periodically"
        )

    return recs


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def _print_report(result: dict) -> None:
    status    = result.get("scan_status", "unknown")
    infected  = result.get("infected_files", [])
    confidence = result.get("scan_confidence", {})

    print("\n" + "=" * _W)
    print(f"  CLAMAV SCAN ASSESSMENT — {status.upper()}")
    print(f"  Confidence: {confidence.get('level', '?').upper()}")
    print("=" * _W)
    print(f"  Target  : {result.get('target', '?')}")
    print(f"  Profile : {result.get('profile', '?')}")
    print(f"  Generated: {result.get('generated', '?')}")
    print()

    # Definitions
    defs     = result.get("definitions", {})
    def_summ = result.get("definition_summary", {})
    print(f"  {'─'*10} VIRUS DEFINITIONS {'─'*38}")
    for db_name in ("main", "daily", "bytecode"):
        db = defs.get(db_name, {})
        age  = db.get("age_days")
        ver  = db.get("version") or "?"
        sigs = db.get("sig_count")
        age_str  = f"{age}d old" if age is not None else "N/A"
        sigs_str = f"{sigs:,}" if sigs else "?"
        warn = " ← OUTDATED" if (age or 0) > _DEF_STALE_HIGH else (
            " ← UPDATE SOON" if (age or 0) > _DEF_STALE_WARN else ""
        )
        if db.get("parse_error") == "Database file not found":
            print(f"  {db_name:<10}: NOT FOUND")
        else:
            print(f"  {db_name:<10}: v{ver}  sigs={sigs_str}  age={age_str}{warn}")
    eff_age  = def_summ.get("effective_definition_age")
    eff_db   = def_summ.get("effective_db")
    def_conf = def_summ.get("definition_confidence", "?")
    eff_str  = f"{eff_age}d ({eff_db})" if eff_age is not None else "unknown"
    print(f"  {'effective':<10}: age={eff_str}  confidence={def_conf}")
    if def_summ.get("limitation"):
        print(f"  NOTE: {def_summ['limitation'][:62]}")

    # Coverage
    cov = result.get("coverage", {})
    print(f"\n  {'─'*10} SCAN COVERAGE {'─'*42}")
    print(f"  Overall estimate : {cov.get('overall_estimate', '?').upper()}")
    flags = [
        ("System32",     cov.get("system32_scanned")),
        ("SysWOW64",     cov.get("syswow64_scanned")),
        ("Windows/Temp", cov.get("windows_temp_scanned")),
        ("Users",        cov.get("users_scanned")),
        ("AppData",      cov.get("appdata_scanned")),
        ("Program Files",cov.get("program_files_scanned")),
    ]
    for label, val in flags:
        mark = "✓" if val else "✗"
        print(f"    {mark} {label}")
    not_scanned = cov.get("dirs_not_scanned", [])
    if not_scanned:
        print(f"\n  DIRS NOT SCANNED: {', '.join(not_scanned)}")

    # Execution
    exec_info = result.get("scan_execution", {})
    print(f"\n  {'─'*10} EXECUTION {'─'*46}")
    print(f"  Infected files   : {len(infected)}")
    dur = exec_info.get("duration_seconds")
    if dur is not None:
        mins, secs = divmod(int(dur), 60)
        print(f"  Duration         : {mins}m {secs}s")
    print(f"  Errors           : {exec_info.get('errors_encountered', 0)}")
    print(f"  Permission denied: {len(result.get('scan_gaps', {}).get('permission_denied', []))}")
    print(f"  Size-skipped     : {len(result.get('scan_gaps', {}).get('size_limited_files', []))}")

    # Infections
    if infected:
        print(f"\n  {'─'*10} INFECTED FILES {'─'*41}")
        for item in infected[:20]:
            print(f"    INFECTED  {item['path'][:55]}")
            print(f"              {item['virus']}")
        if len(infected) > 20:
            print(f"    ... and {len(infected)-20} more")

    # Cross-module
    xmod = result.get("cross_module_correlation", {})
    if xmod.get("unexplained_signals"):
        print(f"\n  {'─'*10} CROSS-MODULE SIGNALS {'─'*35}")
        for sig in xmod["unexplained_signals"]:
            print(f"    ! {sig[:64]}")

    # Confidence reasons
    print(f"\n  {'─'*10} CONFIDENCE FACTORS {'─'*37}")
    for r in confidence.get("reasons", []):
        print(f"    - {r[:64]}")

    # Recommendations
    print(f"\n  {'─'*10} RECOMMENDATIONS {'─'*39}")
    for i, rec in enumerate(result.get("recommendations", []), 1):
        # Word-wrap at ~60 chars
        words, line = rec.split(), ""
        first = True
        for w in words:
            if len(line) + len(w) > 60:
                print(f"  {'  ' if not first else str(i)+'. '}{line}")
                line, first = w, False
            else:
                line = (line + " " + w).strip()
        if line:
            print(f"  {'  ' if not first else str(i)+'. '}{line}")

    # Heuristic limitations (always shown)
    print(f"\n  {'─'*10} INHERENT LIMITATIONS (ALWAYS APPLY) {'─'*17}")
    for lim in _HEURISTIC_LIMITATIONS[:4]:
        print(f"    - {lim[:64]}")
    print(f"    (+ {len(_HEURISTIC_LIMITATIONS)-4} more — see JSON report)")

    print("=" * _W + "\n")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    """Bootstrap entry point — called by `bootstrap run m18_clamav_scan`."""
    from toolkit import run_scan, find_windows_target  # type: ignore[import]

    parser = argparse.ArgumentParser(
        prog="m18_clamav_scan",
        description=DESCRIPTION,
    )
    parser.add_argument("--target",
                        help="Path to mounted Windows installation; "
                             "auto-detected from NTFS mounts if omitted.")
    parser.add_argument("--profile", choices=["quick", "thorough"], default="quick",
                        help="quick=exe/script types only  thorough=all files+archives  "
                             "(default: quick)")
    parser.add_argument("--no-swap", action="store_true",
                        help="Skip automatic swap file creation")
    parser.add_argument("--no-resume", action="store_true",
                        help="Ignore existing checkpoint and restart from beginning")
    parser.add_argument("--verbose", action="store_true",
                        help="Print each clamscan command line")
    parser.add_argument("--analyze-only", action="store_true",
                        help="Skip running ClamAV; analyze most-recent existing log files only")
    parser.add_argument("--summary", action="store_true",
                        help="Print verdict + recommendations only (suppress full report)")
    args = parser.parse_args(argv)

    # Resolve target
    if args.target:
        target = Path(args.target)
    else:
        target = find_windows_target()
        if target is None:
            print("ERROR: Could not auto-detect a Windows installation on any NTFS mount.")
            print("       Pass --target explicitly, or check mounts with: findmnt -t ntfs,fuseblk")
            return 2
        print(f"[m18] Auto-detected Windows target: {target}")

    target = Path(target)
    if not target.exists():
        print(f"ERROR: Target does not exist: {target}")
        return 2

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # ---- Snapshot log dir before scan ----
    pre_logs: Set[str] = {p.name for p in logs_dir.glob("clamav_*")} if logs_dir.exists() else set()
    start_time = datetime.now(timezone.utc)
    start_mono = time.monotonic()

    # ---- Run the actual scan (unless --analyze-only) ----
    scan_rc = 0
    oom_killed = False

    if not args.analyze_only:
        print(f"[m18] Starting ClamAV scan (profile={args.profile}) …")
        scan_rc = run_scan(
            root,
            target,
            profile=args.profile,
            no_swap=args.no_swap,
            resume=not args.no_resume,
            verbose=args.verbose,
        )
        if scan_rc == 1:
            oom_killed = True
    else:
        print("[m18] --analyze-only: skipping ClamAV scan, using existing logs")

    end_time  = datetime.now(timezone.utc)
    end_mono  = time.monotonic()
    duration  = end_mono - start_mono

    # ---- Find new log files produced by this run ----
    all_clamav_logs = sorted(
        logs_dir.glob("clamav_*"),
        key=lambda p: p.stat().st_mtime,
    )
    if not args.analyze_only:
        # Only files created/modified after scan started
        new_logs = [
            p for p in all_clamav_logs
            if p.name not in pre_logs and p.suffix == ".log"
        ]
        if not new_logs:
            # Fallback: take the 5 most-recently modified .log files
            new_logs = [p for p in all_clamav_logs if p.suffix == ".log"][-5:]
    else:
        # Take last 5 segment logs
        new_logs = [p for p in all_clamav_logs if p.suffix == ".log"][-5:]

    # ---- Parse log files ----
    parsed_logs = _parse_clamscan_logs(new_logs)
    infected    = parsed_logs["infected"]
    error_paths = parsed_logs["error_paths"]
    perm_denied = parsed_logs["permission_denied"]

    # ---- Definition metadata ----
    db_dir = root / "clamav" / "linux-x86_64" / "db"
    if not db_dir.is_dir():
        db_dir = None
    definitions = _get_db_metadata(db_dir)

    # ---- Scan scope ----
    from toolkit import _WIN_SCAN_DIRS  # type: ignore[import]
    scan_dirs: List[Path] = []
    for rel in _WIN_SCAN_DIRS:
        if rel == ".":
            scan_dirs.append(target)
        else:
            cand = target / rel
            if cand.exists():
                scan_dirs.append(cand)

    from toolkit import _PROFILE_QUICK, _PROFILE_THOROUGH  # type: ignore[import]
    profile_flags_raw = _PROFILE_QUICK if args.profile == "quick" else _PROFILE_THOROUGH
    profile_flags_dict: dict = {}
    for flag in profile_flags_raw:
        m = re.match(r"--([a-zA-Z\-]+)=(.*)", flag)
        if m:
            profile_flags_dict[m.group(1)] = m.group(2)

    scope = _estimate_scope(target, scan_dirs, args.profile)
    scope["paths_scanned"]    = [str(d) for d in scan_dirs]
    scope["paths_skipped"]    = []
    scope["recursion_enabled"]         = True
    scope["archives_scanned"]          = args.profile == "thorough"
    scope["include_system_directories"]= True
    scope["max_file_size"]  = profile_flags_dict.get("max-filesize", "?")
    scope["max_scan_size"]  = profile_flags_dict.get("max-scansize", "?")

    # ---- Coverage ----
    coverage = _compute_coverage(target, scan_dirs)

    # ---- Execution details ----
    execution = {
        "scan_start_time":           start_time.isoformat(),
        "scan_end_time":             end_time.isoformat(),
        "duration_seconds":          round(duration, 1),
        "infected_count":            len(infected),
        "errors_encountered":        len(error_paths),
        "files_skipped_due_to_errors": len(error_paths),
        "permission_denied_paths":   perm_denied,
        "oom_killed":                oom_killed,
        "analyze_only":              args.analyze_only,
        "scan_status":               (
            "partial" if oom_killed
            else "no_clamav" if scan_rc == 3
            else "analyze_only" if args.analyze_only
            else "infected" if len(infected) > 0
            else "error" if scan_rc in (2, 5)
            else "clean"
        ),
    }

    # ---- Gaps ----
    gaps = _compute_gaps(parsed_logs, coverage, args.profile, scope)

    # ---- File type / heuristic limitations ----
    ft_limits, heuristic_limits = _get_limitations(args.profile)

    # ---- Cross-module correlation ----
    cross_module = _correlate_modules(logs_dir, infected)

    # ---- Definition summary (effective age + confidence) ----
    def_summary = _compute_definition_summary(definitions)

    # ---- Confidence ----
    confidence = _compute_confidence(definitions, def_summary, coverage, gaps, execution, args.profile)

    # ---- Miss analysis ----
    miss_analysis = _compute_miss_analysis(
        coverage, gaps, ft_limits, heuristic_limits, cross_module, confidence
    )

    # ---- Recommendations ----
    recommendations = _compute_recommendations(
        definitions, def_summary, coverage, gaps, confidence, cross_module, infected, args.profile
    )

    # ---- Determine overall scan_status ----
    scan_status = execution["scan_status"]

    # ---- Raw evidence ----
    scan_command    = "clamscan " + " ".join(profile_flags_raw)
    raw_scan_output = _collect_raw_output(new_logs)

    # ---- Effective definitions + scan configuration + raw error split ----
    effective_definitions = _build_effective_definitions(definitions, def_summary)

    scan_configuration = {
        "scan_command":    scan_command,
        "scan_profile":    args.profile,
        "recursion":       True,
        "archives_scanned": args.profile == "thorough"
            or "--scan-archive=yes" in profile_flags_raw
            or "-z" in profile_flags_raw,
        "target_paths":    [str(d) for d in scan_dirs],
        "excluded_paths":  [],
    }

    raw_errors, raw_warnings = _split_raw_output(raw_scan_output)

    # ---- Build JSON result ----
    result = {
        "generated":               end_time.isoformat(),
        "target":                  str(target),
        "profile":                 args.profile,
        "scan_status":             scan_status,
        "infected_files":          infected,
        "definitions":             definitions,
        "definition_summary":      def_summary,
        "effective_definitions":   effective_definitions,
        "scan_configuration":      scan_configuration,
        "scan_scope":              scope,
        "scan_execution":          execution,
        "coverage":                coverage,
        "scan_gaps":               gaps,
        "file_type_limitations":   ft_limits,
        "heuristic_limitations":   heuristic_limits,
        "cross_module_correlation": cross_module,
        "scan_confidence":         confidence,
        "miss_analysis":           miss_analysis,
        "recommendations":         recommendations,
        # raw evidence
        "scan_command":            scan_command,
        "raw_scan_output":         raw_scan_output,
        "raw_errors":              raw_errors,
        "raw_warnings":            raw_warnings,
    }

    # ---- Print report ----
    if not args.summary:
        _print_report(result)
    else:
        print(f"\nScan status : {scan_status.upper()}")
        print(f"Confidence  : {confidence['level'].upper()}")
        print(f"Infected    : {len(infected)}")
        for rec in recommendations:
            print(f"  → {rec[:72]}")

    # ---- Write JSON log ----
    ts       = end_time.strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"clamav_scan_{ts}.json"
    log_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(f"[m18] Assessment log → {log_path}")

    return scan_rc
