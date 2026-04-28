"""m41_file_anomalies — Suspicious file anomaly detection.

Detects:
  - Executables/scripts in user-writable locations (Downloads, Temp, AppData, Desktop)
  - Duplicate system binary names in unusual locations
  - Double extensions (file.txt.exe, document.pdf.bat)
  - Misleading filenames (exe named as a document icon, etc.)
  - Random-looking names (high entropy short names)
  - Files with no extension but PE/script magic bytes
  - Recently modified executables (mtime within 90 days)

Scanned paths (read-only, relative to target):
  - Users/*/Downloads
  - Users/*/Desktop
  - Users/*/AppData/Local/Temp
  - Users/*/AppData/Roaming
  - Windows/Temp
  - ProgramData

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m41_file_anomalies -- --target /mnt/windows

Output:
    logs/file_anomalies_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

DESCRIPTION = (
    "File anomaly detection: double-extensions, executables in user-writable paths, "
    "high-entropy names, PE files without .exe extension"
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Extensions that are executables or scripts
_EXEC_EXTS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".scr", ".pif", ".cpl", ".msi", ".jar", ".reg",
    ".com", ".sys", ".drv",
}

# Known legitimate Windows system binary names (in System32)
_SYSTEM_BINARY_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "services.exe", "spoolsv.exe", "explorer.exe", "taskhost.exe",
    "rundll32.exe", "regsvr32.exe", "cmd.exe", "powershell.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "notepad.exe",
    "calc.exe", "regedit.exe", "taskmgr.exe",
}

# Magic bytes for PE executables
_PE_MAGIC = b"MZ"
# Magic bytes for scripts that may lack extension
_SCRIPT_PATTERNS = [
    (b"#!", "shebang_script"),
    (b"<script", "html_script"),
    (b"Set-", "powershell_script"),
    (b"WScript", "wscript"),
    (b"VBScript", "vbscript"),
]

_MAX_FILES_PER_DIR = 2000  # cap to avoid scanning huge dirs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(name: str) -> float:
    if not name:
        return 0.0
    freq: dict = {}
    for c in name:
        freq[c] = freq.get(c, 0) + 1
    n = len(name)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _is_high_entropy(stem: str) -> bool:
    """True if the filename stem looks random (high entropy, mostly hex-like)."""
    if len(stem) < 8:
        return False
    entropy = _shannon_entropy(stem.lower())
    if entropy > 3.8:
        return True
    # Looks like a GUID or random hex
    if re.match(r"^[0-9a-f]{8,}$", stem.lower()):
        return True
    if re.match(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$",
                stem.lower()):
        return False  # GUIDs are common in legit software
    return False


def _has_double_extension(name: str) -> Optional[str]:
    """Return 'docname.pdf.exe' style if double extension detected, else None."""
    parts = name.rsplit(".", 2)
    if len(parts) < 3:
        return None
    outer_ext = "." + parts[-1].lower()
    inner_ext = "." + parts[-2].lower()
    # Only flag if outer is executable and inner looks like a document
    _DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg",
                 ".png", ".zip", ".rar", ".mp3", ".mp4"}
    if outer_ext in _EXEC_EXTS and inner_ext in _DOC_EXTS:
        return f"double_extension:{inner_ext}{outer_ext}"
    return None


def _mtime_iso(path: Path) -> Optional[str]:
    try:
        ts = path.stat().st_mtime
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return None


def _mtime_days_ago(path: Path) -> Optional[float]:
    try:
        ts = path.stat().st_mtime
        now = datetime.now(tz=timezone.utc).timestamp()
        return (now - ts) / 86400
    except OSError:
        return None


def _read_magic(path: Path, n: int = 8) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(n)
    except OSError:
        return b""


def _classify_file(path: Path, recent_days: int) -> Optional[dict]:
    """Return an anomaly record for this file, or None if not anomalous."""
    name      = path.name
    name_low  = name.lower()
    suffix    = path.suffix.lower()
    stem      = path.stem

    flags: List[str] = []

    # Double extension
    dd = _has_double_extension(name)
    if dd:
        flags.append(dd)

    # Executable in user-writable path
    if suffix in _EXEC_EXTS:
        flags.append("executable_in_user_path")

    # High entropy name
    if suffix in _EXEC_EXTS and _is_high_entropy(stem):
        flags.append("high_entropy_name")

    # Duplicate system binary name
    if name_low in _SYSTEM_BINARY_NAMES:
        flags.append("system_binary_name_in_user_path")

    # No extension but PE magic
    if not suffix:
        magic = _read_magic(path)
        if magic[:2] == _PE_MAGIC:
            flags.append("pe_without_extension")
        else:
            for pat, label in _SCRIPT_PATTERNS:
                if magic[:len(pat)].lower() == pat.lower():
                    flags.append(f"script_without_extension:{label}")
                    break

    if not flags:
        return None

    # Recently modified?
    days_ago = _mtime_days_ago(path)
    if days_ago is not None and days_ago <= recent_days:
        flags.append(f"recently_modified ({days_ago:.0f}d ago)")

    return {
        "path":    str(path),
        "name":    name,
        "mtime":   _mtime_iso(path),
        "flags":   flags,
        "size_bytes": _safe_size(path),
    }


def _safe_size(path: Path) -> Optional[int]:
    try:
        return path.stat().st_size
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------

def _scan_dir(directory: Path, recursive: bool, recent_days: int) -> List[dict]:
    anomalies: List[dict] = []
    try:
        it = directory.rglob("*") if recursive else directory.iterdir()
        count = 0
        for p in it:
            if count >= _MAX_FILES_PER_DIR:
                break
            if not p.is_file():
                continue
            count += 1
            r = _classify_file(p, recent_days)
            if r:
                anomalies.append(r)
    except (PermissionError, OSError):
        pass
    return anomalies


def _build_scan_paths(target: Path) -> List[Path]:
    """Return list of paths to scan."""
    paths: List[Path] = []
    users_dir = target / "Users"
    if users_dir.is_dir():
        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            for sub in ("Downloads", "Desktop",
                        "AppData/Local/Temp",
                        "AppData/Roaming"):
                d = user_dir / sub.replace("/", "/")
                if d.is_dir():
                    paths.append(d)

    win_temp = target / "Windows" / "Temp"
    if win_temp.is_dir():
        paths.append(win_temp)

    program_data = target / "ProgramData"
    if program_data.is_dir():
        paths.append(program_data)

    return paths


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path, recent_days: int = 90) -> dict:
    limitations: List[str] = []
    all_anomalies: List[dict] = []

    scan_paths = _build_scan_paths(target)
    if not scan_paths:
        limitations.append("No user-writable directories found")

    for d in scan_paths:
        results = _scan_dir(d, recursive=True, recent_days=recent_days)
        all_anomalies.extend(results)

    # Sort: system-binary-name and double-extension first
    def _severity(a: dict) -> int:
        flags = a.get("flags", [])
        if any("system_binary_name" in f for f in flags):
            return 0
        if any("double_extension" in f for f in flags):
            return 1
        if any("pe_without" in f or "script_without" in f for f in flags):
            return 2
        return 3

    all_anomalies.sort(key=_severity)

    # Flag counts
    counts: dict = {
        "double_extension":      0,
        "system_binary_in_user": 0,
        "pe_without_extension":  0,
        "executable_in_user":    0,
        "high_entropy":          0,
        "recently_modified":     0,
    }
    for a in all_anomalies:
        for f in a.get("flags", []):
            if "double_extension" in f:       counts["double_extension"] += 1
            if "system_binary_name" in f:     counts["system_binary_in_user"] += 1
            if "pe_without_extension" in f:   counts["pe_without_extension"] += 1
            if "executable_in_user" in f:     counts["executable_in_user"] += 1
            if "high_entropy" in f:           counts["high_entropy"] += 1
            if "recently_modified" in f:      counts["recently_modified"] += 1

    if counts["system_binary_in_user"] > 0 or counts["double_extension"] > 0:
        verdict = "SUSPICIOUS"
    elif counts["pe_without_extension"] > 0 or counts["high_entropy"] > 2:
        verdict = "WARNING"
    elif all_anomalies:
        verdict = "WARNING"
    else:
        verdict = "OK"

    return {
        "scan_status":   "ok",
        "verdict":       verdict,
        "summary":       {**counts, "total_anomalies": len(all_anomalies)},
        "anomalies":     all_anomalies[:500],  # cap output
        "scanned_paths": [str(p) for p in scan_paths],
        "limitations":   limitations,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== FILE ANOMALY DETECTION ===")
    print(f"Verdict  : {data.get('verdict', '?')}")
    s = data.get("summary", {})
    print(f"Anomalies: {s.get('total_anomalies', 0)} total")
    for k, v in s.items():
        if k != "total_anomalies" and v > 0:
            print(f"  {k:35} {v}")

    anoms = data.get("anomalies", [])
    if anoms:
        print(f"\nTop anomalies (first 30):")
        for a in anoms[:30]:
            flags = ", ".join(a.get("flags", []))
            print(f"  {a.get('name', '?'):40}  [{flags}]")
            print(f"    {a.get('path', '')}")

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

    parser = argparse.ArgumentParser(prog="m41_file_anomalies", description=DESCRIPTION)
    parser.add_argument("--target", default="")
    parser.add_argument("--days", type=int, default=90,
                        help="Flag recently-modified files within N days (default 90)")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m41] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    print(f"[m41] Scanning for file anomalies in {target_path} ...")
    data = analyse(target_path, recent_days=args.days)

    from datetime import datetime as _dt, timezone as _tz
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"file_anomalies_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m41] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
