"""
m31_system_integrity_audit.py — Nielsoln Rescue Toolkit: offline Windows system integrity audit.

Assesses whether an offline Windows installation appears corrupted or tampered with,
using layered read-only checks:

  1. Protected file coverage  — checks ~60 critical EXE/DLL/SYS files exist and look sane
  2. File sanity             — size, mtime, SHA256, PE version metadata anomalies
  3. WinSxS correlation      — cross-references System32 files against component store
  4. Manifest & catalog      — checks manifests, catroot, servicing/Packages are intact
  5. CBS/servicing logs       — parses CBS.log for repair attempts and corruption messages
  6. Pending operations       — checks pending.xml and PendingFileRenameOperations
  7. Boot integrity           — BIOS vs UEFI, bootmgr/winload/BCD presence
  8. Driver integrity         — registered boot/system drivers with missing binaries
  9. Event log correlation    — disk I/O errors, controller resets, driver load failures
 10. Cross-module correlation — combines signals from m05, m30, m07, m01, m27 logs

Limitations:
  - Authenticode (digital signature) validation is not performed offline from Linux
  - SFC equivalent cannot be run without booting Windows
  - WinSxS correlation uses size/mtime comparison, not hash comparison
  - Old Vista hives handled gracefully

Safety: read-only; no modifications to target files or hives.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m31_system_integrity_audit -- --target /mnt/windows

Output:
    Prints a layered integrity report to stdout.
    Writes logs/system_integrity_<timestamp>.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

DESCRIPTION = (
    "System integrity audit: offline multi-layer check for Windows file corruption "
    "or tampering — protected files, WinSxS correlation, CBS log, boot files, "
    "driver integrity, event-log correlation — requires --target /mnt/windows"
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCAN_DATE = datetime.now(timezone.utc)
_YEAR_NOW  = _SCAN_DATE.year

# Timestamps outside these bounds are flagged as unusual
_TS_TOO_OLD   = datetime(2001, 1, 1, tzinfo=timezone.utc).timestamp()
_TS_FUTURE    = (_YEAR_NOW + 1) * 365.25 * 86400 + 631152000  # rough future threshold

# Max bytes to read from CBS.log (last 1 MB — it grows large)
_CBS_MAX_BYTES = 1 * 1024 * 1024

# Max bytes to hash
_SHA256_MAX = 50 * 1024 * 1024

# PE version string scan limit
_PE_MAX_SCAN = 8 * 1024 * 1024

# WinSxS component dir count thresholds — fewer than this suggests damage
_WINSXS_MIN_COMPONENTS_VISTA = 50
_WINSXS_MIN_MANIFESTS_VISTA  = 40

# Minimum expected .cat files in catroot
_CATROOT_MIN_CATS = 10

_EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Event IDs
_DISK_IO_ERROR_IDS     = {7, 11, 51}
_CONTROLLER_RESET_IDS  = {129}
_DRIVER_FAIL_IDS       = {7000, 7001, 7023, 7024, 7031, 7034}
_CHKDSK_EVENT_IDS      = {26226}
_SFC_REPAIR_IDS        = {4097, 4098}   # Wininit / WER events indicating SFC ran

# ---------------------------------------------------------------------------
# Protected file list
# All paths relative to Windows\ directory.
# optional=True → absence does not count toward missing_files verdict weight.
# ---------------------------------------------------------------------------

_PROTECTED_FILES: List[Dict] = [
    # --- Kernel ---
    {"path": "System32/ntoskrnl.exe",         "cat": "kernel",   "optional": False},
    {"path": "System32/ntkrnlpa.exe",         "cat": "kernel",   "optional": True},   # 32-bit PAE
    {"path": "System32/hal.dll",              "cat": "kernel",   "optional": False},
    {"path": "System32/bootvid.dll",          "cat": "kernel",   "optional": False},
    {"path": "System32/kdcom.dll",            "cat": "kernel",   "optional": True},
    # --- Core runtime ---
    {"path": "System32/ntdll.dll",            "cat": "runtime",  "optional": False},
    {"path": "System32/kernel32.dll",         "cat": "runtime",  "optional": False},
    {"path": "System32/kernelbase.dll",       "cat": "runtime",  "optional": True},   # Vista SP2+
    {"path": "System32/msvcrt.dll",           "cat": "runtime",  "optional": False},
    {"path": "System32/user32.dll",           "cat": "runtime",  "optional": False},
    {"path": "System32/gdi32.dll",            "cat": "runtime",  "optional": False},
    {"path": "System32/advapi32.dll",         "cat": "runtime",  "optional": False},
    {"path": "System32/rpcrt4.dll",           "cat": "runtime",  "optional": False},
    {"path": "System32/ole32.dll",            "cat": "runtime",  "optional": False},
    {"path": "System32/oleaut32.dll",         "cat": "runtime",  "optional": False},
    {"path": "System32/shell32.dll",          "cat": "runtime",  "optional": False},
    {"path": "System32/combase.dll",          "cat": "runtime",  "optional": True},   # Win8+
    {"path": "System32/uxtheme.dll",          "cat": "runtime",  "optional": False},
    # --- Authentication / security ---
    {"path": "System32/lsass.exe",            "cat": "auth",     "optional": False},
    {"path": "System32/lsasrv.dll",           "cat": "auth",     "optional": False},
    {"path": "System32/msv1_0.dll",           "cat": "auth",     "optional": False},
    {"path": "System32/kerberos.dll",         "cat": "auth",     "optional": False},
    {"path": "System32/wdigest.dll",          "cat": "auth",     "optional": False},
    {"path": "System32/secur32.dll",          "cat": "auth",     "optional": False},
    {"path": "System32/samsrv.dll",           "cat": "auth",     "optional": False},
    {"path": "System32/samlib.dll",           "cat": "auth",     "optional": False},
    {"path": "System32/netlogon.dll",         "cat": "auth",     "optional": False},
    # --- Service control ---
    {"path": "System32/services.exe",         "cat": "services", "optional": False},
    {"path": "System32/svchost.exe",          "cat": "services", "optional": False},
    {"path": "System32/scesrv.dll",           "cat": "services", "optional": False},
    # --- Logon / session ---
    {"path": "System32/winlogon.exe",         "cat": "logon",    "optional": False},
    {"path": "System32/userinit.exe",         "cat": "logon",    "optional": False},
    {"path": "System32/logonui.exe",          "cat": "logon",    "optional": False},
    # --- Explorer ---
    {"path": "explorer.exe",                  "cat": "shell",    "optional": False},
    # --- Common tools ---
    {"path": "System32/cmd.exe",              "cat": "tools",    "optional": False},
    {"path": "System32/taskmgr.exe",          "cat": "tools",    "optional": False},
    {"path": "System32/regedit.exe",          "cat": "tools",    "optional": False},
    {"path": "System32/msiexec.exe",          "cat": "tools",    "optional": False},
    {"path": "System32/regsvr32.exe",         "cat": "tools",    "optional": False},
    # --- Boot (Vista/7+) ---
    {"path": "System32/winload.exe",          "cat": "boot",     "optional": True},   # Vista+
    {"path": "System32/winresume.exe",        "cat": "boot",     "optional": True},   # Vista+
    # --- Networking ---
    {"path": "System32/ws2_32.dll",           "cat": "network",  "optional": False},
    {"path": "System32/dnsapi.dll",           "cat": "network",  "optional": False},
    {"path": "System32/iphlpapi.dll",         "cat": "network",  "optional": False},
    {"path": "System32/netapi32.dll",         "cat": "network",  "optional": False},
    # --- Registry / config ---
    {"path": "System32/config/SYSTEM",        "cat": "registry", "optional": False},
    {"path": "System32/config/SOFTWARE",      "cat": "registry", "optional": False},
    {"path": "System32/config/SECURITY",      "cat": "registry", "optional": False},
    {"path": "System32/config/SAM",           "cat": "registry", "optional": False},
    # --- Critical drivers ---
    {"path": "System32/drivers/ntfs.sys",     "cat": "driver",   "optional": False},
    {"path": "System32/drivers/disk.sys",     "cat": "driver",   "optional": False},
    {"path": "System32/drivers/classpnp.sys", "cat": "driver",   "optional": False},
    {"path": "System32/drivers/volmgr.sys",   "cat": "driver",   "optional": True},   # Vista+
    {"path": "System32/drivers/partmgr.sys",  "cat": "driver",   "optional": False},
    {"path": "System32/drivers/pci.sys",      "cat": "driver",   "optional": False},
    {"path": "System32/drivers/acpi.sys",     "cat": "driver",   "optional": False},
    {"path": "System32/drivers/ndis.sys",     "cat": "driver",   "optional": False},
    {"path": "System32/drivers/tcpip.sys",    "cat": "driver",   "optional": False},
    {"path": "System32/drivers/ksecdd.sys",   "cat": "driver",   "optional": False},
    {"path": "System32/drivers/fwpkclnt.sys", "cat": "driver",   "optional": True},   # Vista+
    {"path": "System32/drivers/nsiproxy.sys", "cat": "driver",   "optional": True},   # Vista+
]

# Filenames (lower-case) that should carry Microsoft company metadata
_EXPECT_MS_METADATA: Set[str] = {
    "ntoskrnl.exe", "ntkrnlpa.exe", "hal.dll", "ntdll.dll", "kernel32.dll",
    "kernelbase.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll",
    "lsass.exe", "lsasrv.dll", "msv1_0.dll", "kerberos.dll", "samsrv.dll",
    "services.exe", "svchost.exe", "winlogon.exe", "userinit.exe", "explorer.exe",
    "cmd.exe", "taskmgr.exe", "regedit.exe", "msiexec.exe", "winload.exe",
    "ws2_32.dll", "ntfs.sys", "disk.sys", "tcpip.sys", "acpi.sys",
}

# Safe system paths (lower-case fragments)
_SAFE_DIRS = [
    "windows/system32", "windows/syswow64", "windows/winsxs",
    "windows/servicing", "windows/inf", "windows/microsoft.net",
    "%systemroot%", "%windir%",
]

# ---------------------------------------------------------------------------
# PE version string scanner (standalone, no external deps)
# ---------------------------------------------------------------------------

_PE_VERSION_KEYS = [
    "CompanyName", "ProductName", "FileVersion", "ProductVersion",
    "InternalName", "OriginalFilename", "FileDescription",
]


def _parse_pe_version_strings(data: bytes) -> dict:
    """Scan PE bytes for VS_VERSION_INFO String entries.  Best-effort; {} on error."""
    result: dict = {}
    try:
        for key in _PE_VERSION_KEYS:
            encoded = (key + "\x00").encode("utf-16-le")
            pos = 0
            while True:
                p = data.find(encoded, pos)
                if p < 0:
                    break
                if p < 6:
                    pos = p + 2
                    continue
                hdr       = p - 6
                w_len     = struct.unpack_from("<H", data, hdr)[0]
                w_val_len = struct.unpack_from("<H", data, hdr + 2)[0]
                w_type    = struct.unpack_from("<H", data, hdr + 4)[0]
                if w_type not in (0, 1) or w_len < 8 or w_val_len > 512 or w_len > 4096:
                    pos = p + 2
                    continue
                after_key = p + len(encoded)
                aligned   = hdr + (((after_key - hdr) + 3) & ~3)
                val_bytes = w_val_len * 2
                val_end   = aligned + val_bytes
                if val_end > len(data) or val_bytes == 0:
                    pos = p + 2
                    continue
                value = data[aligned:val_end].decode("utf-16-le", errors="replace").rstrip("\x00")
                if value and 1 <= len(value) <= 200:
                    result[key] = value
                    break
                pos = p + 2
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# File evidence collection
# ---------------------------------------------------------------------------

def _collect_file_evidence(path: Path) -> dict:
    """Collect existence, size, mtime, sha256, version_info for a single file."""
    ev: dict = {
        "exists":       None,
        "size_bytes":   None,
        "modified":     None,
        "sha256":       None,
        "version_info": {},
        "error":        None,
    }
    try:
        if not path.exists():
            ev["exists"] = False
            return ev
        ev["exists"] = True
        st = path.stat()
        ev["size_bytes"] = st.st_size
        ev["modified"]   = datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
        # SHA256
        if st.st_size <= _SHA256_MAX:
            h = hashlib.sha256()
            try:
                with path.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                ev["sha256"] = h.hexdigest()
            except Exception as e:
                ev["error"] = f"sha256: {e}"
        # PE version strings
        suffix = path.suffix.lower()
        if suffix in (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr") and 0 < st.st_size <= _PE_MAX_SCAN:
            try:
                raw = path.read_bytes()
                if raw[:2] == b"MZ":
                    ev["version_info"] = _parse_pe_version_strings(raw)
            except Exception:
                pass
    except Exception as exc:
        ev["error"] = str(exc)
    return ev


def _check_file_anomalies(evidence: dict, win_relpath: str, category: str) -> List[str]:
    """Return list of anomaly tags for a file's collected evidence.

    win_relpath: e.g. 'System32/ntdll.dll' (relative to Windows\)
    """
    anomalies: List[str] = []
    if not evidence.get("exists"):
        return anomalies

    size = evidence.get("size_bytes", 0) or 0
    mtime_str = evidence.get("modified") or ""
    vi = evidence.get("version_info") or {}

    # Zero-byte
    if size == 0:
        anomalies.append("ZERO_BYTE")

    # Unusual timestamp
    if mtime_str:
        try:
            # Parse ISO format with Z
            ts_str = mtime_str.rstrip("Z")
            mtime_dt = datetime.fromisoformat(ts_str)
            mtime_ts  = mtime_dt.replace(tzinfo=timezone.utc).timestamp()
            if mtime_ts < _TS_TOO_OLD:
                anomalies.append("TIMESTAMP_TOO_OLD")
            elif mtime_ts > _SCAN_DATE.timestamp() + 86400:
                anomalies.append("TIMESTAMP_FUTURE")
        except Exception:
            pass

    # Check for non-Microsoft metadata in expected MS files
    fname = Path(win_relpath).name.lower()
    if fname in _EXPECT_MS_METADATA:
        company = vi.get("CompanyName", "")
        if company and "microsoft" not in company.lower():
            anomalies.append("SUSPICIOUS_METADATA")
        # File description mismatch: e.g. svchost.exe described as something else
        if vi.get("InternalName"):
            expected_base = fname.rsplit(".", 1)[0]
            internal = vi["InternalName"].lower().rsplit(".", 1)[0]
            if internal and internal != expected_base and len(internal) > 2:
                anomalies.append("INTERNAL_NAME_MISMATCH")

    # Driver in wrong location
    if category == "driver":
        path_lower = win_relpath.lower()
        in_safe = any(d in path_lower for d in ("system32/drivers", "windows/system32/drivers"))
        if not in_safe:
            anomalies.append("DRIVER_OUTSIDE_EXPECTED_PATH")

    return anomalies


# ---------------------------------------------------------------------------
# Module borrowing: REGF hive parser from m07, evtx from m23
# ---------------------------------------------------------------------------

_m07_cache: Optional[Any] = None

def _borrow_m07():
    """Return m07 module object (for REGF parsing).  Cached; None on failure."""
    global _m07_cache
    if _m07_cache is not None:
        return _m07_cache
    try:
        m07_path = Path(__file__).parent / "m07_service_analysis.py"
        if not m07_path.exists():
            return None
        spec = importlib.util.spec_from_file_location("_m07_for_m31", m07_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _m07_cache = mod
        return mod
    except Exception:
        return None


def _ensure_evtx() -> bool:
    """Load python-evtx from m23's bundled wheel if not already importable."""
    try:
        import Evtx.Evtx  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        m23_path = Path(__file__).parent / "m23_logon_audit.py"
        if not m23_path.exists():
            return False
        spec = importlib.util.spec_from_file_location("_m23_loader_m31", m23_path)
        m23  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m23)
        return m23._ensure_evtx()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 1. Protected-file scan
# ---------------------------------------------------------------------------

def _scan_protected_files(win_root: Path) -> dict:
    """Check each protected file for existence and anomalies.

    Returns:
        checked: int
        missing: list[{path, category}]
        anomalous: list[{path, category, anomalies, evidence}]
        clean: int
        driver_binaries: set[str]  — resolved binary paths found to exist
    """
    missing: List[dict]   = []
    anomalous: List[dict] = []
    clean                 = 0
    driver_binaries: Set[str] = set()

    for fdef in _PROTECTED_FILES:
        relpath = fdef["path"]
        cat     = fdef["cat"]
        local   = win_root / relpath.replace("/", __import__("os").sep)
        ev      = _collect_file_evidence(local)

        if not ev["exists"]:
            if not fdef["optional"]:
                missing.append({"path": relpath, "category": cat})
        else:
            if cat == "driver" and ev["exists"]:
                driver_binaries.add(local.as_posix())
            anomalies = _check_file_anomalies(ev, relpath, cat)
            if anomalies:
                anomalous.append({
                    "path":      relpath,
                    "category":  cat,
                    "anomalies": anomalies,
                    "sha256":    ev.get("sha256"),
                    "size_bytes": ev.get("size_bytes"),
                    "modified":  ev.get("modified"),
                    "version_info": ev.get("version_info") or {},
                })
            else:
                clean += 1

    return {
        "checked":         len(_PROTECTED_FILES),
        "missing":         missing,
        "anomalous":       anomalous,
        "clean":           clean,
        "driver_binaries": driver_binaries,
        "flags":           _pf_flags(missing, anomalous),
    }


def _pf_flags(missing: list, anomalous: list) -> List[str]:
    flags: List[str] = []
    required_missing = [m for m in missing]
    if len(required_missing) >= 5:
        flags.append("MANY_PROTECTED_FILES_MISSING")
    elif len(required_missing) >= 1:
        flags.append("PROTECTED_FILES_MISSING")
    for a in anomalous:
        if "SUSPICIOUS_METADATA" in a["anomalies"]:
            flags.append("SUSPICIOUS_METADATA_IN_SYSTEM_DIR")
            break
    for a in anomalous:
        if "ZERO_BYTE" in a["anomalies"]:
            flags.append("ZERO_BYTE_SYSTEM_FILE")
            break
    for a in anomalous:
        if "TIMESTAMP_FUTURE" in a["anomalies"]:
            flags.append("FUTURE_TIMESTAMP")
            break
    return flags


# ---------------------------------------------------------------------------
# 2. WinSxS correlation
# ---------------------------------------------------------------------------

def _check_winsxs(win_root: Path) -> dict:
    """Compare System32 critical files against WinSxS component store."""
    winsxs = win_root / "WinSxS"
    result = {
        "winsxs_exists":         False,
        "component_count":       0,
        "manifest_count":        0,
        "files_with_match":      0,
        "files_without_match":   0,
        "size_mismatches":       [],
        "flags":                 [],
        "notes":                 [],
    }

    if not winsxs.is_dir():
        result["flags"].append("WINSXS_MISSING")
        result["notes"].append("WinSxS directory not found — component store absent or not mounted")
        return result

    result["winsxs_exists"] = True

    # Count component directories (first-level, excluding Manifests/Catalogs/Backup)
    skip_dirs = {"manifests", "catalogs", "backup", "filemaps", "installtemp",
                 "logs", "temp"}
    component_count = 0
    # Build a filename-to-list-of-winsxs-paths index for spot-check files
    target_names = {
        "ntoskrnl.exe", "ntdll.dll", "kernel32.dll", "user32.dll",
        "lsass.exe", "services.exe", "winlogon.exe", "ntfs.sys", "tcpip.sys",
    }
    winsxs_index: Dict[str, List[Path]] = {n: [] for n in target_names}

    try:
        with __import__("os").scandir(str(winsxs)) as it:
            for entry in it:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                if entry.name.lower() in skip_dirs:
                    continue
                component_count += 1
                # Look for target files inside this component dir
                for tname in target_names:
                    candidate = Path(entry.path) / tname
                    if candidate.exists():
                        winsxs_index[tname].append(candidate)
    except Exception as exc:
        result["notes"].append(f"WinSxS scan error: {exc}")

    result["component_count"] = component_count

    # Count manifests
    manifests_dir = winsxs / "Manifests"
    if manifests_dir.is_dir():
        try:
            result["manifest_count"] = sum(
                1 for _ in manifests_dir.glob("*.manifest")
            )
        except Exception:
            pass

    # Spot-check: compare System32 copy vs WinSxS copy (size)
    sys32 = win_root / "System32"
    for fname, winsxs_copies in winsxs_index.items():
        sys32_file = sys32 / fname
        if not sys32_file.exists():
            continue
        if winsxs_copies:
            result["files_with_match"] += 1
            # Check size consistency
            try:
                sys32_size = sys32_file.stat().st_size
                for wc in winsxs_copies:
                    wc_size = wc.stat().st_size
                    # Allow small size difference (resources stripped etc.)
                    if wc_size > 0 and abs(sys32_size - wc_size) / max(sys32_size, 1) > 0.05:
                        result["size_mismatches"].append({
                            "file":           fname,
                            "system32_bytes": sys32_size,
                            "winsxs_bytes":   wc_size,
                            "winsxs_path":    str(wc.relative_to(win_root)),
                        })
            except Exception:
                pass
        else:
            result["files_without_match"] += 1

    # Flag health signals
    if component_count < _WINSXS_MIN_COMPONENTS_VISTA:
        result["flags"].append("WINSXS_SUSPICIOUSLY_EMPTY")
    if result["manifest_count"] < _WINSXS_MIN_MANIFESTS_VISTA and result["manifest_count"] > 0:
        result["flags"].append("FEW_MANIFESTS")
    elif result["manifest_count"] == 0 and manifests_dir.is_dir():
        result["flags"].append("NO_MANIFESTS")
    if result["size_mismatches"]:
        result["flags"].append("WINSXS_SIZE_MISMATCH")

    return result


# ---------------------------------------------------------------------------
# 3. Manifests and catalogs
# ---------------------------------------------------------------------------

def _check_manifests_and_catalogs(win_root: Path) -> dict:
    """Check manifests, catroot, and servicing/Packages directories."""
    result: dict = {
        "manifests_dir_exists":       False,
        "manifest_count":             0,
        "catroot_exists":             False,
        "catroot_cat_count":          0,
        "catroot2_exists":            False,
        "servicing_packages_exists":  False,
        "servicing_package_count":    0,
        "flags":                      [],
    }

    # Manifests
    manifests = win_root / "WinSxS" / "Manifests"
    if manifests.is_dir():
        result["manifests_dir_exists"] = True
        try:
            result["manifest_count"] = sum(1 for _ in manifests.glob("*.manifest"))
        except Exception:
            pass

    # catroot / catroot2
    catroot = win_root / "System32" / "catroot"
    catroot2 = win_root / "System32" / "catroot2"
    if catroot.is_dir():
        result["catroot_exists"] = True
        try:
            result["catroot_cat_count"] = sum(1 for _ in catroot.rglob("*.cat"))
        except Exception:
            pass
    result["catroot2_exists"] = catroot2.is_dir()

    # servicing/Packages
    svc_pkg = win_root / "servicing" / "Packages"
    if svc_pkg.is_dir():
        result["servicing_packages_exists"] = True
        try:
            result["servicing_package_count"] = sum(
                1 for _ in svc_pkg.iterdir() if _.suffix.lower() in (".mum", ".cat", "")
            )
        except Exception:
            pass

    # Flags
    if not result["manifests_dir_exists"]:
        result["flags"].append("MANIFESTS_DIR_MISSING")
    if not result["catroot_exists"]:
        result["flags"].append("CATROOT_MISSING")
    elif result["catroot_cat_count"] < _CATROOT_MIN_CATS:
        result["flags"].append("CATROOT_SUSPICIOUSLY_EMPTY")
    if result["servicing_packages_exists"] and result["servicing_package_count"] == 0:
        result["flags"].append("SERVICING_PACKAGES_EMPTY")

    return result


# ---------------------------------------------------------------------------
# 4. CBS / servicing logs
# ---------------------------------------------------------------------------

_CBS_CORRUPTION_PATTERNS = [
    re.compile(r"cannot repair member file",           re.IGNORECASE),
    re.compile(r"file is missing",                     re.IGNORECASE),
    re.compile(r"component store.*corrupt",            re.IGNORECASE),
    re.compile(r"checksum.*mismatch",                  re.IGNORECASE),
    re.compile(r"hash.*mismatch",                      re.IGNORECASE),
    re.compile(r"could not repair",                    re.IGNORECASE),
    re.compile(r"CORRUPTION",                          re.IGNORECASE),
]
_CBS_REPAIR_PATTERNS = [
    re.compile(r"repairing.*file",                     re.IGNORECASE),
    re.compile(r"sfc.*scannow",                        re.IGNORECASE),
    re.compile(r"Windows Resource Protection.*repaired",re.IGNORECASE),
    re.compile(r"repair.*successful",                  re.IGNORECASE),
]
_CBS_ERROR_RE = re.compile(r"\b(Error|ERROR|FAILED|Failed)\b")
_CBS_FAILED_REPAIR_RE = re.compile(
    r"(cannot repair|repair.*failed|could not repair)",
    re.IGNORECASE,
)


def _parse_cbs_log(text: str) -> dict:
    """Scan CBS.log text for corruption/repair indicators."""
    corruption_indicators: List[str] = []
    repair_attempts       = 0
    failed_repairs        = 0
    error_count           = 0
    seen: Set[str]        = set()

    for line in text.splitlines():
        # Error count
        if _CBS_ERROR_RE.search(line):
            error_count += 1

        # Corruption patterns
        for pat in _CBS_CORRUPTION_PATTERNS:
            if pat.search(line):
                key = pat.pattern
                if key not in seen:
                    seen.add(key)
                    corruption_indicators.append(line.strip()[:200])
                break

        # Repair attempts
        for pat in _CBS_REPAIR_PATTERNS:
            if pat.search(line):
                repair_attempts += 1
                break

        # Failed repairs
        if _CBS_FAILED_REPAIR_RE.search(line):
            failed_repairs += 1

    return {
        "corruption_indicators": corruption_indicators[:20],
        "repair_attempts":       repair_attempts,
        "failed_repairs":        failed_repairs,
        "error_count":           min(error_count, 9999),
    }


def _check_servicing(win_root: Path) -> dict:
    """Read CBS.log and DISM logs for repair/corruption history."""
    result: dict = {
        "cbs_log_found":          False,
        "cbs_log_path":           None,
        "cbs_log_scanned_bytes":  0,
        "corruption_indicators":  [],
        "repair_attempts":        0,
        "failed_repairs":         0,
        "error_count":            0,
        "dism_log_found":         False,
        "dism_errors":            [],
        "flags":                  [],
    }

    # CBS.log
    cbs_path = win_root / "Logs" / "CBS" / "CBS.log"
    if cbs_path.exists():
        result["cbs_log_found"] = True
        result["cbs_log_path"]  = str(cbs_path.relative_to(win_root.parent))
        try:
            size = cbs_path.stat().st_size
            if size > _CBS_MAX_BYTES:
                # Read last N bytes only
                with cbs_path.open("rb") as fh:
                    fh.seek(-_CBS_MAX_BYTES, 2)
                    text = fh.read().decode("utf-8", errors="replace")
            else:
                text = cbs_path.read_text(encoding="utf-8", errors="replace")
            result["cbs_log_scanned_bytes"] = min(size, _CBS_MAX_BYTES)
            parsed = _parse_cbs_log(text)
            result.update(parsed)
        except Exception as exc:
            result["flags"].append(f"CBS_READ_ERROR: {exc}")

    # DISM log
    dism_path = win_root / "Logs" / "DISM" / "dism.log"
    if dism_path.exists():
        result["dism_log_found"] = True
        try:
            text = dism_path.read_text(encoding="utf-8", errors="replace")
            errors = [l.strip()[:200] for l in text.splitlines()
                      if "Error" in l or "ERROR" in l]
            result["dism_errors"] = errors[:10]
        except Exception:
            pass

    # Set flags
    if result["corruption_indicators"]:
        result["flags"].append("CBS_CORRUPTION_INDICATOR")
    if result["failed_repairs"] > 0:
        result["flags"].append("CBS_FAILED_REPAIRS")
    if result["repair_attempts"] > 0 and result["failed_repairs"] == 0:
        result["flags"].append("CBS_REPAIRS_SUCCEEDED")

    return result


# ---------------------------------------------------------------------------
# 5. Pending operations
# ---------------------------------------------------------------------------

def _check_pending_xml(win_root: Path) -> dict:
    """Parse pending.xml for pending servicing operations."""
    result: dict = {
        "found": False, "path": None,
        "pending_operations": 0, "pending_renames": 0,
        "pending_moves": 0, "parse_error": None,
    }

    candidates = [
        win_root / "WinSxS" / "pending.xml",
        win_root / "servicing" / "pending.xml",
    ]
    for cand in candidates:
        if cand.exists():
            result["found"] = True
            result["path"]  = str(cand.relative_to(win_root.parent))
            try:
                tree = ET.parse(str(cand))
                root = tree.getroot()
                # Count operations (HardLink, MoveFile, CreateFile, etc.)
                for elem in root.iter():
                    tag = elem.tag.lower().split("}")[-1] if "}" in elem.tag else elem.tag.lower()
                    if tag in ("hardlink", "movefile", "createfile", "delete", "mkdir"):
                        result["pending_operations"] += 1
                    if tag in ("movefile",):
                        result["pending_moves"] += 1
                    if tag in ("hardlink",):
                        result["pending_renames"] += 1
            except ET.ParseError as exc:
                result["parse_error"] = str(exc)
            break

    return result


def _check_pfro(win_root: Path, hive_fns) -> Optional[int]:
    """Check PendingFileRenameOperations from SYSTEM hive.  Returns count or None."""
    if hive_fns is None:
        return None
    try:
        _RegHive, _open_hive, _values_dict, _get_ccs_context = hive_fns
        hive_path = win_root / "System32" / "config" / "SYSTEM"
        if not hive_path.exists():
            return None
        hive = _open_hive(hive_path)
        if hive is None:
            return None
        ccs_ctx = _get_ccs_context(hive)
        ccs     = ccs_ctx.get("active", "ControlSet001")
        key_off = hive.get_key_offset(
            rf"{ccs}\Control\Session Manager"
        )
        if key_off is None:
            return None
        vals = _values_dict(hive, key_off)
        pfro = vals.get("PendingFileRenameOperations")
        if pfro is None:
            return 0
        if isinstance(pfro, list):
            return len(pfro)
        return 1
    except Exception:
        return None


def _check_pending(win_root: Path, hive_fns) -> dict:
    """Aggregate pending operation checks."""
    xml_result = _check_pending_xml(win_root)
    pfro_count = _check_pfro(win_root, hive_fns)

    flags: List[str] = []
    if xml_result["found"] and xml_result["pending_operations"] > 0:
        flags.append("PENDING_OPERATIONS")
    if pfro_count and pfro_count > 0:
        flags.append("PENDING_FILE_RENAMES")
    if xml_result.get("parse_error"):
        flags.append("PENDING_XML_CORRUPT")

    return {
        "pending_xml":             xml_result,
        "pfro_registry_entries":   pfro_count,
        "flags":                   flags,
    }


# ---------------------------------------------------------------------------
# 6. Boot integrity
# ---------------------------------------------------------------------------

def _check_boot(target: Path, win_root: Path) -> dict:
    """Check boot files and mode."""
    result: dict = {
        "boot_mode":            "unknown",
        "efi_found":            False,
        "bootmgr":              None,
        "ntldr":                None,
        "winload_exe":          None,
        "bcd_store":            None,
        "boot_dir_exists":      False,
        "unusual_boot_files":   [],
        "flags":                [],
    }

    # UEFI detection: look for /EFI or /efi directory at target root or a few levels up
    # On RescueZilla, EFI partition may be separately mounted; we can only check at target
    efi_candidates = [
        target / "EFI",
        target / "efi",
        target.parent / "EFI",
        target.parent / "efi",
    ]
    for efi in efi_candidates:
        if efi.is_dir():
            result["efi_found"] = True
            result["boot_mode"] = "uefi"
            break

    # bootmgr (Vista+ BIOS) — at root of system partition
    for bootmgr_cand in [target / "bootmgr", target / "BOOTMGR"]:
        if bootmgr_cand.exists():
            st = bootmgr_cand.stat()
            result["bootmgr"] = {"exists": True, "size_bytes": st.st_size,
                                 "modified": datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"}
            if result["boot_mode"] == "unknown":
                result["boot_mode"] = "bios"
            break
    if result["bootmgr"] is None:
        result["bootmgr"] = {"exists": False}

    # NTLDR (XP/2003)
    ntldr = target / "ntldr"
    result["ntldr"] = {"exists": ntldr.exists()}
    if ntldr.exists() and result["boot_mode"] == "unknown":
        result["boot_mode"] = "bios_legacy"

    # winload.exe (Vista+)
    winload = win_root / "System32" / "winload.exe"
    if winload.exists():
        st = winload.stat()
        result["winload_exe"] = {"exists": True, "size_bytes": st.st_size}
    else:
        result["winload_exe"] = {"exists": False}

    # BCD store
    bcd_candidates = [
        target / "Boot" / "BCD",
        target / "EFI" / "Microsoft" / "Boot" / "BCD",
    ]
    for bcd in bcd_candidates:
        if bcd.exists():
            st = bcd.stat()
            result["bcd_store"] = {
                "exists": True,
                "path":   str(bcd.relative_to(target)),
                "size_bytes": st.st_size,
            }
            break
    if result["bcd_store"] is None:
        result["bcd_store"] = {"exists": False}

    result["boot_dir_exists"] = (target / "Boot").is_dir()

    # Flag issues
    if result["boot_mode"] in ("bios", "uefi"):
        if not result["bootmgr"]["exists"] and not result["efi_found"]:
            result["flags"].append("BOOTMGR_MISSING")
        if not result["bcd_store"]["exists"]:
            result["flags"].append("BCD_STORE_MISSING")
        if not result["winload_exe"]["exists"]:
            result["flags"].append("WINLOAD_MISSING")
    elif result["boot_mode"] == "unknown":
        result["flags"].append("BOOT_MODE_UNKNOWN")

    return result


# ---------------------------------------------------------------------------
# 7. Driver integrity
# ---------------------------------------------------------------------------

def _check_driver_integrity(win_root: Path, hive_fns) -> dict:
    """Cross-check registered boot/system drivers against filesystem."""
    result: dict = {
        "hive_available":        False,
        "total_drivers":         0,
        "checked_drivers":       0,
        "missing_driver_files":  [],
        "suspicious_paths":      [],
        "flags":                 [],
    }

    if hive_fns is None:
        result["flags"].append("HIVE_READER_UNAVAILABLE")
        return result

    _RegHive, _open_hive, _values_dict, _get_ccs_context = hive_fns
    hive_path = win_root / "System32" / "config" / "SYSTEM"
    if not hive_path.exists():
        result["flags"].append("SYSTEM_HIVE_MISSING")
        return result

    hive = _open_hive(hive_path)
    if hive is None:
        result["flags"].append("SYSTEM_HIVE_UNREADABLE")
        return result

    result["hive_available"] = True

    try:
        ccs_ctx = _get_ccs_context(hive)
        ccs     = ccs_ctx.get("active", "ControlSet001")
        svc_off = hive.get_key_offset(f"{ccs}\\Services")
        if svc_off is None:
            result["flags"].append("SERVICES_KEY_MISSING")
            return result

        _DRIVER_TYPE_BITS = {0x01, 0x02, 0x04, 0x08}
        _EARLY_START_VALS = {0, 1}  # BOOT, SYSTEM

        for svc_name in hive.list_subkey_names(svc_off):
            sub_off = hive.get_subkey_offset(svc_off, svc_name)
            if sub_off is None:
                continue
            try:
                vals      = _values_dict(hive, sub_off)
                svc_type  = vals.get("Type")
                start_val = vals.get("Start")
                img_path  = vals.get("ImagePath") or ""

                # Filter to drivers only
                if svc_type is None or (svc_type & 0x0F) not in _DRIVER_TYPE_BITS:
                    continue

                result["total_drivers"] += 1

                if not img_path:
                    continue

                result["checked_drivers"] += 1

                # Expand env vars and convert to local path
                img_lower = img_path.lower()
                # system32\drivers\ relative path
                m = re.match(r"^\\systemroot\\(.+)$", img_path, re.IGNORECASE)
                if m:
                    local = win_root / m.group(1).replace("\\", "/")
                else:
                    m2 = re.match(r"^[A-Za-z]:\\(.+)$", img_path)
                    if m2:
                        local = win_root.parent / m2.group(1).replace("\\", "/")
                    elif img_path.startswith("\\"):
                        local = win_root.parent / img_path.lstrip("\\").replace("\\", "/")
                    else:
                        # Relative — assume system32\drivers
                        local = win_root / "System32" / "drivers" / Path(img_path).name

                if not local.exists():
                    result["missing_driver_files"].append({
                        "name":       svc_name,
                        "image_path": img_path,
                        "start":      {0: "BOOT", 1: "SYSTEM", 2: "AUTO",
                                       3: "DEMAND", 4: "DISABLED"}.get(start_val, str(start_val)),
                        "type":       hex(svc_type),
                    })
                else:
                    # Check for suspicious driver locations
                    path_lower = img_path.lower()
                    safe = any(s in path_lower for s in (
                        "system32", "syswow64", "%systemroot%", "%windir%",
                    ))
                    if not safe and start_val in _EARLY_START_VALS:
                        result["suspicious_paths"].append({
                            "name":       svc_name,
                            "image_path": img_path,
                            "start":      start_val,
                        })
            except Exception:
                continue
    except Exception as exc:
        result["flags"].append(f"DRIVER_SCAN_ERROR: {exc}")
        return result

    if result["missing_driver_files"]:
        result["flags"].append("MISSING_DRIVER_FILES")
    if result["suspicious_paths"]:
        result["flags"].append("SUSPICIOUS_DRIVER_PATHS")

    return result


# ---------------------------------------------------------------------------
# 8. Event log correlation
# ---------------------------------------------------------------------------

def _correlate_events(win_root: Path) -> dict:
    """Parse System.evtx and Application.evtx for disk/driver/SFC events."""
    result: dict = {
        "evtx_available":    False,
        "disk_io_errors":    0,
        "controller_resets": 0,
        "driver_failures":   0,
        "chkdsk_events":     0,
        "sfc_repair_events": 0,
        "flags":             [],
    }

    logs_path = win_root / "System32" / "winevt" / "Logs"
    if not logs_path.is_dir():
        result["flags"].append("EVTX_LOGS_DIR_MISSING")
        return result

    if not _ensure_evtx():
        result["flags"].append("EVTX_LIBRARY_UNAVAILABLE")
        return result

    result["evtx_available"] = True

    def _parse_log(evtx_path: Path, target_ids: Set[int]) -> Dict[int, int]:
        counts: Dict[int, int] = {}
        if not evtx_path.exists():
            return counts
        try:
            import Evtx.Evtx as evtx
            with evtx.Evtx(str(evtx_path)) as log:
                for record in log.records():
                    try:
                        root = ET.fromstring(record.xml())
                        ns   = _EVTX_NS
                        sys_el = root.find(f"{{{ns}}}System")
                        if sys_el is None:
                            continue
                        eid_el = sys_el.find(f"{{{ns}}}EventID")
                        if eid_el is None:
                            continue
                        eid = int(eid_el.text or 0)
                        if eid in target_ids:
                            counts[eid] = counts.get(eid, 0) + 1
                    except Exception:
                        continue
        except Exception:
            pass
        return counts

    # System.evtx: disk errors + controller resets + driver failures
    sys_evtx = logs_path / "System.evtx"
    all_sys_ids = _DISK_IO_ERROR_IDS | _CONTROLLER_RESET_IDS | _DRIVER_FAIL_IDS
    sys_counts = _parse_log(sys_evtx, all_sys_ids)
    result["disk_io_errors"]    = sum(sys_counts.get(i, 0) for i in _DISK_IO_ERROR_IDS)
    result["controller_resets"] = sum(sys_counts.get(i, 0) for i in _CONTROLLER_RESET_IDS)
    result["driver_failures"]   = sum(sys_counts.get(i, 0) for i in _DRIVER_FAIL_IDS)

    # Application.evtx: CHKDSK events
    app_evtx = logs_path / "Application.evtx"
    app_counts = _parse_log(app_evtx, _CHKDSK_EVENT_IDS | _SFC_REPAIR_IDS)
    result["chkdsk_events"]     = sum(app_counts.get(i, 0) for i in _CHKDSK_EVENT_IDS)
    result["sfc_repair_events"] = sum(app_counts.get(i, 0) for i in _SFC_REPAIR_IDS)

    if result["disk_io_errors"] > 5:
        result["flags"].append("DISK_IO_ERRORS")
    elif result["disk_io_errors"] > 0:
        result["flags"].append("SOME_DISK_IO_ERRORS")
    if result["controller_resets"] > 0:
        result["flags"].append("CONTROLLER_RESETS")
    if result["driver_failures"] > 0:
        result["flags"].append("DRIVER_LOAD_FAILURES")
    if result["chkdsk_events"] > 0:
        result["flags"].append("CHKDSK_WAS_RUN")

    return result


# ---------------------------------------------------------------------------
# 9. Cross-module log correlation
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


def _correlate_other_modules(logs_dir: Path) -> dict:
    """Read sibling module logs and extract relevant signals."""
    result: dict = {
        "disk_health_log":     None,
        "disk_health_verdict": None,
        "disk_integrity_log":  None,
        "disk_errors_found":   False,
        "service_analysis_log": None,
        "service_suspicious":  0,
        "persistence_log":     None,
        "persistence_suspicious": 0,
        "device_manager_log":  None,
        "device_problem_count": 0,
        "combined_signals":    [],
        "flags":               [],
    }

    # m05 disk health
    dh_path = _latest_log(logs_dir, "disk_health_*.json")
    if dh_path:
        result["disk_health_log"] = dh_path.name
        dh = _read_json_log(dh_path)
        if dh:
            drives = dh if isinstance(dh, list) else dh.get("drives", dh.get("disks", []))
            worst = "CLEAN"
            for d in (drives if isinstance(drives, list) else []):
                v = str(d.get("verdict") or d.get("health") or "")
                if "FAIL" in v.upper():
                    worst = "FAILING"
                elif "CAUTION" in v.upper() or "WARN" in v.upper():
                    if worst != "FAILING":
                        worst = "CAUTION"
            result["disk_health_verdict"] = worst

    # m30 disk integrity
    di_path = _latest_log(logs_dir, "disk_integrity_*.json")
    if di_path:
        result["disk_integrity_log"] = di_path.name
        di = _read_json_log(di_path)
        if di:
            events = di.get("io_error_events", {})
            disk_err_count = (
                events.get("disk_errors", 0)
                if isinstance(events, dict)
                else 0
            )
            if disk_err_count > 0 or di.get("dirty_bit", {}).get("dirty"):
                result["disk_errors_found"] = True

    # m07 service analysis
    sa_path = _latest_log(logs_dir, "service_analysis_*.json")
    if sa_path:
        result["service_analysis_log"] = sa_path.name
        sa = _read_json_log(sa_path)
        if sa:
            result["service_suspicious"] = sa.get("summary", {}).get("suspicious_count", 0)

    # m01 persistence scan
    ps_path = _latest_log(logs_dir, "persist_*.jsonl")
    if ps_path:
        result["persistence_log"] = ps_path.name
        try:
            lines = ps_path.read_text(encoding="utf-8", errors="replace").splitlines()
            suspicious = sum(
                1 for l in lines if l.strip()
                and json.loads(l).get("severity") in ("HIGH", "MEDIUM")
            )
            result["persistence_suspicious"] = suspicious
        except Exception:
            pass

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

    # Build combined signals
    dh_v = result.get("disk_health_verdict") or ""
    if result["disk_errors_found"] and result["disk_health_verdict"] in ("CAUTION", "FAILING"):
        result["combined_signals"].append(
            "DISK_HEALTH_" + result["disk_health_verdict"] +
            " + disk I/O errors → probable disk-related corruption"
        )
        result["flags"].append("DISK_RELATED_CORRUPTION_SUSPECTED")
    elif result["disk_errors_found"]:
        result["combined_signals"].append(
            "Disk I/O errors found in event log → possible disk-related corruption"
        )

    if result["persistence_suspicious"] > 0 and result["service_suspicious"] > 0:
        result["combined_signals"].append(
            f"Persistence suspicious={result['persistence_suspicious']} "
            f"+ service suspicious={result['service_suspicious']} → possible tampering"
        )
        result["flags"].append("CROSS_MODULE_TAMPERING_SIGNAL")

    return result


# ---------------------------------------------------------------------------
# 10. Verdict engine
# ---------------------------------------------------------------------------

def _collect_all_flags(sections: dict) -> Set[str]:
    flags: Set[str] = set()
    for section_data in sections.values():
        if isinstance(section_data, dict):
            for f in section_data.get("flags", []):
                flags.add(str(f))
    return flags


def _compute_verdict(sections: dict) -> Tuple[str, str, List[str], List[str]]:
    """Return (verdict, confidence, limitations, recommendations)."""
    flags = _collect_all_flags(sections)

    pf    = sections.get("protected_files", {})
    svc   = sections.get("servicing", {})
    evts  = sections.get("events", {})
    cross = sections.get("cross_module", {})
    boot  = sections.get("boot", {})
    drv   = sections.get("driver_integrity", {})

    missing_count  = len(pf.get("missing", []))
    anomalous_count = len(pf.get("anomalous", []))
    cbs_corrupt    = bool(svc.get("corruption_indicators"))
    disk_io_errs   = evts.get("disk_io_errors", 0)
    missing_drivers = len(drv.get("missing_driver_files", []))

    # Tampering signals
    tampering = (
        "SUSPICIOUS_METADATA_IN_SYSTEM_DIR" in flags
        or (anomalous_count >= 2 and "CROSS_MODULE_TAMPERING_SIGNAL" in flags)
        or ("SUSPICIOUS_METADATA_IN_SYSTEM_DIR" in flags and missing_count > 0)
    )

    # Disk-related signals
    disk_related = (
        "DISK_RELATED_CORRUPTION_SUSPECTED" in flags
        or (disk_io_errs > 5 and (missing_count > 3 or cbs_corrupt))
        or ("CONTROLLER_RESETS" in flags and cbs_corrupt)
    )

    # General corruption signals
    corruption = (
        missing_count >= 5
        or (missing_count >= 2 and cbs_corrupt)
        or (cbs_corrupt and "CBS_FAILED_REPAIRS" in flags)
        or "MANY_PROTECTED_FILES_MISSING" in flags
        or "WINSXS_SIZE_MISMATCH" in flags
        or missing_drivers >= 3
    )

    minor = (
        missing_count >= 1
        or cbs_corrupt
        or missing_drivers >= 1
        or "CATROOT_MISSING" in flags
        or "CBS_FAILED_REPAIRS" in flags
        or "PENDING_OPERATIONS" in flags
        or anomalous_count >= 1
    )

    # Check if we had limited data
    limited = (
        not pf.get("checked")
        and "HIVE_READER_UNAVAILABLE" in flags
        and not svc.get("cbs_log_found")
    )

    if limited:
        verdict    = "INCOMPLETE"
        confidence = "unknown"
    elif tampering:
        verdict    = "TAMPERING_SUSPECTED"
        confidence = "medium"
    elif disk_related:
        verdict    = "DISK_RELATED_CORRUPTION_SUSPECTED"
        confidence = "medium"
    elif corruption:
        verdict    = "CORRUPTION_SUSPECTED"
        confidence = "medium"
    elif minor:
        verdict    = "MINOR_ISSUES"
        confidence = "medium"
    else:
        verdict    = "CLEAN"
        confidence = "medium"

    # Lower confidence if evtx unavailable or hive unreadable
    if ("EVTX_LIBRARY_UNAVAILABLE" in flags or
            "HIVE_READER_UNAVAILABLE" in flags) and verdict != "CLEAN":
        confidence = "low"
    elif missing_count == 0 and not cbs_corrupt and disk_io_errs == 0:
        confidence = "medium"

    # Limitations
    limitations = [
        "Authenticode signature validation not performed (requires Windows tooling)",
        "WinSxS correlation uses filename/size comparison only",
        "SFC /scannow equivalent cannot run without booting the target OS",
    ]
    if "EVTX_LIBRARY_UNAVAILABLE" in flags:
        limitations.append("python-evtx not available — event log checks skipped")
    if "HIVE_READER_UNAVAILABLE" in flags:
        limitations.append("SYSTEM hive reader unavailable — driver integrity checks skipped")
    if "EVTX_LOGS_DIR_MISSING" in flags:
        limitations.append("Windows event logs directory not found at expected path")

    # Recommendations
    recs: List[str] = []
    if missing_count > 0:
        recs.append(
            f"Run SFC /scannow when Windows is bootable — "
            f"{missing_count} protected system file(s) missing"
        )
    if disk_io_errs > 0 or "CONTROLLER_RESETS" in flags:
        recs.append(
            "Run CHKDSK C: /F /R — disk I/O errors detected in event logs"
        )
    dh_v = cross.get("disk_health_verdict") or ""
    if dh_v in ("CAUTION", "FAILING"):
        recs.append(
            f"Clone disk before any repairs — disk health verdict is {dh_v}"
        )
    if cbs_corrupt:
        recs.append(
            "Review CBS.log for details; run DISM /Online /Cleanup-Image /RestoreHealth "
            "when Windows is bootable"
        )
    if anomalous_count > 0:
        for a in pf.get("anomalous", []):
            if "SUSPICIOUS_METADATA" in a["anomalies"]:
                recs.append(
                    f"Investigate {a['path']} — company metadata "
                    f"'{a.get('version_info', {}).get('CompanyName', '')}' "
                    f"does not match Microsoft Corporation"
                )
    if missing_drivers > 0:
        recs.append(
            f"{missing_drivers} registered driver file(s) missing — "
            "investigate affected devices and reinstall drivers when Windows is bootable"
        )
    if "PENDING_OPERATIONS" in flags:
        recs.append(
            "Pending repair operations exist — boot Windows to complete pending servicing"
        )
    if verdict == "TAMPERING_SUSPECTED":
        recs.append(
            "Consider full re-installation — tampering indicators found in system directories"
        )
    if not recs:
        recs.append("No immediate action required — monitor system performance")

    return verdict, confidence, limitations, recs


# ---------------------------------------------------------------------------
# Windows version hint
# ---------------------------------------------------------------------------

def _detect_os_version(win_root: Path) -> str:
    """Best-effort OS version detection from ntoskrnl.exe version strings."""
    krnl = win_root / "System32" / "ntoskrnl.exe"
    if not krnl.exists():
        krnl = win_root / "System32" / "ntkrnlpa.exe"
    if not krnl.exists():
        return "Unknown"
    try:
        data = krnl.read_bytes()
        if data[:2] != b"MZ":
            return "Unknown"
        vi = _parse_pe_version_strings(data[:_PE_MAX_SCAN])
        pv = vi.get("ProductVersion") or vi.get("FileVersion") or ""
        if pv.startswith("6.0"):
            return "Windows Vista"
        if pv.startswith("6.1"):
            return "Windows 7"
        if pv.startswith("6.2"):
            return "Windows 8"
        if pv.startswith("6.3"):
            return "Windows 8.1"
        if pv.startswith("10."):
            return "Windows 10/11"
        if pv.startswith("5.1") or pv.startswith("5.2"):
            return "Windows XP/2003"
        return f"Windows ({pv})"
    except Exception:
        return "Unknown"


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

_W = 70


def _print_report(result: dict) -> None:
    verdict    = result["verdict"]
    confidence = result["confidence"]
    print("\n" + "=" * _W)
    print(f"  SYSTEM INTEGRITY AUDIT — {verdict}")
    print(f"  Confidence: {confidence}")
    print("=" * _W)
    print(f"  Target  : {result['target']}")
    print(f"  OS hint : {result.get('windows_version_hint', 'Unknown')}")
    print(f"  Generated: {result['generated']}")
    print()

    # Protected files
    pf = result.get("protected_files_scan", {})
    print(f"  Protected files checked : {pf.get('checked', 0)}")
    print(f"  Missing                 : {len(pf.get('missing', []))}")
    print(f"  Anomalous               : {len(pf.get('anomalous', []))}")
    if pf.get("missing"):
        print(f"\n  {'─'*8} MISSING PROTECTED FILES {'─'*36}")
        for m in pf["missing"][:15]:
            print(f"    MISSING  [{m['category']:<8}]  {m['path']}")
        if len(pf["missing"]) > 15:
            print(f"    ... and {len(pf['missing']) - 15} more")
    if pf.get("anomalous"):
        print(f"\n  {'─'*8} ANOMALOUS FILES {'─'*44}")
        for a in pf["anomalous"]:
            print(f"    [{a['category']:<8}]  {a['path']}")
            for anom in a["anomalies"]:
                extra = ""
                if anom == "SUSPICIOUS_METADATA":
                    extra = f"  CompanyName='{a.get('version_info', {}).get('CompanyName', '')}'"
                print(f"               ^ {anom}{extra}")

    # Servicing
    svc = result.get("servicing_findings", {})
    print(f"\n  CBS.log found           : {svc.get('cbs_log_found', False)}")
    if svc.get("cbs_log_found"):
        print(f"  CBS corruption lines    : {len(svc.get('corruption_indicators', []))}")
        print(f"  CBS repair attempts     : {svc.get('repair_attempts', 0)}")
        print(f"  CBS failed repairs      : {svc.get('failed_repairs', 0)}")
        for line in svc.get("corruption_indicators", [])[:3]:
            print(f"    ! {line[:70]}")

    # Driver integrity
    drv = result.get("driver_integrity_findings", {})
    if drv.get("hive_available"):
        print(f"\n  Registered drivers      : {drv.get('total_drivers', 0)}")
        print(f"  Missing driver files    : {len(drv.get('missing_driver_files', []))}")
        for d in drv.get("missing_driver_files", [])[:5]:
            print(f"    MISSING  {d['name']:<20}  {d['image_path'][:45]}  [{d.get('start','')}]")

    # Boot
    boot = result.get("boot_findings", {})
    print(f"\n  Boot mode               : {boot.get('boot_mode', 'unknown')}")
    print(f"  bootmgr                 : {'present' if (boot.get('bootmgr') or {}).get('exists') else 'absent'}")
    print(f"  BCD store               : {'present' if (boot.get('bcd_store') or {}).get('exists') else 'absent'}")

    # Event log correlation
    evts = result.get("event_log_correlations", {})
    if evts.get("evtx_available"):
        print(f"\n  Disk I/O errors (evtx)  : {evts.get('disk_io_errors', 0)}")
        print(f"  Controller resets       : {evts.get('controller_resets', 0)}")
        print(f"  Driver load failures    : {evts.get('driver_failures', 0)}")
        print(f"  CHKDSK events           : {evts.get('chkdsk_events', 0)}")

    # WinSxS
    winsxs = result.get("winsxs_findings", {})
    if winsxs.get("winsxs_exists"):
        print(f"\n  WinSxS components       : {winsxs.get('component_count', 0)}")
        print(f"  Manifests               : {winsxs.get('manifest_count', 0)}")
        if winsxs.get("size_mismatches"):
            print(f"  WinSxS size mismatches  : {len(winsxs['size_mismatches'])}")

    # Pending
    pend = result.get("pending_repair_findings", {})
    if pend.get("pending_xml", {}).get("found"):
        print(f"\n  Pending operations      : {pend['pending_xml'].get('pending_operations', 0)}")

    # Recommendations
    print(f"\n  {'─'*8} RECOMMENDATIONS {'─'*44}")
    for i, rec in enumerate(result.get("recommendations", []), 1):
        words = rec.split()
        line  = ""
        for w in words:
            if len(line) + len(w) > 60:
                print(f"  {i if not line else ' '}. {line}")
                line = w
                i = " "
            else:
                line = (line + " " + w).strip()
        if line:
            print(f"  {i}. {line}")

    # Limitations
    print(f"\n  {'─'*8} LIMITATIONS {'─'*48}")
    for lim in result.get("limitations", []):
        print(f"    - {lim}")

    print("=" * _W + "\n")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    """Bootstrap entry point.

    root : Path to USB root (for writing logs)
    argv : list of string args
    """
    parser = argparse.ArgumentParser(
        prog="m31_system_integrity_audit",
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--target", required=True,
        help="Path to the mounted offline Windows installation, e.g. /mnt/windows",
    )
    parser.add_argument("--no-events", action="store_true",
                        help="Skip event log correlation (faster, requires python-evtx)")
    parser.add_argument("--no-winsxs", action="store_true",
                        help="Skip WinSxS correlation (faster on slow USB mounts)")
    parser.add_argument("--summary", action="store_true",
                        help="Print verdict + recommendations only")
    args = parser.parse_args(argv)

    target   = Path(args.target)
    win_root = target / "Windows"

    if not win_root.is_dir():
        print(f"ERROR: Windows directory not found at {win_root}")
        return 1

    print(f"[m31] Target        : {target}")
    print(f"[m31] Windows root  : {win_root}")

    # Borrow REGF reader from m07
    m07 = _borrow_m07()
    hive_fns = None
    if m07 is not None:
        hive_fns = (
            m07._RegHive,
            m07._open_hive,
            m07._values_dict,
            m07._get_control_set_context,
        )
        print("[m31] REGF hive reader loaded from m07")
    else:
        print("[m31] WARNING: m07 not available — driver integrity checks limited")

    # OS version hint
    os_hint = _detect_os_version(win_root)
    print(f"[m31] OS hint       : {os_hint}")

    # Run all checks
    print("[m31] Scanning protected files ...")
    pf_result = _scan_protected_files(win_root)
    print(f"[m31]   {pf_result['checked']} files checked, "
          f"{len(pf_result['missing'])} missing, "
          f"{len(pf_result['anomalous'])} anomalous")

    winsxs_result: dict = {}
    if not args.no_winsxs:
        print("[m31] Checking WinSxS ...")
        winsxs_result = _check_winsxs(win_root)
        print(f"[m31]   {winsxs_result['component_count']} components, "
              f"{winsxs_result['manifest_count']} manifests")

    print("[m31] Checking manifests and catalogs ...")
    mc_result = _check_manifests_and_catalogs(win_root)

    print("[m31] Checking CBS/servicing logs ...")
    svc_result = _check_servicing(win_root)
    if svc_result["cbs_log_found"]:
        print(f"[m31]   CBS: {len(svc_result['corruption_indicators'])} corruption lines, "
              f"{svc_result['repair_attempts']} repairs, "
              f"{svc_result['failed_repairs']} failed")

    print("[m31] Checking pending operations ...")
    pend_result = _check_pending(win_root, hive_fns)

    print("[m31] Checking boot files ...")
    boot_result = _check_boot(target, win_root)
    print(f"[m31]   Boot mode: {boot_result['boot_mode']}")

    print("[m31] Checking driver integrity ...")
    drv_result = _check_driver_integrity(win_root, hive_fns)
    if drv_result["hive_available"]:
        print(f"[m31]   {drv_result['total_drivers']} drivers, "
              f"{len(drv_result['missing_driver_files'])} missing files")

    evts_result: dict = {}
    if not args.no_events:
        print("[m31] Correlating event logs ...")
        evts_result = _correlate_events(win_root)
        if evts_result.get("evtx_available"):
            print(f"[m31]   disk_io={evts_result['disk_io_errors']} "
                  f"ctrl_resets={evts_result['controller_resets']} "
                  f"drv_fail={evts_result['driver_failures']}")

    print("[m31] Correlating other module logs ...")
    logs_dir = root / "logs"
    cross_result = _correlate_other_modules(logs_dir)

    # Assemble sections for verdict computation
    sections = {
        "protected_files": pf_result,
        "winsxs":          winsxs_result,
        "manifests":       mc_result,
        "servicing":       svc_result,
        "pending":         pend_result,
        "boot":            boot_result,
        "driver_integrity": drv_result,
        "events":          evts_result,
        "cross_module":    cross_result,
    }

    verdict, confidence, limitations, recommendations = _compute_verdict(sections)
    print(f"[m31] Verdict: {verdict}  (confidence: {confidence})")

    result = {
        "generated":              datetime.now(timezone.utc).isoformat(),
        "target":                 str(target),
        "windows_version_hint":   os_hint,
        "scan_status":            "complete",
        "verdict":                verdict,
        "confidence":             confidence,
        "limitations":            limitations,
        "protected_files_checked": pf_result.get("checked", 0),
        "files_checked":          pf_result.get("checked", 0),
        "missing_files":          pf_result.get("missing", []),
        "anomalous_files":        pf_result.get("anomalous", []),
        "recommendations":        recommendations,
        "protected_files_scan":   pf_result,
        "winsxs_findings":        winsxs_result,
        "manifest_catalog_findings": mc_result,
        "servicing_findings":     svc_result,
        "pending_repair_findings": pend_result,
        "boot_findings":          boot_result,
        "driver_integrity_findings": drv_result,
        "event_log_correlations": evts_result,
        "cross_module_correlation": cross_result,
    }

    if not args.summary:
        _print_report(result)
    else:
        print(f"\nVerdict: {verdict} (confidence={confidence})")
        for rec in recommendations:
            print(f"  → {rec}")

    # Write JSON log
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"system_integrity_{ts}.json"
    log_path.write_text(json.dumps(result, indent=2, default=str))
    print(f"[m31] Log written → {log_path}")
    return 0
