"""
toolkit.py — Nielsoln Rescue Toolkit: all core logic.

Run from repo root:
    import runpy ; temp = runpy._run_module_as_main("toolkit")
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import csv
import hashlib
import html
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# env — Platform detection and path helpers
# ---------------------------------------------------------------------------

def get_platform() -> str:
    """Return a short platform tag, e.g. 'linux-x86_64'."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ("amd64", "x86_64"):
        machine = "x86_64"
    elif machine in ("aarch64", "arm64"):
        machine = "arm64"

    return f"{system}-{machine}"


def get_python_executable(root: Path) -> Path:
    """Return path to bundled Python for the current platform, if present."""
    tag = get_platform()
    return root / "runtimes" / tag / "python" / "bin" / "python3"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_macos() -> bool:
    return platform.system().lower() == "darwin"


def is_windows() -> bool:
    return platform.system().lower() == "windows"


# ---------------------------------------------------------------------------
# triage — Python-only suspicious file triage
# ---------------------------------------------------------------------------

_triage_log = logging.getLogger("triage")

SUSPICIOUS_EXTS = {
    ".exe", ".dll", ".sys", ".scr",
    ".bat", ".cmd", ".vbs", ".js", ".ps1",
    ".hta", ".wsf", ".pif",
}

SUSPICIOUS_PATH_HINTS = [
    "/appdata/roaming/",
    "/appdata/local/temp/",
    "/temp/",
    "/startup/",
    "/windows/temp/",
    "/recycler/",
    "/$recycle.bin/",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def interesting(path: Path, relative_to: Path = None) -> bool:
    if relative_to is not None:
        try:
            text = str(path.relative_to(relative_to)).replace("\\", "/").lower()
        except ValueError:
            text = str(path).replace("\\", "/").lower()
    else:
        text = str(path).replace("\\", "/").lower()
    if path.suffix.lower() in SUSPICIOUS_EXTS:
        return True
    return any(hint in text for hint in SUSPICIOUS_PATH_HINTS)


def run_triage(root: Path, target: Path) -> int:
    if not target.exists():
        _triage_log.error("Target does not exist: %s", target)
        print("Target does not exist:", target)
        return 2

    report_path = root / "reports" / "triage_report.csv"
    _triage_log.info("Starting triage: target=%s", target)

    count = 0
    errors = 0

    with report_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "size_bytes", "modified_time", "sha256", "reason", "error"])

        for dirpath, _dirnames, filenames in os.walk(str(target)):
            for name in filenames:
                path = Path(dirpath) / name

                if not interesting(path, relative_to=target):
                    continue

                try:
                    st = path.stat()
                    mtime = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)
                    )
                    digest = sha256_file(path)
                    writer.writerow([
                        str(path),
                        st.st_size,
                        mtime,
                        digest,
                        "suspicious extension or path",
                        "",
                    ])
                    count += 1
                except Exception as exc:
                    writer.writerow([str(path), "", "", "", "", str(exc)])
                    errors += 1
                    _triage_log.debug("Could not read %s: %s", path, exc)

    _triage_log.info(
        "Triage complete: %d files flagged, %d errors. Report: %s",
        count, errors, report_path,
    )
    print(f"Triage complete: {count} file(s) flagged, {errors} error(s).")
    print("Report:", report_path)
    return 0


# ---------------------------------------------------------------------------
# scan — ClamAV orchestration
# ---------------------------------------------------------------------------

_scan_log = logging.getLogger("scan")


def run_scan(root: Path, target: Path) -> int:
    if not target.exists():
        _scan_log.error("Target does not exist: %s", target)
        print("Target does not exist:", target)
        return 2

    clamscan = shutil.which("clamscan")
    if clamscan is None:
        msg = (
            "clamscan not found. "
            "ClamAV is not installed or not on PATH. "
            "Run 'triage' for a Python-only scan instead."
        )
        _scan_log.warning(msg)
        print(msg)
        return 3

    log_path = root / "logs" / "clamav_scan.log"

    cmd = [
        clamscan,
        "--recursive",
        "--infected",
        f"--log={log_path}",
        str(target),
    ]

    _scan_log.info("Running ClamAV: %s", " ".join(cmd))
    print("Running:", " ".join(cmd))

    result = subprocess.run(cmd)  # noqa: S603 — clamscan path verified by shutil.which

    _scan_log.info("ClamAV finished with exit code %d. Log: %s", result.returncode, log_path)
    print("ClamAV log:", log_path)

    if result.returncode == 1:
        _scan_log.warning("ClamAV found infected files — see log for details.")
        return 4  # toolkit exit code: suspicious/infected found

    return result.returncode


# ---------------------------------------------------------------------------
# mount_detect — Detect likely Windows installations
# ---------------------------------------------------------------------------

_detect_log = logging.getLogger("mount_detect")

SEARCH_BASES = [Path("/mnt"), Path("/media")]
WINDOWS_MARKER = "Windows/System32"


def find_windows_installations() -> list:
    candidates = []

    for base in SEARCH_BASES:
        if not base.exists():
            continue
        try:
            for marker in base.rglob(WINDOWS_MARKER):
                candidate = marker.parents[1]
                if candidate not in candidates:
                    candidates.append(candidate)
        except PermissionError as exc:
            _detect_log.debug("Permission error scanning %s: %s", base, exc)

    return candidates


def run_detect(root: Path) -> int:
    _detect_log.info("Scanning for Windows installations under %s", SEARCH_BASES)
    candidates = find_windows_installations()

    if not candidates:
        msg = "No likely Windows installations found under /mnt or /media."
        _detect_log.info(msg)
        print(msg)
        return 1

    print("Likely Windows installations:")
    for path in candidates:
        print("  " + str(path))
        _detect_log.info("Found: %s", path)

    return 0


# ---------------------------------------------------------------------------
# report — CSV and HTML report helpers
# ---------------------------------------------------------------------------

_report_log = logging.getLogger("report")

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Nielsoln Rescue Toolkit — {title}</title>
<style>
  body {{ font-family: monospace; font-size: 13px; margin: 20px; }}
  h1 {{ font-size: 16px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: 4px 8px; text-align: left; }}
  th {{ background: #eee; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p>Generated: {generated}</p>
<table>
<thead><tr>{headers}</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""


def csv_to_html(csv_path: Path, html_path: Path, title: str = "Report") -> None:
    import datetime

    with csv_path.open(encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        rows_data = list(reader)

    if not rows_data:
        _report_log.warning("CSV is empty: %s", csv_path)
        return

    headers = "".join(f"<th>{html.escape(h)}</th>" for h in rows_data[0])
    row_html_parts = []
    for row in rows_data[1:]:
        cells = "".join(f"<td>{html.escape(cell)}</td>" for cell in row)
        row_html_parts.append(f"<tr>{cells}</tr>")

    import datetime as _dt
    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = _HTML_TEMPLATE.format(
        title=html.escape(title),
        generated=generated,
        headers=headers,
        rows="\n".join(row_html_parts),
    )

    html_path.write_text(content, encoding="utf-8")
    _report_log.info("HTML report written: %s", html_path)
    print("HTML report:", html_path)


# ---------------------------------------------------------------------------
# updater — Fetch bootstrap.py / bootstrap.sh / toolkit.py from GitHub master
# ---------------------------------------------------------------------------
#
# run_update()           — foreground, prints per-file progress
# start_background_update() — daemon thread; never blocks or crashes main op
#
# Staging protocol:
#   All three files are downloaded to cache/update_staging/ first.
#   Live files are only replaced after every download succeeds.
#   os.replace() is atomic on POSIX; best-effort on Windows.
#   bootstrap.py safely replaces itself — Python already loaded it into
#   memory at startup, so the new version takes effect on the next run.

import threading

_updater_log = logging.getLogger("updater")

VERSION_FILE = "cache/version.txt"

_REPO_RAW_BASE = (
    "https://raw.githubusercontent.com/davidnoz123/nielsoln_rescue_toolkit/master"
)

_UPDATE_FILES = ["bootstrap.py", "bootstrap.sh", "toolkit.py"]


def current_version(root: Path) -> str:
    vf = root / VERSION_FILE
    if vf.exists():
        return vf.read_text(encoding="utf-8").strip()
    return "unknown"


def _fetch_url(url: str, timeout: int = 30) -> bytes:
    """Download url and return raw bytes. Raises RuntimeError on any failure."""
    import urllib.request
    import urllib.error

    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status} for {url}")
            return resp.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error fetching {url}: {exc}") from exc


def run_update(root: Path, offline: bool = False) -> int:
    """Foreground update — prints per-file progress. Returns toolkit exit code."""
    _updater_log.info("Update requested. Current version: %s", current_version(root))
    print(f"Current version: {current_version(root)}")

    if offline:
        msg = "Offline mode -- skipping update."
        _updater_log.info(msg)
        print(msg)
        return 0

    staging = root / "cache" / "update_staging"
    staging.mkdir(parents=True, exist_ok=True)

    # Stage all files before touching anything live.
    staged: list = []
    for filename in _UPDATE_FILES:
        url = f"{_REPO_RAW_BASE}/{filename}"
        _updater_log.info("Fetching %s", url)
        print(f"Fetching {filename} ...", end=" ", flush=True)
        try:
            data = _fetch_url(url)
        except RuntimeError as exc:
            print("FAILED")
            _updater_log.error("%s", exc)
            print(f"\nUpdate aborted: {exc}")
            print("No files were changed.")
            return 1

        if not data:
            print("FAILED (empty response)")
            _updater_log.error("Empty response for %s", url)
            print("\nUpdate aborted: empty response. No files were changed.")
            return 1

        dest = staging / filename
        dest.write_bytes(data)
        staged.append((dest, root / filename))
        print("ok")

    # All downloads succeeded -- promote staged files atomically.
    for src, dst in staged:
        _updater_log.info("Replacing %s", dst)
        os.replace(str(src), str(dst))

    print("\nUpdate complete. Changes take effect on the next run.")
    _updater_log.info("Update complete.")
    return 0


def _background_update_worker(root: Path) -> None:
    """Thread target — silently updates files; never raises."""
    try:
        staging = root / "cache" / "update_staging"
        staging.mkdir(parents=True, exist_ok=True)

        staged: list = []
        for filename in _UPDATE_FILES:
            url = f"{_REPO_RAW_BASE}/{filename}"
            try:
                data = _fetch_url(url)
            except RuntimeError as exc:
                _updater_log.debug("Background update: fetch failed for %s: %s", filename, exc)
                return  # abort silently; live files untouched

            if not data:
                _updater_log.debug("Background update: empty response for %s", filename)
                return

            dest = staging / filename
            dest.write_bytes(data)
            staged.append((dest, root / filename))

        for src, dst in staged:
            os.replace(str(src), str(dst))

        _updater_log.info("Background update complete. Changes take effect on the next run.")

    except Exception as exc:  # noqa: BLE001 — must never crash the main operation
        _updater_log.debug("Background update failed: %s", exc)


def start_background_update(root: Path) -> threading.Thread:
    """Start a daemon thread that silently updates toolkit files from GitHub.

    The thread runs entirely in the background and never blocks or crashes
    the main operation. Results are visible on the next run.
    """
    t = threading.Thread(
        target=_background_update_worker,
        args=(root,),
        daemon=True,
        name="toolkit-updater",
    )
    t.start()
    _updater_log.debug("Background update thread started.")
    return t


# ---------------------------------------------------------------------------
# download_portable_python — Print download plan for bundled Python runtimes
# ---------------------------------------------------------------------------
#
# NOTE: requires internet access. Do not run on the rescue USB itself.
# In v1 this is a stub; full download logic will be added in a later phase.
#
# Portable Python source: python-build-standalone (indygreg releases on GitHub)
#   https://github.com/indygreg/python-build-standalone/releases
#
# Linux runtime: use musl (statically linked) rather than gnu to avoid glibc
# version mismatches on older rescue targets (e.g. Ubuntu 14 / glibc 2.17).
# The gnu variant may fail with "GLIBC_2.34 not found" on older live systems.

_RUNTIME_BASE_URL = (
    "https://github.com/indygreg/python-build-standalone/releases/download"
    "/20240415"
)

_RUNTIME_TARGETS = [
    {
        "platform": "linux-x86_64",
        "filename": "cpython-3.12.3+20240415-x86_64-unknown-linux-musl-install_only.tar.gz",
    },
    {
        "platform": "macos-x86_64",
        "filename": "cpython-3.12.3+20240415-x86_64-apple-darwin-install_only.tar.gz",
    },
    {
        "platform": "macos-arm64",
        "filename": "cpython-3.12.3+20240415-aarch64-apple-darwin-install_only.tar.gz",
    },
]


def print_runtime_download_plan(dist_root: Path) -> None:
    print("Portable Python download plan")
    print("=" * 60)
    for t in _RUNTIME_TARGETS:
        url = f"{_RUNTIME_BASE_URL}/{t['filename']}"
        dest = dist_root / "runtimes" / t["platform"]
        print(f"\nPlatform : {t['platform']}")
        print(f"URL      : {url}")
        print(f"Dest     : {dest}")

    print()
    print("Full download not yet implemented in v1.")
    print("Download each archive manually, extract, and place under:")
    print("  dist/NIELSOLN_RESCUE_USB/runtimes/<platform>/python/")
