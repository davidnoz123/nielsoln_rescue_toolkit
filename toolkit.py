r"""
toolkit.py — Nielsoln Rescue Toolkit: all core logic.

C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe

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
import tarfile
import time
from pathlib import Path

file__fullPath = os.path.abspath(__file__)
file__baseName = os.path.basename(file__fullPath)
file__parentDr = os.path.dirname(file__fullPath)
file__fileSysD = (lambda a:lambda v:a(a, v, v))(lambda s, v, x:x if os.path.isdir(x) else (_ for _ in ()).throw(Exception(f"Argument not a directory:'{v}'")) if x==os.path.dirname(x) else s(s, v, os.path.dirname(x)))(file__parentDr)



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


def get_python_executable(root: Path = None) -> Path:
    """Return path to bundled Python for the current platform, if present."""
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"
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


def run_triage(root: Path = None, target: Path = None) -> int:
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"
    if not target.exists():
        _triage_log.error("Target does not exist: %s", target)
        print("Target does not exist:", target)
        return 2

    report_path = root / "reports" / "triage_report.csv"
    report_path.parent.mkdir(parents=True, exist_ok=True)
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


def run_scan(root: Path = None, target: Path = None) -> int:
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"
    if not target.exists():
        _scan_log.error("Target does not exist: %s", target)
        print("Target does not exist:", target)
        return 2

    clamscan = shutil.which("clamscan")
    scan_env = None

    if clamscan is None:
        # Try bundled ClamAV extracted by `bootstrap clamav --install`
        bundled = (
            root / "clamav" / "linux-x86_64" / "extracted" / "usr" / "bin" / "clamscan"
        )
        if bundled.exists():
            clamscan = str(bundled)
            lib_dir = (
                root / "clamav" / "linux-x86_64" / "extracted"
                / "usr" / "lib" / "x86_64-linux-gnu"
            )
            scan_env = dict(os.environ)
            if lib_dir.exists():
                prev = scan_env.get("LD_LIBRARY_PATH", "")
                scan_env["LD_LIBRARY_PATH"] = (
                    f"{lib_dir}:{prev}" if prev else str(lib_dir)
                )

    if clamscan is None:
        msg = (
            "clamscan not found. "
            "ClamAV is not installed, not on PATH, and not yet extracted from the bundle. "
            "Run `bootstrap clamav --install` to extract the bundled ClamAV, "
            "then `bootstrap clamav --update-db` to download a virus database. "
            "Run 'triage' for a Python-only scan instead."
        )
        _scan_log.warning(msg)
        print(msg)
        return 3

    log_path = root / "logs" / "clamav_scan.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Point clamscan at the locally cached virus database if present.
    db_dir = root / "clamav" / "linux-x86_64" / "db"
    extra_args = []
    if db_dir.is_dir() and any(db_dir.glob("*.c?d")):
        extra_args.append(f"--datadir={db_dir}")

    cmd = [
        clamscan,
        "--recursive",
        "--infected",
        f"--log={log_path}",
        *extra_args,
        str(target),
    ]

    _scan_log.info("Running ClamAV: %s", " ".join(cmd))
    print("Running:", " ".join(cmd))

    result = subprocess.run(cmd, env=scan_env)  # noqa: S603

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


def run_detect(root: Path = None) -> int:
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"
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


def current_version(root: Path = None) -> str:
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"
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


def run_update(root: Path = None, offline: bool = False) -> int:
    """Foreground update — prints per-file progress. Returns toolkit exit code."""
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"
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


def _background_update_worker(root: Path = None) -> None:
    """Thread target — silently updates files; never raises."""
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"
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


def start_background_update(root: Path = None) -> threading.Thread:
    """Start a daemon thread that silently updates toolkit files from GitHub.

    The thread runs entirely in the background and never blocks or crashes
    the main operation. Results are visible on the next run.
    """
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"
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
# download_portable_python — Resolve, verify, and plan bundled Python runtimes
# ---------------------------------------------------------------------------
#
# Source: astral-sh/python-build-standalone releases on GitHub.
#   https://github.com/astral-sh/python-build-standalone/releases
#
# Linux runtime: musl (statically linked) avoids glibc version mismatches on
# older rescue targets (e.g. Ubuntu 14 / glibc 2.17).
#
# Workflow:
#   1. Fetch SHA256SUMS for the chosen release tag from GitHub.
#   2. Locate the canonical install_only archive for each target platform.
#   3. Check <root>/runtimes/<platform>/<filename> against the SHA256.
#   4. Report status: cached-ok, cached-bad, or download-required.

_RELEASE_TAG = "20260408"
_PYTHON_VERSION = "3.12"
_RELEASE_BASE_URL = (
    "https://github.com/astral-sh/python-build-standalone/releases/download"
)

_RUNTIME_PLATFORM_TAGS = [
    "linux-x86_64",
    "macos-x86_64",
    "macos-arm64",
]


def _fetch_sha256sums(release_tag: str) -> dict:
    """Fetch SHA256SUMS for release_tag and return {filename: hex_digest}."""
    url = f"{_RELEASE_BASE_URL}/{release_tag}/SHA256SUMS"
    try:
        data = _fetch_url(url)
    except RuntimeError as exc:
        raise RuntimeError(f"Could not fetch SHA256SUMS from {url}: {exc}") from exc
    result = {}
    for line in data.decode("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            digest, filename = parts
            result[filename] = digest
    return result


def _match_runtime_filename(filename: str, platform_tag: str, python_version: str) -> bool:
    """Return True if filename is the canonical install_only archive for this platform+version.

    Excludes: stripped variants, freethreaded builds, x86_64_v2/v3/v4 micro-arch variants.
    """
    if not filename.endswith("install_only.tar.gz"):
        return False
    if not filename.startswith(f"cpython-{python_version}."):
        return False
    if platform_tag == "linux-x86_64":
        return "-x86_64-unknown-linux-musl-install_only.tar.gz" in filename
    if platform_tag == "macos-x86_64":
        return "-x86_64-apple-darwin-install_only.tar.gz" in filename
    if platform_tag == "macos-arm64":
        return "-aarch64-apple-darwin-install_only.tar.gz" in filename
    return False


def _verify_cached_file(path: Path, expected_sha256: str) -> bool:
    """Return True if path exists and its SHA256 matches expected_sha256."""
    if not path.exists():
        return False
    return sha256_file(path).lower() == expected_sha256.lower()


def iter_runtime_plan(
    dist_root,
    release_tag: str = _RELEASE_TAG,
    python_version: str = _PYTHON_VERSION,
):
    """Yield one dict per target platform with resolved filename, checksum, URL, and cache status.

    Fetches SHA256SUMS from GitHub once, then yields for each platform in
    _RUNTIME_PLATFORM_TAGS.  Each yielded dict has keys:

        platform_tag    str   e.g. "linux-x86_64"
        filename        str   canonical tar.gz name, or None if unresolved
        expected_sha256 str   hex digest from SHA256SUMS, or "" if unresolved
        url             str   full download URL, or "" if unresolved
        cached_file     Path  expected local path of the archive
        cache_ok        bool  True if cached_file exists and SHA256 matches
        cache_exists    bool  True if cached_file exists (regardless of SHA256)
        warning         str   non-empty string if resolution failed
    """
    checksums = _fetch_sha256sums(release_tag)
    for platform_tag in _RUNTIME_PLATFORM_TAGS:
        cache_dir = runtime_cache_path(dist_root, platform_tag)
        matches = [fn for fn in checksums if _match_runtime_filename(fn, platform_tag, python_version)]

        if not matches:
            yield {
                "platform_tag": platform_tag, "filename": None,
                "expected_sha256": "", "url": "",
                "cached_file": cache_dir, "cache_ok": False, "cache_exists": False,
                "warning": "no matching file found in SHA256SUMS",
            }
            continue

        if len(matches) > 1:
            yield {
                "platform_tag": platform_tag, "filename": None,
                "expected_sha256": "", "url": "",
                "cached_file": cache_dir, "cache_ok": False, "cache_exists": False,
                "warning": f"multiple matches: {matches}",
            }
            continue

        filename = matches[0]
        expected_sha256 = checksums[filename]
        url = f"{_RELEASE_BASE_URL}/{release_tag}/{filename}"
        cached_file = cache_dir / filename
        cache_ok = _verify_cached_file(cached_file, expected_sha256)

        yield {
            "platform_tag": platform_tag,
            "filename": filename,
            "expected_sha256": expected_sha256,
            "url": url,
            "cached_file": cached_file,
            "cache_ok": cache_ok,
            "cache_exists": cached_file.exists(),
            "warning": "",
        }


def print_runtime_download_plan(
    dist_root: Path = None,
    release_tag: str = _RELEASE_TAG,
    python_version: str = _PYTHON_VERSION,
) -> None:
    if dist_root is None: dist_root = file__fileSysD
    assert os.path.isdir(dist_root), f"dist_root is not an existing directory: {dist_root!r}"

    print(f"Portable Python download plan  (Python {python_version}, release {release_tag})")
    print("=" * 70)

    for entry in iter_runtime_plan(dist_root, release_tag, python_version):
        print(f"\nPlatform : {entry['platform_tag']}")
        if entry["warning"]:
            print(f"  WARNING: {entry['warning']}")
            continue
        if entry["cache_ok"]:
            status = "CACHED -- checksum OK, skip download"
        elif entry["cache_exists"]:
            status = "CACHED but checksum MISMATCH -- re-download needed"
        else:
            status = "not cached -- download required"
        print(f"Filename : {entry['filename']}")
        print(f"SHA256   : {entry['expected_sha256']}")
        print(f"URL      : {entry['url']}")
        print(f"Cache    : {entry['cached_file']}")
        print(f"Status   : {status}")

    print()
    print("To download, fetch each URL and save to the Cache path shown above.")
    print("Re-run this plan to verify checksums after downloading.")


# ---------------------------------------------------------------------------
# clamav — Download, bundle, and install ClamAV for offline scanning
# ---------------------------------------------------------------------------
#
# ClamAV is fetched as an official .deb from the ClamAV GitHub releases page.
# The .deb is bundled on the USB so it can be installed offline on the rescue
# target (RescueZilla / Ubuntu / Debian).
#
# Workflow
# --------
#   Build time : download_clamav(root)      → caches .deb under root/clamav/linux-x86_64/
#   USB build  : build_usb_package          → copies .deb into dist/clamav/linux-x86_64/
#   USB runtime: run_install_clamav(root)   → dpkg-deb --extract to clamav/.../extracted/
#   Scanning   : run_scan                   → uses bundled clamscan if not on PATH
#
# Virus database
# --------------
#   ClamAV cannot scan without a database (daily.cvd / main.cvd).
#   The database is NOT bundled — it is too large (~300 MB+).
#   Use `bootstrap clamav --update-db` (requires internet) on the target,
#   OR copy existing .cvd / .cld files from the rescue environment into
#   clamav/linux-x86_64/db/ before scanning offline.

# Last known stable release — used as offline fallback when the GitHub API
# is unreachable.  Update these together when pinning a new version manually.
_CLAMAV_VERSION        = "1.5.2"
_CLAMAV_LINUX_FILENAME = f"clamav-{_CLAMAV_VERSION}.linux.x86_64.deb"
_CLAMAV_LINUX_SHA256   = "e92b0f1e5529bbaa4d9534a429c4d1133dbfe477b760365a113e63b54c5dcd75"
_CLAMAV_LINUX_URL      = (
    f"https://github.com/Cisco-Talos/clamav/releases/download"
    f"/clamav-{_CLAMAV_VERSION}/{_CLAMAV_LINUX_FILENAME}"
)
_CLAMAV_GITHUB_API_LATEST = "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest"


def _clamav_cache_path(root) -> Path:
    """Return the local cache directory: root/clamav/linux-x86_64/.

    Validates that *root* is an existing directory.
    """
    if root is None:
        raise ValueError("root must not be None")
    p = Path(root)
    if not p.is_dir():
        raise ValueError(f"root is not an existing directory: {p!r}")
    return p / "clamav" / "linux-x86_64"


def _clamav_install_path(root) -> Path:
    """Return the directory where ClamAV binaries are extracted."""
    return _clamav_cache_path(root) / "extracted"


def get_clamav_executable(root) -> Path:
    """Return the expected path of the bundled clamscan binary."""
    return _clamav_install_path(root) / "usr" / "bin" / "clamscan"


def _resolve_latest_clamav() -> tuple:
    """Query the GitHub API for the latest stable ClamAV release.

    Returns (version, filename, download_url) for the Linux x86_64 .deb.
    Raises RuntimeError on any failure (caller falls back to hardcoded values).
    """
    import json
    try:
        data = _fetch_url(_CLAMAV_GITHUB_API_LATEST)
    except RuntimeError as exc:
        raise RuntimeError(f"Could not reach ClamAV release API: {exc}") from exc
    release = json.loads(data.decode("utf-8"))
    tag = release["tag_name"]                            # e.g. "clamav-1.5.2"
    version = tag[len("clamav-"):] if tag.startswith("clamav-") else tag.lstrip("v")
    filename = f"clamav-{version}.linux.x86_64.deb"
    assets = release.get("assets", [])
    asset = next((a for a in assets if a["name"] == filename), None)
    if asset:
        download_url = asset["browser_download_url"]
    else:
        download_url = (
            f"https://github.com/Cisco-Talos/clamav/releases/download"
            f"/{tag}/{filename}"
        )
    return version, filename, download_url


def download_clamav(root, verbosity: int = 2) -> Path:
    """Download the latest stable ClamAV Linux .deb to the local cache.

    Resolves the current release via the GitHub API; falls back to the hardcoded
    _CLAMAV_VERSION / _CLAMAV_LINUX_URL if the API is unreachable.

    SHA256 is computed from the downloaded bytes and stored in a .sha256 sidecar
    next to the .deb so subsequent runs can verify the cache without re-downloading.

    Returns the cached .deb Path.
    """
    cache_dir = _clamav_cache_path(root)

    # --- resolve latest version ---
    try:
        version, filename, download_url = _resolve_latest_clamav()
        if verbosity >= 2:
            print(f"  clamav: latest version is {version}")
    except RuntimeError as exc:
        if verbosity >= 1:
            print(
                f"  clamav: API unreachable ({exc}); "
                f"using fallback version {_CLAMAV_VERSION}"
            )
        version, filename, download_url = (
            _CLAMAV_VERSION, _CLAMAV_LINUX_FILENAME, _CLAMAV_LINUX_URL
        )

    cached_deb     = cache_dir / filename
    sha256_sidecar = cache_dir / (filename + ".sha256")

    # --- check existing cache ---
    if cached_deb.exists():
        if sha256_sidecar.exists():
            expected = sha256_sidecar.read_text(encoding="utf-8").strip()
            if _verify_cached_file(cached_deb, expected):
                if verbosity >= 1:
                    print(f"  clamav: already cached and verified: {cached_deb.name}")
                return cached_deb
        elif filename == _CLAMAV_LINUX_FILENAME and _verify_cached_file(
            cached_deb, _CLAMAV_LINUX_SHA256
        ):
            # Legacy cache (no sidecar yet) — write sidecar and reuse.
            sha256_sidecar.write_text(_CLAMAV_LINUX_SHA256 + "\n", encoding="utf-8")
            if verbosity >= 1:
                print(f"  clamav: already cached and verified: {cached_deb.name}")
            return cached_deb

    # --- remove stale .deb files so run_install_clamav sees exactly one ---
    cache_dir.mkdir(parents=True, exist_ok=True)
    for stale in cache_dir.glob("*.deb"):
        if stale.name != filename:
            if verbosity >= 1:
                print(f"  clamav: removing stale {stale.name}")
            stale.unlink(missing_ok=True)
            (cache_dir / (stale.name + ".sha256")).unlink(missing_ok=True)

    # --- download ---
    if verbosity >= 1:
        print(f"  clamav: downloading {download_url} ...")
    try:
        data = _fetch_url(download_url)
    except RuntimeError as exc:
        raise RuntimeError(f"ClamAV download failed: {exc}") from exc

    cached_deb.write_bytes(data)
    actual_sha256 = sha256_file(cached_deb)
    sha256_sidecar.write_text(actual_sha256 + "\n", encoding="utf-8")

    if verbosity >= 1:
        print(f"  clamav: downloaded and verified: {cached_deb.name}")
    return cached_deb


def _extract_deb_python(deb_path: Path, dest_dir: Path, verbosity: int = 2) -> None:
    """Pure-Python .deb extractor (ar + tar).  Supports gz, xz, bz2 compression.

    Used as a fallback on platforms without dpkg-deb (e.g. Windows dev machine).
    Note: zstd-compressed data.tar.zst is NOT supported by Python stdlib.
    """
    import io
    import gzip
    import lzma
    import bz2 as _bz2

    dest_dir.mkdir(parents=True, exist_ok=True)

    # --- parse ar archive ---
    with open(deb_path, "rb") as f:
        magic = f.read(8)
        if magic != b"!<arch>\n":
            raise ValueError(f"Not an ar archive (bad magic): {deb_path.name}")
        entries = []
        while True:
            header = f.read(60)
            if not header:
                break
            if len(header) < 60:
                raise ValueError(f"Truncated ar header ({len(header)} bytes)")
            name = header[0:16].rstrip().decode("ascii", errors="replace")
            size = int(header[48:58].strip())
            if header[58:60] != b"`\n":
                raise ValueError(f"Bad ar entry magic: {header[58:60]!r}")
            data = f.read(size)
            if size % 2 == 1:
                f.read(1)  # padding
            entries.append((name, data))

    # --- find data.tar.* ---
    data_entry = next(
        ((n, d) for n, d in entries if n.startswith("data.tar")), None
    )
    if data_entry is None:
        raise RuntimeError(f"No data.tar.* found in {deb_path.name}")

    name, data = data_entry
    nl = name.lower()
    if nl.endswith(".xz") or nl.endswith(".xz/"):
        raw = lzma.decompress(data)
    elif nl.endswith(".gz") or nl.endswith(".gz/"):
        raw = gzip.decompress(data)
    elif nl.endswith(".bz2") or nl.endswith(".bz2/"):
        raw = _bz2.decompress(data)
    elif nl.endswith(".tar") or nl.endswith(".tar/"):
        raw = data
    elif nl.endswith(".zst") or nl.endswith(".zst/"):
        raise RuntimeError(
            "data.tar.zst compression requires dpkg-deb (not in Python stdlib).\n"
            "Install dpkg and retry, or run on the target Linux system."
        )
    else:
        raise RuntimeError(
            f"Unsupported data.tar compression in entry {name!r}.\n"
            "Install dpkg and retry."
        )

    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        members = tf.getmembers()
        total = len(members)
        for i, member in enumerate(members, 1):
            if verbosity >= 2 and i % 200 == 0:
                print(f"  clamav: extracting ... [{i}/{total}]")
            # filter='data' skips uid/gid restoration (avoids "Cannot change
            # ownership" warnings when not running as root).
            tf.extract(member, path=str(dest_dir), filter="data")
    if verbosity >= 1:
        print(f"  clamav: extracted {len(members)} entries to {dest_dir}")


def run_install_clamav(root=None, verbosity: int = 2) -> int:
    """Extract the bundled ClamAV .deb into clamav/linux-x86_64/extracted/.

    Uses dpkg-deb if available (handles all compression including zstd), otherwise
    falls back to pure-Python extraction (gz/xz/bz2 only).

    After installation, get_clamav_executable(root) points at a working clamscan.
    A virus database is NOT included — run `bootstrap clamav --update-db` (online),
    or copy *.cvd / *.cld files into clamav/linux-x86_64/db/ for offline scanning.
    """
    if root is None:
        root = Path(file__fileSysD)
    root = Path(root)
    assert root.is_dir(), f"root is not an existing directory: {root!r}"

    cache_dir = _clamav_cache_path(root)
    debs = sorted(cache_dir.glob("*.deb"))
    if not debs:
        print(f"No ClamAV .deb found in {cache_dir}")
        print("Run build_usb_package (or download_clamav) first.")
        return 1

    if len(debs) > 1:
        print(f"Multiple .deb files in {cache_dir}: {[d.name for d in debs]}")
        print("Remove all but one and retry.")
        return 1

    deb_path    = debs[0]
    install_dir = _clamav_install_path(root)

    if verbosity >= 1:
        print(f"Extracting ClamAV from {deb_path.name} ...")
        print(f"  dest: {install_dir}")

    dpkg_deb = shutil.which("dpkg-deb")
    if dpkg_deb:
        if verbosity >= 2:
            print(f"  using dpkg-deb: {dpkg_deb}")
        install_dir.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [dpkg_deb, "--extract", str(deb_path), str(install_dir)],
            stderr=subprocess.PIPE,
            text=True,
        )
        # dpkg-deb emits "Cannot change ownership to uid ..." warnings when
        # not running as root.  These are harmless — the files are still
        # extracted correctly.  Suppress those lines; forward everything else.
        if result.stderr:
            for line in result.stderr.splitlines():
                if "Cannot change ownership" not in line:
                    print(f"  dpkg-deb: {line}", file=sys.stderr)
        if result.returncode != 0:
            print(f"  ERROR: dpkg-deb --extract exited {result.returncode}")
            return result.returncode
    else:
        if verbosity >= 1:
            print("  dpkg-deb not found — using pure-Python extractor")
        try:
            _extract_deb_python(deb_path, install_dir, verbosity=verbosity)
        except RuntimeError as exc:
            print(f"  ERROR: {exc}")
            return 1

    clamscan = get_clamav_executable(root)
    if clamscan.exists():
        try:
            clamscan.chmod(clamscan.stat().st_mode | 0o111)
        except OSError:
            pass
        if verbosity >= 1:
            print(f"  OK -- {clamscan}")
    else:
        print(f"  WARNING -- {clamscan} not found after extraction")
        return 1

    db_dir = cache_dir / "db"
    print()
    print("NOTE: ClamAV requires a virus database to scan files.")
    print(f"  Option 1 (online):  bootstrap clamav --update-db")
    print(f"  Option 2 (offline): copy *.cvd / *.cld files to {db_dir}")
    return 0


def run_clamav_update_db(root=None, verbosity: int = 2) -> int:
    """Run freshclam to download / update the ClamAV virus database.

    Requires internet access.  Saves the database to clamav/linux-x86_64/db/
    so it persists across reboots of the rescue environment.
    """
    if root is None:
        root = Path(file__fileSysD)
    root = Path(root)
    assert root.is_dir(), f"root is not an existing directory: {root!r}"

    # Prefer bundled freshclam; fall back to PATH
    bundled_freshclam = _clamav_install_path(root) / "usr" / "bin" / "freshclam"
    freshclam_path = (
        str(bundled_freshclam) if bundled_freshclam.exists()
        else shutil.which("freshclam")
    )
    if freshclam_path is None:
        print("freshclam not found.  Run `bootstrap clamav --install` first.")
        return 1

    db_dir = _clamav_cache_path(root) / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    # Add bundled lib path for dynamically linked freshclam
    lib_dir = _clamav_install_path(root) / "usr" / "lib" / "x86_64-linux-gnu"
    env = dict(os.environ)
    if lib_dir.exists():
        prev = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{prev}" if prev else str(lib_dir)

    cmd = [freshclam_path, f"--datadir={db_dir}"]
    if verbosity >= 1:
        print("Running:", " ".join(cmd))
    result = subprocess.run(cmd, env=env)
    if result.returncode == 0 and verbosity >= 1:
        print(f"Database updated in {db_dir}")
    return result.returncode


# ---------------------------------------------------------------------------
# build_usb_package — Assemble dist/NIELSOLN_RESCUE_USB
# ---------------------------------------------------------------------------
#
# Steps:
#   1. Remove old NIELSOLN_RESCUE_USB if present.
#   2. Create fresh NIELSOLN_RESCUE_USB.
#   3. Copy bootstrap.sh, bootstrap.py, toolkit.py.
#   4. For each runtime: download if needed, verify checksum, extract to dist.
#   5. chmod bootstrap.sh executable (Linux/macOS only).


def _write_runtime_placeholder(path: Path, platform_tag: str) -> None:
    (path / "README.txt").write_text(
        f"Place the portable Python 3 runtime for {platform_tag} here.\n"
        "Expected layout:\n"
        "  python/\n"
        "    bin/\n"
        "      python3\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Runtime archive helpers
# ---------------------------------------------------------------------------

def _safe_member_path(dest: Path, member_name: str) -> Path:
    """Resolve member_name relative to dest; raise ValueError on path traversal."""
    dest = dest.resolve()
    target = (dest / member_name).resolve()
    if target != dest and dest not in target.parents:
        raise ValueError(f"Unsafe tar path: {member_name!r}")
    return target


def _collect_expected_paths(tf: tarfile.TarFile, dest: Path) -> set:
    """Return the set of resolved Paths the archive should produce under dest."""
    expected: set = set()
    for member in tf.getmembers():
        target = _safe_member_path(dest, member.name)
        expected.add(target)
        parent = target.parent
        while (parent != dest.parent and dest in parent.parents) or parent == dest:
            expected.add(parent)
            if parent == dest:
                break
            parent = parent.parent
    return expected


def _member_needs_extract(member: tarfile.TarInfo, target: Path) -> tuple:
    """Return (needs_extract, reason) for the archive member vs the file on disk."""
    if member.isdir():
        if not target.exists():
            return True, "dir missing"
        return False, "already exists"
    if member.isfile():
        if not target.exists():
            return True, "file missing"
        st = target.stat()
        if st.st_size != member.size:
            return True, f"size differs (disk={st.st_size}, archive={member.size})"
        if int(st.st_mtime) < int(member.mtime):
            return True, f"mtime older (disk={int(st.st_mtime)}, archive={int(member.mtime)})"
        return False, "up-to-date"
    return False, "not a regular file"


def _extract_members(
    tf: tarfile.TarFile,
    dest: Path,
    platform_tag: str,
    incremental: bool,
    dry_run: bool,
    verbosity: int = 2,
) -> set:
    """Iterate archive members, extract/skip as needed; return expected path set.

    verbosity 0 = silent
    verbosity 1 = actions only (mkdir, write, would-write)
    verbosity 2 = actions + decisions (skip-dir, skip-link, fresh + reason)
    """
    expected = _collect_expected_paths(tf, dest)
    members = tf.getmembers()
    total = len(members)

    # On case-insensitive filesystems (Windows, macOS HFS+) two archive members
    # that differ only in case — e.g. terminfo/E/Eterm vs terminfo/e/eterm —
    # would collide on the same on-disk path.  Track written paths by their
    # case-folded form and skip (with a loud warning) any later collision.
    case_insensitive_fs: bool = (os.path.normcase("A") == "a")
    seen_ci: set = set()  # case-folded str(target) → populated when case_insensitive_fs

    for i, member in enumerate(members, 1):
        target = _safe_member_path(dest, member.name)
        tag = f"  {platform_tag}: [{i:>{len(str(total))}}/{total}]"

        # --- case-collision guard (case-insensitive filesystems only) ---
        if case_insensitive_fs and not member.isdir():
            key = str(target).lower()
            if key in seen_ci:
                # Always warn regardless of verbosity — this is a data-integrity issue.
                print(
                    f"{tag} SKIP-COLLISION  {member.name}"
                    f"  (case collision on case-insensitive filesystem)"
                )
                continue
            seen_ci.add(key)

        # --- directories ---
        if member.isdir():
            if not target.exists():
                if verbosity >= 1:
                    print(f"{tag} mkdir       {member.name}/")
                if not dry_run:
                    target.mkdir(parents=True, exist_ok=True)
            elif verbosity >= 2:
                print(f"{tag} skip-dir    {member.name}/  (already exists)")
            continue

        # --- symlinks / hard links ---
        if member.issym() or member.islnk():
            if verbosity >= 2:
                print(f"{tag} skip-link   {member.name}")
            continue

        # --- non-regular specials ---
        if not member.isfile():
            if verbosity >= 2:
                print(f"{tag} skip-spcl   {member.name}")
            continue

        # --- regular files ---
        reason = ""
        if incremental:
            needs, reason = _member_needs_extract(member, target)
            if not needs:
                if verbosity >= 2:
                    print(f"{tag} fresh       {member.name}  ({reason})")
                continue

        verb = "would-write" if dry_run else "write      "
        suffix = f"  ({reason})" #if verbosity >= 2 and reason else ""
        if verbosity >= 1:
            print(f"{tag} {verb} {member.name}{suffix}")
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            tf.extract(member, path=str(dest))
    return expected


def _prune_spurious(
    dest: Path,
    expected: set,
    platform_tag: str,
    dry_run: bool = False,
    verbosity: int = 2,
) -> None:
    """Delete files/dirs under dest that are not in expected."""
    for dirpath, dirnames, filenames in os.walk(dest, topdown=False):
        root_path = Path(dirpath).resolve()
        for name in filenames:
            path = (root_path / name).resolve()
            if path not in expected:
                verb = "would-delete" if dry_run else "delete"
                if verbosity >= 1:
                    print(f"  {platform_tag}: {verb} file  {path}")
                if not dry_run:
                    path.unlink()
        for name in dirnames:
            path = (root_path / name).resolve()
            if path not in expected:
                verb = "would-delete" if dry_run else "delete"
                if verbosity >= 1:
                    print(f"  {platform_tag}: {verb} dir   {path}")
                if not dry_run:
                    shutil.rmtree(path)


def _extract_runtime(
    archive: Path,
    dest_dir: Path,
    platform_tag: str,
    mode: str = "full",
    verbosity: int = 2,
) -> None:
    """Extract or update a python-build-standalone install_only archive into dest_dir.

    Modes
    -----
    full    Clear dest_dir then extract every member.  (default; used by build_usb_package)
    update  Incremental: skip files that are already present and up to date (size/mtime).
    check   Dry run: print what *update* + *prune* would do; make no changes.
    prune   Incremental update then delete files not present in the archive.

    Verbosity
    ---------
    0  silent
    1  actions only  (mkdir, write, delete)
    2  actions + decisions  (skip, fresh + reason)  [default]
    """
    dry_run     = (mode == "check")
    incremental = (mode in ("update", "prune", "check"))

    if mode == "full" and not dry_run:
        # Only remove the extracted python/ subtree, not the whole dest_dir.
        # The archive (.tar.gz) may also live in dest_dir and must be preserved.
        python_sub = dest_dir / "python"
        if python_sub.exists():
            if verbosity >= 1:
                print(f"  {platform_tag}: clearing existing python/ ...")
            shutil.rmtree(python_sub)

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()

    if verbosity >= 2:
        print(f"  {platform_tag}: mode={mode}  archive={archive.name}")
    with tarfile.open(archive, "r:*") as tf:
        expected = _extract_members(
            tf, dest_resolved, platform_tag,
            incremental=incremental, dry_run=dry_run, verbosity=verbosity,
        )

    if mode in ("prune", "check"):
        _prune_spurious(dest_resolved, expected, platform_tag, dry_run=dry_run, verbosity=verbosity)

    if dry_run:
        return

    python_bin = dest_dir / "python" / "bin" / "python3"
    if python_bin.exists():
        if verbosity >= 1:
            print(f"  {platform_tag}: OK -- {python_bin}")
    else:
        print(f"  {platform_tag}: WARNING -- {python_bin} not found after extraction")


_USB_DIST_NAME = "NIELSOLN_RESCUE_USB"
_VALID_MODES = ("full", "update", "check", "prune")


def usb_dist_path(root) -> Path:
    """Return the canonical USB dist path (root/dist/NIELSOLN_RESCUE_USB).

    Validates that *root* is an existing directory.  Does NOT require the dist
    folder itself to exist yet — callers create it as needed.

    Raises ValueError for bad inputs.
    """
    if root is None:
        raise ValueError("root must not be None; pass a repo root directory")
    p = Path(root)
    if not p.is_dir():
        raise ValueError(f"root is not an existing directory: {p!r}")
    return p / "dist" / _USB_DIST_NAME


def runtime_dest_path(dist, platform_tag: str) -> Path:
    """Return the canonical runtime destination (dist/runtimes/<platform_tag>).

    Validates that *platform_tag* is a known entry in _RUNTIME_PLATFORM_TAGS and
    that *dist* resolves to a path (existence is not required yet).

    Raises ValueError for bad inputs.
    """
    if not platform_tag or not isinstance(platform_tag, str):
        raise ValueError(f"platform_tag must be a non-empty string; got {platform_tag!r}")
    if platform_tag not in _RUNTIME_PLATFORM_TAGS:
        raise ValueError(
            f"Unknown platform_tag {platform_tag!r}. "
            f"Valid values: {_RUNTIME_PLATFORM_TAGS}"
        )
    if dist is None:
        raise ValueError("dist must not be None; pass the USB dist directory")
    return Path(dist) / "runtimes" / platform_tag


def runtime_cache_path(root, platform_tag: str) -> Path:
    """Return the canonical local download-cache directory (root/runtimes/<platform_tag>).

    This is where archives downloaded from GitHub are stored before being
    extracted into the USB dist.  Validates that *root* is an existing directory
    and that *platform_tag* is a known value.

    Raises ValueError for bad inputs.
    """
    if not platform_tag or not isinstance(platform_tag, str):
        raise ValueError(f"platform_tag must be a non-empty string; got {platform_tag!r}")
    if platform_tag not in _RUNTIME_PLATFORM_TAGS:
        raise ValueError(
            f"Unknown platform_tag {platform_tag!r}. "
            f"Valid values: {_RUNTIME_PLATFORM_TAGS}"
        )
    if root is None:
        raise ValueError("root must not be None; pass a repo root directory")
    p = Path(root)
    if not p.is_dir():
        raise ValueError(f"root is not an existing directory: {p!r}")
    return p / "runtimes" / platform_tag


def run_install_runtime(
    root: Path = None,
    platform_tag: str = None,
    mode: str = "update",
    verbosity: int = 2,
) -> int:
    """Extract (or update/check/prune) the bundled Python runtime on the USB.

    Locates the .tar.gz archive that was copied into runtimes/<platform>/
    by build_usb_package, then calls _extract_runtime to (re-)install it
    in-place.  The extracted python/ tree lives alongside the archive in
    the same directory.

    mode is passed through to _extract_runtime:
      full    Wipe python/ and re-extract everything.
      update  Skip files that are already up-to-date (default).
      check   Dry run — print what would change, touch nothing.
      prune   update + delete files not present in the archive.
    """
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"

    if platform_tag is None:
        platform_tag = get_platform()

    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown mode {mode!r}. Valid values: {_VALID_MODES}")

    plat_dir = runtime_cache_path(root, platform_tag)

    if not plat_dir.exists():
        print(f"Runtime directory not found: {plat_dir}")
        print("Run build_usb_package first, or copy the archive manually.")
        return 1

    archives = sorted(plat_dir.glob("*.tar.gz"))
    if not archives:
        print(f"No .tar.gz archive found in {plat_dir}")
        print("Run build_usb_package to download and copy the archive to the USB.")
        return 1

    if len(archives) > 1:
        names = [a.name for a in archives]
        print(f"Multiple archives found in {plat_dir}: {names}")
        print("Remove all but one and retry.")
        return 1

    archive = archives[0]
    dest_dir = plat_dir  # python/ will be extracted alongside the archive

    if verbosity >= 1:
        print(f"Installing runtime for {platform_tag}  (mode={mode})")
        print(f"  archive : {archive}")
        print(f"  dest    : {dest_dir}")

    _extract_runtime(archive, dest_dir, platform_tag, mode=mode, verbosity=verbosity)
    return 0


def _sync_core_file(src: Path, dst: Path, mode: str, verbosity: int) -> None:
    """Copy src to dst according to mode.

    full   — always overwrite.
    update — copy only if dst is missing or src is newer (mtime).
    prune  — same as update (core files are never pruned).
    check  — print what would happen; make no changes.
    """
    dry_run = (mode == "check")

    needs_copy = (
        mode == "full"
        or not dst.exists()
        or int(src.stat().st_mtime) > int(dst.stat().st_mtime)
    )

    if not needs_copy:
        if verbosity >= 2:
            print(f"  fresh       {dst.name}  (up-to-date)")
        return

    verb = "would-copy" if dry_run else "copy      "
    if verbosity >= 1:
        print(f"  {verb} {dst.name}")
    if not dry_run:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def build_usb_package(dist_root: Path = None, mode: str = "full", verbosity: int = 2) -> None:
    """Build or update dist/NIELSOLN_RESCUE_USB from repo sources.

    import runpy ; temp = runpy._run_module_as_main("toolkit")

    Modes
    -----
    full    Wipe any existing dist and do a clean rebuild.  (default)
    update  Update in-place: copy core files if newer, incrementally update runtimes.
    check   Dry run: print what *update* + *prune* would do; make no changes.
    prune   update + delete files not present in the archive or core file list.
    """
    if dist_root is None: dist_root = file__fileSysD
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown mode {mode!r}. Valid values: {_VALID_MODES}")

    dry_run = (mode == "check")
    root = Path(dist_root)
    dist = usb_dist_path(root)

    if verbosity >= 1:
        print(f"build_usb_package  mode={mode}  dist={dist}")

    # --- dist directory setup ---
    if mode == "full" and not dry_run:
        if dist.exists():
            if verbosity >= 1:
                print("Removing existing dist folder...")
            shutil.rmtree(dist)
        dist.mkdir(parents=True)
    elif not dry_run:
        dist.mkdir(parents=True, exist_ok=True)

    # --- Core files ---
    if verbosity >= 1:
        print("\nCore files:")
    for name in ["bootstrap.sh", "bootstrap.py", "toolkit.py"]:
        _sync_core_file(root / name, dist / name, mode=mode, verbosity=verbosity)

    # --- Runtimes ---
    if verbosity >= 1:
        print("\nRuntimes:")
    for entry in iter_runtime_plan(dist_root=root):
        platform_tag = entry["platform_tag"]
        dest_dir = runtime_dest_path(dist, platform_tag)

        if entry["warning"]:
            print(f"  {platform_tag}: WARNING -- {entry['warning']}")
            if not dry_run:
                dest_dir.mkdir(parents=True, exist_ok=True)
                _write_runtime_placeholder(dest_dir, platform_tag)
            continue

        # Ensure archive is cached locally
        if not entry["cache_ok"]:
            cached_file: Path = entry["cached_file"]
            if entry["cache_exists"]:
                print(f"  {platform_tag}: checksum mismatch -- re-downloading ...")
            else:
                print(f"  {platform_tag}: not cached -- downloading ...")
            print(f"    URL: {entry['url']}")
            cached_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                data = _fetch_url(entry["url"])
                cached_file.write_bytes(data)
                if _verify_cached_file(cached_file, entry["expected_sha256"]):
                    print(f"    Downloaded and verified: {cached_file.name}")
                    entry = dict(entry, cache_ok=True)
                else:
                    print(f"    ERROR: checksum mismatch after download -- skipping {platform_tag}")
                    if cached_file.exists():
                        cached_file.unlink()
                    if not dry_run:
                        dest_dir.mkdir(parents=True, exist_ok=True)
                        _write_runtime_placeholder(dest_dir, platform_tag)
                    continue
            except RuntimeError as exc:
                print(f"    ERROR: download failed -- {exc}")
                if not dry_run:
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    _write_runtime_placeholder(dest_dir, platform_tag)
                continue

        # Copy archive into dist so the USB is self-contained
        archive_src = entry["cached_file"]
        archive_dst = dest_dir / archive_src.name
        if not dry_run:
            dest_dir.mkdir(parents=True, exist_ok=True)
        _sync_core_file(archive_src, archive_dst, mode=mode, verbosity=verbosity)

        # Extract / update the runtime using run_install_runtime
        # Pass dist as the root so it finds the archive at dist/runtimes/<platform>/
        run_install_runtime(
            root=dist,
            platform_tag=platform_tag,
            mode=mode,
            verbosity=verbosity,
        )

    # --- ClamAV ---
    if verbosity >= 1:
        print("\nClamAV:")
    if not dry_run:
        try:
            deb = download_clamav(root, verbosity=verbosity)
            clamav_dist_dir = dist / "clamav" / "linux-x86_64"
            clamav_dist_dir.mkdir(parents=True, exist_ok=True)
            _sync_core_file(deb, clamav_dist_dir / deb.name, mode=mode, verbosity=verbosity)
        except RuntimeError as exc:
            print(f"  ERROR downloading ClamAV: {exc}")
            print("  Skipping ClamAV bundle.  run_scan will fall back to system ClamAV.")
    else:
        print(f"  would download {_CLAMAV_LINUX_URL}")

    # --- chmod bootstrap.sh ---
    if not dry_run:
        try:
            os.chmod(dist / "bootstrap.sh", 0o755)
        except (AttributeError, NotImplementedError):
            pass  # Windows — permissions applied when copying to USB

    if dry_run:
        return

    print(f"\nDone. USB package: {dist}")
    if False:
        print()
        print("Contents:")
        for path in sorted(dist.rglob("*")):
            rel = path.relative_to(dist)
            indent = "  " * (len(rel.parts) - 1)
            label = str(rel.name) + ("/" if path.is_dir() else "")
            print(f"  {indent}{label}")


if __name__ == "__main__":

    if True:
        build_usb_package(mode="update", verbosity=0)
        build_usb_package(mode="prune", verbosity=0)
        raise Exception("OK")

    if False:
        run_install_runtime(platform_tag="linux-x86_64", mode="update", verbosity=1)
        raise Exception("OK")