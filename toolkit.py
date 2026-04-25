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
    log_path.parent.mkdir(parents=True, exist_ok=True)

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
        cache_dir = Path(os.path.join(dist_root, "runtimes", platform_tag))
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


def _member_needs_extract(member: tarfile.TarInfo, target: Path) -> bool:
    """Return True if the archive member should overwrite (or create) target."""
    if member.isdir():
        return not target.exists()
    if member.isfile():
        if not target.exists():
            return True
        if target.stat().st_size != member.size:
            return True
        if int(target.stat().st_mtime) < int(member.mtime):
            return True
    return False


def _extract_members(
    tf: tarfile.TarFile,
    dest: Path,
    platform_tag: str,
    incremental: bool,
    dry_run: bool,
) -> set:
    """Iterate archive members, extract/skip as needed; return expected path set."""
    expected = _collect_expected_paths(tf, dest)
    members = tf.getmembers()
    total = len(members)
    for i, member in enumerate(members, 1):
        target = _safe_member_path(dest, member.name)
        tag = f"  {platform_tag}: [{i:>{len(str(total))}}/{total}]"
        if member.isdir():
            if not target.exists():
                print(f"{tag} mkdir       {member.name}/")
                if not dry_run:
                    target.mkdir(parents=True, exist_ok=True)
            else:
                print(f"{tag} skip-dir    {member.name}/")
            continue
        if member.issym() or member.islnk():
            print(f"{tag} skip-link   {member.name}")
            continue
        if not member.isfile():
            print(f"{tag} skip-spcl   {member.name}")
            continue
        if incremental and not _member_needs_extract(member, target):
            print(f"{tag} fresh       {member.name}")
            continue
        verb = "would-write" if dry_run else "write      "
        print(f"{tag} {verb} {member.name}")
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            tf.extract(member, path=str(dest))
    return expected


def _prune_spurious(
    dest: Path, expected: set, platform_tag: str, dry_run: bool = False
) -> None:
    """Delete files/dirs under dest that are not in expected."""
    for dirpath, dirnames, filenames in os.walk(dest, topdown=False):
        root_path = Path(dirpath).resolve()
        for name in filenames:
            path = (root_path / name).resolve()
            if path not in expected:
                verb = "would-delete" if dry_run else "delete"
                print(f"  {platform_tag}: {verb} file  {path}")
                if not dry_run:
                    path.unlink()
        for name in dirnames:
            path = (root_path / name).resolve()
            if path not in expected:
                verb = "would-delete" if dry_run else "delete"
                print(f"  {platform_tag}: {verb} dir   {path}")
                if not dry_run:
                    shutil.rmtree(path)


def _extract_runtime(
    archive: Path,
    dest_dir: Path,
    platform_tag: str,
    mode: str = "full",
) -> None:
    """Extract or update a python-build-standalone install_only archive into dest_dir.

    Modes
    -----
    full    Clear dest_dir then extract every member.  (default; used by build_usb_package)
    update  Incremental: skip files that are already present and up to date (size/mtime).
    check   Dry run: print what *update* + *prune* would do; make no changes.
    prune   Incremental update then delete files not present in the archive.
    """
    dry_run     = (mode == "check")
    incremental = (mode in ("update", "prune", "check"))

    if mode == "full" and dest_dir.exists() and not dry_run:
        print(f"  {platform_tag}: clearing existing dir ...")
        shutil.rmtree(dest_dir)

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()

    print(f"  {platform_tag}: mode={mode}  archive={archive.name}")
    with tarfile.open(archive, "r:*") as tf:
        expected = _extract_members(
            tf, dest_resolved, platform_tag,
            incremental=incremental, dry_run=dry_run,
        )

    if mode in ("prune", "check"):
        _prune_spurious(dest_resolved, expected, platform_tag, dry_run=dry_run)

    if dry_run:
        return

    python_bin = dest_dir / "python" / "bin" / "python3"
    if python_bin.exists():
        print(f"  {platform_tag}: OK -- {python_bin}")
    else:
        print(f"  {platform_tag}: WARNING -- {python_bin} not found after extraction")


def build_usb_package(dist_root: Path = None) -> None:
    """Build dist/NIELSOLN_RESCUE_USB from repo sources.

    import runpy ; temp = runpy._run_module_as_main("toolkit")
    """
    if dist_root is None: dist_root = file__fileSysD
    assert os.path.isdir(dist_root), f"dist_root is not an existing directory: {dist_root!r}"

    root = Path(dist_root)
    dist = root / "dist" / "NIELSOLN_RESCUE_USB"

    print(f"Building USB package into: {dist}")

    if dist.exists():
        print("Removing existing dist folder...")
        shutil.rmtree(dist)

    dist.mkdir(parents=True)

    # Core files
    for name in ["bootstrap.sh", "bootstrap.py", "toolkit.py"]:
        shutil.copy2(root / name, dist / name)
        print(f"  Copied {name}")

    # Runtimes — download if needed, verify checksum, extract to dist
    print("\nChecking runtime caches ...")
    for entry in iter_runtime_plan(dist_root=root):
        platform_tag = entry["platform_tag"]
        dest_dir = dist / "runtimes" / platform_tag
        dest_dir.mkdir(parents=True, exist_ok=True)

        if entry["warning"]:
            print(f"  {platform_tag}: WARNING -- {entry['warning']}")
            _write_runtime_placeholder(dest_dir, platform_tag)
            continue

        if not entry["cache_ok"]:
            # Need to (re-)download
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
                    # Refresh entry so the copy block below runs
                    entry = dict(entry, cache_ok=True)
                else:
                    print(f"    ERROR: checksum mismatch after download -- skipping {platform_tag}")
                    if cached_file.exists():
                        cached_file.unlink()
                    _write_runtime_placeholder(dest_dir, platform_tag)
                    continue
            except RuntimeError as exc:
                print(f"    ERROR: download failed -- {exc}")
                _write_runtime_placeholder(dest_dir, platform_tag)
                continue

        _extract_runtime(entry["cached_file"], dest_dir, platform_tag)

    # Make bootstrap.sh executable on Unix-like systems
    try:
        os.chmod(dist / "bootstrap.sh", 0o755)
    except (AttributeError, NotImplementedError):
        pass  # Windows -- permissions applied when copying to USB

    print(f"\nDone. USB package: {dist}")
    print()
    print("Contents:")
    for path in sorted(dist.rglob("*")):
        rel = path.relative_to(dist)
        indent = "  " * (len(rel.parts) - 1)
        label = str(rel.name) + ("/" if path.is_dir() else "")
        print(f"  {indent}{label}")


if __name__ == "__main__":

    if True:
        build_usb_package()
        raise Exception("OK")