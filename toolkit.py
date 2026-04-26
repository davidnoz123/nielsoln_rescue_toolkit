r"""
toolkit.py — Nielsoln Rescue Toolkit: all core logic.

C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe

import runpy ; temp = runpy._run_module_as_main("toolkit")
    
"""

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import bz2 as _bz2
import csv
import dataclasses
import gzip
import hashlib
import html
import io
import json
import logging
import lzma
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
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
# scan — ClamAV orchestration (robust low-memory profiles)
# ---------------------------------------------------------------------------

_scan_log = logging.getLogger("scan")

# Ordered list of Windows subdirectories scanned as separate checkpointed
# units, from highest malware prevalence to lowest.
_WIN_SCAN_DIRS = [
    "Windows/System32",
    "Windows/SysWOW64",
    "Windows/Temp",
    "Windows",               # remaining Windows files (not System32/SysWOW64/Temp)
    "Users",
    "ProgramData",
    "Program Files",
    "Program Files (x86)",
    ".",                     # root-level files only (non-recursive catch-all)
]

# Extensions targeted by the quick profile (no archive scanning).
_QUICK_EXTENSIONS = [
    "*.exe", "*.dll", "*.sys", "*.bat", "*.cmd",
    "*.ps1", "*.vbs", "*.js", "*.jse", "*.wsf",
    "*.scr", "*.pif", "*.com", "*.cpl", "*.msi",
    "*.hta", "*.lnk",
]

# clamscan flags common to all profiles.
_CLAMSCAN_COMMON = [
    "--recursive",
    "--infected",
    "--no-summary",
]

# Quick profile: executable/script types only, no archive expansion.
_PROFILE_QUICK = [
    "--scan-archive=no",
    "--max-filesize=20M",
    "--max-scansize=50M",
    "--max-recursion=3",
    "--max-files=500",
    "--pcre-max-filesize=5M",
]

# Thorough profile: archives enabled but tightly bounded to prevent OOM.
_PROFILE_THOROUGH = [
    "--scan-archive=yes",
    "--scan-ole2=yes",
    "--scan-pdf=yes",
    "--scan-html=yes",
    "--max-filesize=50M",
    "--max-scansize=200M",
    "--max-recursion=5",
    "--max-files=500",
    "--max-embeddedpe=10M",
    "--max-htmlnormalize=5M",
    "--max-scriptnormalize=5M",
    "--max-ziptypercg=5M",
    "--max-partitions=50",
    "--pcre-max-filesize=10M",
]


def _setup_swap(swap_mb: int = 2048) -> str | None:
    """Create and activate a swap file of *swap_mb* MiB on /tmp.

    Returns the path to the swap file on success, None if it could not be
    created (e.g. not root, not enough space, already present).
    """
    swap_path = "/tmp/nrt_rescue_swap"
    try:
        if os.path.exists(swap_path):
            _scan_log.info("Swap file already exists at %s — skipping creation.", swap_path)
            return swap_path

        _scan_log.info("Creating %d MiB swap file at %s …", swap_mb, swap_path)
        print(f"  Setting up {swap_mb} MiB swap file ({swap_path}) …", flush=True)

        # fallocate is faster; fall back to dd.
        rc = subprocess.run(  # noqa: S603
            ["fallocate", "-l", f"{swap_mb}M", swap_path],
            capture_output=True,
        ).returncode
        if rc != 0:
            subprocess.run(  # noqa: S603
                ["dd", "if=/dev/zero", f"of={swap_path}", "bs=1M", f"count={swap_mb}"],
                capture_output=True,
                check=True,
            )

        os.chmod(swap_path, 0o600)
        subprocess.run(["mkswap", swap_path], capture_output=True, check=True)  # noqa: S603
        subprocess.run(["swapon", swap_path], capture_output=True, check=True)  # noqa: S603
        _scan_log.info("Swap activated: %s", swap_path)
        print(f"  Swap activated ({swap_mb} MiB).", flush=True)
        return swap_path

    except Exception as exc:
        _scan_log.warning("Could not set up swap: %s", exc)
        print(f"  WARNING: Could not set up swap: {exc}", flush=True)
        return None


def _teardown_swap(swap_path: str) -> None:
    """Deactivate and remove the swap file created by _setup_swap."""
    try:
        subprocess.run(["swapoff", swap_path], capture_output=True)  # noqa: S603
        os.unlink(swap_path)
        _scan_log.info("Swap removed: %s", swap_path)
    except Exception as exc:
        _scan_log.warning("Could not remove swap %s: %s", swap_path, exc)


def _check_free_ram_mb() -> int:
    """Return available RAM in MiB from /proc/meminfo (0 if unreadable)."""
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except Exception:
        pass
    return 0


def _check_oom_killed(pid: int | None = None) -> bool:
    """Return True if dmesg shows a recent OOM kill (optionally for *pid*)."""
    try:
        out = subprocess.run(  # noqa: S603
            ["dmesg"],
            capture_output=True, text=True,
        ).stdout
        needle = str(pid) if pid else "clamscan"
        for line in out.splitlines():
            low = line.lower()
            if "oom" in low or "out of memory" in low or "killed process" in low:
                if needle in line:
                    return True
        return False
    except Exception:
        return False


def _stage_clamav_certs(extracted_root: Path) -> None:
    """Ensure /usr/local/etc/certs exists so the bundled clamscan can verify CVDs.

    The bundled clamscan binary has '/usr/local/etc/certs' compiled in as the
    certificate directory.  In the live environment that path doesn't exist,
    which causes 'Broken or not a CVD file' errors.
    """
    dst = Path("/usr/local/etc/certs")
    if dst.exists():
        return
    src = extracted_root / "usr" / "local" / "etc" / "certs"
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.exists():
            shutil.copytree(str(src), str(dst))
            _scan_log.info("Staged ClamAV certs: %s -> %s", src, dst)
        else:
            dst.mkdir(parents=True, exist_ok=True)
            _scan_log.info("Created empty certs dir %s (no bundled certs found)", dst)
    except Exception as exc:
        _scan_log.warning("Could not stage certs dir: %s", exc)


def _resolve_clamscan(root: Path) -> tuple[str | None, dict | None]:
    """Return (clamscan_path, env) or (None, None) if not found."""
    clamscan = shutil.which("clamscan")
    scan_env = None

    if clamscan is None:
        bundled = (
            root / "clamav" / "linux-x86_64" / "extracted"
            / "usr" / "local" / "bin" / "clamscan"
        )
        if bundled.exists():
            extracted_root = root / "clamav" / "linux-x86_64" / "extracted"
            lib_dir = extracted_root / "usr" / "local" / "lib"
            scan_env = dict(os.environ)
            _stage_clamav_certs(extracted_root)
            if lib_dir.exists():
                try:
                    _lib_tmp_str, _ = _stage_clamav_libs(lib_dir)
                    scan_env["_NRT_LIB_TMP"] = _lib_tmp_str
                    prev = scan_env.get("LD_LIBRARY_PATH", "")
                    scan_env["LD_LIBRARY_PATH"] = (
                        f"{_lib_tmp_str}:{prev}" if prev else _lib_tmp_str
                    )
                except Exception as exc:
                    _scan_log.warning("Could not stage ClamAV libs: %s", exc)
                    prev = scan_env.get("LD_LIBRARY_PATH", "")
                    scan_env["LD_LIBRARY_PATH"] = (
                        f"{lib_dir}:{prev}" if prev else str(lib_dir)
                    )
                    scan_env["_NRT_LIB_TMP"] = ""
            try:
                clamscan, _clamscan_tmp = _ensure_executable(str(bundled))
                scan_env["_NRT_CLAMSCAN_TMP"] = _clamscan_tmp or ""
            except RuntimeError as exc:
                _scan_log.warning("%s", exc)

    return clamscan, scan_env


def _run_clamscan_on_dir(
    clamscan: str,
    scan_env: dict | None,
    target_dir: Path,
    profile_flags: list,
    include_exts: list | None,
    db_args: list,
    log_path: Path,
    verbose: bool = False,
) -> int:
    """Run clamscan against a single directory. Returns the raw exit code."""
    cmd = [clamscan] + _CLAMSCAN_COMMON + profile_flags + db_args
    if include_exts:
        for ext in include_exts:
            cmd += ["--include", ext]
    cmd += [f"--log={log_path}", str(target_dir)]

    if verbose:
        print(f"    cmd: {' '.join(cmd)}", flush=True)

    # Strip internal lifecycle keys — don't pass them to clamscan, and don't
    # delete the files here; run_scan owns that lifecycle across all segments.
    clean_env = None
    if scan_env is not None:
        clean_env = {k: v for k, v in scan_env.items()
                     if k not in ("_NRT_CLAMSCAN_TMP", "_NRT_LIB_TMP")}

    result = subprocess.run(cmd, env=clean_env)  # noqa: S603
    return result.returncode


def run_scan(
    root: Path = None,
    target: Path = None,
    profile: str = "quick",
    no_swap: bool = False,
    resume: bool = True,
    verbose: bool = False,
) -> int:
    """Run a ClamAV scan against *target* with OOM-safe memory limits.

    Usage (from REPL):
        import runpy ; temp = runpy._run_module_as_main("bootstrap")

    Profiles:
        quick    — executables/scripts only, no archive scanning (~350 MB RAM)
        thorough — archives enabled, tightly bounded (~600 MB peak, needs swap)

    Exit codes:
        0  clean
        1  interrupted / partial (SIGKILL / OOM)
        2  target not found
        3  clamscan not available
        4  infected files found
        5  error during scan
    """
    if root is None:
        root = Path(file__fileSysD)  # noqa: F821
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"

    if target is None or not target.exists():
        _scan_log.error("Target does not exist: %s", target)
        print(f"ERROR: Target does not exist: {target}")
        return 2

    # ---- resolve clamscan binary (staged once; cleaned up in finally below) ----
    clamscan, scan_env = _resolve_clamscan(root)
    clamscan_tmp = (scan_env or {}).get("_NRT_CLAMSCAN_TMP") or None
    lib_tmp = (scan_env or {}).get("_NRT_LIB_TMP") or None
    if clamscan is None:
        msg = (
            "clamscan not found. ClamAV is not installed, not on PATH, and not bundled.\n"
            "Run `bootstrap clamav --install` then `bootstrap clamav --update-db`.\n"
            "Run `bootstrap triage` for a Python-only scan instead."
        )
        _scan_log.warning(msg)
        print(msg)
        return 3

    # ---- select profile ----
    if profile == "thorough":
        profile_flags = _PROFILE_THOROUGH
        include_exts = None        # scan all file types
        swap_mb = 2048
    else:
        profile = "quick"          # default / normalise
        profile_flags = _PROFILE_QUICK
        include_exts = _QUICK_EXTENSIONS
        swap_mb = 1024

    # ---- check RAM and set up swap ----
    free_ram = _check_free_ram_mb()
    swap_path = None
    if not no_swap:
        min_ram = 500 if profile == "quick" else 700
        if free_ram < min_ram:
            print(
                f"  Available RAM: {free_ram} MiB — below {min_ram} MiB threshold. "
                f"Setting up swap …",
                flush=True,
            )
            swap_path = _setup_swap(swap_mb)
        else:
            print(f"  Available RAM: {free_ram} MiB — swap not required.", flush=True)
    else:
        print(f"  Available RAM: {free_ram} MiB (swap disabled by --no-swap).", flush=True)

    # ---- prepare log / report dirs ----
    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    timestamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_log_path = logs_dir / f"clamav_{profile}_{timestamp}.log"

    # ---- database args ----
    db_dir = root / "clamav" / "linux-x86_64" / "db"
    db_args = [f"--database={db_dir}"] if (db_dir.is_dir() and any(db_dir.glob("*.c?d"))) else []

    # ---- checkpoint file ----
    checkpoint_path = root / "logs" / f"scan_checkpoint_{profile}.txt"
    completed_dirs: set[str] = set()
    if resume and checkpoint_path.exists():
        completed_dirs = set(checkpoint_path.read_text(encoding="utf-8").splitlines())
        if completed_dirs:
            print(
                f"  Resuming: {len(completed_dirs)} director(ies) already completed "
                f"({checkpoint_path.name}).",
                flush=True,
            )

    # ---- build the list of directories to scan ----
    scan_dirs: list[Path] = []
    for rel in _WIN_SCAN_DIRS:
        if rel == ".":
            scan_dirs.append(target)
        else:
            candidate = target / rel
            if candidate.exists():
                scan_dirs.append(candidate)

    # If target doesn't look like a Windows root, scan it directly as one unit.
    if not scan_dirs:
        scan_dirs = [target]

    print(
        f"\n=== NIELSOLN ClamAV SCAN ({profile.upper()}) ===",
        flush=True,
    )
    print(f"  Target : {target}", flush=True)
    print(f"  Profile: {profile}", flush=True)
    print(f"  Log    : {scan_log_path}", flush=True)
    print(f"  Units  : {len(scan_dirs)} director(ies)", flush=True)
    print(flush=True)

    infected_total = 0
    oom_killed = False
    errored = False
    scanned_count = 0

    try:
        for scan_dir in scan_dirs:
            dir_key = str(scan_dir)
            if dir_key in completed_dirs:
                print(f"  [skip]  {scan_dir} (already done)", flush=True)
                continue

            print(f"  [scan]  {scan_dir} …", flush=True)
            _scan_log.info("Scanning: %s", scan_dir)

            # Each dir gets its own numbered log segment so partial results survive.
            seg_log = logs_dir / f"clamav_{profile}_{timestamp}_{scanned_count:02d}.log"
            scanned_count += 1

            rc = _run_clamscan_on_dir(
                clamscan,
                dict(scan_env) if scan_env else None,  # fresh copy each time
                scan_dir,
                profile_flags,
                include_exts,
                db_args,
                seg_log,
                verbose=verbose,
            )

            _scan_log.info("Segment exit code %d: %s", rc, scan_dir)

            if rc in (-9, 137):
                # SIGKILL — almost certainly OOM
                oom_hint = " (OOM killer likely — check: dmesg | grep -i oom)" if _check_oom_killed() else ""
                msg = f"  [KILL]  clamscan killed (SIGKILL) while scanning {scan_dir}{oom_hint}"
                print(msg, flush=True)
                _scan_log.error(msg)
                oom_killed = True
                break  # stop — don't attempt more dirs under memory pressure

            if rc == 1:
                infected_total += 1
                print(f"  [INFECTED] threats found in {scan_dir}", flush=True)
            elif rc == 2:
                print(f"  [ERROR] clamscan error in {scan_dir}", flush=True)
                errored = True
            elif rc == 0:
                print(f"  [clean]  {scan_dir}", flush=True)

            # Only checkpoint dirs that completed successfully (rc 0=clean, 1=infected).
            # rc 2 = clamscan error — do not checkpoint so the dir is retried next run.
            if rc in (0, 1):
                with checkpoint_path.open("a", encoding="utf-8") as f:
                    f.write(dir_key + "\n")
                completed_dirs.add(dir_key)

    finally:
        # Clean up the staged clamscan binary and libs (created once for all segments).
        if clamscan_tmp:
            try:
                os.unlink(clamscan_tmp)
            except OSError:
                pass
        if lib_tmp:
            shutil.rmtree(lib_tmp, ignore_errors=True)
        if swap_path:
            _teardown_swap(swap_path)

    # ---- summary report ----
    total_dirs = len(scan_dirs)
    skipped = len([d for d in scan_dirs if str(d) in completed_dirs - {str(d) for d in scan_dirs if d not in scan_dirs}])
    status = "PARTIAL (killed)" if oom_killed else ("COMPLETE" if not errored else "COMPLETE with errors")

    summary_lines = [
        "=" * 50,
        "NIELSOLN SCAN SUMMARY",
        f"  Date       : {timestamp}",
        f"  Target     : {target}",
        f"  Profile    : {profile}",
        f"  Status     : {status}",
        f"  Infected   : {infected_total} segment(s) with threats",
        f"  Scanned    : {scanned_count}/{total_dirs} unit(s)",
        f"  Log        : {scan_log_path}",
    ]
    if oom_killed:
        summary_lines.append("  ACTION     : Add more swap and re-run (--resume will skip completed dirs)")
        summary_lines.append("  DIAGNOSE   : dmesg | grep -i oom")
    if checkpoint_path.exists() and not oom_killed:
        # Clean run completed — remove checkpoint so next run starts fresh.
        checkpoint_path.unlink(missing_ok=True)
        summary_lines.append(f"  Checkpoint : removed (scan complete)")
    elif checkpoint_path.exists():
        summary_lines.append(f"  Checkpoint : {checkpoint_path} (resume with --resume)")
    summary_lines.append("=" * 50)

    summary = "\n".join(summary_lines)
    print("\n" + summary, flush=True)
    _scan_log.info(summary)

    # Write summary to a fixed-name file for easy retrieval.
    report_path = logs_dir / f"scan_report_{profile}_{timestamp}.txt"
    report_path.write_text(summary + "\n", encoding="utf-8")
    print(f"  Report: {report_path}", flush=True)

    if oom_killed:
        return 1
    if infected_total > 0:
        return 4
    if errored:
        return 5
    return 0


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

    # Send Cache-Control: no-cache so CDN nodes (e.g. Fastly on
    # raw.githubusercontent.com) revalidate with the origin instead of
    # serving a stale cached copy.  Query-string timestamps alone are not
    # sufficient because Fastly strips query params from its cache key by
    # default for GitHub raw content.
    req = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status} for {url}")
            return resp.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error fetching {url}: {exc}") from exc


# ---------------------------------------------------------------------------
# time_sync — Check and optionally correct the system clock via HTTP Date header
# ---------------------------------------------------------------------------

_time_sync_log = logging.getLogger("time_sync")

# Session flag written to /tmp after a successful clock check.  /tmp is tmpfs
# on Linux — wiped on every reboot — so this is always absent after a fresh
# boot (the most likely time for a dead CMOS to matter).  Its presence means
# we already synced the clock once this session and do not need to do it again.
_NRT_TIME_FLAG = "/tmp/.nrt_time_ok"

# Probed in order; first reachable URL wins.
_TIME_PROBE_URLS = [
    "https://www.google.com",
    "https://www.cloudflare.com",
]


def _get_internet_time(timeout: int = 10) -> float:
    """Return current UTC time as a Unix epoch float, sourced from the internet.

    Primary method: parse the RFC 2822 `Date` response header from a GET
    request to a reliable HTTPS server.  Falls back to the worldtimeapi.org
    JSON body if none of the primary URLs return a usable Date header.

    Raises RuntimeError if all sources fail.
    """
    import urllib.request
    import urllib.error
    import email.utils

    for url in _TIME_PROBE_URLS:
        try:
            req = urllib.request.Request(
                url,
                headers={"Cache-Control": "no-cache"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                date_str = resp.headers.get("Date", "")
                if date_str:
                    dt = email.utils.parsedate_to_datetime(date_str)
                    return dt.timestamp()
        except Exception:  # noqa: BLE001
            continue

    # Fallback: worldtimeapi.org returns a JSON body with a `unixtime` field.
    try:
        fallback_url = "http://worldtimeapi.org/api/ip"
        req = urllib.request.Request(fallback_url, headers={"Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            import json as _json
            data = _json.loads(resp.read().decode("utf-8"))
            return float(data["unixtime"])
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"Could not determine internet time from any source: {exc}"
        ) from exc


def run_sync_time(root=None, threshold_seconds: int = 120, dry_run: bool = False) -> int:
    """Compare the system clock to internet time and correct it if the skew is large.

    Steps:
      1. Fetch internet time via HTTP Date header (see _get_internet_time).
      2. Compute skew = internet_time - time.time().
      3. If abs(skew) <= threshold_seconds: print "Clock OK" and return 0.
      4. On non-Linux or non-root: print a warning about the skew; return 1.
      5. Run `date -s @<epoch>` to set the system clock.  Return 0 on success.

    Non-fatal by design — callers should warn and continue if this returns non-zero.

    Why this matters: RescueZilla boots from a live USB; old laptops frequently
    have a dead CMOS battery.  A hardware clock years in the past causes TLS
    certificate validation failures that look like network errors.

    A session flag (_NRT_TIME_FLAG) is written to /tmp after the first successful
    check.  Subsequent calls this session return 0 immediately — no network probe
    needed.  The flag lives in /tmp (tmpfs) so it is always absent after a reboot.
    """
    # --- session flag: already checked this boot? ---
    _flag = Path(_NRT_TIME_FLAG)
    if _flag.exists():
        _time_sync_log.debug("Clock already verified this session (flag: %s)", _flag)
        return 0

    _time_sync_log.info("Checking system clock against internet time ...")
    print("Checking system clock ...", end=" ", flush=True)
    try:
        internet_ts = _get_internet_time()
    except RuntimeError as exc:
        print(f"SKIP (cannot reach time server: {exc})")
        _time_sync_log.warning("Clock check skipped: %s", exc)
        return 0  # non-fatal; proceed without correction

    skew = internet_ts - time.time()
    _time_sync_log.info("Clock skew: %.1fs (internet=%.0f, local=%.0f)",
                         skew, internet_ts, time.time())

    if abs(skew) <= threshold_seconds:
        print(f"OK (skew {skew:+.1f}s)")
        _time_sync_log.info("Clock OK (skew %.1fs)", skew)
        try:
            _flag.write_text(str(int(time.time())), encoding="utf-8")
        except OSError:
            pass
        return 0

    # Skew exceeds threshold.
    skew_str = f"{skew:+.0f}s"
    print(f"SKEWED ({skew_str})")
    _time_sync_log.warning("Clock skew %s exceeds threshold (%ds)", skew_str, threshold_seconds)

    _correct_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(internet_ts))

    if not is_linux():
        print(f"WARNING: system clock is off by {skew_str} — cannot correct on non-Linux.")
        print(f'  Fix manually: sudo timedatectl set-time "{_correct_str}"')
        return 1

    if os.geteuid() != 0:
        print(f"WARNING: system clock is off by {skew_str} — cannot correct (not root).")
        print(f'  Fix manually: sudo timedatectl set-time "{_correct_str}"')
        _time_sync_log.warning("Not root; cannot set clock.")
        return 1

    if dry_run:
        correct_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(internet_ts))
        print(f"  dry-run: would set clock to {correct_str}")
        return 0

    try:
        result = subprocess.run(  # noqa: S603
            ["date", "-s", f"@{int(internet_ts)}"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            correct_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(internet_ts))
            print(f"  System clock set to {correct_str} (was off by {skew_str})")
            _time_sync_log.info("Clock corrected to %s (skew was %s)", correct_str, skew_str)
            try:
                _flag.write_text(str(int(internet_ts)), encoding="utf-8")
            except OSError:
                pass
            return 0
        else:
            print(f"  WARNING: `date -s` failed (exit {result.returncode}): {result.stderr.strip()}")
            print(f'  Fix manually: sudo timedatectl set-time "{_correct_str}"')
            print( "           or: sudo ntpdate pool.ntp.org")
            _time_sync_log.warning("`date -s` failed: %s", result.stderr.strip())
            return 1
    except OSError as exc:
        print(f"  WARNING: could not run `date -s`: {exc}")
        print(f'  Fix manually: sudo timedatectl set-time "{_correct_str}"')
        print( "           or: sudo ntpdate pool.ntp.org")
        _time_sync_log.warning("Could not run `date -s`: %s", exc)
        return 1


def run_push(
    root: Path = None,
    host: str = "",
    port: int = 22,
    key: str = "",
    remote_root: str = "",
    verbosity: int = 2,
) -> int:
    """Push the three source files to a running RescueZilla over SSH/SCP.

    Bypasses GitHub — pushes local working-tree files directly.
    After transfer, purges __pycache__ on the remote so new code takes effect
    immediately on the next run.

    Returns 0 on success, non-zero on failure.
    """
    if root is None:
        root = Path(__file__).resolve().parent

    if not host:
        print("ERROR: --host is required.")
        return 1

    # Build base ssh/scp options.
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-p", str(port)]
    if key:
        ssh_opts += ["-i", key]

    target = f"root@{host}"

    # Auto-detect remote root if not supplied: find bootstrap.sh under /media or /mnt.
    if not remote_root:
        if verbosity >= 1:
            print(f"  Auto-detecting remote root on {host} ...")
        try:
            result = subprocess.run(  # noqa: S603
                ["ssh"] + ssh_opts + [target,
                    "find /media /mnt /tmp -maxdepth 4 -name bootstrap.sh 2>/dev/null "
                    "| head -1 | xargs -r dirname"],
                capture_output=True, text=True, timeout=15,
            )
            remote_root = result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"ERROR: SSH auto-detect failed: {exc}")
            return 1
        if not remote_root:
            print("ERROR: Could not auto-detect remote root. Use --remote-root.")
            return 1
        if verbosity >= 1:
            print(f"  Remote root: {remote_root}")

    # Compute local LF-normalised SHA256 for each file.
    def _sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()

    files_to_push = [root / f for f in _UPDATE_FILES]
    missing = [f for f in files_to_push if not f.exists()]
    if missing:
        print(f"ERROR: local files not found: {[str(f) for f in missing]}")
        return 1

    if verbosity >= 1:
        print(f"\nPushing {len(files_to_push)} files to {target}:{remote_root}/")

    # SCP all three files in one call.
    scp_cmd = (
        ["scp", "-O", "-P", str(port)]   # -O = legacy SCP protocol (no sftp-server needed)
        + (["-i", key] if key else [])
        + ["-o", "StrictHostKeyChecking=no"]
        + [str(f) for f in files_to_push]
        + [f"{target}:{remote_root}/"]
    )
    if verbosity >= 2:
        print(f"  scp: {' '.join(scp_cmd)}")
    try:
        rc = subprocess.run(scp_cmd).returncode  # noqa: S603
    except OSError as exc:
        print(f"ERROR: scp failed: {exc}")
        return 1
    if rc != 0:
        print(f"ERROR: scp exited with code {rc}")
        return rc

    # Purge stale .pyc files on the remote.
    purge_cmd = (
        f"find {remote_root}/__pycache__ -name '*.pyc' -delete 2>/dev/null; "
        f"chmod +x {remote_root}/bootstrap.sh 2>/dev/null; true"
    )
    try:
        subprocess.run(["ssh"] + ssh_opts + [target, purge_cmd], timeout=15)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"  WARNING: post-push cleanup failed: {exc}")

    # Print local hashes so user can compare against `bootstrap update` output.
    print("\nPushed files (local LF-normalised SHA256):")
    for f in files_to_push:
        print(f"  {_sha(f)}  {f.name}")

    print(f"\nFiles are live on {host}. Changes take effect on the next bootstrap run.")
    return 0


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

    # Sync clock before any TLS-sensitive network activity.  A dead CMOS
    # battery causes the hardware clock to be years in the past, which makes
    # every HTTPS connection fail with a certificate validation error.  This
    # runs exactly once per boot session (guarded by a /tmp flag file).
    _sync_rc = run_sync_time(root)
    if _sync_rc != 0:
        print("  (continuing despite clock warning — update may fail if TLS rejects certs)")

    staging = root / "cache" / "update_staging"
    staging.mkdir(parents=True, exist_ok=True)

    # Snapshot SHA256 of every file before any replacements so we can
    # report clearly what changed.
    def _lf_sha256(path: Path) -> str:
        data = path.read_bytes().replace(b"\r\n", b"\n")
        return hashlib.sha256(data).hexdigest()

    pre_digests: dict = {}
    for filename in _UPDATE_FILES:
        p = root / filename
        if p.exists():
            pre_digests[filename] = _lf_sha256(p)
            _updater_log.info("%s SHA256 before update: %s", filename, pre_digests[filename])

    # Stage all files before touching anything live.
    # Append a timestamp to the URL to bypass GitHub's CDN cache.
    _cache_bust = int(time.time())
    staged: list = []
    for filename in _UPDATE_FILES:
        url = f"{_REPO_RAW_BASE}/{filename}?_={_cache_bust}"
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

    # Purge stale .pyc files from __pycache__.
    # FAT32 timestamps have 2-second granularity, so the mtime of the newly
    # written .py file can round to the same value as the old one.  Python's
    # .pyc invalidation check would then consider the cached bytecode valid
    # and load the old code.  Deleting the .pyc forces a fresh compile.
    pycache = root / "__pycache__"
    if pycache.is_dir():
        for filename in _UPDATE_FILES:
            stem = Path(filename).stem          # e.g. "toolkit"
            for pyc in pycache.glob(f"{stem}.cpython-*.pyc"):
                try:
                    pyc.unlink()
                    _updater_log.info("Removed stale bytecode: %s", pyc.name)
                    print(f"Removed stale bytecode: {pyc.name}")
                except OSError as exc:
                    _updater_log.debug("Could not remove %s: %s", pyc, exc)

    toolkit_dst = root / "toolkit.py"
    if toolkit_dst.exists():
        # Compute LF-normalized digest (matches GitHub raw / AGENTS.md table)
        print()
        any_changed = False
        for filename in _UPDATE_FILES:
            p = root / filename
            if not p.exists():
                continue
            after = _lf_sha256(p)
            before = pre_digests.get(filename, "(not found)")
            changed = after != before
            if changed:
                any_changed = True
            marker = "CHANGED" if changed else "unchanged"
            print(f"  {filename:<16} {marker}")
            print(f"    before: {before}")
            print(f"    after : {after}")
            _updater_log.info("%s SHA256 before: %s", filename, before)
            _updater_log.info("%s SHA256 after : %s", filename, after)
        if any_changed:
            print("\n*** Files changed — new versions active on next run ***")
        else:
            print("\n--- All files unchanged (already up to date) ---")

    print("\nUpdate complete. Changes take effect on the next run.")
    _updater_log.info("Update complete.")

    # --- Ensure dropbear is present (self-healing) ---
    # If the USB was set up manually or dropbear was never copied, fetch it now.
    # Skips silently if already present.
    print("\nChecking _tools/dropbear ...")
    try:
        download_dropbear(root, verbosity=1)
    except RuntimeError as exc:
        print(f"  WARNING: could not fetch dropbear: {exc}")
        print("  SSH will require the binary to be present — run: bootstrap.sh dropbear")
        _updater_log.warning("dropbear download failed during update: %s", exc)

    return 0


def _background_update_worker(root: Path = None) -> None:
    """Thread target — silently updates files; never raises."""
    if root is None: root = Path(file__fileSysD)
    assert root.exists() and root.is_dir(), f"root is not an existing directory: {root!r}"
    try:
        staging = root / "cache" / "update_staging"
        staging.mkdir(parents=True, exist_ok=True)

        # Append a timestamp to bypass GitHub's CDN cache.
        _cache_bust = int(time.time())
        staged: list = []
        for filename in _UPDATE_FILES:
            url = f"{_REPO_RAW_BASE}/{filename}?_={_cache_bust}"
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

        # Purge stale .pyc files (FAT32 mtime granularity — see run_update).
        pycache = root / "__pycache__"
        if pycache.is_dir():
            for filename in _UPDATE_FILES:
                stem = Path(filename).stem
                for pyc in pycache.glob(f"{stem}.cpython-*.pyc"):
                    try:
                        pyc.unlink()
                    except OSError:
                        pass

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
    return _clamav_install_path(root) / "usr" / "local" / "bin" / "clamscan"


def _ensure_executable(binary_path: str) -> tuple:
    """Return (path_to_use, tmp_path_or_None).

    FAT32/exFAT filesystems do not store Unix execute bits, so a binary
    extracted to the USB cannot be made executable via chmod.  When the
    binary is not executable, copy it to /tmp (tmpfs, supports execute
    permissions), chmod it there, and return that path instead.

    The caller is responsible for deleting tmp_path when done.
    """
    if os.access(binary_path, os.X_OK):
        return binary_path, None
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="nrt_bin_")
        os.close(tmp_fd)
        shutil.copy2(binary_path, tmp_path)
        os.chmod(tmp_path, 0o755)
        return tmp_path, tmp_path
    except OSError as exc:
        raise RuntimeError(
            f"Could not copy {binary_path} to /tmp to make it executable: {exc}"
        ) from exc


def _stage_clamav_libs(lib_dir: Path) -> tuple:
    """Copy ClamAV shared libraries to a tmpfs directory and recreate symlinks.

    FAT32/exFAT cannot store symlinks, so versioned stubs like
    libfreshclam.so.4 are absent after extraction to the USB.  The dynamic
    linker looks for exactly that name (from the ELF NEEDED entry), so the
    binary fails to start with 'cannot open shared object file'.

    This function:
      1. Creates a temp directory under /tmp (tmpfs supports symlinks).
      2. Copies all regular .so* files from lib_dir into it.
      3. Re-creates libfoo.so.X -> libfoo.so.X.Y.Z symlinks for each file
         whose name matches the *.so.X.Y[.Z] pattern.

    Returns (tmp_dir_path_str, tmp_dir_path).  Caller must delete tmp_dir_path
    (use shutil.rmtree) when done.
    """
    import re
    so_re = re.compile(r'^(?P<stem>.+\.so)\.(?P<major>\d+)\.\d.*$')

    tmp_dir = Path(tempfile.mkdtemp(prefix="nrt_clamlib_"))
    try:
        for src in lib_dir.iterdir():
            if src.is_file() and not src.is_symlink():
                shutil.copy2(src, tmp_dir / src.name)

        # Recreate libfoo.so.X -> libfoo.so.X.Y.Z symlinks
        for f in list(tmp_dir.iterdir()):
            m = so_re.match(f.name)
            if m:
                link_name = f"{m.group('stem')}.{m.group('major')}"
                link_path = tmp_dir / link_name
                if not link_path.exists():
                    link_path.symlink_to(f.name)
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    return str(tmp_dir), tmp_dir


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

    skipped_links = 0
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        members = tf.getmembers()
        total = len(members)
        for i, member in enumerate(members, 1):
            if verbosity >= 2 and i % 200 == 0:
                print(f"  clamav: extracting ... [{i}/{total}]")
            # filter='data' skips uid/gid restoration (avoids "Cannot change
            # ownership" warnings when not running as root).
            try:
                tf.extract(member, path=str(dest_dir), filter="data")
            except OSError:
                # Symlinks and hardlinks fail on FAT32/exFAT — skip them.
                # ClamAV still works without them.
                if member.issym() or member.islnk():
                    skipped_links += 1
                else:
                    raise
    if skipped_links and verbosity >= 1:
        print(f"  clamav: skipped {skipped_links} symlink(s) (filesystem does not support them)")
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
        # Two-phase extraction to avoid FAT32/exFAT errors:
        #   Phase 1 — extract to a temp dir on the native Linux filesystem
        #             (/tmp is tmpfs; dpkg-deb can set ownership/permissions freely)
        #   Phase 2 — copy regular files only to the USB install dir
        #             (symlinks are skipped because FAT32/exFAT cannot hold them)
        with tempfile.TemporaryDirectory(prefix="clamav_extract_") as _tmp:
            tmp_dir = Path(_tmp)
            result = subprocess.run(
                [dpkg_deb, "--extract", str(deb_path), str(tmp_dir)],
            )
            if result.returncode != 0:
                print(f"  WARNING: dpkg-deb exited {result.returncode} — continuing anyway")
            if verbosity >= 1:
                print("  copying extracted files to USB ...")
            install_dir.mkdir(parents=True, exist_ok=True)
            skipped_links = 0
            for src_item in tmp_dir.rglob("*"):
                rel = src_item.relative_to(tmp_dir)
                dst_item = install_dir / rel
                if src_item.is_symlink():
                    skipped_links += 1
                elif src_item.is_dir():
                    dst_item.mkdir(parents=True, exist_ok=True)
                elif src_item.is_file():
                    dst_item.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_item, dst_item)
            if skipped_links and verbosity >= 1:
                print(f"  skipped {skipped_links} symlink(s) (FAT32 does not support them)")
    else:
        if verbosity >= 1:
            print("  dpkg-deb not found — using pure-Python extractor")
        try:
            _extract_deb_python(deb_path, install_dir, verbosity=verbosity)
        except RuntimeError as exc:
            print(f"  ERROR: {exc}")
            return 1

    # Make all binaries in usr/local/bin/ executable (clamscan, freshclam, etc.)
    bin_dir = _clamav_install_path(root) / "usr" / "local" / "bin"
    if bin_dir.is_dir():
        for binary in bin_dir.iterdir():
            if binary.is_file():
                try:
                    binary.chmod(binary.stat().st_mode | 0o111)
                except OSError:
                    pass

    clamscan = get_clamav_executable(root)
    if clamscan.exists():
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
    bundled_freshclam = _clamav_install_path(root) / "usr" / "local" / "bin" / "freshclam"
    freshclam_path = (
        str(bundled_freshclam) if bundled_freshclam.exists()
        else shutil.which("freshclam")
    )
    if freshclam_path is None:
        print("freshclam not found.  Run `bootstrap clamav --install` first.")
        return 1

    db_dir = _clamav_cache_path(root) / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    # Check and correct the system clock before any TLS-sensitive network
    # activity.  A dead CMOS battery (common on old rescue targets) causes
    # the hardware clock to be years off, which makes TLS cert validation
    # fail with cryptic errors.  Non-fatal: we warn and continue if the
    # correction cannot be applied (e.g. not root on this live session).
    _sync_rc = run_sync_time(root)
    if _sync_rc != 0:
        print("  (continuing despite clock warning — freshclam may fail if TLS rejects certs)")

    # Add bundled lib path for dynamically linked freshclam.
    # FAT32/exFAT strips symlinks on extraction, so versioned stubs like
    # libfreshclam.so.4 are missing.  Stage the libs to /tmp (tmpfs) first
    # so the dynamic linker can find them via recreated symlinks.
    lib_dir = _clamav_install_path(root) / "usr" / "local" / "lib"
    env = dict(os.environ)

    # The bundled freshclam binary was compiled with /usr/local/etc/certs/ as
    # its hard-coded cert path.  That directory does not exist on RescueZilla.
    # SSL_CERT_FILE / SSL_CERT_DIR env vars only reach OpenSSL directly; they
    # do not fix freshclam's own internal cert lookup via the compiled-in path.
    # Solution: if the directory is absent and we are root, create it and
    # populate it with the system CA bundle so freshclam finds its certs.
    _CLAMAV_CERT_DIR = "/usr/local/etc/certs"
    _CERT_FILE_CANDIDATES = [
        "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",    # RHEL/CentOS
        "/etc/ssl/ca-bundle.pem",
    ]
    _system_ca_bundle: str = ""
    for _cf in _CERT_FILE_CANDIDATES:
        if os.path.isfile(_cf):
            _system_ca_bundle = _cf
            break

    if is_linux() and os.geteuid() == 0:
        # The bundled freshclam binary was compiled with /usr/local/etc/certs/ as
        # its hard-coded codesign cert path.  ClamAV's Rust codesign module reads
        # ClamAV-format (.crt) certificates from that directory to verify database
        # signatures.  It does NOT want system CA bundle files there — putting a
        # PEM CA bundle there causes an unwrap() panic in codesign.rs.
        #
        # Fix: copy ClamAV's own codesign certs (extracted from the .deb into the
        # USB bundle) to /usr/local/etc/certs/ on the live tmpfs filesystem.
        # Also remove any stale CA bundle file left by a previous toolkit version.
        _src_certs = _clamav_install_path(root) / "usr" / "local" / "etc" / "certs"
        try:
            os.makedirs(_CLAMAV_CERT_DIR, exist_ok=True)
            # Remove any stale system CA bundle we may have placed here previously.
            for _stale in ("ca-certificates.crt", "ca-bundle.crt", "ca-bundle.pem"):
                _stale_path = os.path.join(_CLAMAV_CERT_DIR, _stale)
                if os.path.isfile(_stale_path):
                    os.unlink(_stale_path)
                    if verbosity >= 2:
                        print(f"  removed stale CA bundle from {_CLAMAV_CERT_DIR}: {_stale}")
            # Copy ClamAV's own codesign certs from the extracted bundle.
            if _src_certs.is_dir():
                _copied = 0
                for _cert_src in _src_certs.iterdir():
                    if _cert_src.is_file():
                        _cert_dst = os.path.join(_CLAMAV_CERT_DIR, _cert_src.name)
                        if not os.path.exists(_cert_dst):
                            shutil.copy2(str(_cert_src), _cert_dst)
                            _copied += 1
                if verbosity >= 2:
                    if _copied:
                        print(f"  copied {_copied} ClamAV codesign cert(s) to {_CLAMAV_CERT_DIR}")
                    else:
                        print(f"  {_CLAMAV_CERT_DIR}: codesign certs already in place")
            else:
                if verbosity >= 1:
                    print(
                        f"  WARNING: no codesign certs found in extracted bundle"
                        f" ({_src_certs}) — freshclam database verification may fail"
                    )
        except OSError as _exc:
            if verbosity >= 1:
                print(f"  WARNING: could not populate {_CLAMAV_CERT_DIR}: {_exc}")
    elif not os.path.isdir(_CLAMAV_CERT_DIR) and verbosity >= 1:
        print(
            f"  WARNING: {_CLAMAV_CERT_DIR} does not exist and cannot be created"
            f" (root={is_linux() and os.geteuid()==0})"
            " — freshclam may fail with a certs error"
        )

    # Also set the standard OpenSSL env vars so any direct OpenSSL calls
    # (e.g. in linked libssl) also find the system CA bundle.
    if _system_ca_bundle:
        env.setdefault("SSL_CERT_FILE", _system_ca_bundle)
    if os.path.isdir("/etc/ssl/certs"):
        env.setdefault("SSL_CERT_DIR", "/etc/ssl/certs")

    freshclam_lib_tmp = None
    if lib_dir.exists():
        try:
            lib_tmp_str, freshclam_lib_tmp = _stage_clamav_libs(lib_dir)
            prev = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = f"{lib_tmp_str}:{prev}" if prev else lib_tmp_str
            if verbosity >= 2:
                print(f"  staged ClamAV libs to {lib_tmp_str}")
        except Exception as exc:
            if verbosity >= 1:
                print(f"  WARNING: could not stage ClamAV libs to /tmp: {exc}")
            prev = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = f"{lib_dir}:{prev}" if prev else str(lib_dir)

    # FAT32/exFAT cannot store execute bits — copy to /tmp if not executable.
    freshclam_tmp = None
    try:
        freshclam_path, freshclam_tmp = _ensure_executable(freshclam_path)
    except RuntimeError as exc:
        if freshclam_lib_tmp:
            shutil.rmtree(freshclam_lib_tmp, ignore_errors=True)
        print(f"ERROR: {exc}")
        return 1

    # freshclam refuses to run without a config file.  Write a minimal one
    # to /tmp so it parses cleanly.  --datadir on the command line overrides
    # the DatabaseDirectory directive inside the file.
    conf_fd, conf_tmp = tempfile.mkstemp(prefix="nrt_freshclam_", suffix=".conf")
    try:
        os.write(conf_fd, (
            f"DatabaseDirectory {db_dir}\n"
            "DatabaseMirror database.clamav.net\n"
            "DatabaseOwner root\n"
        ).encode())
    finally:
        os.close(conf_fd)

    cmd = [freshclam_path, f"--config-file={conf_tmp}", f"--datadir={db_dir}"]
    if verbosity >= 1:
        print("Running:", " ".join(cmd))
    try:
        result = subprocess.run(cmd, env=env)
    finally:
        try:
            os.unlink(conf_tmp)
        except OSError:
            pass
        if freshclam_tmp:
            try:
                os.unlink(freshclam_tmp)
            except OSError:
                pass
        if freshclam_lib_tmp:
            shutil.rmtree(freshclam_lib_tmp, ignore_errors=True)
    if result.returncode == 0 and verbosity >= 1:
        print(f"Database updated in {db_dir}")
    return result.returncode


# ---------------------------------------------------------------------------
# ssh — Start an openssh SSH server for remote VS Code access
# ---------------------------------------------------------------------------
#
# Division of responsibility:
#   bootstrap.sh  — installs openssh-server via apt if absent, starts sshd.
#                   Runs in pure bash so SSH is available even if Python breaks.
#   run_ssh()     — installs the authorised key, sets optional password,
#                   prints the VS Code Remote-SSH connection snippet.
#
# Invocation:
#   sudo bash bootstrap.sh ssh [--port 22] [--password <pw>] [--pubkey "<key>"]

# Add one entry per trusted developer machine.  All keys are installed into
# /root/.ssh/authorized_keys every time 'bootstrap.sh ssh' is run.
_SSH_BUNDLED_PUBKEYS = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOX9wXrgJFMzhn+QSWi0Ee2DgPfTdBa/qckRO7lrD6Lk david@LAPTOP-HB3IGVLU",
]

_ssh_log = logging.getLogger("ssh")


def _get_local_ips() -> list:
    """Return non-loopback IPv4 addresses for this host."""
    import socket
    ips = []
    try:
        # Connect to an external address to discover the outbound interface IP.
        # No data is sent — the socket is never actually connected.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
    except OSError:
        pass
    # Supplement with hostname-based lookup in case the above misses addresses.
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except OSError:
        pass
    return ips


def _install_authorized_key(pubkey: str) -> None:
    """Append pubkey to /root/.ssh/authorized_keys if not already present."""
    ssh_dir = Path("/root/.ssh")
    ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    auth_keys = ssh_dir / "authorized_keys"
    existing = auth_keys.read_text(encoding="utf-8") if auth_keys.exists() else ""
    # Match on the key material (second field) to avoid duplicates across comment changes.
    key_material = pubkey.split()[1] if len(pubkey.split()) >= 2 else pubkey
    if key_material not in existing:
        with auth_keys.open("a", encoding="utf-8") as f:
            f.write(pubkey.strip() + "\n")
    auth_keys.chmod(0o600)


def run_ssh(
    root=None,
    extra_pubkey: str = "",
    password: str = "",
    port: int = 22,
    verbosity: int = 2,
) -> int:
    """Start an SSH daemon (openssh or dropbear) and print connection details.

    Always installs the bundled developer key into /root/.ssh/authorized_keys.
    Optionally adds extra_pubkey and/or sets a temporary root password.

    Returns 0 on success, 1 on failure.
    """
    if not is_linux():
        print("ERROR: SSH server setup is only supported on Linux.")
        return 1

    if os.geteuid() != 0:
        print("ERROR: must run as root (sudo).")
        return 1

    # --- install keys ---
    for _key in _SSH_BUNDLED_PUBKEYS:
        _install_authorized_key(_key)
    if verbosity >= 1:
        print(f"  Installed {len(_SSH_BUNDLED_PUBKEYS)} bundled key(s) into /root/.ssh/authorized_keys.")
    if extra_pubkey.strip():
        _install_authorized_key(extra_pubkey.strip())
        if verbosity >= 1:
            print("  Installed extra public key.")

    # --- optionally set a temporary root password ---
    if password:
        try:
            result = subprocess.run(  # noqa: S603
                ["chpasswd"],
                input=f"root:{password}\n".encode(),
                capture_output=True,
            )
            if result.returncode == 0:
                if verbosity >= 1:
                    print("  Temporary root password set.")
            else:
                print(f"  WARNING: chpasswd failed: {result.stderr.decode().strip()}")
        except OSError as exc:
            print(f"  WARNING: could not set password: {exc}")

    # --- verify dropbear is running ---
    # bootstrap.sh starts dropbear before Python runs.  We just check that
    # the process is up so we can print connection details.  If called
    # directly (not via bootstrap.sh), emit a clear error.
    _dropbear_binary = "/tmp/dropbear_rescue"
    _dropbear_running = False
    try:
        result = subprocess.run(  # noqa: S603
            ["pgrep", "-x", "dropbear_rescue"],
            capture_output=True,
        )
        _dropbear_running = result.returncode == 0
    except OSError:
        pass

    if not _dropbear_running:
        if not os.path.isfile(_dropbear_binary):
            print(
                "ERROR: dropbear is not running and _tools/dropbear was not found.\n"
                "Run:  sudo bash bootstrap.sh ssh"
            )
            return 1
        # Binary exists but process not found — bootstrap.sh may have started
        # dropbear in the foreground (it exited).  Not an error here; connection
        # details are still useful.
        if verbosity >= 1:
            print("  WARNING: dropbear process not detected (may have exited).")

    # --- print connection info ---
    ips = _get_local_ips()
    port_suffix = f" -p {port}" if port != 22 else ""
    config_port = f"\n    Port {port}" if port != 22 else ""

    print()
    print("=" * 60)
    print("  dropbear SSH server is running")
    print("=" * 60)
    if not ips:
        print("  (could not detect IP — check with: ip addr)")
    print()
    print("  Connect from Windows/Mac/Linux terminal:")
    for ip in (ips or ["<IP_ADDRESS>"]):
        print(f"    ssh -i ~/.ssh/id_ed25519 root@{ip}{port_suffix}")
    print()
    print("  VS Code Remote-SSH config (~/.ssh/config):")
    print()
    for ip in (ips or ["<IP_ADDRESS>"]):
        print(f"    Host rescuezilla-{ip.replace('.', '-')}")
        print(f"        HostName {ip}")
        print( "        User root")
        print(f"        IdentityFile ~/.ssh/id_ed25519{config_port}")
        print()
    print("  In VS Code: Ctrl+Shift+P -> Remote-SSH: Connect to Host")
    print("=" * 60)
    _ssh_log.info("SSH server started on port %d. IPs: %s", port, ips)
    return 0


# ---------------------------------------------------------------------------
# dropbear — download and bundle the dropbear SSH server binary
# ---------------------------------------------------------------------------
#
# Dropbear (~160 KB) is a self-contained SSH server.  Bundling it on the USB
# means bootstrap.sh can start an SSH server on RescueZilla with no network
# access or apt-get.
#
# Source: Ubuntu 22.04 LTS (jammy) — binary runs on any modern Linux kernel.
# The .deb is fetched, parsed with a stdlib ar/tar reader, and the ELF binary
# is written to <usb-root>/_tools/dropbear.
#
# The binary also requires four shared libraries that may not be present on
# the live system.  They are bundled alongside the binary so that bootstrap.sh
# can start dropbear with LD_LIBRARY_PATH pointing at _tools/ — no apt-get
# needed at all.  All packages are from Ubuntu 22.04 (jammy), matching the
# dropbear binary.

_DROPBEAR_URLS = [
    "http://security.ubuntu.com/ubuntu/pool/universe/d/dropbear/"
    "dropbear-bin_2020.81-5ubuntu0.1_amd64.deb",
    # archive.ubuntu.com fallback
    "http://archive.ubuntu.com/ubuntu/pool/universe/d/dropbear/"
    "dropbear-bin_2020.81-5ubuntu0.1_amd64.deb",
]

# Each entry: (so_filename, deb_url)
# Versions confirmed via Ubuntu 22.04 (jammy) archive directory listings.
_DROPBEAR_LIB_PACKAGES = [
    (
        "libatomic.so.1",
        "http://archive.ubuntu.com/ubuntu/pool/main/g/gcc-12/"
        "libatomic1_12.3.0-1ubuntu1~22.04.3_amd64.deb",
    ),
    (
        "libtomcrypt.so.1",
        "http://archive.ubuntu.com/ubuntu/pool/universe/libt/libtomcrypt/"
        "libtomcrypt1_1.18.2+dfsg-7build2_amd64.deb",
    ),
    (
        "libtommath.so.1",
        "http://archive.ubuntu.com/ubuntu/pool/main/libt/libtommath/"
        "libtommath1_1.2.0-6ubuntu0.22.04.1_amd64.deb",
    ),
    (
        "libgmp.so.10",
        "http://archive.ubuntu.com/ubuntu/pool/main/g/gmp/"
        "libgmp10_6.2.1+dfsg-3ubuntu1_amd64.deb",
    ),
]


def _iter_ar(data: bytes):
    """Yield (name, content) for each member of an ar archive."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("Not an ar archive")
    pos = 8
    while pos + 60 <= len(data):
        name = data[pos: pos + 16].rstrip().decode("latin-1")
        size = int(data[pos + 48: pos + 58].strip())
        pos += 60
        content = data[pos: pos + size]
        pos += size + (pos + size) % 2  # ar entries are word-aligned
        yield name, content


def _decompress_zst(data: bytes) -> bytes:
    """Decompress zstd-compressed bytes using subprocess (unzstd) or the zstandard library.

    Tries, in order:
      1. unzstd --stdout  (available on most Linux systems, including RescueZilla)
      2. zstd -d --stdout (alternative name on some systems)
      3. zstandard Python library (pip install zstandard — useful on Windows dev machine)

    Raises RuntimeError if none of the above work.
    """
    for cmd in (["unzstd", "--stdout"], ["zstd", "-d", "--stdout"]):
        try:
            result = subprocess.run(  # noqa: S603
                cmd,
                input=data,
                capture_output=True,
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout
        except FileNotFoundError:
            continue  # tool not installed — try next

    try:
        import zstandard  # type: ignore
        dctx = zstandard.ZstdDecompressor()
        return dctx.decompress(data, max_output_size=20 * 1024 * 1024)
    except ImportError:
        pass

    raise RuntimeError(
        "Cannot decompress .zst — install unzstd (sudo apt install zstd) "
        "or the Python zstandard library (pip install zstandard)."
    )


def _extract_dropbear_from_deb(deb_bytes: bytes) -> bytes:
    """Parse a .deb file and return the raw dropbear ELF binary."""
    import io as _io
    data_entry = None
    for name, content in _iter_ar(deb_bytes):
        if name.startswith("data.tar"):
            data_entry = (name, content)
            break
    if data_entry is None:
        raise RuntimeError("No data.tar.* found in .deb")

    ar_name, tar_bytes = data_entry
    if ar_name.endswith(".zst"):
        tar_bytes = _decompress_zst(tar_bytes)

    import tarfile as _tarfile
    with _tarfile.open(fileobj=_io.BytesIO(tar_bytes)) as tf:
        for member in tf.getmembers():
            if member.name.endswith("/dropbear") and "sbin" in member.name:
                fobj = tf.extractfile(member)
                if fobj:
                    return fobj.read()
    raise RuntimeError("dropbear binary not found inside data tarball")


def _extract_so_from_deb(deb_bytes: bytes, so_name: str) -> bytes:
    """Parse a .deb file and return the versioned .so binary for so_name.

    so_name is the unversioned symlink name, e.g. 'libatomic.so.1'.
    We extract the first actual (non-symlink) file whose name contains the
    library base, preferring the longest (most-versioned) name.
    """
    import io as _io
    data_entry = None
    for name, content in _iter_ar(deb_bytes):
        if name.startswith("data.tar"):
            data_entry = (name, content)
            break
    if data_entry is None:
        raise RuntimeError("No data.tar.* found in .deb")

    ar_name, tar_bytes = data_entry
    if ar_name.rstrip().endswith(".zst"):
        tar_bytes = _decompress_zst(tar_bytes)
    elif ar_name.rstrip().endswith(".xz"):
        import lzma as _lzma
        tar_bytes = _lzma.decompress(tar_bytes)

    so_base = so_name.split(".so")[0]  # e.g. "libatomic"
    import tarfile as _tarfile
    with _tarfile.open(fileobj=_io.BytesIO(tar_bytes)) as tf:
        candidates = [
            (m.name, m) for m in tf.getmembers()
            if so_base in m.name and ".so" in m.name
        ]
        # Prefer actual files over symlinks; prefer longer (versioned) names
        candidates.sort(key=lambda x: (x[1].issym(), -len(x[0])))
        for cname, member in candidates:
            if member.isfile():
                fobj = tf.extractfile(member)
                if fobj:
                    return fobj.read()
    raise RuntimeError(f"{so_name} not found as a real file in deb")


def download_dropbear(root, verbosity: int = 1) -> Path:
    """Download the dropbear binary and its companion .so libraries to <root>/_tools/.

    Files written:
      _tools/dropbear          — the SSH server binary
      _tools/libatomic.so.1    \\
      _tools/libtomcrypt.so.1  | companion shared libraries (Ubuntu 22.04 jammy)
      _tools/libtommath.so.1   |
      _tools/libgmp.so.10      /

    bootstrap.sh starts dropbear with LD_LIBRARY_PATH=<usb>/_tools so no
    apt-get install is needed on the live system.

    Skips any file already present.  Returns the Path to the dropbear binary.
    Raises RuntimeError only if the binary itself cannot be obtained.
    """
    tools = Path(root) / "_tools"
    tools.mkdir(parents=True, exist_ok=True)

    # --- dropbear binary ---
    dest = tools / "dropbear"
    if dest.exists():
        if verbosity >= 1:
            print(f"  dropbear: already present ({dest.stat().st_size:,} bytes)")
    else:
        deb_bytes = None
        for url in _DROPBEAR_URLS:
            if verbosity >= 1:
                print(f"  dropbear: downloading {url} ...")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "rescue-toolkit/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    deb_bytes = resp.read()
                if verbosity >= 1:
                    print(f"  dropbear: {len(deb_bytes):,} bytes received")
                break
            except Exception as exc:
                if verbosity >= 1:
                    print(f"  dropbear: {url} — {exc}")

        if deb_bytes is None:
            raise RuntimeError(
                "All dropbear download URLs failed.  "
                "Check network, or manually place the binary at: " + str(dest)
            )

        binary = _extract_dropbear_from_deb(deb_bytes)
        dest.write_bytes(binary)
        if verbosity >= 1:
            print(f"  dropbear: saved {dest}  ({dest.stat().st_size:,} bytes)")

    # --- companion shared libraries ---
    for so_name, url in _DROPBEAR_LIB_PACKAGES:
        lib_dest = tools / so_name
        if lib_dest.exists():
            if verbosity >= 2:
                print(f"  {so_name}: already present ({lib_dest.stat().st_size:,} bytes)")
            continue
        if verbosity >= 1:
            print(f"  {so_name}: downloading {url.split('/')[-1]} ...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "rescue-toolkit/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                deb_bytes = resp.read()
            so_data = _extract_so_from_deb(deb_bytes, so_name)
            lib_dest.write_bytes(so_data)
            if verbosity >= 1:
                print(f"  {so_name}: saved ({lib_dest.stat().st_size:,} bytes)")
        except Exception as exc:
            if verbosity >= 1:
                print(f"  {so_name}: WARNING — {exc}")
            # Non-fatal: dropbear may still work if the system already has the lib.

    return dest


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
            sha256_sidecar = deb.parent / (deb.name + ".sha256")
            if sha256_sidecar.exists():
                _sync_core_file(sha256_sidecar, clamav_dist_dir / sha256_sidecar.name, mode=mode, verbosity=verbosity)
        except RuntimeError as exc:
            print(f"  ERROR downloading ClamAV: {exc}")
            print("  Skipping ClamAV bundle.  run_scan will fall back to system ClamAV.")
    else:
        print(f"  would download {_CLAMAV_LINUX_URL}")

    # --- _tools/ (dropbear binary + companion .so libraries) ---
    # download_dropbear fetches both the binary and the .so files into _tools/.
    # We then mirror everything in _tools/ to the dist package.
    if verbosity >= 1:
        print("\n_tools:")
    tools_dst = dist / "_tools"
    if not dry_run:
        try:
            download_dropbear(root, verbosity=verbosity)
        except RuntimeError as exc:
            print(f"  dropbear: WARNING — download failed: {exc}")
            print("  SSH will not work offline without the binary.")
        tools_src = Path(root) / "_tools"
        tools_dst.mkdir(parents=True, exist_ok=True)
        if tools_src.is_dir():
            for src_file in sorted(tools_src.iterdir()):
                if src_file.is_file():
                    _sync_core_file(src_file, tools_dst / src_file.name, mode=mode, verbosity=verbosity)
    else:
        print("  would download dropbear + companion .so libs if absent")

    # --- chmod bootstrap.sh executable; _tools/dropbear executable; .so files 644 ---
    if not dry_run:
        try:
            os.chmod(dist / "bootstrap.sh", 0o755)
        except (AttributeError, NotImplementedError):
            pass  # Windows — permissions applied when copying to USB
        if tools_dst.is_dir():
            for f in tools_dst.iterdir():
                try:
                    # dropbear binary gets execute bit; .so files do not
                    mode_bits = 0o755 if f.name == "dropbear" else 0o644
                    os.chmod(f, mode_bits)
                except (AttributeError, NotImplementedError):
                    pass

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


# ---------------------------------------------------------------------------
# RoboCopy — fast, incremental directory copy (robocopy on Windows, rsync on Linux)
# ---------------------------------------------------------------------------
#
# Usage:
#   rc = RoboCopy(threads=8)
#   result = rc.update_only(src, dst)
#   result = rc.mirror(src, dst)
#   result = rc.copy_tree(src, dst, dry_run=True)


class RoboCopy:
    @dataclasses.dataclass
    class Result:
        returncode: int
        command: list
        stdout: str
        stderr: str
        backend: str

        @property
        def ok(self) -> bool:
            if self.backend == "robocopy":
                return self.returncode < 8
            return self.returncode == 0

        @property
        def changed(self) -> bool:
            if self.backend == "robocopy":
                return self.returncode in {1, 3, 5, 7}
            return bool(self.stdout.strip() or self.stderr.strip())

    def __init__(
        self,
        threads: int = 8,
        retries: int = 1,
        wait_seconds: int = 1,
        fat_timestamps: bool = True,
        robocopy_exe: str = "robocopy",
        rsync_exe: str = "rsync",
    ):
        self.threads = threads
        self.retries = retries
        self.wait_seconds = wait_seconds
        self.fat_timestamps = fat_timestamps
        self.robocopy_exe = robocopy_exe
        self.rsync_exe = rsync_exe
        self.backend = "robocopy" if os.name == "nt" else "rsync"

    def copy_tree(
        self,
        src,
        dst,
        *,
        include_empty_dirs: bool = True,
        dry_run: bool = False,
        extra_args=None,
    ):
        if self.backend == "robocopy":
            args = ["/E" if include_empty_dirs else "/S"]
        else:
            args = ["-a"]
            if dry_run:
                args.append("--dry-run")
            if not include_empty_dirs:
                args.append("--prune-empty-dirs")
        return self._run(src, dst, args, dry_run=dry_run, extra_args=extra_args)

    def mirror(
        self,
        src,
        dst,
        *,
        dry_run: bool = False,
        extra_args=None,
    ):
        if self.backend == "robocopy":
            args = ["/MIR"]
        else:
            args = ["-a", "--delete"]
            if dry_run:
                args.append("--dry-run")
        return self._run(src, dst, args, dry_run=dry_run, extra_args=extra_args)

    def update_only(
        self,
        src,
        dst,
        *,
        include_empty_dirs: bool = True,
        dry_run: bool = False,
        extra_args=None,
    ):
        if self.backend == "robocopy":
            args = ["/E" if include_empty_dirs else "/S", "/XO"]
        else:
            args = ["-a", "--update"]
            if dry_run:
                args.append("--dry-run")
            if not include_empty_dirs:
                args.append("--prune-empty-dirs")
        return self._run(src, dst, args, dry_run=dry_run, extra_args=extra_args)

    def copy_matching(
        self,
        src,
        dst,
        patterns: list,
        *,
        dry_run: bool = False,
        extra_args=None,
    ):
        if self.backend == "robocopy":
            args = patterns + ["/E"]
        else:
            args = ["-a"]
            for pattern in patterns:
                args.extend(["--include", pattern])
            args.extend(["--exclude", "*"])
            if dry_run:
                args.append("--dry-run")
        return self._run(src, dst, args, dry_run=dry_run, extra_args=extra_args)

    def _run(
        self,
        src,
        dst,
        mode_args: list,
        *,
        dry_run: bool = False,
        extra_args=None,
    ):
        src = Path(src)
        dst = Path(dst)

        if not src.exists():
            raise FileNotFoundError(f"Source does not exist: {src}")

        if self.backend == "robocopy":
            command = self._robocopy_command(src, dst, mode_args, dry_run, extra_args)
        else:
            command = self._rsync_command(src, dst, mode_args, extra_args)

        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        result = self.Result(
            returncode=proc.returncode,
            command=command,
            stdout=proc.stdout,
            stderr=proc.stderr,
            backend=self.backend,
        )

        if not result.ok:
            raise RuntimeError(
                f"{self.backend} failed with exit code {result.returncode}\n"
                f"Command: {' '.join(result.command)}\n\n"
                f"{result.stdout}\n{result.stderr}"
            )

        return result

    def _robocopy_command(
        self,
        src: Path,
        dst: Path,
        mode_args: list,
        dry_run: bool,
        extra_args,
    ) -> list:
        args = [
            self.robocopy_exe,
            str(src),
            str(dst),
            *mode_args,
            f"/R:{self.retries}",
            f"/W:{self.wait_seconds}",
            f"/MT:{self.threads}",
            "/NP",
        ]
        if self.fat_timestamps:
            args.append("/FFT")
        if dry_run:
            args.append("/L")
        if extra_args:
            args.extend(extra_args)
        return args

    def _rsync_command(
        self,
        src: Path,
        dst: Path,
        mode_args: list,
        extra_args,
    ) -> list:
        src_arg = str(src)
        dst_arg = str(dst)
        if src.is_dir():
            src_arg = src_arg.rstrip("/\\") + "/"
        args = [
            self.rsync_exe,
            *mode_args,
            "--human-readable",
            "--info=stats2",
            src_arg,
            dst_arg,
        ]
        if extra_args:
            args.extend(extra_args)
        return args


if __name__ == "__main__":

    if True:
        build_usb_package(mode="update", verbosity=1)
        build_usb_package(mode="prune", verbosity=1)

    if True:
        # Copy dist/NIELSOLN_RESCUE_USB to a physical USB drive.
        # Set usb_dest to the USB root (drive letter on Windows, mount point on Linux).
        # Uses update_only so unchanged files are skipped — much faster than a full copy.
        # Switch to mirror() to also delete files removed from the dist.
        usb_dest = Path("D:\\")               # <-- set your USB drive path here
        src = usb_dist_path(file__fileSysD)
        dst = usb_dest / _USB_DIST_NAME
        print(f"\nCopying {src}")
        print(f"     to {dst} ...")
        rc = RoboCopy(threads=8, fat_timestamps=True)
        result = rc.update_only(src, dst)
        status = "changed" if result.changed else "no changes"
        print(f"Done ({status}, exit {result.returncode})")
        if result.stdout.strip():
            print(result.stdout)
        raise Exception("OK")

    if False:
        run_install_runtime(platform_tag="linux-x86_64", mode="update", verbosity=1)
        raise Exception("OK")

    if False:
        # Delete ALL contents of a USB drive by mirroring an empty directory onto it.
        # robocopy /MIR (Windows) or rsync --delete (Linux) removes everything at usb_dest
        # that is not present in the empty source — i.e. everything.
        # Toggle to True only when you are certain — this cannot be undone.
        import tempfile
        usb_dest = Path("D:\\")               # <-- set your USB drive path here
        print(f"Wiping all contents of {usb_dest} ...")
        with tempfile.TemporaryDirectory() as empty_dir:
            rc = RoboCopy(threads=8, fat_timestamps=True)
            result = rc.mirror(Path(empty_dir), usb_dest)
        status = "changed" if result.changed else "no changes"
        print(f"Done ({status}, exit {result.returncode})")
        if result.stdout.strip():
            print(result.stdout)
        raise Exception("OK")