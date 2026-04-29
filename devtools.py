"""Nielsoln Rescue Toolkit — developer utilities.

Run from the toolkit root folder:
    import runpy ; temp = runpy._run_module_as_main("devtools")

Workflow
--------
1.  Set ``action`` in ``main()`` to the operation you want.
2.  Adjust the corresponding config variables (commit message, script path, etc.).
3.  Run via the runpy invocation above.

Operations
----------
``release``
    py_compile every .py, git add -A, commit, push, then print LF-normalised
    SHA256 of every updateable file.  Compare the hashes against what
    ``bootstrap update`` prints on RescueZilla.

``run_remote``
    Encode a local Python script as gzip+base64 and run it on the remote host
    via ``bootstrap.py exec``.  Output streams to your terminal.
    Passphrase will be prompted once (or skipped if the key is loaded in
    ssh-agent).  Tip: run ``ssh-add`` once per Windows session to avoid the
    prompt on every call.

``push_file``
    SCP a single local file to the USB root on the remote host.

``setup_ssh_agent``
    One-time setup: enable the Windows OpenSSH agent service (requires the
    terminal to be running as Administrator) and load the private key so all
    subsequent ssh/scp calls are passphrase-free.  Run this once per machine.
    If the terminal is not elevated, it prints the manual steps to run.
"""

import base64
import getpass
import gzip
import hashlib
import os
import pathlib
import socket
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Configuration — edit these before running
# ---------------------------------------------------------------------------

HOST        = "192.168.20.4"
PORT        = 22
KEY         = r"C:\Users\david\.ssh\id_ed25519"
USB_PATH    = "/media/ubuntu/GRTMPVOL_EN/NIELSOLN_RESCUE_USB"

# Files kept in sync by bootstrap update / build_usb_package
UPDATE_FILES = [
    "bootstrap.py",
    "bootstrap.sh",
    "toolkit.py",
    "modules/m01_persistence_scan.py",
    "modules/m02_detect.py",
    "modules/m03_triage.py",
    "modules/m04_hardware_profile.py",
    "modules/m05_disk_health.py",
    "modules/m06_software_inventory.py",
    "modules/m09_thermal_health.py",
    "modules/m15_upgrade_advisor.py",
    "modules/m18_clamav_scan.py",
    "modules/m23_logon_audit.py",
    "modules/m33_user_account_analysis.py",
    "modules/m34_task_scheduler_analysis.py",
    "modules/m35_windows_update_analysis.py",
    "modules/m36_execution_history.py",
    "modules/m37_network_analysis.py",
    "modules/m38_browser_activity.py",
    "modules/m39_driver_store_analysis.py",
    "modules/m44_performance_diagnosis.py",
    "modules/m46_recent_change_analysis.py",
    "modules/m40_time_integrity.py",
    "modules/m41_file_anomalies.py",
    "modules/m42_registry_health.py",
    "modules/m43_backup_analysis.py",
    "modules/m45_trust_score.py",
    "modules/m47_module_conflict_analysis.py",
]

_PY = r"C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe"

# ---------------------------------------------------------------------------
# Passphrase cache — read from NRT_SSH_PASSPHRASE env var if set, otherwise
# prompt once and cache in-memory for the life of this process.
#
# To avoid the prompt for a VS Code session, set the env var once in the
# terminal before running devtools:
#
#     $env:NRT_SSH_PASSPHRASE = "your-passphrase"
#
# ---------------------------------------------------------------------------

_passphrase: str = ""
_askpass_bat_path: str = ""


def _write_askpass_bat(passphrase: str) -> str:
    """Write a temp .bat that echoes the passphrase; return its path."""
    encoded = base64.b64encode(passphrase.encode("utf-8")).decode("ascii")
    py_snippet = (
        f"import base64,sys;"
        f"sys.stdout.write(base64.b64decode(b'{encoded}').decode())"
    )
    bat = f'@echo off\n"{_PY}" -c "{py_snippet}"\n'
    tmp = pathlib.Path(tempfile.gettempdir()) / "nrt_devtools_askpass.bat"
    tmp.write_text(bat, encoding="ascii")
    return str(tmp)


def _ensure_passphrase() -> str:
    """Return the SSH key passphrase.

    Resolution order
    ----------------
    1. In-memory cache (already prompted this process).
    2. NRT_SSH_PASSPHRASE environment variable.
    3. getpass prompt — asked once, then cached in-memory.
    """
    global _passphrase, _askpass_bat_path

    if _passphrase:
        return _passphrase

    env_pp = os.environ.get("NRT_SSH_PASSPHRASE", "")
    if env_pp:
        _passphrase = env_pp
    else:
        _passphrase = getpass.getpass("SSH key passphrase: ")

    _askpass_bat_path = _write_askpass_bat(_passphrase)
    return _passphrase


def _askpass_env() -> dict:
    """Return os.environ with SSH_ASKPASS set to the cached passphrase bat."""
    _ensure_passphrase()
    env = os.environ.copy()
    env["SSH_ASKPASS"]         = _askpass_bat_path
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env.setdefault("DISPLAY", "localhost:0")
    return env


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ssh_args(extra: list = None) -> list:
    """Return base SSH argument list (without command)."""
    args = ["ssh", "-p", str(PORT), "-i", KEY,
            "-o", "StrictHostKeyChecking=no", f"root@{HOST}"]
    if extra:
        args += extra
    return args


def _scp_args(src: str, dst: str) -> list:
    return ["scp", "-O", "-P", str(PORT), "-i", KEY,
            "-o", "StrictHostKeyChecking=no", src, dst]


def encode_script(source: str) -> str:
    """Gzip-compress and base64-encode a Python source string."""
    return base64.b64encode(gzip.compress(source.encode("utf-8"))).decode("ascii")


# ---------------------------------------------------------------------------
# SSH Relay client — passphrase-free if ssh_relay.py is running
# ---------------------------------------------------------------------------

RELAY_PORT = 19022
RELAY_ADDR = "127.0.0.1"

_relay_started = False   # set once we've launched the relay this session


def _relay_up() -> bool:
    """Return True if the relay is accepting connections."""
    try:
        with socket.create_connection((RELAY_ADDR, RELAY_PORT), timeout=2):
            return True
    except OSError:
        return False


def _ensure_relay() -> None:
    """If the relay isn't running, launch ssh_relay.py in the background.

    Prompts for the key passphrase once in the current terminal (via
    getpass), then pipes it to the relay process via stdin so the relay
    never needs its own console window.  All subsequent SSH/SCP calls go
    through the relay without further prompting.
    """
    global _relay_started
    if _relay_up():
        return

    pp = _ensure_passphrase()   # prompts once if not already cached

    relay_script = str(pathlib.Path(__file__).with_name("ssh_relay.py"))
    print("SSH relay is not running — launching it now ...")

    # Launch the relay as a background process; pipe the passphrase via stdin.
    # The relay reads it when sys.stdin is not a TTY.
    proc = subprocess.Popen(
        [_PY, relay_script],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        proc.stdin.write((pp + "\n").encode("utf-8"))
        proc.stdin.close()
    except OSError:
        pass

    import time as _t
    deadline = _t.monotonic() + 60
    while _t.monotonic() < deadline:
        _t.sleep(0.5)
        if _relay_up():
            print("Relay is up — proceeding.")
            _relay_started = True
            return

    print("WARNING: relay did not start within 60 s — falling back to direct SSH.")


def _relay_call(op: str, **kwargs):
    """Send one command to the SSH relay daemon.  Returns response dict or None."""
    import json as _json
    req = {"op": op, **kwargs}
    try:
        with socket.create_connection((RELAY_ADDR, RELAY_PORT), timeout=3) as sock:
            sock.sendall((_json.dumps(req) + "\n").encode())
            sock.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        return _json.loads(data.decode())
    except (ConnectionRefusedError, OSError, ValueError):
        return None


def _relay_stream(op: str, **kwargs) -> bool:
    """Like _relay_call but streams stdout/stderr lines to the terminal.

    Returns True if the relay handled it, False if unavailable (caller should
    fall back to direct subprocess).
    """
    import json as _json
    req = {"op": op, "stream": True, **kwargs}
    try:
        with socket.create_connection((RELAY_ADDR, RELAY_PORT), timeout=3) as sock:
            sock.sendall((_json.dumps(req) + "\n").encode())
            sock.shutdown(socket.SHUT_WR)
            buf = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    msg = _json.loads(line)
                    if msg.get("type") == "out":
                        sys.stdout.write(msg["data"])
                        sys.stdout.flush()
                    elif msg.get("type") == "err":
                        sys.stderr.write(msg["data"])
                        sys.stderr.flush()
                    elif msg.get("done"):
                        return True
        return True
    except (ConnectionRefusedError, OSError, ValueError):
        return False


def _ssh_run(cmd: str, stdin_data: bytes = None) -> None:
    """Run an SSH command, using the relay if available, else direct subprocess."""
    _ensure_relay()
    stdin_b64 = base64.b64encode(stdin_data).decode() if stdin_data else None
    if _relay_stream("ssh", cmd=cmd, stdin_b64=stdin_b64):
        return
    # Fallback — use cached passphrase via SSH_ASKPASS
    kwargs = {"input": stdin_data, "env": _askpass_env()} if stdin_data is not None else {"env": _askpass_env()}
    subprocess.run(_ssh_args([cmd]), **kwargs)


def _scp_run(local: str, remote: str) -> None:
    """SCP a local file to the device, using the relay if available."""
    _ensure_relay()
    resp = _relay_call("scp_put", local=local, remote=remote)
    if resp is not None:
        if resp.get("out"):
            sys.stdout.write(resp["out"])
        if resp.get("err"):
            sys.stderr.write(resp["err"])
        return
    # Fallback — use cached passphrase via SSH_ASKPASS
    subprocess.run(_scp_args(local, f"root@{HOST}:{remote}"), env=_askpass_env())


def _scp_get(remote: str, local: str) -> None:
    """SCP a file FROM the device to a local path."""
    _ensure_relay()
    resp = _relay_call("scp_get", remote=remote, local=local)
    if resp is not None:
        if resp.get("out"):
            sys.stdout.write(resp["out"])
        if resp.get("err"):
            sys.stderr.write(resp["err"])
        return
    # Fallback — use cached passphrase via SSH_ASKPASS
    subprocess.run(_scp_args(f"root@{HOST}:{remote}", local), env=_askpass_env())


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def setup_ssh_agent() -> None:
    """Enable the Windows OpenSSH agent service and load the private key.

    Must be run from an elevated (Administrator) terminal.  Safe to re-run;
    if the service is already running it just ensures the key is loaded.
    """
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(
            "Not running as Administrator.  Open an elevated PowerShell and run:\n"
            "\n"
            "  Set-Service ssh-agent -StartupType Automatic\n"
            "  Start-Service ssh-agent\n"
            f"  ssh-add {KEY}\n"
            "\n"
            "After that, all ssh/scp calls are passphrase-free until next reboot,\n"
            "at which point only 'ssh-add' needs to be re-run."
        )
        return
    subprocess.run(
        ["powershell", "-Command",
         "Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent"],
        check=True,
    )
    subprocess.run(["ssh-add", KEY])   # prompts for passphrase once
    print("ssh-agent configured and key loaded.")


def _sync_device_clock() -> None:
    """Set the device system clock to the dev machine's current epoch.

    This is the primary clock correction path when devtools has an active SSH
    connection.  The dev machine's clock is the source of truth — entirely
    independent of the device's potentially-dead CMOS battery.

    Silent on success.  Prints a warning but never raises on failure.
    """
    import time
    epoch = int(time.time())
    try:
        _ssh_run(f"date -s '@{epoch}' > /dev/null 2>&1 || true")
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not sync device clock: {exc}")


def _push_clock_ref() -> None:
    """Write clock_ref.json to the USB and SCP it to the device.

    Allows run_sync_time() to correct the clock offline (no internet) on
    future boots by reading the last known-good timestamp written by devtools.
    """
    import time
    import json
    import tempfile
    import os
    epoch = int(time.time())
    iso   = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
    payload = json.dumps({"utc_unix": epoch, "iso": iso, "source": "devtools"}, indent=2)
    # Write locally so it's available in the working tree too
    pathlib.Path("clock_ref.json").write_text(payload, encoding="utf-8")
    # Push to device
    _scp_run("clock_ref.json", f"{USB_PATH}/clock_ref.json")


def run_remote(script_path: str) -> None:
    """Encode *script_path* and execute it on the remote host via bootstrap exec.

    The script runs inside the USB root directory with ``root`` (Path) and
    ``Path`` available as globals.  stdout/stderr stream directly to your
    terminal so the passphrase prompt works normally.

    The payload is sent via stdin (not as a CLI arg) to avoid ARG_MAX limits
    on large scripts.
    """
    _sync_device_clock()
    code = pathlib.Path(script_path).read_text(encoding="utf-8")
    payload = encode_script(code)
    remote_cmd = (
        f"cd {USB_PATH} && "
        f"python3 bootstrap.py --no-update exec"
    )
    _ssh_run(remote_cmd, stdin_data=payload.encode("ascii"))


def push_file(local_path: str, remote_subpath: str = "") -> None:
    """SCP *local_path* to the USB root (or a subpath below it) on the remote host."""
    _sync_device_clock()
    _push_clock_ref()
    dst_dir = f"{USB_PATH}/{remote_subpath}".rstrip("/")
    remote = f"{dst_dir}/{pathlib.Path(local_path).name}"
    _scp_run(local_path, remote)


def push_module(name: str) -> None:
    """SCP modules/<name>.py to the modules/ directory on the USB.

    Creates the remote modules/ directory if absent via SSH.
    """
    _sync_device_clock()
    _push_clock_ref()
    remote_modules = f"{USB_PATH}/modules"
    _ssh_run(f"mkdir -p {remote_modules}")
    _scp_run(f"modules/{name}.py", f"{remote_modules}/{name}.py")
    print(f"Pushed modules/{name}.py to device.")


def run_module(name: str, module_argv: list = None) -> None:
    """Push modules/<name>.py to device then run it via bootstrap run.

    Streams the file over SSH stdin (cat > remote_path) so the whole
    operation completes in ONE SSH connection — only ONE passphrase prompt.

    *module_argv* is a list of strings passed after ``--`` to the module.
    Example: run_module("m01_persistence_scan", ["--target", "/mnt/windows"])
    """
    _sync_device_clock()
    _push_clock_ref()
    local_path = pathlib.Path(f"modules/{name}.py")
    remote_modules = f"{USB_PATH}/modules"
    remote_file = f"{remote_modules}/{name}.py"

    argv_str = " ".join(module_argv) if module_argv else ""
    sep = " -- " if argv_str else ""

    # cat reads from stdin (the local file), writes to remote_file, then runs
    remote_cmd = (
        f"mkdir -p {remote_modules} && "
        f"cat > {remote_file} && "
        f"echo 'Pushed {name}.py to device.' && "
        f"cd {USB_PATH} && "
        f"python3 bootstrap.py --no-update run {name}{sep}{argv_str}"
    )
    stdin_data = local_path.read_bytes()
    _ssh_run(remote_cmd, stdin_data=stdin_data)


def release(message: str) -> None:
    """Compile-check all .py files, commit, push, print LF-normalised SHA256s.

    Run this after every change you want to land on RescueZilla via
    ``bootstrap update``.  Compare the printed hashes against what
    ``bootstrap update`` shows on the rescue machine.
    """
    import py_compile

    print("=" * 60)
    print("STEP 1 — py_compile")
    print("=" * 60)
    failed = []
    for p in sorted(pathlib.Path(".").glob("*.py")):
        try:
            py_compile.compile(str(p), doraise=True)
            print(f"  OK   {p.name}")
        except py_compile.PyCompileError as exc:
            print(f"  FAIL {p.name}: {exc}")
            failed.append(p.name)
    if failed:
        print(f"\nAborting: {len(failed)} file(s) failed compile check.")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("STEP 2 — git add / commit / push")
    print("=" * 60)
    subprocess.run(["git", "add", "-A"], check=True)
    r = subprocess.run(["git", "commit", "-m", message])
    if r.returncode not in (0, 1):   # 0=committed, 1=nothing to commit
        sys.exit(r.returncode)
    subprocess.run(["git", "push"], check=True)

    print("\n" + "=" * 60)
    print("STEP 3 — SHA256 (LF-normalised)")
    print("=" * 60)
    for fname in UPDATE_FILES:
        p = pathlib.Path(fname)
        if p.exists():
            data = p.read_bytes().replace(b"\r\n", b"\n")
            print(hashlib.sha256(data).hexdigest(), " ", fname)
        else:
            print(f"  (not found) {fname}")


# ---------------------------------------------------------------------------
# Bootstrap lock helpers (serial module orchestration)
# ---------------------------------------------------------------------------

USB_LOCK = f"{USB_PATH}/.lock"


def _lock_info():
    """Return (locked:bool, pid:int|None, cmd:str|None) from the device lock file."""
    import io as _io, contextlib as _cl, json as _json
    buf = _io.StringIO()
    with _cl.redirect_stdout(buf):
        _ssh_run(f"cat {USB_LOCK} 2>/dev/null || echo NOLOCK")
    out = buf.getvalue().strip()
    if "NOLOCK" in out or not out:
        return False, None, None
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                d = _json.loads(line)
                return True, d.get("pid"), d.get("command")
            except Exception:
                pass
    return True, None, None


def _pid_alive(pid: int) -> bool:
    """Return True if pid is alive on the device."""
    import io as _io, contextlib as _cl
    buf = _io.StringIO()
    with _cl.redirect_stdout(buf):
        _ssh_run(f"ps -p {pid} -o pid= 2>/dev/null || true")
    return str(pid) in buf.getvalue()


def wait_for_lock_clear(label: str = "", poll_secs: int = 15) -> None:
    """Block until the bootstrap lock is gone (or the owning PID is dead)."""
    import time as _time
    print(f"  [wait] Waiting for bootstrap lock to clear{' (' + label + ')' if label else ''}...")
    while True:
        locked, lock_pid, lock_cmd = _lock_info()
        if not locked:
            print("  [wait] Lock clear.")
            return
        if lock_pid and not _pid_alive(lock_pid):
            print(f"  [wait] PID {lock_pid} is dead — removing stale lock...")
            _ssh_run(f"rm -f {USB_LOCK}")
            _time.sleep(1)
            return
        print(f"  [wait] {_time.strftime('%H:%M:%S')}  locked by '{lock_cmd}' (PID {lock_pid})")
        _time.sleep(poll_secs)


def run_module_serial(name: str, args: list = None) -> None:
    """Wait for lock, push + run a module, then wait for it to finish."""
    import time as _time
    sep = "=" * 60
    print(f"\n{sep}\n  {name}\n{sep}")
    wait_for_lock_clear(name)
    try:
        run_module(name, args or [])
    except Exception as exc:
        print(f"  [run_module] relay error (module may still be running): {exc}")
    _time.sleep(3)  # brief pause for bootstrap to acquire the lock
    wait_for_lock_clear(name)
    print(f"DONE: {name}")


# ---------------------------------------------------------------------------
# Log fetch helper
# ---------------------------------------------------------------------------

def fetch_logs(local_dir: str = "logs") -> int:
    """SCP logs from USB using MD5 checksum comparison.

    One SSH call retrieves all remote filenames + their MD5 hashes.
    Local files whose MD5 already matches are skipped (CACHED) — whether they
    live at the device subfolder or the flat logs/ root.
    Files that are new or whose content has changed are fetched (FETCH / UPDATE)
    directly into the device-named subfolder (e.g. logs/ASUS_F5GL__Garnet__/).
    If no subfolder exists yet (first run), files land in logs/ root and
    organize_device_logs() will move them afterwards.
    Returns count of newly fetched / updated files.
    """
    import pathlib as _pl, hashlib as _hl, io as _io, contextlib as _cl

    base = _pl.Path(local_dir)
    base.mkdir(exist_ok=True)

    # Determine the fetch destination: use the existing named subfolder if
    # present (subsequent runs), otherwise fall back to flat logs/ root
    # (first run — organize_device_logs will sort them out after).
    existing_subfolders = [d for d in base.iterdir() if d.is_dir()] if base.exists() else []
    if existing_subfolders:
        dest = max(existing_subfolders, key=lambda d: d.stat().st_mtime)
    else:
        dest = base

    # Collect all local log files: device subfolder + flat root fallback
    def _local_candidates(fname: str):
        """Yield all local paths where this file might already live."""
        yield dest / fname
        if dest != base:
            yield base / fname   # also check root for files from old runs

    def _local_md5(path: _pl.Path) -> str:
        h = _hl.md5()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    # ── One SSH call: get md5sum for every log file on the device ────────────
    buf = _io.StringIO()
    with _cl.redirect_stdout(buf):
        _ssh_run(
            f"cd {USB_PATH}/logs 2>/dev/null && "
            f"md5sum *.json *.jsonl 2>/dev/null || true"
        )

    # Parse "md5hash  filename" (two spaces — md5sum format)
    remote: dict = {}   # basename → md5hex
    for line in buf.getvalue().splitlines():
        line = line.strip()
        if not line or line.startswith("md5sum:"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            hash_, name = parts
            # Validate: md5sum hashes are exactly 32 lowercase hex chars
            if len(hash_) == 32 and all(c in "0123456789abcdef" for c in hash_):
                remote[_pl.Path(name).name] = hash_

    if not remote:
        print("No log files found on device.")
        return 0

    fetched = cached = 0
    for fname in sorted(remote):
        remote_md5 = remote[fname]

        # Check flat root AND all device subfolders
        cached_path = None
        for candidate in _local_candidates(fname):
            if candidate.exists():
                if _local_md5(candidate) == remote_md5:
                    cached_path = candidate
                    break

        if cached_path:
            print(f"  CACHED  {fname}")
            cached += 1
            continue

        # Determine label for output
        local = dest / fname
        if local.exists():
            print(f"  UPDATE  {fname}  (checksum changed) ...")
        else:
            print(f"  FETCH   {fname} ...")

        _scp_get(f"{USB_PATH}/logs/{fname}", str(local))
        fetched += 1

    print(f"\nFetched {fetched} new/updated file(s), {cached} already cached (MD5 match)")
    return fetched


# ---------------------------------------------------------------------------
# Device identity helpers (for named log folders)
# ---------------------------------------------------------------------------

# Maps NT major.minor version → friendly OS name
_NT_VERSION_MAP = {
    "5.0": "Win2000", "5.1": "WinXP", "5.2": "WinXP64",
    "6.0": "Vista",   "6.1": "Win7",  "6.2": "Win8",
    "6.3": "Win8.1",  "10.0": "Win10",
}

# Common manufacturer name abbreviations
_MFR_ABBREV = [
    ("ASUSTeK Computer Inc.", "ASUS"),
    ("ASUSTeK", "ASUS"),
    ("Hewlett-Packard", "HP"),
    ("Hewlett Packard", "HP"),
    ("Toshiba Corporation", "Toshiba"),
    ("Dell Inc.", "Dell"),
    ("Acer Inc.", "Acer"),
    ("Samsung Electronics", "Samsung"),
    ("Sony Corporation", "Sony"),
    ("Fujitsu", "Fujitsu"),
]


def _read_device_info(logs_dir: str = "logs") -> dict:
    """Scan a local logs directory and extract device identity fields.

    Returns a dict with keys: manufacturer, model, serial, os_name,
    registered_owner, computer_name.
    Any key may be absent if the source log was not found.

    Falls back to existing device subfolders when logs_dir root has no
    hardware_profile or os_profile files (happens after organize_device_logs
    has already moved files into a named subfolder).
    """
    import pathlib as _pl, json as _json
    base = _pl.Path(logs_dir)
    info: dict = {}

    def _find_logs(pattern: str) -> list:
        """Search root first, then most-recent subfolder as fallback."""
        hits = sorted(base.glob(pattern), reverse=True)
        if hits:
            return hits
        # Fallback: look inside existing device subfolders
        subfolders = [d for d in base.iterdir() if d.is_dir()] if base.exists() else []
        if subfolders:
            newest = max(subfolders, key=lambda d: d.stat().st_mtime)
            hits = sorted(newest.glob(pattern), reverse=True)
        return hits

    # hardware_profile → manufacturer / model / serial
    hw_files = _find_logs("hardware_profile_*.json")
    if hw_files:
        try:
            d = _json.loads(hw_files[0].read_text(encoding="utf-8", errors="replace"))
            sys_block = d.get("system", {})
            if sys_block.get("manufacturer"):
                info["manufacturer"] = sys_block["manufacturer"]
            if sys_block.get("product_name"):
                info["model"] = sys_block["product_name"]
            if sys_block.get("serial_number"):
                info["serial"] = sys_block["serial_number"]
        except Exception:
            pass

    # os_profile → OS name / version / owner / computer name
    os_files = _find_logs("os_profile_*.json")
    if os_files:
        try:
            d = _json.loads(os_files[0].read_text(encoding="utf-8", errors="replace"))
            os_block = d.get("os", {})
            product = os_block.get("product_name", "")
            version  = os_block.get("version", "")
            if product and product not in ("unknown", ""):
                # Strip edition noise: "Windows Vista Home Premium" → "Vista"
                for token in ("Home Premium", "Home Basic", "Ultimate",
                              "Professional", "Enterprise", "Starter",
                              "Service Pack", "SP1", "SP2", "SP3",
                              "32-bit", "64-bit", "Windows"):
                    product = product.replace(token, "").strip()
                # Strip trademark/registered symbols
                product = product.replace("™", "").replace("®", "")
                product = product.replace("(TM)", "").replace("(R)", "").strip()
                info["os_name"] = product.strip()
            elif version and version not in ("unknown", ""):
                major_minor = ".".join(version.split(".")[:2])
                info["os_name"] = _NT_VERSION_MAP.get(major_minor, f"NT{major_minor}")
            owner = os_block.get("registered_owner", "")
            if owner and owner not in ("unknown", ""):
                info["registered_owner"] = owner
            cn = os_block.get("computer_name", "")
            if cn and cn not in ("unknown", ""):
                info["computer_name"] = cn
        except Exception:
            pass

    return info


def device_label(logs_dir: str = "logs") -> str:
    """Generate a filesystem-safe label for a device based on its local logs.

    Format: {Mfr}_{Model}__{Owner}__{PCName}__{OS}__{serial_suffix}
    Example: ASUS_F5GL__GarnetTregonning__GARNET-PC__Vista__960013

    Owner and PCName are omitted if not available.
    Falls back gracefully to whatever fields are available.
    """
    import re as _re
    info = _read_device_info(logs_dir)

    def slug(s: str) -> str:
        return _re.sub(r"[^A-Za-z0-9]+", "_", s.strip()).strip("_")

    mfr = info.get("manufacturer", "")
    for long, short in _MFR_ABBREV:
        if mfr.startswith(long):
            mfr = short
            break
    mfr = slug(mfr) or "Unknown"

    model  = slug(info.get("model", "")) or "Unknown"
    os_str = slug(info.get("os_name", ""))
    serial = info.get("serial", "")
    serial_suffix = serial[-6:] if len(serial) >= 6 else serial

    # Owner: "Garnet Tregonning" → "GarnetTregonning" (no separators between words)
    owner_raw = info.get("registered_owner", "")
    owner_str = _re.sub(r"[^A-Za-z0-9]", "", owner_raw)  # strip all non-alphanumeric

    pc_name = slug(info.get("computer_name", ""))

    hw_part     = f"{mfr}_{model}"
    owner_part  = f"__{owner_str}" if owner_str else ""
    pc_part     = f"__{pc_name}" if pc_name else ""
    os_part     = f"__{os_str}" if os_str else ""
    serial_part = f"__{serial_suffix}" if serial_suffix else ""

    return f"{hw_part}{owner_part}{pc_part}{os_part}{serial_part}"


def organize_device_logs(logs_dir: str = "logs") -> str:
    """Move all log files in logs_dir into a named device subfolder.

    Reads hardware_profile and os_profile logs to build the folder name, then
    moves every .json/.jsonl file found at the top level of logs_dir into
    logs_dir/{device_label}/.

    Returns the path to the device subfolder.
    """
    import pathlib as _pl, shutil as _shutil
    base  = _pl.Path(logs_dir)
    label = device_label(logs_dir)
    dest  = base / label
    dest.mkdir(parents=True, exist_ok=True)

    moved = 0
    for f in sorted(base.glob("*.json")) + sorted(base.glob("*.jsonl")):
        target = dest / f.name
        if not target.exists():
            _shutil.move(str(f), str(target))
            moved += 1
        else:
            f.unlink()   # duplicate — already in dest

    print(f"Organized {moved} file(s) → {dest}")
    return str(dest)


# ---------------------------------------------------------------------------
# Full module sequence + run_all helper
# ---------------------------------------------------------------------------

# Canonical module run order.  Each entry is a 3-tuple:
#   (module_name,  needs_target: bool,  extra_args: list)
# run_all() builds the final argv as:
#   ["--target", target] + extra_args   (when needs_target=True)
#   extra_args                          (when needs_target=False / aggregate module)
FULL_MODULE_SEQUENCE = [
    # ── Core hardware & storage ─────────────────────────────────────────────
    ("m04_hardware_profile",            True,  []),
    ("m05_disk_health",                 True,  []),
    ("m48_bad_sector_scan",             True,  []),
    ("m06_software_inventory",          True,  []),
    ("m07_service_analysis",            True,  []),
    ("m09_thermal_health",              False, []),
    ("m15_upgrade_advisor",             False, []),
    # ── Users & event logs ──────────────────────────────────────────────────
    ("m23_logon_audit",                 True,  []),
    ("m01_persistence_scan",            True,  []),
    ("m25_event_archive",               True,  []),
    # ── Device & OS inventory ───────────────────────────────────────────────
    ("m26_os_profile",                  True,  []),
    ("m27_device_manager",              True,  []),
    ("m28_cmos_health",                 True,  []),
    ("m29_storage_usage",               True,  []),
    ("m30_disk_integrity",              True,  []),
    # ── Deep analysis ───────────────────────────────────────────────────────
    ("m31_system_integrity_audit",      True,  []),
    ("m33_user_account_analysis",       True,  []),
    ("m34_task_scheduler_analysis",     True,  []),
    ("m35_windows_update_analysis",     True,  []),
    ("m36_execution_history",           True,  []),
    ("m37_network_analysis",            True,  []),
    ("m38_browser_activity",            True,  []),
    ("m39_driver_store_analysis",       True,  []),
    ("m40_time_integrity",              True,  []),
    ("m41_file_anomalies",              True,  []),
    ("m42_registry_health",             True,  []),
    ("m43_backup_analysis",             True,  []),
    ("m44_performance_diagnosis",       True,  []),
    # ── Aggregate (read existing logs, no --target) ─────────────────────────
    ("m45_trust_score",                 False, []),
    ("m46_recent_change_analysis",      True,  []),
    ("m47_module_conflict_analysis",    False, []),
    # ── Cross-module correlation (depends on all others) ────────────────────
    ("m18_clamav_scan",                 True,  ["--profile", "quick"]),
    ("m32_execution_surface_analysis",  True,  []),
    ("m17_system_summary",              True,  []),
]


def run_all(
    target: str = "/mnt/windows",
    modules: list = None,
    skip_existing: bool = False,
) -> None:
    """Run all (or a subset of) modules serially, waiting for each lock to clear.

    Args:
        target: Windows mount path on the rescue device.
        modules: List of 3-tuples (name, needs_target, extra_args).
                 Defaults to FULL_MODULE_SEQUENCE.
        skip_existing: If True, check the device for an existing log before
                       running each module and skip if found.
    """
    import time as _time, io as _io, contextlib as _cl
    if modules is None:
        modules = FULL_MODULE_SEQUENCE

    sep = "=" * 60
    total = len(modules)

    # Optionally fetch the list of existing logs on the device
    existing: set = set()
    if skip_existing:
        print("Checking existing logs on device...")
        buf = _io.StringIO()
        with _cl.redirect_stdout(buf):
            _ssh_run(f"ls {USB_PATH}/logs/ 2>/dev/null || true")
        existing = {line.strip() for line in buf.getvalue().splitlines() if line.strip()}
        print(f"  {len(existing)} log file(s) already on device")

    wait_for_lock_clear("initial")

    for i, (name, needs_target, extra_args) in enumerate(modules, 1):
        print(f"\n{sep}\n  [{i}/{total}] {name}\n{sep}")

        if skip_existing:
            # Module log prefix matches "mXX_<stem>_YYYYMMDD_HHMMSS.json"
            stem = name.split("_", 1)[1] if "_" in name else name
            if any(stem in f for f in existing):
                print(f"  SKIP — log already on device")
                continue

        args = (["--target", target] if needs_target else []) + extra_args
        run_module_serial(name, args)

    print(f"\n{sep}")
    print("ALL MODULES COMPLETE")
    print(sep)


# ---------------------------------------------------------------------------
# Inline schema validation (replaces validate_logs.py subprocess call)
# ---------------------------------------------------------------------------

def _validate_logs(logs_dir: str = "logs") -> int:
    """Validate locally-fetched logs against their JSON Schemas.

    Reads schemas/_index.json to discover module→schema mappings, then
    validates the most-recent local log file for each module.  Prints a
    summary table.  Returns 0 if all present logs pass, 1 if any fail.
    """
    import pathlib as _pl, json as _json
    try:
        from jsonschema import Draft7Validator, ValidationError  # noqa: F401
    except ImportError:
        print("  WARNING: jsonschema not installed — skipping validation.")
        return 0

    schemas_dir = _pl.Path(__file__).parent / "schemas"
    index_file  = schemas_dir / "_index.json"
    if not index_file.exists():
        print(f"  WARNING: {index_file} not found — skipping validation.")
        return 0

    index    = _json.loads(index_file.read_text(encoding="utf-8"))
    logs_dir = _pl.Path(logs_dir)
    results: dict = {}

    def _validate_file(schema_path, data_path, is_jsonl):
        schema = _json.loads(schema_path.read_text(encoding="utf-8"))
        errors = []
        if is_jsonl:
            for lineno, raw in enumerate(
                    data_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = _json.loads(raw)
                except _json.JSONDecodeError as exc:
                    errors.append(f"  line {lineno}: JSON parse error — {exc}")
                    continue
                for err in Draft7Validator(schema).iter_errors(obj):
                    errors.append(f"  line {lineno}: {err.json_path}: {err.message}")
        else:
            try:
                obj = _json.loads(data_path.read_text(encoding="utf-8", errors="replace"))
            except _json.JSONDecodeError as exc:
                return [f"  JSON parse error — {exc}"]
            for err in Draft7Validator(schema).iter_errors(obj):
                errors.append(f"  {err.json_path}: {err.message}")
        return errors

    for mod, info in index["modules"].items():
        schema_key  = "schema" if "schema" in info else "schema_run"
        schema_file = info.get(schema_key)
        if not schema_file:
            continue
        glob     = info.get("log_glob") or info.get("log_glob_run", "")
        pat      = _pl.Path(glob).name
        fmt      = info.get("format", "JSON")
        is_jsonl = "JSONL" in fmt and "JSON +" not in fmt

        local_files = sorted(logs_dir.glob(pat))
        if not local_files:
            # Also search device subfolders (logs get moved there after organize)
            for sub in sorted(logs_dir.iterdir()) if logs_dir.exists() else []:
                if sub.is_dir():
                    local_files = sorted(sub.glob(pat))
                    if local_files:
                        break
        if not local_files:
            results[mod] = {"status": "MISSING", "file": None, "errors": []}
            continue

        data_path   = local_files[-1]
        schema_path = schemas_dir / schema_file
        errors = _validate_file(schema_path, data_path, is_jsonl)
        results[mod] = {
            "status": "PASS" if not errors else "FAIL",
            "file":   data_path.name,
            "errors": errors,
        }

    # Print report
    pass_n  = sum(1 for r in results.values() if r["status"] == "PASS")
    fail_n  = sum(1 for r in results.values() if r["status"] == "FAIL")
    miss_n  = sum(1 for r in results.values() if r["status"] == "MISSING")
    sep68   = "=" * 68
    print()
    print(sep68)
    print("  SCHEMA VALIDATION REPORT")
    print(sep68)
    for mod, r in sorted(results.items()):
        icon  = {"PASS": "✓", "FAIL": "✗", "MISSING": "–"}.get(r["status"], "?")
        fname = r["file"] or "(no log)"
        print(f"  {icon}  {mod:<36}  {r['status']:<7}  {fname}")
        for e in r["errors"]:
            print(f"         {e}")
    print(sep68)
    print(f"  PASS {pass_n}  |  FAIL {fail_n}  |  MISSING {miss_n}  |  TOTAL {len(results)}")
    print(sep68)
    print()
    return 1 if fail_n else 0


# ---------------------------------------------------------------------------
# ChatGPT bundle — zip logs + schemas for AI report generation
# ---------------------------------------------------------------------------

_CHATGPT_PROMPT = """\
# Nielsoln Rescue Toolkit — AI Report Instructions

You are analysing diagnostic scan data from the **Nielsoln Rescue Toolkit**, a
portable USB tool that scans offline Windows installations from a RescueZilla
live-Linux environment.

## What's in this zip

| Path | Contents |
|---|---|
| `logs/*.json` / `logs/*.jsonl` | Scan output from each diagnostic module |
| `schemas/*.json` | JSON Schema files describing each log's structure |

The log filenames follow the pattern `<module_name>_YYYYMMDD_HHMMSS.json`.
See each schema file's `title` and `description` for field definitions.

## Your task

Generate a **customer-facing diagnostic report** in Markdown.  The customer is
a non-technical home user.  Write plainly — avoid jargon.  Use the following
structure:

1. **Executive Summary** — one paragraph, overall health verdict, most urgent action
2. **Hardware** — machine make/model, CPU, RAM, disk model and age
3. **Disk Health** — SMART verdict, any wear indicators or bad sectors
4. **Thermal Status** — temperature verdict, throttling, fan warnings
5. **Antivirus Scan** — ClamAV result, definition age, coverage
6. **Security Findings** — persistence scan, suspicious services, execution surface
7. **System Integrity** — missing/modified system files, event log anomalies
8. **Software** — notable installed apps, legacy software, flagged items
9. **Logon History** — summary of logon events, any anomalies
10. **Recommendations** — numbered list, most critical first.  Highlight
    anything marked ACTION REQUIRED or CRITICAL in the source data.
11. **Upgrade Advice** — upgrade_advisor recommendation verbatim if present

## Tone and formatting

- Bold any **ACTION REQUIRED** or **WARNING** items
- Use tables where data is tabular
- Keep the report under 2 pages when printed
- Date the report using the most recent log timestamp
"""


def bundle_chatgpt(device_folder: str = "", output_dir: str = ".") -> str:
    """Create a zip bundle for uploading to ChatGPT to generate a customer report.

    Includes only the most-recent log file for each scan type from the named
    device subfolder (or the most recent subfolder in logs/), plus every schema
    file, plus a prompt file for ChatGPT.

    Returns the path to the created zip file.
    """
    import pathlib as _pl, zipfile as _zf, re as _re

    base = _pl.Path("logs")

    if device_folder:
        device_dir  = _pl.Path(device_folder)
        folder_name = device_dir.name
    else:
        subfolders = [d for d in base.iterdir() if d.is_dir()] if base.exists() else []
        if subfolders:
            device_dir  = max(subfolders, key=lambda d: d.stat().st_mtime)
            folder_name = device_dir.name
        else:
            device_dir  = base
            folder_name = "scan_data"

    zip_path    = _pl.Path(output_dir) / f"{folder_name}.zip"
    schemas_dir = _pl.Path(__file__).parent / "schemas"

    # Pick the most-recent file per scan-type prefix.
    # Filenames look like: <scan_type>_YYYYMMDD_HHMMSS.json[l]
    # Group by prefix (everything before the first date-like segment).
    _DATE_PAT = _re.compile(r"_\d{8}_\d{6}")
    by_prefix: dict = {}
    all_logs = sorted(device_dir.glob("*.json")) + sorted(device_dir.glob("*.jsonl"))
    for f in all_logs:
        prefix = _DATE_PAT.split(f.name)[0]   # e.g. "hardware_profile"
        # Keep whichever is lexicographically latest (timestamp is in the name)
        if prefix not in by_prefix or f.name > by_prefix[prefix].name:
            by_prefix[prefix] = f

    log_files    = sorted(by_prefix.values(), key=lambda f: f.name)
    schema_files = sorted(schemas_dir.glob("*.json"))

    with _zf.ZipFile(zip_path, "w", compression=_zf.ZIP_DEFLATED) as zf:
        for f in log_files:
            zf.write(f, f"logs/{f.name}")
        for f in schema_files:
            zf.write(f, f"schemas/{f.name}")
        zf.writestr("INSTRUCTIONS_FOR_CHATGPT.md", _CHATGPT_PROMPT)

    print(f"Bundle: {zip_path}")
    print(f"  {len(log_files)} log file(s) (most recent per scan type),  {len(schema_files)} schema file(s)")
    for f in log_files:
        print(f"    {f.name}")
    print(f"  Upload to ChatGPT and ask it to follow INSTRUCTIONS_FOR_CHATGPT.md")
    return str(zip_path)


# ---------------------------------------------------------------------------
# fetch-and-validate convenience helper
# ---------------------------------------------------------------------------

def fetch_and_validate(logs_dir: str = "logs", organize: bool = True) -> int:
    """Fetch logs from the device, run schema validation, then optionally
    organise logs into a named device subfolder.  Returns 0 if all schemas pass."""
    print("=" * 60)
    print("STEP 1 — Fetch logs from device")
    print("=" * 60)
    fetch_logs(logs_dir)

    print()
    print("=" * 60)
    print("STEP 2 — Schema validation")
    print("=" * 60)
    rc = _validate_logs(logs_dir)

    if organize:
        print()
        print("=" * 60)
        print("STEP 3 — Organise into device folder")
        print("=" * 60)
        organize_device_logs(logs_dir)

    return rc


def fetch_validate_bundle(logs_dir: str = "logs") -> None:
    """Fetch all logs, validate schemas, organise into device folder, and create
    a ChatGPT bundle zip named after the device folder."""
    print("=" * 60)
    print("STEP 1 — Fetch logs from device")
    print("=" * 60)
    fetch_logs(logs_dir)

    print()
    print("=" * 60)
    print("STEP 2 — Schema validation")
    print("=" * 60)
    _validate_logs(logs_dir)

    print()
    print("=" * 60)
    print("STEP 3 — Organise into device folder")
    print("=" * 60)
    device_path = organize_device_logs(logs_dir)

    print()
    print("=" * 60)
    print("STEP 4 — Bundle for ChatGPT")
    print("=" * 60)
    bundle_chatgpt(device_folder=device_path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    # ---- Toggle the action you want to run ----
    action = "release"  # "release" | "run_remote" | "push_file" | "push_module" | "run_module" | "run_module_serial" | "run_all" | "fetch_logs" | "organize_logs" | "fetch_and_validate" | "fetch_validate_bundle" | "bundle_chatgpt" | "setup_ssh_agent" | "relay" | "relay_status" | "ssh_test"

    # --- release config ---
    commit_message = "feat(m31): file-disk correlation, volume context, CBS file extraction, event classification, classification block, anomaly breakdown, tampering indicators, cross-module reasoning"

    # --- run_remote config ---
    remote_script = "_debug_computername.py"

    # --- push_file config ---
    push_local  = "toolkit.py"
    push_subpath = ""               # "" = USB root

    # --- run_module / push_module config ---
    module_name = "m48_bad_sector_scan"
    module_args = ["--target", "/mnt/windows"]

    # --- run_all config ---
    run_all_target        = "/mnt/windows"
    run_all_skip_existing = False   # True = skip modules that already have a log on device
    # Set to a list of (name, needs_target, extra_args) tuples to run only those modules;
    # set to None to run FULL_MODULE_SEQUENCE.
    run_all_custom_modules = [
        # These modules find their own target internally — do NOT pass --target
        ("m09_thermal_health",   False, []),
        ("m15_upgrade_advisor",  False, []),
        # Updated this session: new schema fields (source_module, interpretation, etc.)
        ("m48_bad_sector_scan",  True,  []),
        # Aggregate last — reads all other logs including the fresh ones above
        ("m17_system_summary",   True,  []),
    ]

    # ---------------------------------------------------
    if action == "release":
        release(commit_message)
    elif action == "run_remote":
        run_remote(remote_script)
    elif action == "push_file":
        push_file(push_local, push_subpath)
    elif action == "push_module":
        push_module(module_name)
    elif action == "run_module":
        run_module(module_name, module_args)
    elif action == "run_module_serial":
        run_module_serial(module_name, module_args)
    elif action == "run_all":
        run_all(target=run_all_target, skip_existing=run_all_skip_existing,
                modules=run_all_custom_modules)
    elif action == "fetch_logs":
        fetch_logs()
    elif action == "organize_logs":
        organize_device_logs()
    elif action == "fetch_and_validate":
        import sys as _sys
        _sys.exit(fetch_and_validate())
    elif action == "fetch_validate_bundle":
        fetch_validate_bundle()
    elif action == "bundle_chatgpt":
        bundle_chatgpt()
    elif action == "setup_ssh_agent":
        setup_ssh_agent()
    elif action == "relay":
        import runpy as _rp
        _rp._run_module_as_main("ssh_relay")
    elif action == "relay_status":
        resp = _relay_call("status")
        if resp is None:
            print("Relay is NOT running (no response on 127.0.0.1:19022).")
        else:
            import datetime as _dt
            uptime = resp.get("uptime_s", 0)
            h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
            print(f"Relay UP  uptime={h:02d}:{m:02d}:{s:02d}  log={resp.get('log_path','?')}")
            print()
            for line in resp.get("recent", [])[-30:]:
                print(line)
    elif action == "ssh_test":
        out = _ssh_run("echo 'session_secrets test OK'; hostname; uptime")
        print(out)
    elif action not in ("release", "run_remote", "push_file", "push_module",
                        "run_module", "run_module_serial", "run_all",
                        "fetch_logs", "organize_logs", "fetch_and_validate",
                        "fetch_validate_bundle", "bundle_chatgpt", "setup_ssh_agent",
                        "relay", "relay_status", "ssh_test"):
        print(f"Unknown action {action!r}. Valid actions: release, run_remote, push_file, push_module, run_module, run_module_serial, run_all, fetch_logs, organize_logs, fetch_and_validate, fetch_validate_bundle, bundle_chatgpt, setup_ssh_agent, relay, relay_status, ssh_test")
        sys.exit(1)


if __name__ == "__main__":
    main()
