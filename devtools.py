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
import gzip
import hashlib
import pathlib
import socket
import subprocess
import sys

# ---------------------------------------------------------------------------
# Configuration — edit these before running
# ---------------------------------------------------------------------------

HOST        = "192.168.1.67"
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
]

_PY = r"C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe"

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
    """If the relay isn't running, launch ssh_relay.py in a new console window.

    The user types the passphrase once in that window.  We wait up to 60 s
    for the relay to come up, then proceed.  All subsequent SSH/SCP calls go
    through the relay without further prompts.
    """
    global _relay_started
    if _relay_up():
        return

    relay_script = str(pathlib.Path(__file__).with_name("ssh_relay.py"))
    print("SSH relay is not running — launching it now.")
    print("Please enter the key passphrase in the new console window that opens.")
    print("Waiting for relay to start (up to 60 s)...")

    # Open a new visible console window so the passphrase prompt is visible.
    import subprocess as _sp
    _sp.Popen(
        ["cmd", "/c", "start", "SSH Relay",
         _PY, relay_script],
        creationflags=0,   # no hidden flags — window is visible
    )

    deadline = __import__("time").monotonic() + 60
    while __import__("time").monotonic() < deadline:
        __import__("time").sleep(1)
        if _relay_up():
            print("Relay is up — proceeding.")
            _relay_started = True
            return

    print("WARNING: relay did not start within 60 s — falling back to direct SSH (will prompt for passphrase).")


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
    # Fallback — prompts for passphrase
    kwargs = {"input": stdin_data} if stdin_data is not None else {}
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
    # Fallback
    subprocess.run(_scp_args(local, f"root@{HOST}:{remote}"))


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


def run_remote(script_path: str) -> None:
    """Encode *script_path* and execute it on the remote host via bootstrap exec.

    The script runs inside the USB root directory with ``root`` (Path) and
    ``Path`` available as globals.  stdout/stderr stream directly to your
    terminal so the passphrase prompt works normally.

    The payload is sent via stdin (not as a CLI arg) to avoid ARG_MAX limits
    on large scripts.
    """
    code = pathlib.Path(script_path).read_text(encoding="utf-8")
    payload = encode_script(code)
    remote_cmd = (
        f"cd {USB_PATH} && "
        f"python3 bootstrap.py --no-update exec"
    )
    _ssh_run(remote_cmd, stdin_data=payload.encode("ascii"))


def push_file(local_path: str, remote_subpath: str = "") -> None:
    """SCP *local_path* to the USB root (or a subpath below it) on the remote host."""
    dst_dir = f"{USB_PATH}/{remote_subpath}".rstrip("/")
    remote = f"{dst_dir}/{pathlib.Path(local_path).name}"
    _scp_run(local_path, remote)


def push_module(name: str) -> None:
    """SCP modules/<name>.py to the modules/ directory on the USB.

    Creates the remote modules/ directory if absent via SSH.
    """
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
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    # ---- Toggle the action you want to run ----
    action = "release"              # "release" | "run_remote" | "push_file" | "push_module" | "run_module" | "setup_ssh_agent" | "relay" | "relay_status"

    # --- release config ---
    commit_message = "feat: m25 full channel discovery + progress logging; docs: AGENTS deploy method rule"

    # --- run_remote config ---
    remote_script = "_setup_clamav.py"  # local path to the script to run remotely

    # --- push_file config ---
    push_local  = "toolkit.py"
    push_subpath = ""               # "" = USB root

    # --- run_module / push_module config ---
    module_name = "m26_os_profile"
    module_args = ["--target", "/mnt/windows"]

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
    else:
        print(f"Unknown action {action!r}. Set action to one of: release, run_remote, push_file, push_module, run_module, setup_ssh_agent")
        sys.exit(1)


if __name__ == "__main__":
    main()
