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
    "modules/m18_clamav_scan.py",
]

_PY = r"C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ssh_args(extra: list = None) -> list:
    """Return base SSH argument list (without command)."""
    args = ["ssh", "-p", str(PORT), "-i", KEY, "-o", "StrictHostKeyChecking=no",
            f"root@{HOST}"]
    if extra:
        args += extra
    return args


def _scp_args(src: str, dst: str) -> list:
    return ["scp", "-O", "-P", str(PORT), "-i", KEY, "-o", "StrictHostKeyChecking=no",
            src, dst]


def encode_script(source: str) -> str:
    """Gzip-compress and base64-encode a Python source string."""
    return base64.b64encode(gzip.compress(source.encode("utf-8"))).decode("ascii")


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
    """
    code = pathlib.Path(script_path).read_text(encoding="utf-8")
    payload = encode_script(code)
    remote_cmd = (
        f"cd {USB_PATH} && "
        f"python3 bootstrap.py --no-update exec --payload {payload}"
    )
    subprocess.run(_ssh_args([remote_cmd]))


def push_file(local_path: str, remote_subpath: str = "") -> None:
    """SCP *local_path* to the USB root (or a subpath below it) on the remote host."""
    dst_dir = f"{USB_PATH}/{remote_subpath}".rstrip("/")
    dst = f"root@{HOST}:{dst_dir}/"
    subprocess.run(_scp_args(local_path, dst))


def push_module(name: str) -> None:
    """SCP modules/<name>.py to the modules/ directory on the USB.

    Creates the remote modules/ directory if absent via SSH.
    """
    remote_modules = f"{USB_PATH}/modules"
    subprocess.run(_ssh_args([f"mkdir -p {remote_modules}"]))
    subprocess.run(_scp_args(f"modules/{name}.py", f"root@{HOST}:{remote_modules}/"))
    print(f"Pushed modules/{name}.py to device.")


def run_module(name: str, module_argv: list = None) -> None:
    """Push modules/<name>.py to device then run it via bootstrap run.

    *module_argv* is a list of strings passed after ``--`` to the module.
    Example: run_module("m01_persistence_scan", ["--target", "/mnt/windows"])
    """
    push_module(name)
    argv_str = " ".join(module_argv) if module_argv else ""
    sep = " -- " if argv_str else ""
    remote_cmd = (
        f"cd {USB_PATH} && "
        f"python3 bootstrap.py --no-update run {name}{sep}{argv_str}"
    )
    subprocess.run(_ssh_args([remote_cmd]))


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
    action = "release"            # "release" | "run_remote" | "push_file" | "setup_ssh_agent"

    # --- release config ---
    commit_message = "refactor: dynamic module dispatch; modules/ subfolder; run/load/status commands"

    # --- run_remote config ---
    remote_script = "svc_diag.py"   # local path to the script to run remotely

    # --- push_file config ---
    push_local  = "modules/m01_persistence_scan.py"
    push_subpath = "modules"        # "" = USB root; e.g. "modules" for a module file

    # --- run_module / push_module config ---
    module_name = "m01_persistence_scan"
    module_args = ["--target", "/mnt/windows", "--summary"]

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
    else:
        print(f"Unknown action {action!r}. Set action to one of: release, run_remote, push_file, push_module, run_module, setup_ssh_agent")
        sys.exit(1)


if __name__ == "__main__":
    main()
