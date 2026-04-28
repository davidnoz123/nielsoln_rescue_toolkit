# AGENTS.md

You are building the Nielsoln Rescue Toolkit.

## Mission

Create a portable USB-based rescue toolkit for scanning and triaging offline Windows installations, especially old Windows Vista laptops booted from RescueZilla or another Linux live environment.

## Repository name

Use:

```text
nielsoln-rescue-toolkit
```

## Primary target environment

- RescueZilla live Linux terminal
- Ubuntu/Debian-like environment
- x86_64 laptop hardware
- Mounted offline Windows Vista installation

## Important constraints

- Do not assume internet access.
- Do not assume Git is installed on the rescue environment.
- Do not assume Python packages can be installed online.
- Prefer standard library Python.
- Do not modify the target Windows installation in version 1.
- Do not delete files.
- Do not quarantine files by default.
- Produce logs and reports.
- **NEVER hard-code or guess the Windows mount path** (e.g. do not assume
  `/mnt/windows`). Always resolve it at runtime: call `find_windows_target()`
  from `toolkit.py`, or run `findmnt -t ntfs,fuseblk` on the device first.
  The actual mount point depends on how the rescue environment mounts the disk
  (RescueZilla uses `/mnt/windows` today, but this must never be assumed).

## Development constraints

- Stage builds locally first.
- Do not write directly to the user's USB until explicitly instructed.
- Build into `dist/NIELSOLN_RESCUE_USB`.
- Keep `bootstrap.sh` minimal.
- Put as much logic as practical into Python.

## Housekeeping — never delete, always archive to `old/`

When cleaning up the repository, **never delete files**.  Move them to `old/`
and stop tracking them in git instead:

```bash
# Move and untrack in one step:
git rm --cached <file-or-dir>
Move-Item <file-or-dir> old\
```

This applies to:
- Ad-hoc session Python scripts (`run_*.py`, `wait_*.py`, `_*.py`) once their
  logic has been absorbed into `devtools.py`.
- Stale planning/design markdown docs once the work they describe is complete.
- Any other file that is no longer part of the active codebase.

The `old/` folder is gitignored (`old/` in `.gitignore`), so archived files
never re-appear in `git status`.

## Self-healing USB principle

The toolkit must be self-healing: a USB stick containing only the three source
files (`bootstrap.sh`, `bootstrap.py`, `toolkit.py`) should be able to fully
provision itself given a network connection.

Rules that follow from this:

- `run_update()` must fetch all binary dependencies (currently: `dropbear`)
  in addition to updating the source files.  When adding a new bundled binary,
  also add its download call to `run_update()`.
- `build_usb_package()` must include the same binaries so an offline USB built
  on the dev machine is also complete.
- Do not commit binaries to Git.  Store them under `_tools/` (gitignored) and
  always provide a `download_<tool>(root)` function in `toolkit.py` that
  fetches them from a stable public URL.
- If a binary download fails (no network), `run_update` must warn clearly and
  continue — never abort the source-file update.
- `dropbear` does not include an SFTP server — always use `scp -O` (legacy SCP
  protocol) when copying files to the rescue machine.

## GitHub

Use the `gh` CLI if available and authenticated:

```bash
gh repo create nielsoln-rescue-toolkit --private --source=. --remote=origin --push
```

## Safety

The first release must be report-only.

Allowed:

- read files
- hash files
- run ClamAV if available
- write logs to USB
- write reports to USB
- run offline persistence scan (`modules/m01_persistence_scan.py`) — produces JSONL report

Disallowed in v1:

- delete infected files
- modify registry hives
- repair boot records
- change permissions on the target drive
- mount Windows partitions read-write unless explicitly requested



# Project Agent Instructions

## Environment

- **Python interpreter**: `C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe`
  - Use this interpreter for all Python jobs unless stated otherwise.

## Coding Style / REPL Workflow

The developer runs Python modules interactively from a command prompt (outside VS Code),
launched from the script's folder, using:

```python
import runpy ; temp = runpy._run_module_as_main("<module-name>")
```

Rules that follow from this:

- **Always include the runpy invocation in the module docstring** of every runnable
  module, so it is immediately visible when the file is opened.
- **When suggesting how to run a module, give the `runpy` form**, not `python script.py`.
- **CLI args are not available in the REPL.** Instead, desired argument values are
  hardcoded directly in `main()` (e.g. `args.all_items = True`) and toggled by the
  developer before running. This is intentional — do not remove or refactor these
  hardcoded overrides.
- The working directory at the prompt is the script's folder, so the module name
  resolves without any path manipulation.

## Python Compile-Time Checks + Release (mandatory before every commit)

Use `devtools.py` with `action = "release"`.  It compiles every `.py`, commits,
pushes, and prints LF-normalised SHA256 hashes in one step.

Run it with:

```python
import runpy ; temp = runpy._run_module_as_main("devtools")
```

`release()` aborts before committing if any `.py` file fails `py_compile`.
Never bypass this — a syntax error in `bootstrap.py` or `toolkit.py` would
break the auto-updater on the rescue machine with no recovery path.

## SHA256 Hashes After Every Push (mandatory)

`devtools.py release()` prints LF-normalised SHA256 for every file listed in
`UPDATE_FILES` automatically at the end of each push.  Compare these against
the hashes printed by `bootstrap update` on RescueZilla.  All hashes must
match exactly.  If any differ, the update did not land (stale CDN, partial
download, or `.pyc` cache issue).

## CRITICAL: Deploy via SSH/SCP — NEVER use `bootstrap update` from the dev machine

There are **two separate deployment paths** and they must never be confused:

| Path | When to use | How it works |
|---|---|---|
| **`push_module` / `push_file`** (devtools.py) | Dev machine → device | Direct SCP over SSH via relay. Instant. No internet needed on device. |
| **`bootstrap update`** (on device) | Device self-update in the field | Device pulls from GitHub over the internet. Has CDN lag after a push. |

**Rules:**

- **When deploying a change or collecting data from the dev machine, ALWAYS use
  `run_module` or `push_module` / `push_file` in `devtools.py`.**
  Set `action = "run_module"` (to push+run) or `action = "push_module"` (push
  only), edit `module_name` and `module_args`, then run devtools via `runpy`.
- **NEVER run `bootstrap update` from the dev machine as a deploy step.**
  It tells the *device* to fetch from GitHub.  This requires internet on the device,
  has CDN propagation delay after a `git push`, and is slower than SCP.
- **NEVER SSH into the device and run `python3 bootstrap.py update` manually.**
  Use `run_module` instead.
- `bootstrap update` is the *self-healing* mechanism for the rescue machine when
  it has internet access in the field.  It is not a dev tool.
- If you accidentally `bootstrap update` instead of `push_module`, you may deploy
  a stale version (GitHub CDN may not have the latest commit yet).

### Standard workflow for collecting data from all modules

1. Commit and push changes with `action = "release"` in `devtools.py`.
2. For each module that needs to run, set `action = "run_module"` in `devtools.py`,
   set `module_name` and `module_args`, and run via `runpy`.
   - `run_module` pushes the latest `.py` via SCP then immediately runs it on the
     device via `bootstrap.py run`.  One relay connection. No GitHub needed.
3. After all modules have run, use `validate_logs.py` with `--no-fetch` if logs
   were already SCP'd locally, or set `action = "run_remote"` with a fetch script.
4. Run `validate_logs.py` (see JSON Schema section) to validate all logs.

## CRITICAL: Lock File Safety — NEVER Delete Blindly

The USB toolkit uses a `.lock` file to prevent concurrent operations.  When a
lock exists, it contains the command name, start timestamp, and PID of the
owning process.

**Before removing `.lock` you MUST verify the process is dead:**

```bash
# Step 1 — check if the PID is still running
ssh ... "ps -p <PID> 2>&1"

# Only if the process is NOT found in ps output:
# Step 2 — then it is safe to remove
ssh ... "rm -f /media/ubuntu/GRTMPVOL_EN/NIELSOLN_RESCUE_USB/.lock && echo 'lock cleared'"
```

**Rules that must never be broken:**

- **NEVER run `rm .lock` without first running `ps -p <PID>` over SSH.**
  Deleting the lock while the process is alive creates two concurrent Python
  processes writing to the same log files — data corruption and race conditions.
- The PID is printed in the error message:
  `Another operation is already running: '...' (PID 36425)` — extract it
  and check it before acting.
- If `ps -p <PID>` shows the process is alive, **wait for it to finish**
  (poll with `get_terminal_output`) rather than killing it or deleting the lock.
- `toolkit.py` already has `_pid_alive()` self-healing for stale locks.  Trust
  that mechanism; only intervene manually when you have confirmed the PID is gone.
- Inform the user before removing any lock and explain why it is safe to do so.

---

## Ad-hoc Remote Python (use devtools.py run_remote)

To run a diagnostic script on RescueZilla without copying a file:

1. Write the script locally (it will NOT be committed).
2. In `devtools.py`, set `action = "run_remote"` and `remote_script = "<script>.py"`.
3. Run `devtools` via `runpy` — the script is gzip+base64 encoded, sent over
   SSH, and executed by `bootstrap.py exec` on the remote host.  Output
   streams back to your terminal.

## Module index

All scan/analysis tools live in `modules/mNN_*.py`.  See `MODULES.md` (when
created) for a concise per-module API reference.  Until then, read the
`DESCRIPTION` constant and `run()` signature at the top/bottom of each file.

### Built-in vs. module rule

| Category | Examples | Location |
|---|---|---|
| **USB lifecycle** | `update`, `load`, `run`, `status`, `exec`, `ssh`, `runtime`, `clamav` (install), `dropbear` | Hardcoded in `bootstrap.py` + `toolkit.py` |
| **Analysis modules** | everything that scans a target | `modules/mNN_*.py` |

Never add a new analysis command as a hardcoded `if args.command ==` block in
`bootstrap.py`.  Create a module file instead.

### Module protocol (required symbols)

Every `modules/mNN_*.py` must expose:

```python
DESCRIPTION: str               # one-line summary shown by bootstrap status
def run(root: Path, argv: list) -> int:  # argv = raw string args; module owns its own argparse
```

### Running a module on the device

```bash
# From RescueZilla:
cd /media/ubuntu/GRTMPVOL_EN/NIELSOLN_RESCUE_USB
python3 bootstrap.py run m01_persistence_scan -- --target /mnt/windows

# Via devtools.py from dev machine:
action = "run_module"
module_name = "m01_persistence_scan"
module_args = ["--target", "/mnt/windows", "--summary"]
```

### Deploying a new module to device (without a full update)

```python
# In devtools.py:
action = "push_module"
module_name = "m02_disk_overview"   # pushes modules/m02_disk_overview.py
```

Or push-and-run in one step:

```python
action = "run_module"
module_name = "m02_disk_overview"
module_args = ["--target", "/mnt/windows"]
```

### Checking USB state

```bash
# On RescueZilla:
python3 bootstrap.py status
# Prints SHA256 + present/absent for all core files and installed modules.
# Compare hashes against those printed by devtools release.
```

## Pushing a File to the Device (use devtools.py push_file)

To copy a single file to the USB root on the rescue machine:

1. In `devtools.py`, set `action = "push_file"`, `push_local = "<file>"`, and
   optionally `push_subpath = "<subdir>"` (default `""` = USB root).
2. Run `devtools` via `runpy`.

Note: the underlying `scp` call always uses the `-O` flag (legacy SCP protocol)
because the remote host runs `dropbear`, which does not include an SFTP server.
Always use `-O` in any manual `scp` commands to the rescue machine.

## CRITICAL: SSH Passphrase — Always Use session_secrets, Never Prompt

The passphrase for `C:\Users\david\.ssh\id_ed25519` is stored in the
`session_secrets` module (in-memory key/value store, populated at the start of
each dev session).

**Rules that must never be broken:**

- **NEVER call `devtools._ensure_passphrase()` directly in a Python one-liner
  or standalone script** unless `session_secrets` has already been imported and
  queried first.  Calling it cold drops to an interactive `getpass.getpass()`
  prompt which blocks the terminal.
- **NEVER pass the passphrase as a CLI argument or write it to a file.**
- **Always load the passphrase via `session_secrets` first:**

```python
import sys, pathlib
sys.path.insert(0, str(pathlib.Path('.').resolve()))
import session_secrets          # loads NRT_SSH_PASSPHRASE into os.environ
import devtools as dt           # _ensure_passphrase() will find it in env — no prompt

# now safe to call any dt function
dt._ssh_run("echo OK")
```

- If `session_secrets` is not available (cold terminal), the passphrase will be
  prompted once and cached in `devtools._passphrase` for the rest of the process.
  In that case accept the prompt — do NOT try to bypass it.

## CRITICAL: SSH Transport — Always Use the Relay

All SSH and SCP calls from the dev machine go through `ssh_relay.py`, a local
TCP relay daemon that caches the authenticated SSH connection.  This avoids
a passphrase prompt on every call and is **significantly faster** than spawning
a new `ssh` subprocess each time.

**Rules:**

- **NEVER call `subprocess.run(["ssh", ...])` or `subprocess.run(["scp", ...])`
  directly in scripts or one-liners.**  Always use `devtools._ssh_run()` and
  `devtools._scp_run()` / `devtools._scp_get()` — these automatically route
  through the relay.
- `devtools._ssh_run()` calls `_ensure_relay()` internally.  If the relay is
  not running it starts it automatically.
- The relay listens on `127.0.0.1:19022`.  Check with
  `action = "relay_status"` in `devtools.py`.
- **Do NOT write Python one-liners that contain the full SSH connection string.**
  Use the devtools helpers instead.

### Correct pattern for any ad-hoc SSH task from the dev machine

```python
import sys, pathlib
sys.path.insert(0, str(pathlib.Path('.').resolve()))
import session_secrets          # 1. Load passphrase into env
import devtools as dt           # 2. Import devtools (relay auto-starts)

dt._ssh_run("your command here")   # 3. Use the helpers — relay handles auth
```

## SSH Key Passphrase Caching (one-time setup per machine)

The `devtools.py` SSH/SCP calls all use the key
`C:\Users\david\.ssh\id_ed25519`.  To avoid passphrase prompts on every call:

**One-time setup (requires an elevated (Admin) PowerShell):**

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
ssh-add C:\Users\david\.ssh\id_ed25519   # prompts for passphrase once
```

After this, all ssh/scp/devtools calls in any terminal session are
passphrase-free until the machine is rebooted (at which point the agent
auto-starts and you re-run just `ssh-add`).

Alternatively, set `action = "setup_ssh_agent"` in `devtools.py` and run it
from an elevated terminal — it performs the same steps automatically.

**Do NOT store the passphrase in any source file or AGENTS.md.**

## JSON Schemas for Module Logs

All module output formats are documented as JSON Schema draft-07 files in
`schemas/`.  See `schemas/_index.json` for the full module → schema → log-glob
mapping.

### Validating logs on the dev machine

Use `validate_logs.py` (root of repo) to validate locally-fetched logs against
their schemas:

```python
import runpy ; temp = runpy._run_module_as_main("validate_logs")
```

Set `logs_dir` and optionally `module_filter` inside `main()` before running.
Requires the `jsonschema` package (already available in the dev venv).

### Future consideration — VS Code live validation

Adding a `"$schema"` key pointing to the schema file at the top of each
generated log would give inline red-underline validation when browsing logs in
VS Code.  This is low-value today because logs are auto-generated and rarely
edited by hand.  Worth adding if logs start being reviewed interactively
(e.g., open `disk_health_*.json` in VS Code and see field annotations).

## Process Visibility

- **No hidden processes.** Never start Python or Excel processes invisibly.
  - VBA `Shell` calls must use `vbNormalFocus` (not `vbHide` or `vbMinimizedNoFocus`).
  - Excel COM automation must set `Application.Visible = True` (never `False`).
  - Do not use `subprocess` flags or any other mechanism that hides a window from the user.
  - Chrome launched via `ChromeLauncher.start()` must use `headless=False` always.

## Office COM / VBA Coding Rules

- **Never use `Active*` objects.** Avoid `ActiveDocument`, `ActiveSheet`,
  `ActiveWorkbook`, `ActiveWindow`, `Selection` (when avoidable), and any other
  implicit-context object in both Python `win32com` code and generated VBA.
  - Always hold an explicit reference to the document/workbook/sheet/range
    you intend to operate on and use that reference directly.
  - Reason: `Active*` objects change silently when the user clicks, when a COM
    call switches the active document (e.g. `shape.Select()` activates its
    parent), or when `ScreenUpdating` is toggled — causing operations to land
    in the wrong document with no error.
