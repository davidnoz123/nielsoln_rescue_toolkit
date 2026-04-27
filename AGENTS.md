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

## Development constraints

- Stage builds locally first.
- Do not write directly to the user's USB until explicitly instructed.
- Build into `dist/NIELSOLN_RESCUE_USB`.
- Keep `bootstrap.sh` minimal.
- Put as much logic as practical into Python.

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
