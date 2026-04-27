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

## Python Compile-Time Checks (mandatory before every commit)

Every `.py` file that is **added or modified** in a commit must pass a compile
check before the commit is made.  A syntax error in `toolkit.py` or
`bootstrap.py` would be downloaded by the auto-updater and immediately break
the rescue toolkit on the target machine with no recovery path.

**Run this for every changed `.py` file:**

```powershell
C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe -m py_compile toolkit.py bootstrap.py
```

Or for all `.py` files in the repo at once:

```powershell
Get-ChildItem -Recurse -Filter *.py | ForEach-Object {
    C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe -m py_compile $_.FullName
}
```

`py_compile` exits 0 on success and prints the offending line on any syntax
error.  **Do not `git commit` or `git push` if this command fails.**

This check is in addition to any manual testing — it must be run even for
one-line changes.

## SHA256 Checksum After Every Push (mandatory)

After every `git push`, compute the **LF-normalized SHA256** of **all three
updateable files** (`bootstrap.py`, `bootstrap.sh`, `toolkit.py`) and
**display them to the user** so they can be compared against what
`bootstrap update` prints on RescueZilla.  Do NOT write the hash values into
this file.

**Run after every push and show the output to the user:**

```powershell
C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe -c "
import hashlib, pathlib
for f in ['bootstrap.py', 'bootstrap.sh', 'toolkit.py']:
    data = pathlib.Path(f).read_bytes().replace(b'\r\n', b'\n')
    print(hashlib.sha256(data).hexdigest(), ' ', f)
"
```

The user will compare these against the lines printed by `bootstrap update`
on RescueZilla.  All three hashes must match exactly.  If any differ, the
update did not land (stale CDN, partial download, or `.pyc` cache issue).

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
