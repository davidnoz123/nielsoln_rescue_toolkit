#!/usr/bin/env python3
"""Fetch the most recent module log for each schema from the device and
validate it against the corresponding JSON Schema (draft-07).

Usage (from toolkit root, with NRT_SSH_PASSPHRASE set):
    import runpy; runpy._run_module_as_main("validate_logs")

Or directly:
    python validate_logs.py [--no-fetch]

Options
-------
--no-fetch   Skip fetching from the device; validate whatever is already in
             logs/ locally.
"""

import argparse
import fnmatch
import json
import pathlib
import subprocess
import sys

ROOT        = pathlib.Path(__file__).parent
SCHEMAS_DIR = ROOT / "schemas"
LOGS_DIR    = ROOT / "logs"
USB_LOGS    = "/media/ubuntu/GRTMPVOL_EN/NIELSOLN_RESCUE_USB/logs"

# ---------------------------------------------------------------------------

def _ssh_capture(cmd: str) -> str:
    """Run SSH command via devtools auth helpers; return stdout as str."""
    import devtools as _dt
    result = subprocess.run(
        _dt._ssh_args([cmd]),
        capture_output=True, text=True, env=_dt._askpass_env(),
    )
    return result.stdout


def fetch_most_recent(remote_files: list[str], glob: str) -> str | None:
    """Return the most recent remote filename matching glob, or None."""
    matches = sorted(f for f in remote_files if fnmatch.fnmatch(f, glob))
    return matches[-1] if matches else None


def fetch_logs(remote_files: list[str], index: dict) -> None:
    """scp the most-recent log for each schema entry into LOGS_DIR."""
    import devtools as _dt
    LOGS_DIR.mkdir(exist_ok=True)

    for mod, info in index["modules"].items():
        globs = []
        if "log_glob" in info:
            globs.append(("log_glob", info["log_glob"]))
        if "log_glob_run" in info:
            globs.append(("log_glob_run", info["log_glob_run"]))
        # Chunk files are large JSONL — skip fetching event_archive chunks
        # (chunk files live in a subdirectory; validate run summary only)

        for key, lg in globs:
            # lg is like "logs/hardware_profile_*.json" — extract filename part
            pat = pathlib.Path(lg).name
            match = fetch_most_recent(remote_files, pat)
            if not match:
                print(f"  [SKIP] {mod}: no file matching {pat}")
                continue
            remote_path = f"{USB_LOGS}/{match}"
            local_path  = LOGS_DIR / match
            if local_path.exists():
                print(f"  [CACHED] {match}")
            else:
                print(f"  [FETCH]  {match} ...")
                _dt._scp_get(remote_path, str(local_path))


def validate_file(schema_path: pathlib.Path, data_path: pathlib.Path,
                  validator_cls, is_jsonl: bool) -> list[str]:
    """Validate data_path against schema_path.  Return list of error strings."""
    from jsonschema import ValidationError

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = []

    if is_jsonl:
        lines = data_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for lineno, raw in enumerate(lines, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                errors.append(f"  line {lineno}: JSON parse error — {exc}")
                continue
            for err in validator_cls(schema).iter_errors(obj):
                errors.append(f"  line {lineno}: {err.json_path}: {err.message}")
    else:
        try:
            obj = json.loads(data_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            return [f"  JSON parse error — {exc}"]
        for err in validator_cls(schema).iter_errors(obj):
            errors.append(f"  {err.json_path}: {err.message}")

    return errors


def run_validation(index: dict) -> dict:
    """Validate all locally present log files.  Return results dict."""
    from jsonschema import Draft7Validator

    results = {}

    for mod, info in index["modules"].items():
        schema_key = "schema" if "schema" in info else "schema_run"
        schema_file = info.get(schema_key)
        if not schema_file:
            continue

        glob = info.get("log_glob") or info.get("log_glob_run", "")
        pat  = pathlib.Path(glob).name
        fmt  = info.get("format", "JSON")
        is_jsonl = "JSONL" in fmt and "JSON +" not in fmt  # pure JSONL only

        # Pick the most recent local file matching the pattern
        local_files = sorted(LOGS_DIR.glob(pat))
        if not local_files:
            results[mod] = {"status": "MISSING", "file": None, "errors": []}
            continue

        data_path   = local_files[-1]
        schema_path = SCHEMAS_DIR / schema_file
        errors = validate_file(schema_path, data_path, Draft7Validator, is_jsonl)

        results[mod] = {
            "status": "PASS" if not errors else "FAIL",
            "file":   data_path.name,
            "errors": errors,
        }

    return results


def print_report(results: dict) -> int:
    """Print a human-readable summary.  Returns exit code (0=all pass)."""
    pass_count = sum(1 for r in results.values() if r["status"] == "PASS")
    fail_count = sum(1 for r in results.values() if r["status"] == "FAIL")
    skip_count = sum(1 for r in results.values() if r["status"] == "MISSING")
    total = len(results)

    print()
    print("=" * 68)
    print("  SCHEMA VALIDATION REPORT")
    print("=" * 68)

    for mod, r in sorted(results.items()):
        icon = {"PASS": "✓", "FAIL": "✗", "MISSING": "–"}.get(r["status"], "?")
        fname = r["file"] or "(no log)"
        print(f"  {icon}  {mod:<36}  {r['status']:<7}  {fname}")
        for e in r["errors"]:
            print(f"         {e}")

    print("=" * 68)
    print(f"  PASS {pass_count}  |  FAIL {fail_count}  |  MISSING {skip_count}  |  TOTAL {total}")
    print("=" * 68)
    print()
    return 1 if fail_count else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-fetch", action="store_true",
                        help="Skip fetching logs from device; use local copies.")
    args = parser.parse_args(argv)

    # Check jsonschema is available
    try:
        import jsonschema  # noqa
    except ImportError:
        sys.exit("ERROR: jsonschema not installed.\n"
                 "  pip install jsonschema")

    # Load index
    index = json.loads((SCHEMAS_DIR / "_index.json").read_text(encoding="utf-8"))

    if not args.no_fetch:
        sys.path.insert(0, str(ROOT))
        import devtools as _dt  # noqa — side effect: sets up auth

        print("Listing remote logs ...")
        raw = _ssh_capture(f"ls {USB_LOGS}/")
        remote_files = [f.strip() for f in raw.splitlines() if f.strip()]
        print(f"  {len(remote_files)} files found on device.")
        print()
        print("Fetching most-recent log per module ...")
        fetch_logs(remote_files, index)
        print()

    results = run_validation(index)
    rc = print_report(results)
    return rc


if __name__ == "__main__":
    sys.exit(main())
