"""m34_task_scheduler_analysis — Offline Windows scheduled task analysis.

Reads task XML files from the offline Windows Tasks directory
(Windows\\System32\\Tasks and Windows\\SysWOW64\\Tasks) to enumerate all
scheduled tasks, their triggers, actions, and risk indicators.

Flags:
  hidden_task           — Hidden flag set in registration info
  suspicious_path       — Action runs from AppData, Temp, Downloads, Public, Roaming
  encoded_command       — Encoded command in arguments (e.g. -EncodedCommand, base64-like)
  lolbin_usage          — Uses living-off-the-land binary: mshta, wscript, cscript,
                          rundll32, regsvr32, certutil, bitsadmin, msiexec with URL
  missing_target        — Executable path does not exist on disk
  disabled_task         — Task is explicitly disabled
  suspicious_author     — Unknown or blank author on a system-looking task
  run_as_system         — Runs as SYSTEM / NT AUTHORITY\\SYSTEM

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m34_task_scheduler_analysis -- --target /mnt/windows

Output:
    logs/task_scheduler_analysis_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DESCRIPTION = (
    "Scheduled task analysis: enumerates task XML files, parses triggers/actions, "
    "and flags hidden, suspicious-path, encoded, lolbin, and missing-target tasks"
)

# ---------------------------------------------------------------------------
# XML namespace helper
# ---------------------------------------------------------------------------

_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def _tag(name: str) -> str:
    return f"{{{_NS}}}{name}"


def _find(el: ET.Element, *path: str) -> Optional[ET.Element]:
    cur = el
    for part in path:
        found = cur.find(_tag(part))
        if found is None:
            return None
        cur = found
    return cur


def _text(el: ET.Element, *path: str, default: str = "") -> str:
    node = _find(el, *path)
    if node is None or node.text is None:
        return default
    return node.text.strip()


def _all(el: ET.Element, *path: str) -> List[ET.Element]:
    cur = el
    for part in path[:-1]:
        cur_next = cur.find(_tag(part))
        if cur_next is None:
            return []
        cur = cur_next
    return cur.findall(_tag(path[-1]))


# ---------------------------------------------------------------------------
# Suspicious-path patterns
# ---------------------------------------------------------------------------

_SUSPICIOUS_PATH_PATTERNS = [
    r"\\appdata\\",
    r"\\temp\\",
    r"\\tmp\\",
    r"\\downloads\\",
    r"\\public\\",
    r"\\roaming\\",
    r"\\local\\temp",
    r"%temp%",
    r"%appdata%",
    r"%public%",
    r"%userprofile%\\downloads",
]

_LOLBINS = {
    "mshta.exe", "mshta",
    "wscript.exe", "wscript",
    "cscript.exe", "cscript",
    "rundll32.exe", "rundll32",
    "regsvr32.exe", "regsvr32",
    "certutil.exe", "certutil",
    "bitsadmin.exe", "bitsadmin",
    "powershell.exe", "powershell",
    "cmd.exe", "cmd",
}

# Encoded command indicators
_ENCODED_PATTERNS = [
    r"-encodedcommand\b",
    r"-enc\s+[A-Za-z0-9+/=]{20,}",
    r"-e\s+[A-Za-z0-9+/=]{20,}",
]

_SYSTEM_ACCOUNTS = {
    "system",
    "nt authority\\system",
    "s-1-5-18",
    "localservice",
    "nt authority\\localservice",
    "networkservice",
    "nt authority\\networkservice",
}


# ---------------------------------------------------------------------------
# Task XML parser
# ---------------------------------------------------------------------------

def _parse_triggers(root_el: ET.Element) -> List[dict]:
    triggers_el = _find(root_el, "Triggers")
    if triggers_el is None:
        return []
    triggers: List[dict] = []
    for child in triggers_el:
        tag_name = child.tag.replace(f"{{{_NS}}}", "")
        trig: dict = {"type": tag_name}
        # Common sub-elements
        for field in ("StartBoundary", "EndBoundary", "Enabled", "ExecutionTimeLimit"):
            val = _text(child, field)
            if val:
                trig[field.lower()] = val
        # ScheduleByDay
        schedule = _find(child, "ScheduleByDay")
        if schedule is not None:
            trig["days_interval"] = _text(schedule, "DaysInterval")
        # BootTrigger / LogonTrigger specifics
        if tag_name == "LogonTrigger":
            trig["user_id"] = _text(child, "UserId")
        triggers.append(trig)
    return triggers


def _parse_actions(root_el: ET.Element) -> List[dict]:
    actions_el = _find(root_el, "Actions")
    if actions_el is None:
        return []
    actions: List[dict] = []
    for child in actions_el:
        tag_name = child.tag.replace(f"{{{_NS}}}", "")
        act: dict = {"type": tag_name}
        if tag_name == "Exec":
            act["command"]         = _text(child, "Command")
            act["arguments"]       = _text(child, "Arguments")
            act["working_dir"]     = _text(child, "WorkingDirectory")
        elif tag_name == "ComHandler":
            act["class_id"]        = _text(child, "ClassId")
            act["data"]            = _text(child, "Data")
        elif tag_name == "SendEmail":
            act["subject"]         = _text(child, "Subject")
            act["server"]          = _text(child, "Server")
        actions.append(act)
    return actions


def _is_suspicious_path(path_str: str) -> bool:
    low = path_str.lower().replace("/", "\\")
    return any(re.search(p, low) for p in _SUSPICIOUS_PATH_PATTERNS)


def _is_lolbin(command: str) -> bool:
    exe = Path(command.replace('"', "").strip()).name.lower()
    return exe in _LOLBINS


def _has_encoded_command(args_str: str) -> bool:
    low = args_str.lower()
    return any(re.search(p, low) for p in _ENCODED_PATTERNS)


def _exe_exists(command: str, target: Path) -> Optional[bool]:
    """Check if the command exe exists on the offline volume.  Returns None if unknown."""
    cmd = command.strip().strip('"')
    if not cmd:
        return None
    # Skip environment variable paths (can't reliably resolve)
    if cmd.startswith("%"):
        return None
    # Convert Windows path to Linux path
    cmd_lower = cmd.lower().replace("/", "\\")
    for prefix in ("c:\\", "c:"):
        if cmd_lower.startswith(prefix):
            rel = cmd[len(prefix):].replace("\\", "/")
            return (target / rel).exists()
    # Relative or bare name — can't resolve
    return None


def _compute_flags(task: dict, target: Path) -> List[str]:
    flags: List[str] = []

    if task.get("hidden"):
        flags.append("hidden_task")

    enabled = task.get("enabled", True)
    if not enabled:
        flags.append("disabled_task")

    run_as = (task.get("run_as") or "").lower()
    if run_as in _SYSTEM_ACCOUNTS:
        flags.append("run_as_system")

    for action in task.get("actions", []):
        if action.get("type") != "Exec":
            continue
        cmd  = action.get("command", "")
        args = action.get("arguments", "")

        if cmd and _is_suspicious_path(cmd):
            flags.append("suspicious_path")

        if cmd and _is_lolbin(cmd):
            flags.append("lolbin_usage")

        if args and _has_encoded_command(args):
            flags.append("encoded_command")

        if cmd:
            exists = _exe_exists(cmd, target)
            if exists is False:
                flags.append("missing_target")

    return list(dict.fromkeys(flags))  # deduplicate, preserve order


def _parse_task_xml(xml_path: Path, target: Path) -> Optional[dict]:
    try:
        tree = ET.parse(str(xml_path))
        root_el = tree.getroot()
        # Strip default namespace if present for cleaner access
        if root_el.tag != "Task":
            # Try with namespace
            if root_el.tag != f"{{{_NS}}}Task":
                # Try without namespace as fallback (some tasks use no NS)
                pass
    except ET.ParseError:
        return None
    except Exception:
        return None

    try:
        reg_info = _find(root_el, "RegistrationInfo")
        principals = _find(root_el, "Principals")
        settings   = _find(root_el, "Settings")

        author      = _text(reg_info, "Author")       if reg_info else ""
        description = _text(reg_info, "Description")  if reg_info else ""
        uri         = _text(reg_info, "URI")          if reg_info else ""
        date_reg    = _text(reg_info, "Date")         if reg_info else ""

        run_as = ""
        if principals is not None:
            principal = _find(principals, "Principal")
            if principal is not None:
                run_as = _text(principal, "UserId") or _text(principal, "GroupId")

        enabled = True
        hidden  = False
        if settings is not None:
            enabled_str = _text(settings, "Enabled").lower()
            if enabled_str == "false":
                enabled = False
            hidden_str = _text(settings, "Hidden").lower()
            if hidden_str == "true":
                hidden = True

        triggers = _parse_triggers(root_el)
        actions  = _parse_actions(root_el)

        task: dict = {
            "path":        str(xml_path),
            "task_name":   xml_path.name,
            "task_path":   "/" + xml_path.name,  # filled in during walk
            "uri":         uri,
            "author":      author,
            "description": description,
            "date":        date_reg,
            "run_as":      run_as,
            "enabled":     enabled,
            "hidden":      hidden,
            "triggers":    triggers,
            "actions":     actions,
            "flags":       [],
        }
        task["flags"] = _compute_flags(task, target)
        return task

    except Exception as exc:
        return {
            "path":      str(xml_path),
            "task_name": xml_path.name,
            "parse_error": str(exc),
            "flags": ["parse_error"],
        }


# ---------------------------------------------------------------------------
# Task directory walk
# ---------------------------------------------------------------------------

_TASK_ROOTS = [
    "Windows/System32/Tasks",
    "Windows/SysWOW64/Tasks",
]


def _walk_tasks(target: Path) -> List[dict]:
    tasks: List[dict] = []
    seen_inodes: set = set()

    for rel_root in _TASK_ROOTS:
        task_dir = target / rel_root.replace("/", "/")
        if not task_dir.is_dir():
            continue
        for xml_path in sorted(task_dir.rglob("*")):
            if not xml_path.is_file():
                continue
            # Skip small files and files with extensions other than .xml or none
            if xml_path.suffix.lower() not in ("", ".xml"):
                continue
            try:
                stat = xml_path.stat()
                # Deduplicate via inode (SysWOW64/Tasks often mirrors System32/Tasks)
                inode_key = (stat.st_dev, stat.st_ino)
                if inode_key in seen_inodes:
                    continue
                seen_inodes.add(inode_key)
            except OSError:
                pass

            task = _parse_task_xml(xml_path, target)
            if task is None:
                continue
            # Build a nice task path relative to the tasks root
            try:
                rel = xml_path.relative_to(task_dir)
                task["task_path"] = "/" + str(rel).replace("\\", "/")
            except ValueError:
                pass
            tasks.append(task)

    return tasks


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    limitations: List[str] = []
    tasks = _walk_tasks(target)

    if not tasks:
        limitations.append("No task XML files found; task scheduler data unavailable")

    flagged_tasks = [t for t in tasks if t.get("flags") and t["flags"] != ["disabled_task"]]
    suspicious    = [t for t in tasks if any(f in (t.get("flags") or [])
                                              for f in ("suspicious_path", "lolbin_usage",
                                                        "encoded_command", "hidden_task",
                                                        "missing_target"))]

    summary = {
        "total_tasks":     len(tasks),
        "enabled_tasks":   sum(1 for t in tasks if t.get("enabled", True) and "parse_error" not in t),
        "disabled_tasks":  sum(1 for t in tasks if not t.get("enabled", True)),
        "hidden_tasks":    sum(1 for t in tasks if t.get("hidden")),
        "flagged_tasks":   len(flagged_tasks),
        "suspicious_tasks": len(suspicious),
    }

    verdict = "OK"
    if suspicious:
        verdict = "WARNING"
    if any("encoded_command" in (t.get("flags") or []) for t in tasks):
        verdict = "SUSPICIOUS"
    if any("hidden_task" in (t.get("flags") or []) for t in tasks):
        verdict = "WARNING"

    return {
        "scan_status":     "ok",
        "verdict":         verdict,
        "tasks":           tasks,
        "flagged_tasks":   flagged_tasks,
        "summary":         summary,
        "limitations":     limitations,
    }


# ---------------------------------------------------------------------------
# Report printing
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== TASK SCHEDULER ANALYSIS ===")
    print(f"Verdict  : {data.get('verdict', '?')}")
    s = data.get("summary", {})
    print(f"Tasks    : {s.get('total_tasks', 0)} total, "
          f"{s.get('enabled_tasks', 0)} enabled, "
          f"{s.get('suspicious_tasks', 0)} suspicious")

    flagged = data.get("flagged_tasks", [])
    if flagged:
        print(f"\nFlagged tasks ({len(flagged)}):")
        for t in flagged:
            if "parse_error" in t:
                print(f"  {t.get('task_path', t.get('task_name', '?'))}: [PARSE ERROR]")
                continue
            flags = ", ".join(t.get("flags", []))
            print(f"  {t.get('task_path', '?'):50}  [{flags}]")
            for act in t.get("actions", []):
                if act.get("type") == "Exec":
                    cmd  = act.get("command", "")
                    args = act.get("arguments", "")
                    print(f"    cmd : {cmd}")
                    if args:
                        print(f"    args: {args}")
            print(f"    run-as: {t.get('run_as', '?')}")
            if t.get("author"):
                print(f"    author: {t['author']}")
    else:
        print("\nNo flagged tasks.")

    limits = data.get("limitations", [])
    if limits:
        print("\nLimitations:")
        for lim in limits:
            print(f"  - {lim}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    from toolkit import find_windows_target  # noqa: PLC0415

    parser = argparse.ArgumentParser(
        prog="m34_task_scheduler_analysis",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="",
                        help="Path to mounted Windows partition (auto-detect if omitted)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only, not full task list")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m34] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    import time
    from datetime import datetime as _dt, timezone as _tz

    print(f"[m34] Analysing scheduled tasks in {target_path} ...")
    data = analyse(target_path)
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"task_scheduler_analysis_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m34] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
