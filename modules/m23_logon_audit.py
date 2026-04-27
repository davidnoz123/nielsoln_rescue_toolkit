"""m23_logon_audit — Windows Security event log: failed logons, lockouts, password changes.

Answers the question: why did the customer's password stop working?
  • Many 4625 events   → repeated wrong-password attempts (forgotten password or brute-force)
  • 4740 event         → account was formally locked out by Windows
  • 4723/4724 events   → password was changed or reset (when? by whom?)
  • 4648 events        → logon with explicit credentials (could be malware or saved creds)

Requires python-evtx (pure-Python EVTX parser).  The module will attempt to
install it via pip3 if absent — RescueZilla has internet access.

Usage:
    bootstrap run m23_logon_audit --target /mnt/windows
"""

from __future__ import annotations
import datetime
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

DESCRIPTION = "Analyse Security.evtx for failed logons, lockouts, and password events"

# ---------------------------------------------------------------------------
# Event ID catalogue (Vista/Win7 "new" style 4xxx IDs)
# ---------------------------------------------------------------------------

_EVENTS: dict[int, str] = {
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4648: "Logon with explicit credentials",
    4720: "User account created",
    4722: "User account enabled",
    4723: "Password change attempt (by user)",
    4724: "Password reset (by admin)",
    4725: "User account disabled",
    4726: "User account deleted",
    4740: "Account locked out",
    4767: "Account unlocked",
}

_INTERESTING_IDS = set(_EVENTS.keys())

# SubStatus / Status hex codes that appear in 4625 records
_SUB_STATUS: dict[str, str] = {
    "0xc000006a": "Wrong password",
    "0xc0000064": "Unknown username",
    "0xc000006d": "Bad credentials",
    "0xc000006f": "Logon outside allowed hours",
    "0xc0000070": "Workstation restriction",
    "0xc0000072": "Account disabled",
    "0xc000015b": "Logon type not granted",
    "0xc0000193": "Account expired",
    "0xc0000234": "Account locked out",
}

# ---------------------------------------------------------------------------
# Dependency management
# ---------------------------------------------------------------------------

def _ensure_evtx() -> bool:
    """Import python-evtx; auto-install via pip3 if absent. Returns True on success."""
    try:
        import Evtx.Evtx  # noqa: F401
        return True
    except ImportError:
        pass

    print("[m23] python-evtx not found — installing via pip3 ...")
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", "python-evtx", "--quiet"],
        capture_output=True,
    )
    if r.returncode != 0:
        print(f"[m23] pip install failed:\n{r.stderr.decode(errors='replace')}")
        return False

    try:
        import Evtx.Evtx  # noqa: F401
        print("[m23] python-evtx installed successfully.")
        return True
    except ImportError:
        print("[m23] Import still failed after install — check pip output above.")
        return False

# ---------------------------------------------------------------------------
# EVTX parsing
# ---------------------------------------------------------------------------

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _tag(name: str) -> str:
    return f"{{{_NS}}}{name}"


def _parse_evtx(path: Path) -> list[dict]:
    """Return a list of interesting event dicts from *path*."""
    import Evtx.Evtx as evtx
    import xml.etree.ElementTree as ET

    events: list[dict] = []

    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except Exception:
                continue

            sys_el = root.find(_tag("System"))
            if sys_el is None:
                continue

            eid_el = sys_el.find(_tag("EventID"))
            if eid_el is None:
                continue

            try:
                eid = int(eid_el.text)
            except (TypeError, ValueError):
                continue

            if eid not in _INTERESTING_IDS:
                continue

            time_el = sys_el.find(_tag("TimeCreated"))
            ts = time_el.get("SystemTime", "") if time_el is not None else ""

            # EventData — name/value pairs
            data: dict[str, str] = {}
            ed = root.find(_tag("EventData"))
            if ed is not None:
                for item in ed:
                    name = item.get("Name", "")
                    if name:
                        data[name] = (item.text or "").strip()

            events.append({
                "event_id":   eid,
                "event_name": _EVENTS.get(eid, str(eid)),
                "timestamp":  ts,
                "data":       data,
            })

    return events

# ---------------------------------------------------------------------------
# Analysis / summary
# ---------------------------------------------------------------------------

def _reason(sub_status: str) -> str:
    return _SUB_STATUS.get(sub_status.lower(), sub_status or "unknown")


def _summarize(events: list[dict]) -> dict:
    failed   = [e for e in events if e["event_id"] == 4625]
    lockouts = [e for e in events if e["event_id"] == 4740]
    pwd_evts = [e for e in events if e["event_id"] in {4723, 4724}]
    explicit = [e for e in events if e["event_id"] == 4648]
    acc_mgmt = [e for e in events if e["event_id"] in {4720, 4722, 4725, 4726}]

    fail_by_user  = Counter(e["data"].get("TargetUserName", "?") for e in failed)
    fail_by_date  = Counter((e["timestamp"] or "?")[:10] for e in failed)
    fail_reasons  = Counter(
        _reason(e["data"].get("SubStatus", e["data"].get("Status", "")))
        for e in failed
    )

    # Verdict
    n = len(failed)
    if n >= 50:
        verdict = "SUSPICIOUS"
        verdict_note = (
            f"{n} failed logon attempts — volume consistent with automated brute-force "
            "or repeated scripted attempts (possible virus activity)."
        )
    elif n >= 10:
        verdict = "REVIEW"
        verdict_note = (
            f"{n} failed logon attempts — could be a forgotten/changed password or "
            "a confused user trying repeatedly."
        )
    elif n >= 1:
        verdict = "MINOR"
        verdict_note = (
            f"{n} failed logon attempt(s) — low count, consistent with a single "
            "wrong-password entry."
        )
    else:
        verdict = "CLEAN"
        verdict_note = "No failed logon attempts found in the Security log."

    if lockouts:
        if verdict in ("CLEAN", "MINOR"):
            verdict = "REVIEW"
        verdict_note += (
            f"  Account was locked out {len(lockouts)} time(s) — "
            "Windows enforced a lockout policy after too many wrong attempts."
        )

    notes = [verdict_note]

    if pwd_evts:
        notes.append(
            f"{len(pwd_evts)} password change/reset event(s) recorded — "
            "check timestamps below to see if this correlates with the lockout."
        )

    if explicit:
        notes.append(
            f"{len(explicit)} 'logon with explicit credentials' event(s) — "
            "could be a scheduled task, cached credentials, or malware."
        )

    if acc_mgmt:
        notes.append(
            f"{len(acc_mgmt)} account management event(s) (create/enable/disable/delete) "
            "— review details below."
        )

    # Recent failed logon detail rows (most recent first, cap at 30)
    recent_fails = sorted(failed, key=lambda e: e["timestamp"], reverse=True)[:30]
    recent_fail_rows = [
        {
            "timestamp":   e["timestamp"],
            "user":        e["data"].get("TargetUserName", "?"),
            "workstation": e["data"].get("WorkstationName", "?"),
            "ip":          e["data"].get("IpAddress", "?"),
            "reason":      _reason(e["data"].get("SubStatus", e["data"].get("Status", ""))),
        }
        for e in recent_fails
    ]

    lockout_rows = [
        {
            "timestamp": e["timestamp"],
            "user":      e["data"].get("TargetUserName", "?"),
            "caller":    e["data"].get("CallerComputerName", "?"),
        }
        for e in lockouts
    ]

    pwd_rows = [
        {
            "event_id":    e["event_id"],
            "event_name":  e["event_name"],
            "timestamp":   e["timestamp"],
            "target_user": e["data"].get("TargetUserName", "?"),
            "by_user":     e["data"].get("SubjectUserName", "?"),
        }
        for e in pwd_evts
    ]

    acc_mgmt_rows = [
        {
            "event_id":    e["event_id"],
            "event_name":  e["event_name"],
            "timestamp":   e["timestamp"],
            "target_user": e["data"].get("TargetUserName", "?"),
            "by_user":     e["data"].get("SubjectUserName", "?"),
        }
        for e in acc_mgmt
    ]

    return {
        "verdict": verdict,
        "notes":   notes,
        "totals": {
            "failed_logons":              len(failed),
            "account_lockouts":           len(lockouts),
            "password_change_events":     len(pwd_evts),
            "explicit_credential_logons": len(explicit),
            "account_management_events":  len(acc_mgmt),
        },
        "failed_logon_reasons":    dict(fail_reasons.most_common()),
        "failed_logons_by_user":   dict(fail_by_user.most_common(15)),
        "failed_logons_by_date":   dict(sorted(fail_by_date.items())),
        "lockout_events":          lockout_rows,
        "password_change_events":  pwd_rows,
        "account_management_events": acc_mgmt_rows,
        "recent_failed_logons":    recent_fail_rows,
    }

# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------

def _print_summary(s: dict) -> None:
    verdict = s["verdict"]
    bar = "=" * 60
    print(f"\n{bar}")
    print(f"  LOGON AUDIT — {verdict}")
    print(bar)
    for note in s["notes"]:
        print(f"  {note}")

    print("\nTotals:")
    for k, v in s["totals"].items():
        print(f"  {k.replace('_', ' '):40s} {v}")

    if s["failed_logon_reasons"]:
        print("\nFailed logon reasons:")
        for reason, n in s["failed_logon_reasons"].items():
            print(f"  {reason:45s} {n}")

    if s["failed_logons_by_user"]:
        print("\nFailed logons by username:")
        for user, n in s["failed_logons_by_user"].items():
            print(f"  {user:40s} {n}")

    if s["lockout_events"]:
        print("\nAccount lockout events:")
        for ev in s["lockout_events"]:
            print(f"  {ev['timestamp']}  user={ev['user']}  caller={ev['caller']}")

    if s["password_change_events"]:
        print("\nPassword change / reset events:")
        for ev in s["password_change_events"]:
            print(f"  {ev['timestamp']}  [{ev['event_name']}]  "
                  f"target={ev['target_user']}  by={ev['by_user']}")

    if s["account_management_events"]:
        print("\nAccount management events:")
        for ev in s["account_management_events"]:
            print(f"  {ev['timestamp']}  [{ev['event_name']}]  "
                  f"target={ev['target_user']}  by={ev['by_user']}")

    if s["recent_failed_logons"]:
        print(f"\nRecent failed logons (up to 30, newest first):")
        print(f"  {'Timestamp':30s}  {'User':20s}  {'Reason':30s}  {'IP'}")
        print(f"  {'-'*29}  {'-'*19}  {'-'*29}  {'-'*15}")
        for ev in s["recent_failed_logons"]:
            print(f"  {ev['timestamp']:30s}  {ev['user']:20s}  "
                  f"{ev['reason']:30s}  {ev['ip']}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    target = Path("/")
    for i, a in enumerate(argv):
        if a == "--target" and i + 1 < len(argv):
            target = Path(argv[i + 1])

    evtx_path = target / "Windows/System32/winevt/Logs/Security.evtx"
    if not evtx_path.exists():
        print(f"[m23] Security.evtx not found at {evtx_path}")
        print("[m23] Check that the Windows partition is mounted and --target is correct.")
        return 1

    print("[m23] Checking python-evtx dependency ...")
    if not _ensure_evtx():
        print("[m23] Cannot continue without python-evtx.")
        print("[m23] On RescueZilla: pip3 install python-evtx")
        return 1

    print(f"[m23] Parsing {evtx_path} ...")
    events = _parse_evtx(evtx_path)
    print(f"[m23] {len(events)} relevant event(s) extracted from Security log.")

    summary = _summarize(events)
    _print_summary(summary)

    # Write JSON log
    log_dir = root / "logs"
    log_dir.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = log_dir / f"logon_audit_{ts}.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\n[m23] Log written → {out_path}")
    return 0
