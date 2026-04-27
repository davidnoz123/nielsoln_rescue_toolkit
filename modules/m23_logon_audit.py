"""m23_logon_audit — Windows Security event log: failed logons, lockouts, password changes.

Answers the question: why did the customer's password stop working?
  • Many 4625 events   → repeated wrong-password attempts (forgotten password or brute-force)
  • 4740 event         → account was formally locked out by Windows
  • 4723/4724 events   → password was changed or reset (when? by whom?)
  • 4648 events        → logon with explicit credentials (could be malware or saved creds)

python-evtx 0.8.1 is bundled inline as a gzip+base64 wheel — no pip or apt needed.

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
# Bundled python-evtx wheel (Apache 2.0, © Willi Ballenthin)
# python-evtx 0.8.1 — gzip-compressed, base64-encoded .whl (zip)
# No pip or apt required: decoded to a temp file and added to sys.path.
# ---------------------------------------------------------------------------

_EVTX_WHEEL_B64 = (
    "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"
)

# ---------------------------------------------------------------------------
# Dependency management
# ---------------------------------------------------------------------------

def _ensure_evtx() -> bool:
    """Load python-evtx from the bundled wheel.  No pip or apt needed.

    The wheel is gzip-compressed and base64-encoded in _EVTX_WHEEL_B64.
    We decode it to a temp file and add it to sys.path.  Works offline.

    python-evtx optionally imports 'hexdump' for debug output only; we
    inject a no-op stub so it never needs to be installed.
    """
    try:
        import Evtx.Evtx  # noqa: F401
        return True
    except ImportError:
        pass

    import base64, gzip, os, tempfile, types

    # Inject a no-op hexdump stub — python-evtx only uses it for debug prints
    if "hexdump" not in sys.modules:
        stub = types.ModuleType("hexdump")
        stub.hexdump = lambda *a, **kw: None       # type: ignore[attr-defined]
        stub.dump = lambda *a, **kw: ""            # type: ignore[attr-defined]
        sys.modules["hexdump"] = stub

    print("[m23] Loading bundled python-evtx 0.8.1 wheel ...")
    try:
        wheel_bytes = gzip.decompress(base64.b64decode(_EVTX_WHEEL_B64))
        fd, whl_path = tempfile.mkstemp(suffix=".whl")
        os.write(fd, wheel_bytes)
        os.close(fd)
        # A .whl is a zip — Python can import directly from it
        if whl_path not in sys.path:
            sys.path.insert(0, whl_path)
        import Evtx.Evtx  # noqa: F401
        print("[m23] python-evtx loaded from bundled wheel.")
        return True
    except Exception as exc:
        print(f"[m23] Failed to load bundled wheel: {exc}")
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
        verdict_note = (
            "No failed logon attempts found in the Security log.  "
            "NOTE: Windows Vista Home editions disable Failure auditing for Logon "
            "events by default — this means failed logon attempts may have occurred "
            "but were never written to the Security log.  Absence of 4625 events "
            "does NOT guarantee the password was never guessed."
        )

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
