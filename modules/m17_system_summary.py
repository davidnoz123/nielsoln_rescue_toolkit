"""
m17_system_summary.py — Nielsoln Rescue Toolkit: consolidated system summary.

Reads the most-recent log file produced by each completed module and prints a
single-page report suitable for showing a customer or pasting into a ticket.
Does NOT re-run any scans — it only reads existing logs from <USB>/logs/.

Modules it summarises (if logs are present):
  m04  hardware_profile   — CPU, RAM, storage
  m05  disk_health        — SMART verdict
  m06  software_inventory — app count, flags
  m07  service_analysis   — service verdict
  m09  thermal_health     — temperature verdict
  m15  upgrade_advisor    — upgrade recommendation
  m18  clamav_scan        — AV result (text log)
  m23  logon_audit        — logon forensics verdict
  m01  persistence_scan   — persistence finding count (JSONL)

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m17_system_summary

Output:
    Prints a one-page report to stdout.
    Writes a JSON summary to <USB>/logs/system_summary_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DESCRIPTION = (
    "System summary: reads the most-recent log from each completed module and "
    "prints a consolidated one-page report — no scans are re-run"
)

# ---------------------------------------------------------------------------
# Log-finding helpers
# ---------------------------------------------------------------------------

def _latest(logs_dir: Path, glob: str) -> Optional[Path]:
    """Return the most recently modified file matching glob, or None."""
    matches = sorted(logs_dir.glob(glob), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Per-module extractors — each returns a small dict with display fields
# ---------------------------------------------------------------------------

def _hw(logs_dir: Path) -> Optional[dict]:
    p = _latest(logs_dir, "hardware_profile_*.json")
    if not p:
        return None
    d = _read_json(p)
    if not d:
        return None
    cpu   = d.get("cpu", {})
    ram   = d.get("ram", {})
    stor  = d.get("storage", [])
    sys   = d.get("system", {})
    bios  = d.get("bios", {})
    disks = [f"{s.get('model','?')} {s.get('size_gb','?')} GB" for s in stor if isinstance(s, dict)]
    return {
        "log": p.name,
        "machine": sys.get("product_name") or sys.get("manufacturer") or "Unknown",
        "cpu": f"{cpu.get('name','?')}  {cpu.get('cores','?')}c / {cpu.get('threads','?')}t",
        "ram_gb": ram.get("total_gb") or ram.get("total_mb", 0) // 1024,
        "disks": disks,
        "bios_date": bios.get("date") or bios.get("release_date") or "?",
    }


def _disk(logs_dir: Path) -> Optional[dict]:
    p = _latest(logs_dir, "disk_health_*.json")
    if not p:
        return None
    d = _read_json(p)
    if not d:
        return None
    # May be a list of drives or a dict wrapping them
    drives = d if isinstance(d, list) else d.get("drives", d.get("disks", []))
    results = []
    for drv in (drives if isinstance(drives, list) else []):
        model   = drv.get("model") or drv.get("device") or "?"
        verdict = drv.get("verdict") or drv.get("health") or "?"
        flags   = drv.get("flags") or drv.get("warnings") or []
        results.append({"model": model, "verdict": verdict, "flags": flags})
    return {"log": p.name, "drives": results}


def _software(logs_dir: Path) -> Optional[dict]:
    p = _latest(logs_dir, "software_inventory_*.json")
    if not p:
        return None
    d = _read_json(p)
    if not d:
        return None
    summary = d.get("summary", {})
    entries = d.get("entries", [])
    total   = summary.get("total", len(entries))
    flags   = {}
    for e in (entries if isinstance(entries, list) else []):
        for f in (e.get("flags") or []):
            flags[f] = flags.get(f, 0) + 1
    return {
        "log": p.name,
        "total": total,
        "flags": flags,
    }


def _services(logs_dir: Path) -> Optional[dict]:
    p = _latest(logs_dir, "service_analysis_*.json")
    if not p:
        return None
    d = _read_json(p)
    if not d:
        return None
    s = d.get("summary", {})
    return {
        "log": p.name,
        "verdict":     s.get("verdict", "?"),
        "total":       s.get("total", "?"),
        "suspicious":  s.get("suspicious_count", 0),
        "deleted":     s.get("deleted_count", 0),
        "third_party": s.get("third_party_count", 0),
        "auto_start":  s.get("auto_start_services", 0),
    }


def _thermal(logs_dir: Path) -> Optional[dict]:
    p = _latest(logs_dir, "thermal_health_*.json")
    if not p:
        return None
    d = _read_json(p)
    if not d:
        return None
    temps = d.get("temperatures", [])
    hottest = None
    for t in (temps if isinstance(temps, list) else []):
        v = t.get("value") or t.get("current")
        if v and (hottest is None or v > hottest):
            hottest = v
    return {
        "log": p.name,
        "verdict":  d.get("verdict", "?"),
        "warnings": d.get("warnings", []),
        "hottest_c": hottest,
    }


def _upgrade(logs_dir: Path) -> Optional[dict]:
    p = _latest(logs_dir, "upgrade_advisor_*.json")
    if not p:
        return None
    d = _read_json(p)
    if not d:
        return None
    recs = d.get("recommendations", [])
    if isinstance(recs, list):
        top = recs[0] if recs else {}
        recommendation = top.get("recommendation") or top.get("title") or str(top)
    else:
        recommendation = str(recs)
    return {
        "log": p.name,
        "recommendation": recommendation,
        "count": len(recs) if isinstance(recs, list) else 1,
    }


def _clamav(logs_dir: Path) -> Optional[dict]:
    p = _latest(logs_dir, "scan_report_*.txt")
    if not p:
        # fall back to raw log
        p = _latest(logs_dir, "clamav_*.log")
    if not p:
        return None
    text = p.read_text(encoding="utf-8", errors="replace")
    infected = 0
    m = re.search(r"Infected files:\s*(\d+)", text)
    if m:
        infected = int(m.group(1))
    scanned = 0
    m2 = re.search(r"Scanned files:\s*(\d+)", text)
    if m2:
        scanned = int(m2.group(1))
    verdict = "CLEAN" if infected == 0 else f"{infected} INFECTED"
    return {
        "log": p.name,
        "verdict":  verdict,
        "infected": infected,
        "scanned":  scanned,
    }


def _logon(logs_dir: Path) -> Optional[dict]:
    p = _latest(logs_dir, "logon_audit_*.json")
    if not p:
        return None
    d = _read_json(p)
    if not d:
        return None
    totals = d.get("totals", {})
    return {
        "log": p.name,
        "verdict":          d.get("verdict", "?"),
        "failed_logons":    totals.get("failed_logons", 0),
        "lockouts":         totals.get("account_lockouts", 0),
        "pw_changes":       totals.get("password_change_events", 0),
        "explicit_creds":   totals.get("explicit_credential_logons", 0),
    }


def _persistence(logs_dir: Path) -> Optional[dict]:
    p = _latest(logs_dir, "persist_*.jsonl")
    if not p:
        return None
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    findings = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            pass
    suspicious = [f for f in findings if f.get("severity") in ("HIGH", "MEDIUM")]
    return {
        "log": p.name,
        "total":     len(findings),
        "suspicious": len(suspicious),
    }


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

_W = 64

def _bar(label: str, value: str) -> str:
    return f"  {label:<26}{value}"


def _section(title: str) -> None:
    print(f"\n  {'— ' + title + ' ':-<{_W - 4}}")


def _print_report(data: dict, target: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print("\n" + "=" * _W)
    print(f"  NIELSOLN RESCUE TOOLKIT — SYSTEM SUMMARY")
    print(f"  Target : {target}")
    print(f"  Report : {now}")
    print("=" * _W)

    # --- Hardware ---
    hw = data.get("hardware")
    _section("HARDWARE")
    if hw:
        print(_bar("Machine:", hw["machine"]))
        print(_bar("CPU:", hw["cpu"]))
        print(_bar("RAM:", f"{hw['ram_gb']} GB"))
        for d in hw["disks"]:
            print(_bar("Disk:", d))
        print(_bar("BIOS date:", hw["bios_date"]))
    else:
        print("  (no hardware_profile log found — run m04)")

    # --- Disk health ---
    disk = data.get("disk")
    _section("DISK HEALTH")
    if disk:
        for drv in disk["drives"]:
            flags_str = ", ".join(drv["flags"]) if drv["flags"] else "none"
            print(_bar(drv["model"][:26] + ":", f"{drv['verdict']}  flags: {flags_str}"))
    else:
        print("  (no disk_health log found — run m05)")

    # --- Thermal ---
    therm = data.get("thermal")
    _section("THERMAL")
    if therm:
        hot = f"  hottest sensor: {therm['hottest_c']}°C" if therm["hottest_c"] else ""
        print(_bar("Verdict:", f"{therm['verdict']}{hot}"))
        for w in therm["warnings"]:
            print(f"    ! {w}")
    else:
        print("  (no thermal_health log found — run m09)")

    # --- AV scan ---
    av = data.get("clamav")
    _section("ANTIVIRUS (ClamAV)")
    if av:
        print(_bar("Result:", av["verdict"]))
        print(_bar("Files scanned:", str(av["scanned"])))
    else:
        print("  (no ClamAV scan log found — run m18)")

    # --- Logon audit ---
    logon = data.get("logon")
    _section("LOGON AUDIT")
    if logon:
        print(_bar("Verdict:", logon["verdict"]))
        print(_bar("Failed logons:", str(logon["failed_logons"])))
        print(_bar("Account lockouts:", str(logon["lockouts"])))
        print(_bar("Password changes:", str(logon["pw_changes"])))
        if logon["explicit_creds"]:
            print(_bar("Explicit cred events:", str(logon["explicit_creds"])))
    else:
        print("  (no logon_audit log found — run m23)")

    # --- Persistence ---
    persist = data.get("persistence")
    _section("PERSISTENCE SCAN")
    if persist:
        sev = persist["suspicious"]
        label = "SUSPICIOUS findings" if sev else "findings (none suspicious)"
        print(_bar("Total findings:", str(persist["total"])))
        print(_bar("Suspicious:", f"{sev}  ← {label}"))
    else:
        print("  (no persist log found — run m01)")

    # --- Services ---
    svc = data.get("services")
    _section("SERVICES")
    if svc:
        print(_bar("Verdict:", svc["verdict"]))
        print(_bar("Total registered:", str(svc["total"])))
        print(_bar("Auto-start (non-driver):", str(svc["auto_start"])))
        print(_bar("Third-party:", str(svc["third_party"])))
        print(_bar("Suspicious:", str(svc["suspicious"])))
    else:
        print("  (no service_analysis log found — run m07)")

    # --- Software ---
    sw = data.get("software")
    _section("SOFTWARE INVENTORY")
    if sw:
        print(_bar("Installed apps:", str(sw["total"])))
        for flag, count in sorted(sw["flags"].items()):
            print(_bar(f"  flagged {flag}:", str(count)))
    else:
        print("  (no software_inventory log found — run m06)")

    # --- Upgrade recommendation ---
    upg = data.get("upgrade")
    _section("UPGRADE RECOMMENDATION")
    if upg:
        # Wrap long recommendation text
        rec = upg["recommendation"]
        words = rec.split()
        line, lines = "", []
        for w in words:
            if len(line) + len(w) + 1 > 54:
                lines.append(line)
                line = w
            else:
                line = (line + " " + w).strip()
        if line:
            lines.append(line)
        for i, l in enumerate(lines):
            print(_bar("" if i else "Recommendation:", l))
    else:
        print("  (no upgrade_advisor log found — run m15)")

    print("\n" + "=" * _W)

    # Overall health roll-up
    verdicts = []
    for key in ("disk", "thermal", "clamav", "logon", "services"):
        item = data.get(key)
        if item:
            verdicts.append(item.get("verdict", "?"))
    if persist and persist["suspicious"] > 0:
        verdicts.append("SUSPICIOUS")

    if any("SUSPICIOUS" in v or "INFECTED" in v for v in verdicts):
        overall = "ACTION REQUIRED"
    elif any("REVIEW" in v or "CAUTION" in v or "WARN" in v for v in verdicts):
        overall = "REVIEW RECOMMENDED"
    elif any("CLEAN" in v or "OK" in v or "GOOD" in v for v in verdicts):
        overall = "GENERALLY OK"
    else:
        overall = "UNKNOWN (run more modules)"

    print(f"  OVERALL: {overall}")
    print("=" * _W + "\n")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    parser = argparse.ArgumentParser(
        prog="m17_system_summary",
        description=DESCRIPTION,
    )
    parser.add_argument(
        "--target", default="/mnt/windows",
        help="Path to the mounted offline Windows installation (used for display only)",
    )
    args = parser.parse_args(argv)

    logs_dir = root / "logs"
    if not logs_dir.exists():
        print("ERROR: No logs directory found. Run some scan modules first.")
        return 1

    data = {
        "hardware":    _hw(logs_dir),
        "disk":        _disk(logs_dir),
        "thermal":     _thermal(logs_dir),
        "clamav":      _clamav(logs_dir),
        "logon":       _logon(logs_dir),
        "persistence": _persistence(logs_dir),
        "services":    _services(logs_dir),
        "software":    _software(logs_dir),
        "upgrade":     _upgrade(logs_dir),
    }

    _print_report(data, args.target)

    # Write JSON summary
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = logs_dir / f"system_summary_{ts}.json"
    out.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(),
        "target":    args.target,
        "sections":  data,
    }, indent=2, default=str))
    print(f"[m17] Summary written → {out}")
    return 0
