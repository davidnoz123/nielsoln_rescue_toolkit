"""
report_gen.py — Nielsoln Rescue Toolkit: customer-facing report generator.

Reads the most-recent log files from the USB and produces:
  1. customer_report.md  — comprehensive Markdown report for the customer
  2. logon_events.tsv    — all logon, password-change, and account-mgmt events

Run via:
    devtools.py  action = "run_remote", remote_script = "report_gen.py"

Files are written to <USB_ROOT>/ (USB root, not logs/).
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Locate USB root
# ---------------------------------------------------------------------------

def _find_usb_root() -> Path:
    candidates = [
        Path("/media/ubuntu/GRTMPVOL_EN/NIELSOLN_RESCUE_USB"),
        Path("/media/ubuntu/NIELSOLN_RESCUE_USB"),
        Path("/mnt/usb"),
    ]
    # Also try dirname of this script if it contains logs/
    script_dir = Path(__file__).resolve().parent if "__file__" in dir() else None
    if script_dir and (script_dir / "logs").exists():
        candidates.insert(0, script_dir)
    for c in candidates:
        if (c / "logs").exists():
            return c
    # Fall back to first candidate with a 'bootstrap.py'
    for c in candidates:
        if (c / "bootstrap.py").exists():
            return c
    return candidates[0]   # last resort

USB = _find_usb_root()
LOGS = USB / "logs"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _latest(glob: str) -> Path | None:
    matches = sorted(LOGS.glob(glob), key=lambda p: p.stat().st_mtime, reverse=True)
    return matches[0] if matches else None

def _load(glob: str) -> dict | list | None:
    p = _latest(glob)
    if p is None:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def _str(v, default="?") -> str:
    if v is None or v == "" or str(v).strip() in ("", "None", "null", "unknown"):
        return default
    return str(v).strip()

def _na(v) -> str:
    return _str(v, "N/A")

def _int_or(v, default=0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

REPORT_DATE = datetime.now(timezone.utc).strftime("%d %B %Y")

# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def load_hardware() -> dict:
    d = _load("hardware_profile_*.json")
    return d or {}

def load_disk() -> list:
    d = _load("disk_health_*.json")
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        return d.get("drives", d.get("disks", [d]))
    return []

def load_software() -> dict:
    d = _load("software_inventory_*.json")
    return d or {}

def load_services() -> dict:
    d = _load("service_analysis_*.json")
    return d or {}

def load_thermal() -> dict:
    d = _load("thermal_health_*.json")
    return d or {}

def load_upgrade() -> dict:
    d = _load("upgrade_advisor_*.json")
    return d or {}

def load_logon() -> dict:
    d = _load("logon_audit_*.json")
    return d or {}

def load_persistence() -> list:
    p = _latest("persist_*.jsonl")
    if p is None:
        return []
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows

def load_clamav() -> dict | None:
    # Try JSON log first
    d = _load("clamav_*.json")
    if d:
        return d
    # Try text scan report
    p = _latest("scan_report_*.txt")
    if p is None:
        return None
    text = p.read_text(encoding="utf-8", errors="replace")
    infected = 0
    for line in text.splitlines():
        if "Infected files:" in line:
            try:
                infected = int(line.split(":")[-1].strip())
            except ValueError:
                pass
    return {"verdict": "CLEAN" if infected == 0 else "INFECTED", "infected_files": infected, "_from_txt": True}

def load_system_summary() -> dict:
    d = _load("system_summary_*.json")
    return d or {}

# ---------------------------------------------------------------------------
# Markdown sections
# ---------------------------------------------------------------------------

def _badge(verdict: str) -> str:
    v = (verdict or "").upper()
    if any(x in v for x in ("INFECTED", "CRITICAL", "FAIL")):
        return f"🔴 **{verdict}**"
    if any(x in v for x in ("SUSPICIOUS", "SUSPECT", "CAUTION", "WARN", "ACTION")):
        return f"🟡 **{verdict}**"
    if any(x in v for x in ("CLEAN", "HEALTHY", "OK", "GOOD", "PASSED", "GENERALLY")):
        return f"🟢 **{verdict}**"
    return f"⚪ **{verdict}**"

def section_header() -> str:
    hw = load_hardware()
    sys_info = hw.get("system", {})
    hostname = _str(sys_info.get("hostname") or sys_info.get("product_name"), "Unknown")
    mfr      = _na(sys_info.get("manufacturer"))
    model    = _na(sys_info.get("product_name"))
    version  = _str(sys_info.get("product_version"), "")
    serial   = _na(sys_info.get("serial_number"))
    bios     = _na(hw.get("bios", {}).get("date") if isinstance(hw.get("bios"), dict) else None)

    ss = load_system_summary()
    overall = ss.get("overall_verdict") or ss.get("verdict") or "REVIEW RECOMMENDED"

    lines = [
        f"# Laptop Diagnostic Report",
        f"",
        f"**Prepared by:** Nielsoln Rescue Toolkit  ",
        f"**Date:** {REPORT_DATE}  ",
        f"**Machine:** {mfr} {model} {version}".strip(),
        f"**Serial number:** {serial}  ",
        f"**BIOS date:** {bios}  ",
        f"",
        f"---",
        f"",
        f"## Overall Assessment",
        f"",
        f"> {_badge(overall)}",
        f"",
    ]
    if ss:
        rec = ss.get("recommendation") or ss.get("upgrade_recommendation") or ""
        if rec:
            lines += [f"> {rec}", f""]
    return "\n".join(lines)

def section_hardware() -> str:
    hw = load_hardware()
    if not hw:
        return "## Hardware\n\n_No hardware profile available._\n\n"

    sys_info = hw.get("system", {})
    cpu      = hw.get("cpu", {})
    ram      = hw.get("ram", {})
    storage  = hw.get("storage", [])
    network  = hw.get("network", [])
    gpu      = hw.get("gpu", [])
    bios     = hw.get("bios", {})

    lines = [
        "## Hardware",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Manufacturer | {_na(sys_info.get('manufacturer'))} |",
        f"| Model | {_na(sys_info.get('product_name'))} {_str(sys_info.get('product_version'), '')} |",
        f"| Serial number | {_na(sys_info.get('serial_number'))} |",
        f"| Form factor | {_na(sys_info.get('form_factor') or hw.get('form_factor'))} |",
        f"| BIOS date | {_na(bios.get('date') if isinstance(bios, dict) else None)} |",
        f"| CPU | {_na(cpu.get('model') if isinstance(cpu, dict) else None)} |",
        f"| CPU cores / threads | {_na(cpu.get('cores') if isinstance(cpu, dict) else None)} / {_na(cpu.get('threads') if isinstance(cpu, dict) else None)} |",
        f"| RAM | {_na(ram.get('total_gib') if isinstance(ram, dict) else None)} GiB |",
        f"",
    ]

    if storage:
        lines += ["**Storage devices:**", ""]
        lines += ["| Device | Model | Size | Type |", "|---|---|---|---|"]
        for dev in storage:
            if isinstance(dev, dict):
                lines.append(
                    f"| {_na(dev.get('device'))} | {_na(dev.get('model'))} "
                    f"| {_na(dev.get('size_gib') or dev.get('size'))} GB "
                    f"| {_na(dev.get('type') or dev.get('media_type'))} |"
                )
            else:
                lines.append(f"| {_na(dev)} | | | |")
        lines.append("")

    if gpu:
        lines += ["**Display adapters:**", ""]
        for g in (gpu if isinstance(gpu, list) else [gpu]):
            if isinstance(g, dict):
                lines.append(f"- {_na(g.get('model') or g.get('name'))}")
            else:
                lines.append(f"- {_na(g)}")
        lines.append("")

    if network:
        lines += ["**Network adapters:**", ""]
        for n in (network if isinstance(network, list) else [network]):
            if isinstance(n, dict):
                lines.append(f"- {_na(n.get('model') or n.get('name'))} — MAC: {_na(n.get('mac'))}")
            else:
                lines.append(f"- {_na(n)}")
        lines.append("")

    return "\n".join(lines)

def section_disk() -> str:
    disks = load_disk()
    if not disks:
        return "## Disk Health\n\n_No disk health data available._\n\n"

    lines = ["## Disk Health", ""]
    for d in disks:
        dev     = _na(d.get("device"))
        model   = _na(d.get("model"))
        verdict = _str(d.get("overall_verdict"), "?")
        health  = _str(d.get("overall_health"), "?")
        urgency = _str(d.get("clone_urgency"), "N/A")
        rec     = _str(d.get("recommendation"), "")
        findings = d.get("critical_findings") or []
        info    = d.get("info") or {}

        lines += [
            f"### {dev} — {model}",
            f"",
            f"| | |",
            f"|---|---|",
            f"| SMART health | {health} |",
            f"| Overall verdict | {_badge(verdict)} |",
            f"| Clone urgency | **{urgency}** |",
        ]

        for key in ("Power_On_Hours", "Spin_Retry_Count", "Reallocated_Sector_Ct",
                    "Current_Pending_Sector", "Offline_Uncorrectable"):
            val = info.get(key)
            if val is not None:
                label = key.replace("_", " ")
                lines.append(f"| {label} | {val} |")

        lines.append("")

        if findings:
            lines += ["**Findings:**", ""]
            for f_item in findings:
                lines.append(f"- {f_item}")
            lines.append("")

        if rec:
            lines += [f"**Recommendation:** {rec}", ""]

    return "\n".join(lines)

def section_antivirus() -> str:
    clamav = load_clamav()
    if clamav is None:
        return "## Antivirus Scan\n\n_No ClamAV scan results found._\n\n"

    verdict      = _str(clamav.get("verdict"), "UNKNOWN")
    scanned      = _int_or(clamav.get("scanned_files") or clamav.get("files_scanned"))
    infected     = _int_or(clamav.get("infected_files") or clamav.get("threats"))
    scan_date    = _str(clamav.get("scan_date") or clamav.get("timestamp"), "")
    engine_ver   = _str(clamav.get("engine_version"), "")
    db_ver       = _str(clamav.get("database_version") or clamav.get("sig_version"), "")

    lines = [
        "## Antivirus Scan",
        "",
        f"| | |",
        f"|---|---|",
        f"| Result | {_badge(verdict)} |",
        f"| Threats found | {infected} |",
        f"| Files scanned | {scanned:,} |",
    ]
    if scan_date:
        lines.append(f"| Scan date | {scan_date} |")
    if engine_ver:
        lines.append(f"| ClamAV version | {engine_ver} |")
    if db_ver:
        lines.append(f"| Definition version | {db_ver} |")
    lines.append("")

    if infected > 0:
        threats = clamav.get("threats_list") or clamav.get("infected_list") or []
        if threats:
            lines += ["**Threats detected:**", ""]
            for t in threats[:30]:
                lines.append(f"- {t}")
            lines.append("")

    return "\n".join(lines)

def section_logon() -> str:
    la = load_logon()
    if not la:
        return "## Windows Security — Logon Audit\n\n_No logon audit data available._\n\n"

    verdict = _str(la.get("verdict"), "UNKNOWN")
    totals  = la.get("totals", {})
    notes   = la.get("notes", [])

    lines = [
        "## Windows Security — Logon Audit",
        "",
        f"| | |",
        f"|---|---|",
        f"| Verdict | {_badge(verdict)} |",
        f"| Failed logon attempts | {totals.get('failed_logons', 0)} |",
        f"| Account lockouts | {totals.get('account_lockouts', 0)} |",
        f"| Password change events | {totals.get('password_change_events', 0)} |",
        f"| Explicit credential logons | {totals.get('explicit_credential_logons', 0)} |",
        f"| Account management events | {totals.get('account_management_events', 0)} |",
        f"",
    ]

    if notes:
        lines += ["**Notes:**", ""]
        for n in notes:
            lines.append(f"- {n}")
        lines.append("")

    pwd_rows = la.get("password_change_events", [])
    if pwd_rows:
        lines += [
            "**Password change / reset events:**",
            "",
            "| Timestamp | Event | Target user | Changed by |",
            "|---|---|---|---|",
        ]
        for r in pwd_rows:
            lines.append(
                f"| {_na(r.get('timestamp'))} | {_na(r.get('event_name'))} "
                f"| {_na(r.get('target_user'))} | {_na(r.get('by_user'))} |"
            )
        lines.append("")

    acc_rows = la.get("account_management_events", [])
    if acc_rows:
        lines += [
            "**Account management events:**",
            "",
            "| Timestamp | Event | Target user | By user |",
            "|---|---|---|---|",
        ]
        for r in acc_rows:
            lines.append(
                f"| {_na(r.get('timestamp'))} | {_na(r.get('event_name'))} "
                f"| {_na(r.get('target_user'))} | {_na(r.get('by_user'))} |"
            )
        lines.append("")

    fail_rows = la.get("recent_failed_logons", [])
    if fail_rows:
        lines += [
            "**Recent failed logons (newest first, up to 30):**",
            "",
            "| Timestamp | User | Reason | IP | Workstation |",
            "|---|---|---|---|---|",
        ]
        for r in fail_rows:
            lines.append(
                f"| {_na(r.get('timestamp'))} | {_na(r.get('user'))} "
                f"| {_na(r.get('reason'))} | {_na(r.get('ip'))} "
                f"| {_na(r.get('workstation'))} |"
            )
        lines.append("")

    return "\n".join(lines)

def section_persistence() -> str:
    rows = load_persistence()
    if not rows:
        return "## Persistence / Autorun Analysis\n\n_No persistence scan data available._\n\n"

    total      = len(rows)
    suspicious = [r for r in rows if str(r.get("verdict", "")).upper() in
                  ("SUSPICIOUS", "MALICIOUS", "WARN", "REVIEW")]
    clean      = total - len(suspicious)

    lines = [
        "## Persistence / Autorun Analysis",
        "",
        f"| | |",
        f"|---|---|",
        f"| Total autorun entries | {total} |",
        f"| Suspicious | {len(suspicious)} |",
        f"| Clean | {clean} |",
        f"",
    ]

    if suspicious:
        lines += [
            "**Suspicious entries:**",
            "",
            "| Location | Name | Value | Verdict |",
            "|---|---|---|---|",
        ]
        for r in suspicious[:30]:
            lines.append(
                f"| {_na(r.get('hive') or r.get('location'))} "
                f"| {_na(r.get('name'))} | {_na(r.get('value') or r.get('data'))} "
                f"| {_na(r.get('verdict'))} |"
            )
        lines.append("")
    else:
        lines += ["> No suspicious autorun entries found.", ""]

    return "\n".join(lines)

def section_services() -> str:
    sv = load_services()
    if not sv:
        return "## Windows Services\n\n_No service analysis data available._\n\n"

    # service_analysis log has top-level keys: summary, services
    summ    = sv.get("summary") or sv
    verdict    = _str(summ.get("verdict"), "UNKNOWN")
    total      = _int_or(summ.get("total") or summ.get("total_entries"))
    autostart  = _int_or(summ.get("auto_start_services") or summ.get("autostart_non_driver") or summ.get("autostart"))
    third_party = _int_or(summ.get("third_party_count") or summ.get("third_party"))
    susp_count  = _int_or(summ.get("suspicious_count") or summ.get("suspicious"))
    suspicious  = sv.get("suspicious") or []   # top-level list in some formats

    lines = [
        "## Windows Services",
        "",
        f"| | |",
        f"|---|---|",
        f"| Verdict | {_badge(verdict)} |",
        f"| Total registered | {total} |",
        f"| Auto-start (non-driver) | {autostart} |",
        f"| Third-party | {third_party} |",
        f"| Suspicious | {susp_count} |",
        f"",
    ]

    # suspicious list lives in services[] filtered, or top-level in some log versions
    susp_services = suspicious
    if not susp_services and sv.get("services"):
        susp_services = [s for s in sv["services"] if s.get("suspicious_reason") or s.get("verdict") == "SUSPICIOUS"]

    if susp_services:
        lines += [
            "**Suspicious services:**",
            "",
            "| Service | Display name | Image path | Reason |",
            "|---|---|---|---|",
        ]
        for s in susp_services[:20]:
            lines.append(
                f"| {_na(s.get('name'))} | {_na(s.get('display_name'))} "
                f"| {_na(s.get('image_path'))} | {_na(s.get('suspicious_reason') or s.get('reason'))} |"
            )
        lines.append("")

    return "\n".join(lines)

def section_software() -> str:
    sw = load_software()
    if not sw:
        return "## Software Inventory\n\n_No software inventory available._\n\n"

    # software_inventory log uses: summary.total, entries[]
    summ  = sw.get("summary") or {}
    apps  = sw.get("entries") or sw.get("apps") or sw.get("installed_apps") or sw.get("applications") or []
    total = _int_or(summ.get("total") or sw.get("total_count") or len(apps))
    flagged = [a for a in apps if a.get("flags")]

    lines = [
        "## Software Inventory",
        "",
        f"**{total} applications found** on the Windows installation.",
        "",
    ]

    if flagged:
        lines += [
            "**Flagged items:**",
            "",
            "| Name | Version | Publisher | Flags |",
            "|---|---|---|---|",
        ]
        for a in flagged[:40]:
            flags = ", ".join(a.get("flags", [])) if isinstance(a.get("flags"), list) else _na(a.get("flags"))
            lines.append(
                f"| {_na(a.get('name') or a.get('display_name'))} "
                f"| {_na(a.get('version') or a.get('display_version'))} "
                f"| {_na(a.get('publisher'))} | {flags} |"
            )
        lines.append("")

    if apps:
        lines += [
            "<details>",
            "<summary>Full software list (click to expand)</summary>",
            "",
            "| Name | Version | Publisher | Install date |",
            "|---|---|---|---|",
        ]
        for a in sorted(apps, key=lambda x: (_str(x.get("name") or x.get("display_name"), "")).lower()):
            lines.append(
                f"| {_na(a.get('name') or a.get('display_name'))} "
                f"| {_na(a.get('version') or a.get('display_version'))} "
                f"| {_na(a.get('publisher'))} "
                f"| {_na(a.get('install_date'))} |"
            )
        lines += ["", "</details>", ""]

    return "\n".join(lines)

def section_thermal() -> str:
    th = load_thermal()
    if not th:
        return "## Thermal & Performance\n\n_No thermal data available._\n\n"

    verdict = _str(th.get("verdict"), "UNKNOWN")
    notes   = th.get("notes") or th.get("warnings") or []
    cpu_mhz = th.get("cpu_current_mhz") or th.get("current_mhz")
    cpu_max = th.get("cpu_max_mhz") or th.get("max_mhz")

    lines = [
        "## Thermal & Performance",
        "",
        f"| | |",
        f"|---|---|",
        f"| Verdict | {_badge(verdict)} |",
    ]
    if cpu_mhz and cpu_max:
        lines.append(f"| CPU frequency | {cpu_mhz} MHz / {cpu_max} MHz max |")
    lines.append("")

    if notes:
        lines += ["**Notes:**", ""]
        for n in notes:
            lines.append(f"- {n}")
        lines.append("")

    return "\n".join(lines)

def section_upgrade() -> str:
    ug = load_upgrade()
    if not ug:
        return "## Upgrade Recommendation\n\n_No upgrade advisor data available._\n\n"

    rec     = _str(ug.get("recommendation") or ug.get("summary"), "")
    details = ug.get("details") or ug.get("reasons") or []
    os_ver  = _str(ug.get("windows_version") or ug.get("os_version"), "")

    lines = [
        "## Upgrade Recommendation",
        "",
    ]
    if os_ver:
        lines += [f"**Windows version:** {os_ver}", ""]
    if rec:
        lines += [f"> {rec}", ""]
    if details:
        for d in details:
            lines.append(f"- {d}")
        lines.append("")

    return "\n".join(lines)

def section_next_steps() -> str:
    disks   = load_disk()
    urgency = "OK"
    for d in disks:
        u = _str(d.get("clone_urgency"), "").upper()
        if "CRITICAL" in u or "HIGH" in u or "NOW" in u:
            urgency = "CRITICAL"
            break
        elif "MODERATE" in u or "MEDIUM" in u or "SOON" in u or "CAUTION" in u:
            if urgency != "CRITICAL":
                urgency = "SOON"

    steps = [
        "## Recommended Next Steps",
        "",
    ]
    if urgency == "CRITICAL":
        steps += [
            "1. **Back up your data immediately** — the hard drive is showing signs of failure.",
            "   Do not delay; a failing drive can become unreadable at any time.",
        ]
    elif urgency == "SOON":
        steps += [
            "1. **Back up your data soon** — the hard drive has early warning signs of wear.",
        ]
    else:
        steps += [
            "1. **Keep regular backups** — good practice regardless of drive health.",
        ]

    steps += [
        "2. **Replace the hard drive with an SSD** — this will dramatically improve speed,",
        "   reliability, and battery life. The machine will feel like new.",
        "3. **Upgrade the operating system** — Windows Vista is no longer supported and",
        "   receives no security updates. Consider Windows 10/11 or a lightweight Linux",
        "   distribution.",
        "4. **Run a full ClamAV scan** with updated definitions — the definitions on this",
        "   machine date from 2016. Updated definitions may find threats that were missed.",
        "5. **Clean the vents and fan** — the machine is running warm and the CPU is",
        "   throttling. A dust clean-out and fresh thermal paste will help.",
        "",
    ]

    return "\n".join(steps)

def section_footer() -> str:
    return "\n".join([
        "---",
        "",
        "_This report was generated automatically by the Nielsoln Rescue Toolkit_  ",
        f"_Report date: {REPORT_DATE}_",
        "",
    ])

# ---------------------------------------------------------------------------
# TSV generator
# ---------------------------------------------------------------------------

def _tsv_row(*fields) -> str:
    return "\t".join(str(f).replace("\t", " ").replace("\n", " ") for f in fields)

def build_logon_tsv() -> str:
    la = load_logon()
    if not la:
        return _tsv_row("event_id", "event_name", "timestamp", "target_user",
                        "by_user", "workstation", "ip", "reason") + "\n"

    lines = [_tsv_row("event_id", "event_name", "timestamp", "target_user",
                      "by_user", "workstation", "ip", "reason")]

    # Failed logons (4625)
    for r in la.get("recent_failed_logons", []):
        lines.append(_tsv_row(
            4625, "FailedLogon",
            r.get("timestamp", ""),
            r.get("user", ""),
            "",
            r.get("workstation", ""),
            r.get("ip", ""),
            r.get("reason", ""),
        ))

    # Lockouts (4740)
    for r in la.get("lockout_events", []):
        lines.append(_tsv_row(
            4740, "AccountLockout",
            r.get("timestamp", ""),
            r.get("user", ""),
            "",
            r.get("caller", ""),
            "",
            "",
        ))

    # Password changes (4723/4724)
    for r in la.get("password_change_events", []):
        lines.append(_tsv_row(
            r.get("event_id", ""),
            r.get("event_name", ""),
            r.get("timestamp", ""),
            r.get("target_user", ""),
            r.get("by_user", ""),
            "",
            "",
            "",
        ))

    # Account management (4720, 4722, etc.)
    for r in la.get("account_management_events", []):
        lines.append(_tsv_row(
            r.get("event_id", ""),
            r.get("event_name", ""),
            r.get("timestamp", ""),
            r.get("target_user", ""),
            r.get("by_user", ""),
            "",
            "",
            "",
        ))

    return "\n".join(lines) + "\n"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"[report_gen] USB root: {USB}")
    print(f"[report_gen] Logs dir: {LOGS}")

    # Build markdown
    md = "\n".join([
        section_header(),
        section_hardware(),
        section_disk(),
        section_antivirus(),
        section_logon(),
        section_persistence(),
        section_services(),
        section_software(),
        section_thermal(),
        section_upgrade(),
        section_next_steps(),
        section_footer(),
    ])

    md_path = USB / "customer_report.md"
    md_path.write_text(md, encoding="utf-8")
    print(f"[report_gen] customer_report.md written → {md_path}  ({len(md):,} chars)")

    # Build TSV
    tsv = build_logon_tsv()
    tsv_path = USB / "logon_events.tsv"
    tsv_path.write_text(tsv, encoding="utf-8")
    line_count = tsv.count("\n")
    print(f"[report_gen] logon_events.tsv written → {tsv_path}  ({line_count} rows including header)")

main()
