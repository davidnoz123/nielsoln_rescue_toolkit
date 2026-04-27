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
        raw = d
    elif isinstance(d, dict):
        raw = d.get("drives", d.get("disks", [d]))
    else:
        return []
    # Skip removable / USB drives — they're rescue media, not the patient's disk
    return [disk for disk in raw if not _is_removable(disk)]

def _is_removable(disk: dict) -> bool:
    note = str(disk.get("note") or "").lower()
    media = str(disk.get("media_type") or disk.get("type") or "").lower()
    if "removable" in note or "usb" in note:
        return True
    if "removable" in media or "usb" in media:
        return True
    return False

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

def load_event_archive_summary() -> dict:
    """Read checkpoint files from event_archive/ and return a summary dict."""
    archive_root = USB / "event_archive"
    if not archive_root.exists():
        return {}
    result = {}
    for checkpoint in sorted(archive_root.glob("*/channels/*/checkpoint.json")):
        parts = checkpoint.parts
        # ...event_archive/<machine_id>/channels/<channel>/checkpoint.json
        try:
            channel = parts[-2]
            data = json.loads(checkpoint.read_text(encoding="utf-8"))
            result[channel] = data
        except Exception:
            pass
    return result

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

def load_os_profile() -> dict:
    d = _load("os_profile_*.json")
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
    bios     = hw.get("bios", {}) if isinstance(hw.get("bios"), dict) else {}
    boot_mode = hw.get("boot_mode", "")

    # CPU field names differ slightly across m04 versions
    cpu_model   = _na(cpu.get("model"))
    cpu_arch    = _na(cpu.get("architecture"))
    cpu_phys    = cpu.get("physical_cores") or cpu.get("cores")
    cpu_logical = cpu.get("logical_cores") or cpu.get("threads")
    cores_str   = (f"{cpu_phys} physical / {cpu_logical} logical"
                   if cpu_phys and cpu_logical else _na(None))

    # RAM
    ram_total  = _na(ram.get("total_gib"))
    ram_type   = _na(ram.get("type"))
    ram_speed  = _na(ram.get("speed"))
    ram_slots_p = ram.get("slots_populated", "")
    ram_slots_t = ram.get("slots_total", "")
    ram_slots_str = (f"{ram_slots_p} of {ram_slots_t} slots used"
                     if ram_slots_p not in ("", "unknown") else "")

    # BIOS
    bios_vendor  = _na(bios.get("vendor"))
    bios_version = _na(bios.get("version"))
    bios_date    = _na(bios.get("date"))
    bios_str     = bios_date
    if bios_vendor not in ("N/A", "?") or bios_version not in ("N/A", "?"):
        bios_str = f"{bios_vendor}  v{bios_version}  ({bios_date})"
    if boot_mode:
        bios_str += f"  — {boot_mode}"

    lines = [
        "## Hardware",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Manufacturer | {_na(sys_info.get('manufacturer'))} |",
        f"| Model | {_na(sys_info.get('product_name'))} {_str(sys_info.get('product_version'), '')} |",
        f"| Serial number | {_na(sys_info.get('serial_number'))} |",
        f"| Form factor | {_na(sys_info.get('form_factor') or hw.get('form_factor'))} |",
        f"| BIOS | {bios_str} |",
        f"| CPU | {cpu_model} |",
        f"| CPU architecture | {cpu_arch} |",
        f"| CPU cores / threads | {cores_str} |",
        f"| RAM | {ram_total} GiB  ({ram_type} / {ram_speed}) |",
    ]
    if ram_slots_str:
        lines.append(f"| RAM slots | {ram_slots_str} |")
    lines.append("")

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

def section_os_profile() -> str:
    op = load_os_profile()
    if not op:
        return "## Windows OS Profile\n\n_No OS profile data available. Run m26_os_profile._\n\n"

    os_info = op.get("os", {})
    drivers = op.get("drivers", [])
    kernel_svcs = op.get("kernel_services", [])

    product   = _na(os_info.get("product_name"))
    version   = _na(os_info.get("version"))
    build     = _na(os_info.get("build"))
    sp        = _str(os_info.get("service_pack"), "")
    bitness   = _na(os_info.get("os_bitness"))
    installed = _na(os_info.get("install_date"))
    owner     = _str(os_info.get("registered_owner"), "")
    org       = _str(os_info.get("registered_org"), "")

    # CPU bitness from hardware profile
    hw = load_hardware()
    cpu_arch = _na(hw.get("cpu", {}).get("architecture") if isinstance(hw.get("cpu"), dict) else None)

    lines = [
        "## Windows OS Profile",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| OS Edition | {product} |",
        f"| Version / Build | {version} / {build} |",
    ]
    if sp:
        lines.append(f"| Service Pack | {sp} |")
    lines += [
        f"| OS Bitness | {bitness} |",
        f"| CPU Architecture | {cpu_arch} |",
        f"| Install Date | {installed} |",
    ]
    if owner:
        lines.append(f"| Registered Owner | {owner} |")
    if org:
        lines.append(f"| Organisation | {org} |")
    lines.append("")

    return "\n".join(lines)

def section_drivers() -> str:
    op = load_os_profile()
    if not op:
        return ""

    drivers     = op.get("drivers", [])
    kernel_svcs = op.get("kernel_services", [])

    if not drivers and not kernel_svcs:
        return "## Drivers\n\n_No driver data available._\n\n"

    lines = [
        "## Drivers",
        "",
        f"**{len(drivers)} kernel driver files** found in `System32\\drivers\\`  ",
        f"**{len(kernel_svcs)} kernel/filesystem driver services** in registry",
        "",
    ]

    # Flag drivers with unusual characteristics
    # (very small = likely stub; very large = unusual for a driver)
    flagged = [d for d in drivers if d.get("size_kb", 0) > 5000]
    if flagged:
        lines += [
            "**Unusually large driver files (> 5 MB):**",
            "",
            "| File | Size |",
            "|---|---|",
        ]
        for d in flagged:
            lines.append(f"| `{d['name']}` | {d['size_kb']:.0f} KB |")
        lines.append("")

    # Services with non-standard image paths (not \\SystemRoot\\ or \\system32\\)
    unusual_svcs = [
        s for s in kernel_svcs
        if s.get("image_path") and
        not any(x in s["image_path"].lower()
                for x in ("\\systemroot\\", "system32", "\\windows\\", ""))
        and s["image_path"].lower() not in ("", "n/a", "?")
    ]
    if unusual_svcs:
        lines += [
            "**Kernel services with non-standard image paths:**",
            "",
            "| Service | Path |",
            "|---|---|",
        ]
        for s in unusual_svcs[:20]:
            lines.append(f"| `{s['name']}` | `{s['image_path']}` |")
        lines.append("")

    # Full driver list in collapsible block
    if drivers:
        lines += [
            "<details>",
            "<summary>Full driver file list (click to expand)</summary>",
            "",
            "| File | Size (KB) | Modified |",
            "|---|---|---|",
        ]
        for d in drivers:
            lines.append(f"| `{d['name']}` | {d['size_kb']:.0f} | {d['modified']} |")
        lines += ["", "</details>", ""]

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

        # Bearing-wear detail block when Spin_Retry_Count is non-zero
        spin_retry = info.get("Spin_Retry_Count")
        try:
            spin_int = int(spin_retry) if spin_retry is not None else 0
        except (TypeError, ValueError):
            spin_int = 0
        if spin_int > 0:
            lines += [
                "<details>",
                "<summary>What does Spin Retry Count mean? (click to expand)</summary>",
                "",
                f"The drive has recorded **{spin_int} spin-up retries**.",
                "",
                "When a hard drive powers on, its motor must spin the magnetic platters up to",
                "operating speed (typically 5,400 RPM for laptop drives). The spindle bearings",
                "that support the rotating platters are lubricated at the factory. Over time,",
                "and especially with heat cycling and vibration, this lubricant degrades.",
                "A retried spin-up means the drive\'s motor controller tried to reach speed,",
                "detected it hadn\'t reached it within the allowed time window, and tried again.",
                "",
                "Each retry is a sign the bearings are worn and the motor is struggling.",
                "The drive may still function for weeks or months, but it is mechanically",
                "degraded — a full backup and drive replacement are strongly recommended",
                "before it seizes completely.",
                "",
                "</details>",
                "",
            ]

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
    archive = load_event_archive_summary()
    if not la and not archive:
        return "## Windows Security — Logon Audit\n\n_No logon audit data available._\n\n"
    if not la:
        la = {}

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

    # Warn prominently when failed count is zero — Vista Home disables Failure auditing
    if totals.get("failed_logons", 0) == 0:
        lines += [
            "> **Audit policy caveat:** Windows Vista Home editions disable Failure "
            "auditing for Logon events by default.  A count of zero failed logons "
            "does **not** prove that no failed attempts occurred — they may simply "
            "not have been recorded by the OS.",
            "",
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

    # Event archive summary
    if archive:
        lines += [
            "**Event log archive (incremental capture):**",
            "",
            "| Channel | Records archived | Last record | Last run |",
            "|---|---|---|---|",
        ]
        for channel, cp in sorted(archive.items()):
            last_id  = cp.get("last_record_id", "?")
            last_ts  = cp.get("last_timestamp", "?")
            last_run = cp.get("last_run", "?")
            lines.append(f"| {channel} | {last_id:,} | {last_ts} | {last_run} |"
                         if isinstance(last_id, int)
                         else f"| {channel} | {last_id} | {last_ts} | {last_run} |")
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

        lines += [
            "<details>",
            "<summary>Analysis of suspicious services (click to expand)</summary>",
            "",
        ]
        for s in susp_services[:20]:
            name        = _na(s.get('name'))
            display     = _na(s.get('display_name'))
            image_path  = _na(s.get('image_path'))
            reason      = _na(s.get('suspicious_reason') or s.get('reason'))
            img_lower   = image_path.lower()

            lines += [f"**{display}** (`{name}`)", ""]
            lines.append(f"- Image path: `{image_path}`")
            lines.append(f"- Flagged reason: {reason}")

            # Per-service contextual analysis
            if "system32" not in img_lower and "syswow64" not in img_lower and img_lower not in ("", "n/a", "?"):
                lines.append("- **Not in System32** — executable is outside the standard Windows directory, "
                             "which is unusual for a system service and may indicate a third-party or rogue install.")
            if "temp" in img_lower or "appdata" in img_lower:
                lines.append("- **Runs from a user temp/AppData path** — a known malware persistence pattern.")
            if img_lower.endswith(".bat") or img_lower.endswith(".vbs") or img_lower.endswith(".ps1"):
                lines.append("- **Script-based service** — services normally run native executables (.exe). "
                             "A script-backed service is highly unusual and warrants investigation.")
            if "svchost" in img_lower:
                lines.append("- Runs under `svchost.exe` — this is normal for Windows built-in services, "
                             "but the service key itself should be verified against known-good lists.")
            if "teamviewer" in img_lower or "vnc" in img_lower or "anydesk" in img_lower:
                lines.append("- **Remote access software** — this service provides remote desktop access. "
                             "Verify the owner knowingly installed this.")
            if "tor" in name.lower() or "proxy" in name.lower() or "tunnel" in name.lower():
                lines.append("- **Network tunnelling indicator** — name suggests this service may route "
                             "traffic through a proxy or anonymising network.")

            lines.append("")

        lines += ["</details>", ""]

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

def section_chatgpt_context() -> str:
    """
    A plain-text block formatted for pasting into ChatGPT (or similar)
    to get an independent assessment of the hardware's historical tier and value.
    """
    hw = load_hardware()
    op = load_os_profile()
    disks = load_disk()

    sys_info  = hw.get("system", {}) if hw else {}
    cpu       = hw.get("cpu", {}) if hw else {}
    ram       = hw.get("ram", {}) if hw else {}
    gpu_list  = hw.get("gpu", []) if hw else []
    bios      = hw.get("bios", {}) if isinstance(hw.get("bios"), dict) else {}
    boot_mode = hw.get("boot_mode", "") if hw else ""
    form      = hw.get("form_factor", "") if hw else ""

    os_info   = op.get("os", {}) if op else {}

    # Estimate release year from BIOS date (format: MM/DD/YYYY or similar)
    release_year = "unknown"
    bios_date = bios.get("date", "")
    if bios_date and len(bios_date) >= 4:
        # Try YYYY at end or start
        import re as _re
        m = _re.search(r"(20\d{2}|19\d{2})", bios_date)
        if m:
            release_year = m.group(1)
    # Cross-check with OS install date
    install_date = os_info.get("install_date", "")
    if install_date and release_year == "unknown" and len(install_date) >= 4:
        release_year = install_date[:4]

    mfr   = _str(sys_info.get("manufacturer"), "Unknown manufacturer")
    model = _str(sys_info.get("product_name"), "Unknown model")
    cpu_model = _str(cpu.get("model"), "unknown CPU")
    cpu_arch  = _str(cpu.get("architecture"), "")
    cpu_cores = cpu.get("physical_cores") or cpu.get("cores") or "?"
    ram_gib   = _str(ram.get("total_gib"), "?")
    ram_type  = _str(ram.get("type"), "")
    ram_speed = _str(ram.get("speed"), "")

    gpu_str = "; ".join(
        (g.get("model") or str(g)) if isinstance(g, dict) else str(g)
        for g in (gpu_list if isinstance(gpu_list, list) else [gpu_list])
    ) or "unknown"

    disk_parts = []
    for d in disks:
        size = d.get("size_gib") or d.get("size") or "?"
        dtype = d.get("type") or d.get("media_type") or "disk"
        dmodel = d.get("model") or ""
        disk_parts.append(f"{size} GB {dtype}" + (f" ({dmodel})" if dmodel else ""))
    disk_str = "; ".join(disk_parts) if disk_parts else "unknown"

    os_edition = _str(os_info.get("product_name"), "Windows Vista")
    os_bitness = _str(os_info.get("os_bitness"), "")
    os_str     = f"{os_edition}{(' ' + os_bitness) if os_bitness else ''}"

    ram_detail = ram_gib + " GiB"
    if ram_type not in ("", "N/A", "?", "unknown"):
        ram_detail += f"  {ram_type}"
    if ram_speed not in ("", "N/A", "?", "unknown"):
        ram_detail += f" @ {ram_speed}"

    cpu_detail = cpu_model
    if cpu_arch:
        cpu_detail += f"  ({cpu_arch})"
    if cpu_cores and cpu_cores != "?":
        cpu_detail += f"  {cpu_cores} core(s)"

    lines = [
        "---",
        "",
        "## Hardware Context (paste this into ChatGPT)",
        "",
        "> Copy everything below this line and paste it into ChatGPT to get an",
        "> independent assessment of this hardware's historical tier and value.",
        "",
        "---",
        "",
        "Please analyse the following hardware specifications for a laptop.",
        "Answer these questions:",
        "",
        "1. What performance tier was this laptop when it was released —",
        "   budget, mid-range, or high-end?",
        "2. How does each component (CPU, RAM, storage, GPU) compare to what was",
        "   typical for a laptop of this class at the time of release?",
        "3. What tasks was this machine well-suited for when it was new?",
        "4. Is it still usable today, and for what kinds of tasks?",
        "5. Roughly how much would this laptop have cost new, and how does",
        "   that reflect its value to the original owner?",
        "",
        f"**Estimated release year:** {release_year}",
        f"**Manufacturer / Model:** {mfr} {model}",
        f"**CPU:** {cpu_detail}",
        f"**RAM:** {ram_detail}",
        f"**Storage:** {disk_str}",
        f"**GPU / Display adapter:** {gpu_str}",
        f"**OS installed:** {os_str}",
        f"**Form factor:** {form or 'laptop'}",
        f"**BIOS / Firmware:** {bios.get('vendor', '')} {bios.get('version', '')} "
        f"dated {bios.get('date', 'unknown')} — {boot_mode or 'Legacy BIOS'}".strip(),
        "",
        "---",
        "",
    ]
    return "\n".join(lines)

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
        section_os_profile(),
        section_drivers(),
        section_disk(),
        section_antivirus(),
        section_logon(),
        section_persistence(),
        section_services(),
        section_software(),
        section_thermal(),
        section_upgrade(),
        section_next_steps(),
        section_chatgpt_context(),
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
