"""m45_trust_score — Unified machine trust/risk score.

Aggregates results from all previously-run module logs to produce:
  - Overall trust score (0–100, higher = more trustworthy)
  - Category scores (malware, persistence, integrity, network, backup, etc.)
  - Top contributing risks
  - Confidence level (depends on how many modules have run)
  - Recommended next actions

Only reads log files from the USB logs/ directory — does NOT re-run any scans.
Run after all other relevant modules have completed.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m45_trust_score -- (no --target needed)

Output:
    logs/trust_score_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DESCRIPTION = (
    "Unified trust score: aggregates all module logs → overall score, "
    "category scores, top risks, confidence, recommended actions"
)

# ---------------------------------------------------------------------------
# Score model
#
# Each module contributes to one or more categories.
# Each finding deducts points from the base score of 100.
# A module that hasn't run is counted as "unknown" and reduces confidence.
# ---------------------------------------------------------------------------

# Maximum deduction per finding type
_DEDUCTIONS: Dict[str, int] = {
    # Malware
    "clamav_infected":             40,
    "clamav_suspicious":           20,
    # Persistence
    "suspicious_autorun":          25,
    "suspicious_service":          20,
    "scheduled_task_suspicious":   20,
    "ifeo_debugger_hijack":        25,
    "appinit_dlls":                20,
    "winlogon_override":           20,
    # File integrity
    "sfc_violations":              20,
    "file_anomaly_suspicious":     20,
    "file_anomaly_warning":        10,
    # Network exposure
    "rdp_firewall_both_off":       20,
    "rdp_enabled":                 10,
    "firewall_disabled":           10,
    # Backup / data safety
    "no_backup":                   15,
    # Browser
    "browser_suspicious_ext":      15,
    "browser_suspicious_download": 10,
    # Registry
    "registry_parse_error":         5,
    "orphaned_services":             5,
    # User accounts
    "builtin_admin_active":         10,
    "guest_active":                  5,
    "no_password":                  10,
    # Time integrity
    "clock_unreliable":             10,
    # Execution history
    "lolbin_usage":                 10,
    # Windows Update
    "no_updates":                   10,
    "pending_reboot":                5,
    # Performance
    "critical_hardware":             5,
}

# Module log globs and their category + key findings to extract
_MODULE_SPECS: List[dict] = [
    {
        "name": "clamav_scan",
        "glob": "clamav_scan_*.json",
        "category": "malware",
    },
    {
        "name": "persistence_scan",
        "glob": "persistence_scan_*.json",
        "category": "persistence",
    },
    {
        "name": "service_analysis",
        "glob": "service_analysis_*.json",
        "category": "persistence",
    },
    {
        "name": "system_integrity_audit",
        "glob": "system_integrity_audit_*.json",
        "category": "integrity",
    },
    {
        "name": "network_analysis",
        "glob": "network_analysis_*.json",
        "category": "network",
    },
    {
        "name": "browser_activity",
        "glob": "browser_activity_*.json",
        "category": "browser",
    },
    {
        "name": "registry_health",
        "glob": "registry_health_*.json",
        "category": "integrity",
    },
    {
        "name": "user_account_analysis",
        "glob": "user_account_analysis_*.json",
        "category": "access_control",
    },
    {
        "name": "task_scheduler_analysis",
        "glob": "task_scheduler_analysis_*.json",
        "category": "persistence",
    },
    {
        "name": "file_anomalies",
        "glob": "file_anomalies_*.json",
        "category": "integrity",
    },
    {
        "name": "backup_analysis",
        "glob": "backup_analysis_*.json",
        "category": "backup",
    },
    {
        "name": "time_integrity",
        "glob": "time_integrity_*.json",
        "category": "integrity",
    },
    {
        "name": "execution_history",
        "glob": "execution_history_*.json",
        "category": "persistence",
    },
    {
        "name": "windows_update_analysis",
        "glob": "windows_update_analysis_*.json",
        "category": "patching",
    },
    {
        "name": "performance_diagnosis",
        "glob": "performance_diagnosis_*.json",
        "category": "performance",
    },
    {
        "name": "execution_surface_analysis",
        "glob": "execution_surface_analysis_*.json",
        "category": "persistence",
    },
]


def _load_latest(logs_dir: Path, glob: str) -> Optional[dict]:
    """Load the most recent JSON log matching the glob pattern."""
    matches = sorted(logs_dir.glob(glob), reverse=True)
    if not matches:
        return None
    try:
        return json.loads(matches[0].read_text(encoding="utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Per-module finding extractors
# ---------------------------------------------------------------------------

def _extract_clamav(log: dict) -> List[Tuple[str, int, str]]:
    """Returns list of (finding_key, deduction, description)."""
    findings = []
    verdict = (log.get("verdict") or "").upper()
    if verdict == "INFECTED":
        count = log.get("infected_count", 1)
        findings.append(("clamav_infected", _DEDUCTIONS["clamav_infected"],
                          f"ClamAV: {count} infected file(s)"))
    elif verdict == "SUSPICIOUS":
        findings.append(("clamav_suspicious", _DEDUCTIONS["clamav_suspicious"],
                          "ClamAV: suspicious findings"))
    return findings


def _extract_persistence(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    if verdict == "SUSPICIOUS":
        suspicious_count = len([
            e for e in log.get("entries", [])
            if "suspicious" in str(e.get("flags", "")).lower()
        ])
        findings.append(("suspicious_autorun", _DEDUCTIONS["suspicious_autorun"],
                          f"Persistence: {suspicious_count} suspicious autorun entries"))
    return findings


def _extract_network(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    exp = log.get("exposure_flags", {})
    if exp.get("rdp_enabled") and exp.get("firewall_disabled"):
        findings.append(("rdp_firewall_both_off", _DEDUCTIONS["rdp_firewall_both_off"],
                          "RDP enabled AND firewall disabled — high exposure"))
    elif exp.get("rdp_enabled"):
        findings.append(("rdp_enabled", _DEDUCTIONS["rdp_enabled"],
                          "RDP enabled (Remote Desktop)"))
    elif exp.get("firewall_disabled"):
        findings.append(("firewall_disabled", _DEDUCTIONS["firewall_disabled"],
                          "Windows Firewall disabled"))
    return findings


def _extract_browser(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    if verdict == "SUSPICIOUS":
        findings.append(("browser_suspicious_ext", _DEDUCTIONS["browser_suspicious_ext"],
                          "Browser: known suspicious extension installed"))
    susp_dl = log.get("suspicious_downloads", [])
    if susp_dl:
        findings.append(("browser_suspicious_download", _DEDUCTIONS["browser_suspicious_download"],
                          f"Browser: {len(susp_dl)} suspicious download(s)"))
    return findings


def _extract_registry(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    auto_anoms = log.get("autorun_anomalies", [])
    for a in auto_anoms:
        t = a.get("type", "")
        if "ifeo_debugger" in t:
            findings.append(("ifeo_debugger_hijack", _DEDUCTIONS["ifeo_debugger_hijack"],
                              f"IFEO debugger hijack: {a.get('target')}"))
        elif "appinit" in t:
            findings.append(("appinit_dlls", _DEDUCTIONS["appinit_dlls"],
                              f"AppInit_DLLs: {a.get('value', '')[:60]}"))
        elif "winlogon" in t:
            findings.append(("winlogon_override", _DEDUCTIONS["winlogon_override"],
                              f"Winlogon override: {a.get('value', '')[:60]}"))
    if log.get("parse_errors"):
        findings.append(("registry_parse_error", _DEDUCTIONS["registry_parse_error"],
                          f"{len(log['parse_errors'])} hive parse error(s)"))
    return findings


def _extract_users(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    flags_all = []
    for acct in log.get("accounts", []):
        flags_all.extend(acct.get("flags", []))
    if "builtin_admin_active" in flags_all:
        findings.append(("builtin_admin_active", _DEDUCTIONS["builtin_admin_active"],
                          "Built-in Administrator account is active"))
    if "guest_account_active" in flags_all:
        findings.append(("guest_active", _DEDUCTIONS["guest_active"],
                          "Guest account is active"))
    if "no_password_required" in flags_all:
        findings.append(("no_password", _DEDUCTIONS["no_password"],
                          "One or more accounts have no password required"))
    return findings


def _extract_tasks(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    if verdict == "SUSPICIOUS":
        count = sum(1 for t in log.get("tasks", []) if t.get("verdict") == "SUSPICIOUS")
        findings.append(("scheduled_task_suspicious", _DEDUCTIONS["scheduled_task_suspicious"],
                          f"Task Scheduler: {count} suspicious task(s)"))
    return findings


def _extract_file_anomalies(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    s = log.get("summary", {})
    if verdict == "SUSPICIOUS":
        findings.append(("file_anomaly_suspicious", _DEDUCTIONS["file_anomaly_suspicious"],
                          f"File anomalies: system binary name in user path or double-extension exe"))
    elif verdict == "WARNING":
        findings.append(("file_anomaly_warning", _DEDUCTIONS["file_anomaly_warning"],
                          f"File anomalies: {s.get('total_anomalies', 0)} anomalies detected"))
    return findings


def _extract_backup(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    if log.get("no_backup_risk"):
        findings.append(("no_backup", _DEDUCTIONS["no_backup"],
                          "No backup or cloud sync software detected"))
    return findings


def _extract_time(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    if verdict == "UNRELIABLE":
        findings.append(("clock_unreliable", _DEDUCTIONS["clock_unreliable"],
                          "Clock unreliable: event log timestamps may not be trustworthy"))
    return findings


def _extract_execution(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    lolbin_count = sum(
        1 for e in log.get("prefetch", [])
        if e.get("lolbin")
    )
    if lolbin_count > 2:
        findings.append(("lolbin_usage", _DEDUCTIONS["lolbin_usage"],
                          f"Execution history: {lolbin_count} LOLBin execution(s) found"))
    return findings


def _extract_updates(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    if verdict == "WARNING":
        if log.get("pending_reboot"):
            findings.append(("pending_reboot", _DEDUCTIONS["pending_reboot"],
                              "Pending reboot for Windows Updates"))
        elif not log.get("hotfixes"):
            findings.append(("no_updates", _DEDUCTIONS["no_updates"],
                              "No hotfixes/updates found in registry"))
    return findings


def _extract_integrity(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    if verdict in ("WARNING", "SUSPICIOUS"):
        violations = len(log.get("violations", []))
        if violations:
            findings.append(("sfc_violations", _DEDUCTIONS["sfc_violations"],
                              f"System integrity: {violations} violation(s) detected"))
    return findings


def _extract_performance(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    if verdict == "CRITICAL":
        findings.append(("critical_hardware", _DEDUCTIONS["critical_hardware"],
                          "Performance: critical hardware limitation detected"))
    return findings


def _extract_execution_surface(log: dict) -> List[Tuple[str, int, str]]:
    findings = []
    verdict = (log.get("verdict") or "").upper()
    if verdict == "SUSPICIOUS":
        count = len(log.get("suspicious_items", []))
        if count:
            findings.append(("suspicious_service", _DEDUCTIONS["suspicious_service"],
                              f"Execution surface: {count} suspicious item(s)"))
    return findings


# Mapping from module name to extractor function
_EXTRACTORS = {
    "clamav_scan":              _extract_clamav,
    "persistence_scan":         _extract_persistence,
    "service_analysis":         _extract_execution_surface,
    "system_integrity_audit":   _extract_integrity,
    "network_analysis":         _extract_network,
    "browser_activity":         _extract_browser,
    "registry_health":          _extract_registry,
    "user_account_analysis":    _extract_users,
    "task_scheduler_analysis":  _extract_tasks,
    "file_anomalies":           _extract_file_anomalies,
    "backup_analysis":          _extract_backup,
    "time_integrity":           _extract_time,
    "execution_history":        _extract_execution,
    "windows_update_analysis":  _extract_updates,
    "performance_diagnosis":    _extract_performance,
    "execution_surface_analysis": _extract_execution_surface,
}


# ---------------------------------------------------------------------------
# Category scoring
# ---------------------------------------------------------------------------

_CATEGORY_MODULES: Dict[str, List[str]] = {
    "malware":        ["clamav_scan"],
    "persistence":    ["persistence_scan", "service_analysis", "task_scheduler_analysis",
                       "execution_surface_analysis", "execution_history"],
    "integrity":      ["system_integrity_audit", "file_anomalies", "registry_health",
                       "time_integrity"],
    "network":        ["network_analysis"],
    "browser":        ["browser_activity"],
    "access_control": ["user_account_analysis"],
    "backup":         ["backup_analysis"],
    "patching":       ["windows_update_analysis"],
    "performance":    ["performance_diagnosis"],
}


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(root: Path) -> dict:
    logs_dir = root / "logs"
    all_findings: List[dict] = []
    modules_run: List[str] = []
    modules_missing: List[str] = []
    limitations: List[str] = []

    # Load all module logs and extract findings
    category_deductions: Dict[str, int] = {cat: 0 for cat in _CATEGORY_MODULES}

    for spec in _MODULE_SPECS:
        log = _load_latest(logs_dir, spec["glob"]) if logs_dir.is_dir() else None
        if log is None:
            modules_missing.append(spec["name"])
            continue
        modules_run.append(spec["name"])
        extractor = _EXTRACTORS.get(spec["name"])
        if extractor:
            try:
                for key, deduction, desc in extractor(log):
                    all_findings.append({
                        "module":    spec["name"],
                        "category":  spec["category"],
                        "key":       key,
                        "deduction": deduction,
                        "description": desc,
                    })
                    cat = spec["category"]
                    if cat in category_deductions:
                        category_deductions[cat] = min(
                            category_deductions[cat] + deduction, 100
                        )
            except Exception as exc:
                limitations.append(f"Extractor error for {spec['name']}: {exc}")

    # Compute overall score
    total_deduction = min(sum(f["deduction"] for f in all_findings), 100)
    overall_score   = max(0, 100 - total_deduction)

    # Category scores
    category_scores = {
        cat: max(0, 100 - category_deductions[cat])
        for cat in _CATEGORY_MODULES
    }

    # Confidence: based on proportion of modules run
    coverage = len(modules_run) / max(len(_MODULE_SPECS), 1)
    if coverage >= 0.8:
        confidence = "HIGH"
    elif coverage >= 0.5:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # Sort findings by deduction descending — these are the "top risks"
    all_findings.sort(key=lambda f: f["deduction"], reverse=True)

    # Recommendations
    recommendations: List[str] = []
    if modules_missing:
        recommendations.append(
            f"Run missing modules to improve confidence: "
            + ", ".join(modules_missing[:5])
        )
    for f in all_findings[:5]:
        recommendations.append(f"Address: {f['description']}")

    # Overall trust label
    if overall_score >= 80:
        trust_label = "TRUSTED"
    elif overall_score >= 60:
        trust_label = "CAUTIOUS"
    elif overall_score >= 40:
        trust_label = "RISKY"
    else:
        trust_label = "UNTRUSTED"

    return {
        "scan_status":      "ok",
        "trust_label":      trust_label,
        "overall_score":    overall_score,
        "confidence":       confidence,
        "category_scores":  category_scores,
        "top_risks":        all_findings[:10],
        "all_findings":     all_findings,
        "modules_run":      modules_run,
        "modules_missing":  modules_missing,
        "recommendations":  recommendations,
        "limitations":      limitations,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== TRUST SCORE ===")
    score = data.get("overall_score", 0)
    label = data.get("trust_label", "?")
    conf  = data.get("confidence", "?")
    bar   = "#" * (score // 5) + "-" * (20 - score // 5)
    print(f"Overall  : {score:3}/100  [{bar}]  {label}  (confidence: {conf})")

    print("\nCategory scores:")
    for cat, cscore in data.get("category_scores", {}).items():
        bar2 = "#" * (cscore // 5) + "-" * (20 - cscore // 5)
        print(f"  {cat:18} {cscore:3}/100  [{bar2}]")

    risks = data.get("top_risks", [])
    if risks:
        print(f"\nTop risks (deduction):")
        for r in risks[:8]:
            print(f"  [-{r['deduction']:2}]  {r['description']}")

    recs = data.get("recommendations", [])
    if recs:
        print(f"\nRecommendations:")
        for i, rec in enumerate(recs, 1):
            print(f"  {i}. {rec}")

    missing = data.get("modules_missing", [])
    if missing:
        print(f"\nModules not yet run: {', '.join(missing)}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    parser = argparse.ArgumentParser(prog="m45_trust_score", description=DESCRIPTION)
    parser.add_argument("--summary", action="store_true")
    # --target is accepted but ignored — this module reads from the USB logs/ dir
    parser.add_argument("--target", default="", help="Ignored; reads from USB logs/")
    args = parser.parse_args(argv)

    print(f"[m45] Computing trust score from logs in {root / 'logs'} ...")
    data = analyse(root)

    from datetime import datetime as _dt, timezone as _tz
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"trust_score_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m45] Log written: {out_path}")

    label = data.get("trust_label", "TRUSTED")
    return 0 if label == "TRUSTED" else 1
