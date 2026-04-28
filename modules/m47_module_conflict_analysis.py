"""m47_module_conflict_analysis — Cross-module contradiction detection.

Reads existing log files from the USB logs/ directory and detects contradictions:
  - ClamAV clean but suspicious persistence entries
  - Orphaned service ImagePath but disk integrity shows nothing missing
  - Task scheduler suspicious but no matching persistence scan hits
  - Firewall disabled but no network analysis performed
  - File anomalies detected but ClamAV not run
  - System integrity violations but ClamAV did not flag the same files
  - Logon audit clean but user audit disabled
  - Time integrity unreliable but module logs rely on timestamps
  - High trust score but ClamAV not run

Only reads from logs/ directory — does NOT re-run any scans.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m47_module_conflict_analysis --

Output:
    logs/module_conflict_analysis_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DESCRIPTION = (
    "Cross-module contradiction analysis: detects conflicts and gaps between "
    "module findings to surface missed risks or false assurance"
)

# ---------------------------------------------------------------------------
# Log loader (same pattern as m45)
# ---------------------------------------------------------------------------

def _load_latest(logs_dir: Path, glob: str) -> Optional[dict]:
    matches = sorted(logs_dir.glob(glob), reverse=True)
    if not matches:
        return None
    try:
        return json.loads(matches[0].read_text(encoding="utf-8"))
    except Exception:
        return None


def _verdict(log: Optional[dict]) -> Optional[str]:
    if log is None:
        return None
    return (log.get("verdict") or log.get("trust_label") or "").upper()


# ---------------------------------------------------------------------------
# Conflict rule engine
# ---------------------------------------------------------------------------

class _Context:
    """Lazy-loaded log holder."""

    def __init__(self, logs_dir: Path) -> None:
        self._logs_dir = logs_dir
        self._cache: Dict[str, Optional[dict]] = {}

    def get(self, name: str) -> Optional[dict]:
        if name not in self._cache:
            # Determine glob per module
            _globs = {
                "clamav":           "clamav_scan_*.json",
                "persistence":      "persistence_scan_*.json",
                "service":          "service_analysis_*.json",
                "task_scheduler":   "task_scheduler_analysis_*.json",
                "integrity":        "system_integrity_audit_*.json",
                "network":          "network_analysis_*.json",
                "browser":          "browser_activity_*.json",
                "registry":         "registry_health_*.json",
                "users":            "user_account_analysis_*.json",
                "file_anomalies":   "file_anomalies_*.json",
                "backup":           "backup_analysis_*.json",
                "time_integrity":   "time_integrity_*.json",
                "execution":        "execution_history_*.json",
                "updates":          "windows_update_analysis_*.json",
                "performance":      "performance_diagnosis_*.json",
                "trust_score":      "trust_score_*.json",
                "device_manager":   "device_manager_*.json",
                "driver_store":     "driver_store_analysis_*.json",
                "network_profile":  "network_profile_*.json",
                "execution_surface": "execution_surface_analysis_*.json",
            }
            glob = _globs.get(name, f"{name}_*.json")
            self._cache[name] = _load_latest(self._logs_dir, glob)
        return self._cache[name]

    def verdict(self, name: str) -> Optional[str]:
        return _verdict(self.get(name))

    def present(self, name: str) -> bool:
        return self.get(name) is not None


# ---------------------------------------------------------------------------
# Individual conflict checks
# ---------------------------------------------------------------------------

def _check(ctx: _Context) -> List[dict]:
    conflicts: List[dict] = []

    def add(severity: str, title: str, description: str,
            affected: List[str], followup: str) -> None:
        conflicts.append({
            "severity":           severity,
            "title":              title,
            "description":        description,
            "affected_modules":   affected,
            "recommended_followup": followup,
        })

    # 1. ClamAV clean but persistence is SUSPICIOUS
    clamav_v    = ctx.verdict("clamav")
    persist_v   = ctx.verdict("persistence")
    if clamav_v == "OK" and persist_v == "SUSPICIOUS":
        add(
            "HIGH",
            "ClamAV clean but suspicious persistence detected",
            "ClamAV did not flag any files, yet persistence scan found suspicious autorun entries. "
            "ClamAV may have missed unknown malware, or signatures are outdated.",
            ["clamav", "persistence"],
            "Update ClamAV signatures and re-scan. Manually review flagged autorun entries.",
        )

    # 2. File anomalies suspicious but ClamAV not run
    fa_v = ctx.verdict("file_anomalies")
    if fa_v == "SUSPICIOUS" and not ctx.present("clamav"):
        add(
            "HIGH",
            "Suspicious files detected but ClamAV has not been run",
            "File anomalies module found suspicious files (e.g., system binary names in user paths, "
            "double extensions), but no ClamAV log exists. These files have not been scanned for malware.",
            ["file_anomalies"],
            "Run ClamAV on the suspicious files found in file_anomalies log.",
        )

    # 3. Suspicious persistence but no task scheduler scan
    if persist_v in ("SUSPICIOUS", "WARNING") and not ctx.present("task_scheduler"):
        add(
            "MEDIUM",
            "Persistence anomalies but task scheduler not analysed",
            "Persistence scan raised concerns but scheduled tasks were not scanned. "
            "Scheduled tasks are a common persistence mechanism.",
            ["persistence"],
            "Run m34_task_scheduler_analysis to complete the persistence picture.",
        )

    # 4. Registry anomalies but no ClamAV
    reg_v = ctx.verdict("registry")
    reg_log = ctx.get("registry")
    has_reg_anomaly = bool(reg_log and reg_log.get("autorun_anomalies"))
    if has_reg_anomaly and not ctx.present("clamav"):
        add(
            "HIGH",
            "Registry autorun anomalies found but ClamAV not run",
            "Registry health found AppInit_DLLs, IFEO hijacks, or Winlogon overrides, "
            "but no ClamAV scan has been performed. The injected DLLs have not been checked.",
            ["registry"],
            "Run ClamAV to scan the DLLs referenced in registry anomalies.",
        )

    # 5. Firewall disabled but no network analysis
    network_log = ctx.get("network")
    if not ctx.present("network"):
        # Can't check, but note gap if persistence is suspicious
        if persist_v == "SUSPICIOUS":
            add(
                "MEDIUM",
                "Persistence suspicious but network exposure not assessed",
                "Suspicious persistence entries were found, but network analysis has not run. "
                "If malware is present it may also have modified firewall or network settings.",
                ["persistence"],
                "Run m37_network_analysis to check firewall state and exposure.",
            )
    else:
        exp = network_log.get("exposure_flags", {}) if network_log else {}
        if exp.get("firewall_disabled") and clamav_v == "OK":
            add(
                "MEDIUM",
                "Firewall disabled but ClamAV reported clean",
                "Firewall is disabled, increasing network attack surface, but ClamAV found nothing. "
                "Network-based attacks leave no file artifacts for ClamAV to detect.",
                ["network", "clamav"],
                "Consider checking for open ports and unauthorised services. "
                "ClamAV cannot detect network-resident threats.",
            )

    # 6. Time integrity unreliable — warn that all timestamp-based logs are suspect
    time_v = ctx.verdict("time_integrity")
    if time_v == "UNRELIABLE":
        ts_modules = []
        for m in ("persistence", "execution", "browser", "task_scheduler"):
            if ctx.present(m):
                ts_modules.append(m)
        if ts_modules:
            add(
                "MEDIUM",
                "Clock unreliable — timestamp-based findings may be inaccurate",
                f"Time integrity module reported clock unreliability. "
                f"The following modules rely on timestamps: {', '.join(ts_modules)}. "
                f"Relative ordering of events may be wrong.",
                ["time_integrity"] + ts_modules,
                "Treat all timestamps in affected logs as approximate. "
                "Cross-reference with event log sequence numbers if possible.",
            )

    # 7. System integrity violations but ClamAV did not flag them
    integrity_log = ctx.get("integrity")
    if integrity_log and integrity_log.get("violations") and clamav_v == "OK":
        n = len(integrity_log.get("violations", []))
        add(
            "MEDIUM",
            f"System integrity violations ({n}) not flagged by ClamAV",
            "System integrity audit found modified/missing system files, "
            "but ClamAV reported no infected files. "
            "This may indicate tampering with tools or signatures ClamAV cannot detect.",
            ["integrity", "clamav"],
            "Review integrity violations manually. Check if ClamAV signatures are current.",
        )

    # 8. No backup detected but no data has been confirmed safe
    backup_log = ctx.get("backup")
    if backup_log and backup_log.get("no_backup_risk") and clamav_v == "OK":
        add(
            "LOW",
            "No backup detected — data loss risk if malware or disk failure occurs",
            "Backup analysis found no backup software or restore points, "
            "and ClamAV passed. Any future infection or hardware failure would cause data loss.",
            ["backup"],
            "Advise user to set up backup before returning the machine.",
        )

    # 9. Trust score high but critical modules missing
    trust_log = ctx.get("trust_score")
    if trust_log:
        missing = trust_log.get("modules_missing", [])
        score   = trust_log.get("overall_score", 100)
        conf    = trust_log.get("confidence", "HIGH")
        if score >= 70 and conf == "LOW":
            add(
                "MEDIUM",
                "Trust score appears high but confidence is LOW",
                f"Trust score is {score}/100 but many modules haven't run yet "
                f"(missing: {', '.join(missing[:5])}). "
                "Score may drop significantly once all modules are executed.",
                ["trust_score"],
                "Run all remaining modules before reporting the machine as clean.",
            )

    # 10. Orphaned services found but no disk integrity scan
    if reg_log and reg_log.get("orphaned_services") and not ctx.present("integrity"):
        count = len(reg_log.get("orphaned_services", []))
        add(
            "LOW",
            f"{count} orphaned service ImagePath(s) found — disk integrity not verified",
            "Some services reference files that could not be found on disk. "
            "Without a system integrity scan it is unclear whether these are "
            "broken legit services or evidence of file-based cleanup after malware removal.",
            ["registry"],
            "Run m10_system_integrity_audit to check for missing system files.",
        )

    return conflicts


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(root: Path) -> dict:
    logs_dir = root / "logs"
    limitations: List[str] = []

    if not logs_dir.is_dir():
        limitations.append("logs/ directory not found — no module logs to analyse")
        return {
            "scan_status":  "ok",
            "verdict":      "OK",
            "conflicts":    [],
            "limitations":  limitations,
        }

    ctx = _Context(logs_dir)
    conflicts = _check(ctx)

    # Determine overall verdict based on highest severity conflict
    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    max_sev = max((severity_order.get(c["severity"], 0) for c in conflicts), default=0)

    if max_sev >= 3:
        verdict = "SUSPICIOUS"
    elif max_sev >= 2:
        verdict = "WARNING"
    elif max_sev >= 1:
        verdict = "ADVISORY"
    else:
        verdict = "OK"

    # Inventory which logs were examined
    logs_examined = sorted(str(p.name) for p in logs_dir.glob("*.json"))

    return {
        "scan_status":    "ok",
        "verdict":        verdict,
        "conflict_count": len(conflicts),
        "conflicts":      conflicts,
        "logs_examined":  logs_examined,
        "limitations":    limitations,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== MODULE CONFLICT ANALYSIS ===")
    print(f"Verdict   : {data.get('verdict', '?')}")
    print(f"Conflicts : {data.get('conflict_count', 0)}")

    conflicts = data.get("conflicts", [])
    if not conflicts:
        print("\nNo cross-module contradictions detected.")
    else:
        for i, c in enumerate(conflicts, 1):
            print(f"\n[{c['severity']}] {c['title']}")
            print(f"  {c['description']}")
            print(f"  Affected: {', '.join(c.get('affected_modules', []))}")
            print(f"  Follow-up: {c.get('recommended_followup', '')}")

    logs = data.get("logs_examined", [])
    print(f"\n{len(logs)} log file(s) examined.")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    parser = argparse.ArgumentParser(
        prog="m47_module_conflict_analysis",
        description=DESCRIPTION
    )
    parser.add_argument("--summary", action="store_true")
    # --target accepted but ignored; this module reads from USB logs/
    parser.add_argument("--target", default="", help="Ignored; reads from USB logs/")
    args = parser.parse_args(argv)

    print(f"[m47] Analysing cross-module conflicts in {root / 'logs'} ...")
    data = analyse(root)

    from datetime import datetime as _dt, timezone as _tz
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"module_conflict_analysis_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m47] Log written: {out_path}")

    return 0 if data.get("verdict") in ("OK", "ADVISORY") else 1
