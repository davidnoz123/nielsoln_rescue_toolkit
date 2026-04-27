"""
m05_disk_health.py — Nielsoln Rescue Toolkit: disk health assessment via S.M.A.R.T.

Reads live hardware — identifies all block devices, collects SMART data, and
highlights critical indicators (reallocated sectors, pending sectors,
uncorrectable errors, power-on hours, temperature, SSD wear).

This module reads live hardware — not the mounted Windows installation.
No --target argument is needed or accepted.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m05_disk_health

Output:
    Prints a formatted report to stdout.
    Writes a JSON summary to <USB>/logs/disk_health_<timestamp>.json
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("disk_health")

DESCRIPTION = (
    "Disk health: S.M.A.R.T. assessment for all block devices — reallocated "
    "sectors, pending sectors, uncorrectable errors, power-on hours, "
    "temperature, SSD wear (live hardware — no --target needed)"
)

# ---------------------------------------------------------------------------
# SMART attribute IDs we care about
# ---------------------------------------------------------------------------

_CRITICAL_ATTRS = {
    "5":   "Reallocated_Sector_Ct",
    "10":  "Spin_Retry_Count",
    "184": "End-to-End_Error",
    "187": "Reported_Uncorrect",
    "188": "Command_Timeout",
    "196": "Reallocated_Event_Count",
    "197": "Current_Pending_Sector",
    "198": "Offline_Uncorrectable",
    "199": "UDMA_CRC_Error_Count",
}

_INFO_ATTRS = {
    "9":   "Power_On_Hours",
    "190": "Airflow_Temperature_Cel",
    "194": "Temperature_Celsius",
    "231": "SSD_Life_Left",
    "232": "Available_Reservd_Space",
    "233": "Media_Wearout_Indicator",
    "177": "Wear_Leveling_Count",
    "173": "Erase_Fail_Count_Chip",
}


def _run(cmd: list[str]) -> tuple[int, str]:
    """Run a command; return (returncode, stdout+stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        return r.returncode, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        return -1, f"command not found: {cmd[0]}"
    except Exception as exc:
        return -1, str(exc)


def _read(path: str | Path, default: str = "") -> str:
    try:
        return Path(path).read_text(errors="replace").strip()
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Device enumeration
# ---------------------------------------------------------------------------

def _enumerate_devices() -> list[str]:
    """Return real block device names (sda, nvme0, mmcblk0, etc.) — no partitions."""
    block = Path("/sys/block")
    if not block.exists():
        return []
    devices = []
    for dev in sorted(block.iterdir()):
        name = dev.name
        if re.match(r"^(loop|ram|dm|sr|fd|nbd)", name):
            continue
        # Skip partition-like names (sda1, nvme0n1p1, etc.)
        if re.search(r"p\d+$", name) or re.search(r"\d+$", name) and not re.match(r"^(nvme|mmcblk|sd[a-z]+$)", name):
            continue
        devices.append(name)
    return devices


def _device_basics(name: str) -> dict:
    """Size, rotational, model from sysfs."""
    dev = Path("/sys/block") / name
    size_sectors = _read(dev / "size", "0")
    try:
        size_bytes = int(size_sectors) * 512
    except ValueError:
        size_bytes = 0
    rotational = _read(dev / "queue" / "rotational", "unknown")
    model = _read(dev / "device" / "model",
                  _read(dev / "device" / "name", "unknown")).strip()

    dev_type = "unknown"
    if name.startswith("nvme"):
        dev_type = "NVMe SSD"
    elif name.startswith("mmc"):
        dev_type = "eMMC/SD"
    elif rotational == "1":
        dev_type = "HDD"
    elif rotational == "0":
        dev_type = "SSD"

    return {
        "device": f"/dev/{name}",
        "model": model,
        "type": dev_type,
        "size_gib": round(size_bytes / (1024 ** 3), 1),
    }


# ---------------------------------------------------------------------------
# SMART collection
# ---------------------------------------------------------------------------

def _parse_smart_attributes(output: str) -> dict[str, dict]:
    """Parse `smartctl -A` tabular output into {id: {name, value, raw}}."""
    attrs = {}
    in_table = False
    for line in output.splitlines():
        if re.match(r"\s*ID#\s+ATTRIBUTE_NAME", line):
            in_table = True
            continue
        if not in_table:
            continue
        m = re.match(
            r"\s*(\d+)\s+(\S+)\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(\S+)",
            line
        )
        if m:
            attr_id, name, value, worst, thresh, raw = m.groups()
            attrs[attr_id] = {
                "name": name,
                "value": int(value),
                "worst": int(worst),
                "thresh": int(thresh),
                "raw": raw,
            }
    return attrs


def _parse_nvme_health(output: str) -> dict[str, str]:
    """Parse `smartctl -A` NVMe output (key: value lines)."""
    result = {}
    for line in output.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip()] = v.strip()
    return result


def _assess_device(name: str) -> dict:
    basics = _device_basics(name)
    dev_path = f"/dev/{name}"
    result = dict(basics)
    result.update({
        "smart_available": False,
        "overall_health": "unknown",
        "overall_verdict": "unknown",
        "critical_findings": [],
        "info": {},
        "raw_smart": {},
        "recommendation": "",
        "clone_urgency": "none",
    })

    # --- Overall SMART health ---
    rc_h, out_h = _run(["smartctl", "-H", dev_path])
    if rc_h == -1:
        result["overall_verdict"] = "smartctl not available"
        result["recommendation"] = "Install smartmontools to assess disk health."
        return result

    result["smart_available"] = True

    if "PASSED" in out_h or "OK" in out_h:
        result["overall_health"] = "PASSED"
    elif "FAILED" in out_h:
        result["overall_health"] = "FAILED"
    else:
        result["overall_health"] = "unknown"

    # --- Detailed SMART attributes ---
    rc_a, out_a = _run(["smartctl", "-A", dev_path])
    is_nvme = name.startswith("nvme")

    if is_nvme:
        nvme = _parse_nvme_health(out_a)
        result["raw_smart"] = nvme

        # Extract key NVMe health indicators
        crit_warn = nvme.get("Critical Warning", "0x00")
        pct_used = nvme.get("Percentage Used", "unknown")
        avail = nvme.get("Available Spare", "unknown")
        temp = nvme.get("Temperature", "unknown")
        unsafe = nvme.get("Unsafe Shutdowns", "unknown")
        result["info"] = {
            "temperature": temp,
            "percentage_used": pct_used,
            "available_spare": avail,
            "unsafe_shutdowns": unsafe,
        }
        if crit_warn not in ("0x00", "0", "unknown", ""):
            result["critical_findings"].append(
                f"Critical Warning: {crit_warn}"
            )
        try:
            if int(pct_used.rstrip("%")) >= 90:
                result["critical_findings"].append(
                    f"NVMe wear at {pct_used} — approaching end of life"
                )
        except (ValueError, AttributeError):
            pass

    else:
        # Traditional ATA/SATA SMART
        attrs = _parse_smart_attributes(out_a)
        result["raw_smart"] = {k: v for k, v in attrs.items()}

        # Check critical attributes
        for attr_id, attr_name in _CRITICAL_ATTRS.items():
            if attr_id in attrs:
                a = attrs[attr_id]
                try:
                    raw_val = int(re.sub(r"[^\d]", "", a["raw"]))
                except (ValueError, TypeError):
                    raw_val = 0
                if raw_val > 0:
                    result["critical_findings"].append(
                        f"{a['name']} = {raw_val} (ID {attr_id})"
                    )

        # Info attributes
        for attr_id, attr_name in _INFO_ATTRS.items():
            if attr_id in attrs:
                a = attrs[attr_id]
                result["info"][a["name"]] = a["raw"]

    # --- Derive verdict ---
    findings = result["critical_findings"]
    health = result["overall_health"]

    if health == "FAILED" or any("Reallocated_Sector" in f or "Pending" in f or "Uncorrect" in f for f in findings):
        verdict = "FAILING"
        urgency = "immediate"
        rec = "Clone this drive immediately before further use. Data loss risk is high."
    elif findings:
        verdict = "CAUTION"
        urgency = "soon"
        rec = "Drive shows warning signs. Plan a clone soon and monitor closely."
    elif health == "PASSED":
        verdict = "HEALTHY"
        urgency = "none"
        rec = "No critical SMART errors detected."
    else:
        verdict = "unknown"
        urgency = "none"
        rec = "SMART data unavailable or inconclusive."

    # Flag USB sticks / removable media
    removable = _read(f"/sys/block/{name}/removable", "0")
    if removable == "1":
        result["note"] = "Removable device — SMART data may be unavailable or unreliable."

    result["overall_verdict"] = verdict
    result["recommendation"] = rec
    result["clone_urgency"] = urgency
    return result


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def _verdict_icon(verdict: str) -> str:
    return {"HEALTHY": "OK ", "CAUTION": "!! ", "FAILING": "!!!",
            "unknown": "?  "}.get(verdict, "?  ")


def _fmt_report(devices: list[dict]) -> str:
    lines = [
        "=" * 58,
        "  DISK HEALTH ASSESSMENT",
        "=" * 58,
    ]
    for d in devices:
        icon = _verdict_icon(d["overall_verdict"])
        lines.append(
            f"\n  [{icon}] {d['device']}  {d['type']:10s}  "
            f"{d['size_gib']:6.1f} GiB  {d['model']}"
        )
        if not d["smart_available"]:
            lines.append(f"       SMART : {d['overall_verdict']}")
            lines.append(f"       Note  : {d['recommendation']}")
            continue

        lines.append(f"       SMART overall : {d['overall_health']}")
        lines.append(f"       Verdict       : {d['overall_verdict']}")

        if d.get("note"):
            lines.append(f"       Note          : {d['note']}")

        if d["info"]:
            for k, v in d["info"].items():
                lines.append(f"       {k:<28s}: {v}")

        if d["critical_findings"]:
            lines.append("       CRITICAL FINDINGS:")
            for f in d["critical_findings"]:
                lines.append(f"         * {f}")

        lines.append(f"       Recommendation: {d['recommendation']}")
        if d["clone_urgency"] not in ("none", ""):
            lines.append(f"       Clone urgency : {d['clone_urgency'].upper()}")

    lines += ["", "=" * 58]

    # Summary line
    failing = [d for d in devices if d["overall_verdict"] == "FAILING"]
    caution = [d for d in devices if d["overall_verdict"] == "CAUTION"]
    healthy = [d for d in devices if d["overall_verdict"] == "HEALTHY"]
    lines.append(
        f"  Summary: {len(healthy)} healthy  {len(caution)} caution  "
        f"{len(failing)} FAILING  ({len(devices)} devices total)"
    )
    if failing:
        lines.append("  *** CLONE IMMEDIATELY: " +
                     ", ".join(d["device"] for d in failing) + " ***")
    lines.append("=" * 58)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    """Module protocol entry point — called by `bootstrap run m05_disk_health`."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    _log.info("Assessing disk health …")

    device_names = _enumerate_devices()
    if not device_names:
        print("No block devices found.")
        return 1

    results = []
    for name in device_names:
        _log.info("Checking /dev/%s …", name)
        results.append(_assess_device(name))

    print(_fmt_report(results))

    # Write JSON
    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"disk_health_{ts}.json"
    out_path.write_text(json.dumps(results, indent=2))
    _log.info("Report written to %s", out_path)

    # Return non-zero if any drive is failing
    return 1 if any(d["overall_verdict"] == "FAILING" for d in results) else 0
