"""
m04_hardware_profile.py — Nielsoln Rescue Toolkit: hardware profile of the rescue machine.

Reads DMI/SMBIOS, /proc/cpuinfo, /sys/class/ and related Linux interfaces to
produce a structured hardware inventory of the *physical machine* being worked on.

This module reads live hardware — not the mounted Windows installation.
No --target argument is needed or accepted.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m04_hardware_profile

Output:
    Prints a formatted report to stdout.
    Writes a JSON summary to <USB>/logs/hardware_profile_<timestamp>.json
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("hw_profile")

DESCRIPTION = (
    "Hardware profile: DMI/SMBIOS, CPU, RAM, storage devices, GPU, network, "
    "boot mode, and upgrade path (live hardware — no --target needed)"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path: str | Path, default: str = "unknown") -> str:
    """Read a sysfs/procfs file, return stripped text or default."""
    try:
        return Path(path).read_text(errors="replace").strip()
    except Exception:
        return default


def _dmi(field: str) -> str:
    """Read a single DMI field from /sys/class/dmi/id/."""
    return _read(f"/sys/class/dmi/id/{field}")


def _run(cmd: list[str]) -> str:
    """Run a command, return stdout; return '' on any error."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Individual collectors
# ---------------------------------------------------------------------------

def _collect_system() -> dict:
    return {
        "manufacturer":  _dmi("sys_vendor"),
        "product_name":  _dmi("product_name"),
        "product_version": _dmi("product_version"),
        "serial_number": _dmi("product_serial"),
        "chassis_type":  _dmi("chassis_type"),
    }


def _form_factor(chassis_type: str) -> str:
    """Map DMI chassis type code to a human-readable form factor."""
    # DMI chassis types: 1=Other, 3=Desktop, 8=Portable, 9=Laptop, 10=Notebook,
    # 11=Hand Held, 14=Sub Notebook, 30=Tablet, 31=Convertible, 32=Detachable
    laptop_types = {"8", "9", "10", "11", "14", "30", "31", "32"}
    desktop_types = {"3", "4", "5", "6", "7", "13", "15", "16", "24", "25"}
    if chassis_type in laptop_types:
        return "laptop"
    if chassis_type in desktop_types:
        return "desktop"
    return "unknown"


def _collect_bios() -> dict:
    return {
        "vendor":  _dmi("bios_vendor"),
        "version": _dmi("bios_version"),
        "date":    _dmi("bios_date"),
    }


def _collect_boot_mode() -> str:
    """UEFI if /sys/firmware/efi exists, otherwise BIOS/Legacy."""
    return "UEFI" if Path("/sys/firmware/efi").exists() else "BIOS/Legacy"


def _collect_cpu() -> dict:
    raw = _read("/proc/cpuinfo")
    model = "unknown"
    physical_cores = 0
    logical_cores = 0
    arch = _run(["uname", "-m"])

    seen_physical = set()
    for block in raw.split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                fields[k.strip()] = v.strip()
        if "model name" in fields:
            model = fields["model name"]
        if "physical id" in fields:
            seen_physical.add(fields["physical id"])
        if "processor" in fields:
            logical_cores += 1
        if "cpu cores" in fields:
            try:
                physical_cores = max(physical_cores, int(fields["cpu cores"]))
            except ValueError:
                pass

    # For single-socket systems, "cpu cores" * sockets = physical
    sockets = max(len(seen_physical), 1)
    if physical_cores == 0:
        physical_cores = logical_cores  # fallback if not reported

    return {
        "model": model,
        "architecture": arch or "unknown",
        "physical_cores": physical_cores * sockets,
        "logical_cores": logical_cores,
        "sockets": sockets,
    }


def _collect_ram() -> dict:
    meminfo = _read("/proc/meminfo")
    total_kb = 0
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            m = re.search(r"(\d+)", line)
            if m:
                total_kb = int(m.group(1))
            break
    total_mib = total_kb // 1024
    total_gib = round(total_mib / 1024, 1)

    # Try dmidecode for slot/type detail (may need root)
    dmi_out = _run(["dmidecode", "-t", "memory"])
    mem_type = "unknown"
    speed = "unknown"
    slots_populated = 0
    slots_total = 0
    if dmi_out:
        for line in dmi_out.splitlines():
            line = line.strip()
            if line.startswith("Type:") and "Unknown" not in line and "No Module" not in line:
                mem_type = line.split(":", 1)[1].strip()
            elif line.startswith("Speed:") and "Unknown" not in line:
                speed = line.split(":", 1)[1].strip()
            elif line.startswith("Size:"):
                val = line.split(":", 1)[1].strip()
                slots_total += 1
                if val and "No Module Installed" not in val and "Unknown" not in val:
                    slots_populated += 1

    return {
        "total_mib": total_mib,
        "total_gib": total_gib,
        "type": mem_type,
        "speed": speed,
        "slots_populated": slots_populated if slots_total > 0 else "unknown",
        "slots_total": slots_total if slots_total > 0 else "unknown",
    }


def _collect_storage() -> list[dict]:
    """Enumerate block devices from /sys/block/."""
    devices = []
    block_path = Path("/sys/block")
    if not block_path.exists():
        return devices

    for dev in sorted(block_path.iterdir()):
        name = dev.name
        # Skip loop devices, ram disks, dm devices
        if re.match(r"^(loop|ram|dm|sr|fd|nbd)", name):
            continue

        size_sectors = _read(dev / "size", "0")
        try:
            size_bytes = int(size_sectors) * 512
        except ValueError:
            size_bytes = 0
        size_gib = round(size_bytes / (1024 ** 3), 1)

        rotational = _read(dev / "queue" / "rotational", "unknown")
        model_str = _read(dev / "device" / "model", _read(dev / "device" / "name", "unknown"))

        # Determine interface/type
        dev_type = "unknown"
        if rotational == "1":
            dev_type = "HDD"
        elif rotational == "0":
            dev_type = "SSD"

        # Refine: NVMe
        if name.startswith("nvme"):
            dev_type = "NVMe SSD"
        # MMC (eMMC/SD)
        elif name.startswith("mmc"):
            dev_type = "eMMC/SD"

        # SMART summary via smartctl (best-effort)
        smart_status = "unknown"
        smart_out = _run(["smartctl", "-H", f"/dev/{name}"])
        if smart_out:
            if "PASSED" in smart_out or "OK" in smart_out:
                smart_status = "PASSED"
            elif "FAILED" in smart_out:
                smart_status = "FAILED"

        devices.append({
            "device": f"/dev/{name}",
            "model": model_str.strip(),
            "type": dev_type,
            "size_gib": size_gib,
            "smart_health": smart_status,
        })

    return devices


def _collect_gpu() -> list[str]:
    """List GPU(s) from lspci if available."""
    out = _run(["lspci"])
    gpus = []
    for line in out.splitlines():
        if re.search(r"VGA|3D controller|Display controller", line, re.IGNORECASE):
            # Strip the PCI address prefix
            desc = re.sub(r"^[\da-f:.]+\s+", "", line)
            gpus.append(desc.strip())
    return gpus if gpus else ["unknown"]


def _collect_network() -> list[str]:
    """List network interfaces from /sys/class/net/."""
    ifaces = []
    net_path = Path("/sys/class/net")
    if not net_path.exists():
        return ifaces
    for iface in sorted(net_path.iterdir()):
        name = iface.name
        if name == "lo":
            continue
        driver = _read(iface / "device" / "driver" / "module" / "description",
                       _read(iface / "device" / "uevent", ""))
        # Try a cleaner approach: read driver name from uevent
        uevent = _read(iface / "device" / "uevent", "")
        driver_name = ""
        for ev_line in uevent.splitlines():
            if ev_line.startswith("DRIVER="):
                driver_name = ev_line.split("=", 1)[1]
                break
        label = name if not driver_name else f"{name} ({driver_name})"
        ifaces.append(label)
    return ifaces if ifaces else ["none detected"]


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def _fmt_report(profile: dict) -> str:
    sys_info = profile["system"]
    cpu = profile["cpu"]
    ram = profile["ram"]
    bios = profile["bios"]

    lines = [
        "=" * 54,
        "  HARDWARE PROFILE",
        "=" * 54,
        f"  Manufacturer  : {sys_info['manufacturer']}",
        f"  Model         : {sys_info['product_name']}  {sys_info['product_version']}".rstrip(),
        f"  Serial        : {sys_info['serial_number']}",
        f"  Form factor   : {profile['form_factor']}",
        f"  Boot mode     : {profile['boot_mode']}",
        "",
        "  CPU",
        f"    {cpu['model']}",
        f"    Architecture : {cpu['architecture']}",
        f"    Cores        : {cpu['physical_cores']} physical / {cpu['logical_cores']} logical",
        "",
        "  RAM",
        f"    Installed    : {ram['total_gib']} GiB ({ram['total_mib']} MiB)",
        f"    Type / Speed : {ram['type']} / {ram['speed']}",
        f"    Slots        : {ram['slots_populated']} populated / {ram['slots_total']} total",
        "",
        "  STORAGE",
    ]
    for dev in profile["storage"]:
        smart = f"  SMART: {dev['smart_health']}" if dev["smart_health"] != "unknown" else ""
        lines.append(
            f"    {dev['device']:12s}  {dev['type']:10s}  {dev['size_gib']:6.1f} GiB"
            f"  {dev['model']}{smart}"
        )
    if not profile["storage"]:
        lines.append("    none detected")

    lines += [
        "",
        "  GPU",
    ]
    for g in profile["gpu"]:
        lines.append(f"    {g}")

    lines += [
        "",
        "  NETWORK",
    ]
    for n in profile["network"]:
        lines.append(f"    {n}")

    lines += [
        "",
        "  BIOS",
        f"    Vendor   : {bios['vendor']}",
        f"    Version  : {bios['version']}",
        f"    Date     : {bios['date']}",
        "=" * 54,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    """Module protocol entry point — called by `bootstrap run m04_hardware_profile`."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    _log.info("Collecting hardware profile …")

    sys_info = _collect_system()
    profile = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": sys_info,
        "form_factor": _form_factor(sys_info["chassis_type"]),
        "boot_mode": _collect_boot_mode(),
        "bios": _collect_bios(),
        "cpu": _collect_cpu(),
        "ram": _collect_ram(),
        "storage": _collect_storage(),
        "gpu": _collect_gpu(),
        "network": _collect_network(),
    }

    print(_fmt_report(profile))

    # Write JSON to USB logs/
    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"hardware_profile_{ts}.json"
    out_path.write_text(json.dumps(profile, indent=2))
    _log.info("Profile written to %s", out_path)

    return 0
