"""m44_performance_diagnosis — Cross-module performance diagnosis.

Correlates hardware facts (CPU, RAM, disk type, disk space, thermal) with
Windows-side data (startup entries, service count, installed software, pagefile)
to answer: "why is this machine slow?" and "what gives the best improvement?"

Data sources:
  /proc/cpuinfo     — live CPU (same hardware as target)
  /proc/meminfo     — live RAM
  os.statvfs        — target disk space (NTFS partition)
  lsblk (optional)  — SSD vs HDD detection
  SOFTWARE hive     — startup entries (Run/RunOnce), installed software count
  SYSTEM hive       — non-Microsoft services count
  pagefile.sys      — presence and size on target

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m44_performance_diagnosis -- --target /mnt/windows

Output:
    logs/performance_diagnosis_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DESCRIPTION = (
    "Performance diagnosis: correlates RAM, disk type/space, CPU, startup entries, "
    "services, pagefile → why is it slow? what helps most?"
)

# ---------------------------------------------------------------------------
# Minimal REGF hive parser (shared pattern — see m33/m35/m36/m37)
# ---------------------------------------------------------------------------

_HIVE_BINS_OFFSET = 0x1000


class _RegHive:
    __slots__ = ("_data", "_root_offset")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._root_offset: int = struct.unpack_from("<I", data, 0x24)[0]

    def _cell(self, offset: int) -> Optional[memoryview]:
        if offset == 0xFFFFFFFF or offset < 0:
            return None
        file_off = _HIVE_BINS_OFFSET + offset
        if file_off + 4 > len(self._data):
            return None
        raw_size = struct.unpack_from("<i", self._data, file_off)[0]
        if raw_size >= 0:
            return None
        body_len = (-raw_size) - 4
        if body_len <= 0 or file_off + 4 + body_len > len(self._data):
            return None
        return memoryview(self._data)[file_off + 4: file_off + 4 + body_len]

    def _str_at(self, abs_offset: int, length: int, is_ascii: bool) -> str:
        if abs_offset + length > len(self._data):
            return ""
        raw = bytes(self._data[abs_offset: abs_offset + length])
        enc = "ascii" if is_ascii else "utf-16-le"
        return raw.decode(enc, errors="replace").rstrip("\x00")

    def _nk_info(self, offset: int) -> Optional[dict]:
        cell = self._cell(offset)
        if cell is None or len(cell) < 0x50 or bytes(cell[0:2]) != b"nk":
            return None
        flags           = struct.unpack_from("<H", cell, 2)[0]
        subkeys_count   = struct.unpack_from("<I", cell, 0x14)[0]
        subkeys_offset  = struct.unpack_from("<I", cell, 0x1C)[0]
        values_count    = struct.unpack_from("<I", cell, 0x24)[0]
        values_list_off = struct.unpack_from("<I", cell, 0x28)[0]
        name_length     = struct.unpack_from("<H", cell, 0x48)[0]
        is_ascii        = bool(flags & 0x0020)
        abs_name_off    = _HIVE_BINS_OFFSET + offset + 4 + 0x4C
        name = self._str_at(abs_name_off, name_length, is_ascii)
        return {
            "name": name,
            "subkeys_count": subkeys_count,
            "subkeys_offset": subkeys_offset,
            "values_count": values_count,
            "values_list_offset": values_list_off,
        }

    def _subkey_offsets(self, list_offset: int) -> List[int]:
        if list_offset == 0xFFFFFFFF:
            return []
        cell = self._cell(list_offset)
        if cell is None or len(cell) < 4:
            return []
        sig   = bytes(cell[0:2])
        count = struct.unpack_from("<H", cell, 2)[0]
        offsets: List[int] = []
        try:
            if sig in (b"lf", b"lh"):
                for i in range(count):
                    pos = 4 + i * 8
                    if pos + 4 > len(cell): break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"li":
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 > len(cell): break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"ri":
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 > len(cell): break
                    sub_off = struct.unpack_from("<I", cell, pos)[0]
                    offsets.extend(self._subkey_offsets(sub_off))
        except Exception:
            pass
        return offsets

    def _find_subkey_offset(self, parent_offset: int, name: str) -> Optional[int]:
        nk = self._nk_info(parent_offset)
        if nk is None:
            return None
        name_lower = name.lower()
        for sub_off in self._subkey_offsets(nk["subkeys_offset"]):
            sub_nk = self._nk_info(sub_off)
            if sub_nk and sub_nk["name"].lower() == name_lower:
                return sub_off
        return None

    def get_key_offset(self, path: str) -> Optional[int]:
        parts = [p for p in path.split("\\") if p]
        current = self._root_offset
        for part in parts:
            found = self._find_subkey_offset(current, part)
            if found is None:
                return None
            current = found
        return current

    def list_subkey_names(self, key_offset: int) -> List[str]:
        nk = self._nk_info(key_offset)
        if nk is None:
            return []
        names: List[str] = []
        for sub_off in self._subkey_offsets(nk["subkeys_offset"]):
            sub_nk = self._nk_info(sub_off)
            if sub_nk:
                names.append(sub_nk["name"])
        return names

    def get_subkey_offset(self, key_offset: int, name: str) -> Optional[int]:
        return self._find_subkey_offset(key_offset, name)

    def list_values(self, key_offset: int) -> List[tuple]:
        nk = self._nk_info(key_offset)
        if nk is None or nk["values_count"] == 0 or nk["values_list_offset"] == 0xFFFFFFFF:
            return []
        vlist_cell = self._cell(nk["values_list_offset"])
        if vlist_cell is None:
            return []
        results: List[tuple] = []
        for i in range(nk["values_count"]):
            pos = i * 4
            if pos + 4 > len(vlist_cell): break
            try:
                vk_off = struct.unpack_from("<I", vlist_cell, pos)[0]
                val = self._read_vk(vk_off)
                if val is not None:
                    results.append(val)
            except Exception:
                pass
        return results

    def _read_vk(self, offset: int) -> Optional[tuple]:
        cell = self._cell(offset)
        if cell is None or len(cell) < 0x18 or bytes(cell[0:2]) != b"vk":
            return None
        name_length   = struct.unpack_from("<H", cell, 2)[0]
        data_size_raw = struct.unpack_from("<I", cell, 4)[0]
        data_offset   = struct.unpack_from("<I", cell, 8)[0]
        data_type     = struct.unpack_from("<I", cell, 12)[0]
        flags         = struct.unpack_from("<H", cell, 16)[0]
        is_ascii      = bool(flags & 0x0001)
        name = ""
        if name_length > 0:
            abs_name = _HIVE_BINS_OFFSET + offset + 4 + 0x14
            name = self._str_at(abs_name, name_length, is_ascii)
        inline      = bool(data_size_raw & 0x80000000)
        actual_size = data_size_raw & 0x7FFFFFFF
        try:
            if inline:
                raw = struct.pack("<I", data_offset)[:actual_size]
            else:
                data_cell = self._cell(data_offset)
                if data_cell is None:
                    return (name, data_type, None)
                raw = bytes(data_cell[:actual_size])
            return (name, data_type, _decode_value(data_type, raw))
        except Exception:
            return (name, data_type, None)


def _decode_value(data_type: int, raw: bytes) -> Any:
    if data_type in (1, 2):
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    if data_type == 4:
        return struct.unpack_from("<I", raw)[0] if len(raw) >= 4 else 0
    if data_type == 7:
        text = raw.decode("utf-16-le", errors="replace")
        return [s for s in text.split("\x00") if s]
    return raw.hex() if isinstance(raw, (bytes, bytearray)) else raw


def _open_hive(path: Path) -> Optional[_RegHive]:
    try:
        data = path.read_bytes()
        if len(data) < 0x1000 or data[:4] != b"regf":
            return None
        return _RegHive(data)
    except Exception:
        return None


def _values_dict(hive: _RegHive, key_offset: int) -> dict:
    return {name: data for name, _dtype, data in hive.list_values(key_offset)}


# ---------------------------------------------------------------------------
# Hardware probes (Linux /proc — available on RescueZilla)
# ---------------------------------------------------------------------------

def _read_cpu_info() -> dict:
    """Parse /proc/cpuinfo.  Returns first-processor summary."""
    result: dict = {"model": None, "cores": 0, "mhz": None}
    try:
        text  = Path("/proc/cpuinfo").read_text(errors="replace")
        procs = text.split("\n\n")
        for block in procs:
            for line in block.splitlines():
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if key == "model name" and result["model"] is None:
                    result["model"] = val
                elif key == "cpu mhz" and result["mhz"] is None:
                    try:
                        result["mhz"] = float(val)
                    except ValueError:
                        pass
        # Count physical cores
        result["cores"] = text.count("processor\t:")
        if result["cores"] == 0:
            result["cores"] = text.lower().count("\nprocessor")
    except Exception:
        pass
    return result


def _read_mem_info() -> dict:
    """Parse /proc/meminfo.  Returns total and free in MB."""
    result: dict = {"total_mb": None, "free_mb": None}
    try:
        text = Path("/proc/meminfo").read_text(errors="replace")
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip()
            kb_str = val.strip().split()[0]
            try:
                kb = int(kb_str)
            except ValueError:
                continue
            if key == "MemTotal":
                result["total_mb"] = kb // 1024
            elif key == "MemFree":
                result["free_mb"] = kb // 1024
    except Exception:
        pass
    return result


def _detect_disk_type(target: Path) -> Optional[str]:
    """Return 'SSD', 'HDD', or None by inspecting lsblk rotational flag."""
    try:
        # Find source device for the target mount
        out = subprocess.check_output(
            ["findmnt", "--output", "SOURCE", "--noheadings", str(target)],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode().strip()
        if not out:
            return None
        # Strip partition number to get disk name: /dev/sda1 → sda
        dev = re.sub(r"^/dev/", "", out)
        dev = re.sub(r"\d+$", "", dev)
        rota_path = Path(f"/sys/block/{dev}/queue/rotational")
        if rota_path.exists():
            rota = rota_path.read_text().strip()
            return "HDD" if rota == "1" else "SSD"
    except Exception:
        pass
    return None


def _read_disk_space(target: Path) -> dict:
    """Return total/free/used GB and percent used for the target partition."""
    result: dict = {"total_gb": None, "free_gb": None, "used_pct": None}
    try:
        st = os.statvfs(str(target))
        block_size = st.f_frsize
        total = st.f_blocks * block_size
        free  = st.f_bavail * block_size
        used  = total - free
        result["total_gb"] = round(total / (1024 ** 3), 1)
        result["free_gb"]  = round(free  / (1024 ** 3), 1)
        if total > 0:
            result["used_pct"] = round(used / total * 100, 1)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Windows-side probes
# ---------------------------------------------------------------------------

def _read_startup_items(target: Path) -> List[str]:
    """Read HKLM Run + RunOnce startup entries from SOFTWARE hive."""
    items: List[str] = []
    sw_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    hive = _open_hive(sw_path)
    if hive is None:
        return items
    for key_path in (
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    ):
        off = hive.get_key_offset(key_path)
        if off is None:
            continue
        for name, _dtype, data in hive.list_values(off):
            if isinstance(data, str) and data.strip():
                items.append(f"{key_path}\\{name} = {data[:120]}")
    return items


def _count_installed_software(target: Path) -> int:
    sw_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    hive = _open_hive(sw_path)
    if hive is None:
        return 0
    uninstall_path = "Microsoft\\Windows\\CurrentVersion\\Uninstall"
    off = hive.get_key_offset(uninstall_path)
    if off is None:
        return 0
    return len(hive.list_subkey_names(off))


def _count_non_microsoft_services(target: Path) -> int:
    sys_path = target / "Windows" / "System32" / "config" / "SYSTEM"
    hive = _open_hive(sys_path)
    if hive is None:
        return 0
    # Try ControlSet001 then CurrentControlSet
    for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
        off = hive.get_key_offset(f"{cs}\\Services")
        if off is not None:
            break
    else:
        return 0
    count = 0
    for svc_name in hive.list_subkey_names(off):
        svc_off = hive.get_subkey_offset(off, svc_name)
        if svc_off is None:
            continue
        vals = _values_dict(hive, svc_off)
        image = (vals.get("ImagePath") or "").lower()
        # Non-Microsoft = not in system32 or sysWOW64 (rough heuristic)
        if image and "system32" not in image and "syswow64" not in image:
            count += 1
    return count


def _pagefile_info(target: Path) -> dict:
    """Check for pagefile.sys presence and size."""
    pf = target / "pagefile.sys"
    result: dict = {"present": False, "size_mb": None}
    if pf.exists():
        result["present"] = True
        try:
            result["size_mb"] = round(pf.stat().st_size / (1024 * 1024), 1)
        except OSError:
            pass
    return result


# ---------------------------------------------------------------------------
# Recommendation engine
# ---------------------------------------------------------------------------

def _build_factors_and_recommendations(
    cpu: dict,
    mem: dict,
    disk_space: dict,
    disk_type: Optional[str],
    startup_count: int,
    svc_count: int,
    sw_count: int,
    pagefile: dict,
) -> tuple:
    """Return (factors: List[dict], recommendations: List[dict], verdict: str)."""
    factors: List[dict] = []
    recs:    List[dict] = []

    # --- RAM ---
    ram_mb = mem.get("total_mb")
    if ram_mb is not None:
        if ram_mb < 512:
            factors.append({"factor": "ram", "value": f"{ram_mb} MB", "severity": "critical",
                             "detail": "Less than 512 MB RAM — Vista minimum is 512 MB"})
            recs.append({"priority": 1, "action": "Upgrade RAM",
                         "detail": f"Current: {ram_mb} MB. Vista performs poorly below 1 GB. "
                                   "Upgrade to 2 GB if the motherboard supports it.",
                         "impact": "very_high"})
        elif ram_mb < 1024:
            factors.append({"factor": "ram", "value": f"{ram_mb} MB", "severity": "poor",
                             "detail": "Less than 1 GB RAM — severe for Vista"})
            recs.append({"priority": 2, "action": "Upgrade RAM",
                         "detail": f"Current: {ram_mb} MB. 2 GB is the practical minimum for Vista.",
                         "impact": "high"})
        elif ram_mb < 2048:
            factors.append({"factor": "ram", "value": f"{ram_mb} MB", "severity": "fair",
                             "detail": "1–2 GB RAM — acceptable but limited for multi-tasking"})
        else:
            factors.append({"factor": "ram", "value": f"{ram_mb} MB", "severity": "ok",
                             "detail": "Adequate RAM for Vista"})

    # --- Disk type ---
    if disk_type == "HDD":
        factors.append({"factor": "disk_type", "value": "HDD", "severity": "poor",
                         "detail": "Spinning hard disk — the biggest single cause of slowness on Vista-era laptops"})
        recs.append({"priority": 1, "action": "Replace HDD with SSD",
                     "detail": "Replacing the mechanical hard disk with an SSD is the single biggest "
                               "performance improvement possible on this hardware.",
                     "impact": "very_high"})
    elif disk_type == "SSD":
        factors.append({"factor": "disk_type", "value": "SSD", "severity": "ok",
                         "detail": "SSD detected — good"})
    else:
        factors.append({"factor": "disk_type", "value": "unknown", "severity": "unknown",
                         "detail": "Could not detect disk type (SSD or HDD)"})

    # --- Disk space ---
    free_gb  = disk_space.get("free_gb")
    used_pct = disk_space.get("used_pct")
    total_gb = disk_space.get("total_gb")
    if used_pct is not None:
        if used_pct >= 95:
            factors.append({"factor": "disk_space", "value": f"{used_pct}% used ({free_gb} GB free)",
                             "severity": "critical",
                             "detail": "Disk nearly full — Windows needs free space for Virtual Memory and temp files"})
            recs.append({"priority": 2, "action": "Free disk space immediately",
                         "detail": f"Only {free_gb} GB free on {total_gb} GB disk. "
                                   "Windows needs 10–15% free space for pagefile and temp files.",
                         "impact": "very_high"})
        elif used_pct >= 85:
            factors.append({"factor": "disk_space", "value": f"{used_pct}% used ({free_gb} GB free)",
                             "severity": "poor",
                             "detail": "Disk over 85% full — limited room for Virtual Memory"})
            recs.append({"priority": 3, "action": "Free disk space",
                         "detail": f"{used_pct}% of {total_gb} GB used. Consider removing unused programs or files.",
                         "impact": "medium"})
        else:
            factors.append({"factor": "disk_space",
                             "value": f"{used_pct}% used ({free_gb} GB free)", "severity": "ok",
                             "detail": "Adequate free disk space"})

    # --- Pagefile ---
    if not pagefile.get("present"):
        factors.append({"factor": "pagefile", "value": "absent", "severity": "poor",
                         "detail": "No pagefile.sys found — Virtual Memory may be disabled or redirected"})
        recs.append({"priority": 3, "action": "Check Virtual Memory settings",
                     "detail": "pagefile.sys not found on the Windows partition. "
                               "Virtual Memory should normally be enabled.",
                     "impact": "medium"})
    else:
        pf_mb = pagefile.get("size_mb")
        if pf_mb and pf_mb < 512:
            factors.append({"factor": "pagefile", "value": f"{pf_mb} MB", "severity": "fair",
                             "detail": "Pagefile present but very small"})
        else:
            factors.append({"factor": "pagefile",
                             "value": f"{pagefile.get('size_mb', '?')} MB", "severity": "ok",
                             "detail": "Pagefile present"})

    # --- CPU ---
    mhz = cpu.get("mhz")
    cores = cpu.get("cores", 0)
    model = cpu.get("model") or "unknown"
    if mhz is not None:
        if mhz < 800:
            factors.append({"factor": "cpu", "value": f"{mhz:.0f} MHz, {cores} core(s): {model}",
                             "severity": "critical",
                             "detail": "Very slow CPU — below 800 MHz"})
        elif mhz < 1200:
            factors.append({"factor": "cpu", "value": f"{mhz:.0f} MHz, {cores} core(s): {model}",
                             "severity": "poor",
                             "detail": "Slow CPU — under 1.2 GHz"})
        elif cores == 1:
            factors.append({"factor": "cpu", "value": f"{mhz:.0f} MHz, single-core: {model}",
                             "severity": "fair",
                             "detail": "Single-core CPU — multi-tab browsing will feel sluggish"})
        else:
            factors.append({"factor": "cpu", "value": f"{mhz:.0f} MHz, {cores} core(s): {model}",
                             "severity": "ok",
                             "detail": "Adequate CPU for Vista-era workload"})

    # --- Startup items ---
    if startup_count > 15:
        factors.append({"factor": "startup_items", "value": str(startup_count), "severity": "poor",
                         "detail": f"{startup_count} startup entries slow boot significantly"})
        recs.append({"priority": 4, "action": "Reduce startup programs",
                     "detail": f"{startup_count} programs registered to run at startup. "
                               "Disable unnecessary ones via msconfig or Task Manager.",
                     "impact": "medium"})
    elif startup_count > 8:
        factors.append({"factor": "startup_items", "value": str(startup_count), "severity": "fair",
                         "detail": f"{startup_count} startup entries"})
    else:
        factors.append({"factor": "startup_items", "value": str(startup_count), "severity": "ok",
                         "detail": "Reasonable number of startup entries"})

    # --- Non-Microsoft services ---
    if svc_count > 20:
        factors.append({"factor": "third_party_services", "value": str(svc_count), "severity": "fair",
                         "detail": f"{svc_count} non-system services may add background CPU/memory load"})

    # --- Software count ---
    if sw_count > 60:
        factors.append({"factor": "installed_software", "value": str(sw_count), "severity": "fair",
                         "detail": f"{sw_count} installed programs — consider reviewing for bloatware"})
        recs.append({"priority": 5, "action": "Review installed software",
                     "detail": f"{sw_count} programs installed. Removing unused software frees disk and may "
                               "reduce startup/service load.",
                     "impact": "low"})

    # --- Derive verdict ---
    severities = [f["severity"] for f in factors]
    if "critical" in severities:
        verdict = "CRITICAL"
    elif severities.count("poor") >= 2:
        verdict = "POOR"
    elif "poor" in severities:
        verdict = "FAIR"
    elif "fair" in severities:
        verdict = "FAIR"
    else:
        verdict = "GOOD"

    recs.sort(key=lambda r: r.get("priority", 99))
    return factors, recs, verdict


# ---------------------------------------------------------------------------
# Analysis entry
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    limitations: List[str] = []

    cpu        = _read_cpu_info()
    mem        = _read_mem_info()
    disk_space = _read_disk_space(target)
    disk_type  = _detect_disk_type(target)
    pagefile   = _pagefile_info(target)

    if cpu["cores"] == 0:
        limitations.append("/proc/cpuinfo not available (not running on Linux)")
    if mem["total_mb"] is None:
        limitations.append("/proc/meminfo not available (not running on Linux)")
    if disk_space["total_gb"] is None:
        limitations.append("Could not read disk space via statvfs")
    if disk_type is None:
        limitations.append("Could not detect disk type (SSD/HDD) — lsblk/findmnt unavailable")

    startup_items = _read_startup_items(target)
    sw_count      = _count_installed_software(target)
    svc_count     = _count_non_microsoft_services(target)

    factors, recs, verdict = _build_factors_and_recommendations(
        cpu, mem, disk_space, disk_type,
        len(startup_items), svc_count, sw_count, pagefile,
    )

    return {
        "scan_status": "ok",
        "verdict":     verdict,
        "hardware": {
            "cpu_model":      cpu.get("model"),
            "cpu_cores":      cpu.get("cores"),
            "cpu_mhz":        cpu.get("mhz"),
            "ram_mb":         mem.get("total_mb"),
            "disk_type":      disk_type,
            "disk_total_gb":  disk_space.get("total_gb"),
            "disk_free_gb":   disk_space.get("free_gb"),
            "disk_used_pct":  disk_space.get("used_pct"),
            "pagefile_mb":    pagefile.get("size_mb"),
        },
        "windows": {
            "startup_item_count":           len(startup_items),
            "startup_items":                startup_items,
            "installed_software_count":     sw_count,
            "non_microsoft_service_count":  svc_count,
            "pagefile_present":             pagefile.get("present"),
        },
        "performance_factors": factors,
        "recommendations":     recs,
        "limitations":         limitations,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

_VERDICT_ICON = {"GOOD": "OK", "FAIR": "FAIR", "POOR": "POOR", "CRITICAL": "!!"}

def _print_report(data: dict) -> None:
    print("\n=== PERFORMANCE DIAGNOSIS ===")
    icon = _VERDICT_ICON.get(data.get("verdict", ""), "?")
    print(f"Verdict  : [{icon}] {data.get('verdict')}")

    hw = data.get("hardware", {})
    print(f"\nHardware:")
    print(f"  CPU  : {hw.get('cpu_model', 'unknown')}  "
          f"({hw.get('cpu_cores', '?')} core(s), {hw.get('cpu_mhz', '?')} MHz)")
    print(f"  RAM  : {hw.get('ram_mb', '?')} MB")
    dt = hw.get("disk_type") or "unknown"
    print(f"  Disk : {dt}  {hw.get('disk_total_gb', '?')} GB total  "
          f"{hw.get('disk_free_gb', '?')} GB free  ({hw.get('disk_used_pct', '?')}% used)")
    print(f"  Page : {hw.get('pagefile_mb', 'absent')} MB pagefile")

    print("\nPerformance factors:")
    for f in data.get("performance_factors", []):
        sev = f.get("severity", "?").upper()
        print(f"  [{sev:8}]  {f.get('factor', '?'):22}  {f.get('value', '')}  — {f.get('detail', '')}")

    recs = data.get("recommendations", [])
    if recs:
        print("\nRecommendations (by priority):")
        for i, r in enumerate(recs, 1):
            print(f"  {i}. [{r.get('impact', '?').upper():9}]  {r.get('action')}")
            print(f"          {r.get('detail', '')[:100]}")

    ww = data.get("windows", {})
    print(f"\nWindows:")
    print(f"  Startup items   : {ww.get('startup_item_count', 0)}")
    print(f"  Installed apps  : {ww.get('installed_software_count', 0)}")
    print(f"  3rd-party svcs  : {ww.get('non_microsoft_service_count', 0)}")

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
        prog="m44_performance_diagnosis",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="",
                        help="Mounted Windows partition path (auto-detect if omitted)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m44] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    print(f"[m44] Running performance diagnosis against {target_path} ...")
    data = analyse(target_path)

    from datetime import datetime as _dt, timezone as _tz
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"performance_diagnosis_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m44] Log written: {out_path}")

    verdict = data.get("verdict", "GOOD")
    return 0 if verdict in ("GOOD", "FAIR") else 1
