"""
m27_device_manager.py — Nielsoln Rescue Toolkit: offline Windows device inventory.

Reads the Windows SYSTEM registry hive (HKLM\\SYSTEM\\CurrentControlSet\\Enum)
to enumerate every device the OS has ever seen, together with its hardware IDs,
device class, driver information (version, provider, date), and problem code
(the "yellow bang" in Device Manager).

This is the offline equivalent of Device Manager — the only way to see broken
or missing drivers without booting the machine.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m27_device_manager -- --target /mnt/windows

Output:
    Prints a formatted report to stdout.
    Writes JSON to <USB>/logs/device_manager_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("m27_device_manager")

DESCRIPTION = (
    "Device manager: reads offline Windows SYSTEM hive (Enum tree) to list "
    "all hardware devices with driver version, provider, and problem codes "
    "(missing/broken drivers) — requires --target /mnt/windows"
)

# ---------------------------------------------------------------------------
# Windows CM_PROB_* device problem codes
# ---------------------------------------------------------------------------

_CM_PROB: dict[int, str] = {
    1:  "CM_PROB_NOT_CONFIGURED",
    3:  "CM_PROB_OUT_OF_MEMORY",
    10: "CM_PROB_FAILED_START",
    12: "CM_PROB_NORMAL_CONFLICT",
    14: "CM_PROB_NEED_RESTART",
    18: "CM_PROB_REINSTALL",
    19: "CM_PROB_REGISTRY",
    22: "CM_PROB_DISABLED",
    24: "CM_PROB_DEVICE_NOT_THERE",
    28: "CM_PROB_FAILED_INSTALL",
    29: "CM_PROB_HARDWARE_DISABLED",
    31: "CM_PROB_FAILED_ADD",
    32: "CM_PROB_DISABLED_SERVICE",
    34: "CM_PROB_INVALID_DATA",
    37: "CM_PROB_SYSTEM_SHUTDOWN",
    43: "CM_PROB_FAILED_POST_START",
    47: "CM_PROB_HELD_FOR_EJECT",
    48: "CM_PROB_DRIVER_BLOCKED",
    50: "CM_PROB_DRIVER_FAILED_LOAD",
    52: "CM_PROB_UNSIGNED_DRIVER",
}

# Device classes we want to highlight for driver issues
_IMPORTANT_CLASSES = {
    "Display", "Net", "HDC", "DiskDrive", "USB", "USBHUB",
    "SCSIAdapter", "AudioEndpoint", "Media", "Battery", "Bluetooth",
    "Modem", "Ports", "PrintQueue", "SmartCardReader", "WPD",
}

# ---------------------------------------------------------------------------
# Minimal offline registry reader (same pattern as m06/m26)
# ---------------------------------------------------------------------------

_REGF_MAGIC = b"regf"
_NK_MAGIC   = b"nk"
_VK_MAGIC   = b"vk"

_REG_SZ        = 1
_REG_EXPAND_SZ = 2
_REG_MULTI_SZ  = 7
_REG_DWORD     = 4
_REG_DWORD_BE  = 5
_REG_QWORD     = 11


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _s32(data: bytes, off: int) -> int:
    return struct.unpack_from("<i", data, off)[0]


class _Hive:
    """Lightweight read-only Windows registry hive parser (same impl as m26)."""

    def __init__(self, path: Path):
        self._data = path.read_bytes()
        if self._data[:4] != _REGF_MAGIC:
            raise ValueError(f"Not a registry hive: {path}")
        self._root_off = _u32(self._data, 0x24) + 0x1000

    def _abs(self, rel: int) -> int:
        return rel + 0x1000

    def _nk_at(self, abs_off: int):
        if abs_off + 0x58 > len(self._data):
            return None
        if self._data[abs_off + 4: abs_off + 6] != _NK_MAGIC:
            return None
        flags        = _u16(self._data, abs_off + 6)
        subkey_count = _u32(self._data, abs_off + 0x18)
        subkey_list  = _u32(self._data, abs_off + 0x20)
        value_count  = _u32(self._data, abs_off + 0x28)
        value_list   = _u32(self._data, abs_off + 0x2C)
        name_len     = _u16(self._data, abs_off + 0x4C)
        name_bytes   = self._data[abs_off + 0x50: abs_off + 0x50 + name_len]
        try:
            name = name_bytes.decode("ascii" if flags & 0x20 else "utf-16-le",
                                     errors="replace")
        except Exception:
            name = name_bytes.decode("latin-1", errors="replace")
        return {
            "name": name, "abs_off": abs_off,
            "subkey_count": subkey_count, "subkey_list": subkey_list,
            "value_count": value_count, "value_list": value_list,
        }

    def _iter_subkeys(self, nk: dict):
        if nk["subkey_count"] == 0 or nk["subkey_list"] == 0xFFFFFFFF:
            return
        list_abs = self._abs(nk["subkey_list"])
        if list_abs + 6 > len(self._data):
            return
        sig = self._data[list_abs + 4: list_abs + 6]
        if sig in (b"lf", b"lh"):
            count = _u16(self._data, list_abs + 6)
            for i in range(count):
                ea = list_abs + 8 + i * 8
                if ea + 4 > len(self._data):
                    break
                child = self._nk_at(self._abs(_u32(self._data, ea)))
                if child:
                    yield child
        elif sig in (b"ri", b"li"):
            count = _u16(self._data, list_abs + 6)
            for i in range(count):
                sub_abs = self._abs(_u32(self._data, list_abs + 8 + i * 4))
                if sub_abs + 6 > len(self._data):
                    break
                sub_sig = self._data[sub_abs + 4: sub_abs + 6]
                if sub_sig in (b"lf", b"lh"):
                    sub_count = _u16(self._data, sub_abs + 6)
                    for j in range(sub_count):
                        ea = sub_abs + 8 + j * 8
                        if ea + 4 > len(self._data):
                            break
                        child = self._nk_at(self._abs(_u32(self._data, ea)))
                        if child:
                            yield child

    def _open_key(self, nk: dict, parts: list[str]):
        if not parts:
            return nk
        want = parts[0].upper()
        for child in self._iter_subkeys(nk):
            if child["name"].upper() == want:
                return self._open_key(child, parts[1:])
        return None

    def open_key(self, path: str):
        root = self._nk_at(self._root_off)
        if root is None:
            return None
        parts = [p for p in path.replace("/", "\\").split("\\") if p]
        return self._open_key(root, parts) if parts else root

    def iter_subkeys(self, nk: dict):
        yield from self._iter_subkeys(nk)

    def _vk_at(self, abs_off: int):
        if abs_off + 0x18 > len(self._data):
            return None
        if self._data[abs_off + 4: abs_off + 6] != _VK_MAGIC:
            return None
        name_len  = _u16(self._data, abs_off + 6)
        data_len  = _u32(self._data, abs_off + 8)
        data_off  = _u32(self._data, abs_off + 0xC)
        data_type = _u32(self._data, abs_off + 0x10)
        name_flag = _u16(self._data, abs_off + 0x14)
        name_bytes = self._data[abs_off + 0x18: abs_off + 0x18 + name_len]
        try:
            name = name_bytes.decode("ascii" if name_flag & 1 else "utf-16-le",
                                     errors="replace")
        except Exception:
            name = name_bytes.decode("latin-1", errors="replace")
        return {"name": name, "data_len": data_len, "data_off": data_off, "data_type": data_type}

    def _read_value_data(self, vk: dict) -> bytes:
        raw_len = vk["data_len"]
        if raw_len & 0x80000000:
            actual_len = raw_len & 0x7FFFFFFF
            return struct.pack("<I", vk["data_off"])[:actual_len]
        data_abs = self._abs(vk["data_off"])
        if data_abs + 4 > len(self._data):
            return b""
        cell_size = abs(_s32(self._data, data_abs))
        actual_len = min(raw_len, cell_size - 4)
        return self._data[data_abs + 4: data_abs + 4 + actual_len]

    def query_value(self, nk: dict, name: str):
        if nk["value_count"] == 0 or nk["value_list"] == 0xFFFFFFFF:
            return None
        list_abs = self._abs(nk["value_list"])
        for i in range(nk["value_count"]):
            ea = list_abs + i * 4
            if ea + 4 > len(self._data):
                break
            vk_off = _u32(self._data, ea)
            if vk_off in (0, 0xFFFFFFFF):
                continue
            vk = self._vk_at(self._abs(vk_off))
            if vk and vk["name"].upper() == name.upper():
                return self._decode(vk["data_type"], self._read_value_data(vk))
        return None

    def _decode(self, dtype: int, raw: bytes):
        if dtype in (_REG_SZ, _REG_EXPAND_SZ):
            try:
                return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            except Exception:
                return raw.decode("latin-1", errors="replace").rstrip("\x00")
        if dtype == _REG_MULTI_SZ:
            try:
                s = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                return [v for v in s.split("\x00") if v]
            except Exception:
                return []
        if dtype == _REG_DWORD:
            return _u32(raw, 0) if len(raw) >= 4 else 0
        if dtype == _REG_DWORD_BE:
            return struct.unpack_from(">I", raw, 0)[0] if len(raw) >= 4 else 0
        if dtype == _REG_QWORD:
            return struct.unpack_from("<Q", raw, 0)[0] if len(raw) >= 8 else 0
        return raw.hex()

    def iter_subkey_names(self, key_path: str) -> list[str]:
        nk = self.open_key(key_path)
        if nk is None:
            return []
        return [c["name"] for c in self._iter_subkeys(nk)]


# ---------------------------------------------------------------------------
# Device enumeration
# ---------------------------------------------------------------------------

def _open_hive(target: Path, relative: str):
    p = target / relative
    if not p.exists():
        _log.warning("Hive not found: %s", p)
        return None
    try:
        return _Hive(p)
    except Exception as exc:
        _log.warning("Failed to open hive %s: %s", p, exc)
        return None


def _q(hive, key_path: str, value_name: str, default=None):
    if hive is None:
        return default
    try:
        nk = hive.open_key(key_path)
        if nk is None:
            return default
        v = hive.query_value(nk, value_name)
        return v if v is not None else default
    except Exception:
        return default


def collect_devices(target: Path) -> list[dict]:
    """
    Enumerate SYSTEM\\CurrentControlSet\\Enum\\<bus>\\<device>\\<instance>
    and return a list of device dicts.
    """
    sys_hive = _open_hive(target, "Windows/System32/config/SYSTEM")
    if sys_hive is None:
        return []

    # Resolve CurrentControlSet
    enum_base = ""
    for ccs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        if sys_hive.open_key(f"{ccs}\\Enum") is not None:
            enum_base = f"{ccs}\\Enum"
            break
    if not enum_base:
        _log.warning("Enum key not found in SYSTEM hive")
        return []

    devices: list[dict] = []
    bus_names = sys_hive.iter_subkey_names(enum_base)

    for bus in bus_names:
        bus_path = f"{enum_base}\\{bus}"
        dev_ids  = sys_hive.iter_subkey_names(bus_path)

        for dev_id in dev_ids:
            dev_path = f"{bus_path}\\{dev_id}"
            instances = sys_hive.iter_subkey_names(dev_path)

            for inst in instances:
                inst_path = f"{dev_path}\\{inst}"
                try:
                    inst_nk = sys_hive.open_key(inst_path)
                    if inst_nk is None:
                        continue

                    desc          = sys_hive.query_value(inst_nk, "DeviceDesc")     or ""
                    class_name    = sys_hive.query_value(inst_nk, "Class")           or ""
                    class_guid    = sys_hive.query_value(inst_nk, "ClassGUID")       or ""
                    mfg           = sys_hive.query_value(inst_nk, "Mfg")             or ""
                    hw_ids        = sys_hive.query_value(inst_nk, "HardwareID")      or []
                    compat_ids    = sys_hive.query_value(inst_nk, "CompatibleIDs")   or []
                    problem_code  = sys_hive.query_value(inst_nk, "Problem")         or 0
                    config_flags  = sys_hive.query_value(inst_nk, "ConfigFlags")     or 0
                    driver_key    = sys_hive.query_value(inst_nk, "Driver")          or ""

                    # Strip localisation prefix e.g. "@diskperf.dll,-305" → "Disk performance filter"
                    if isinstance(desc, str) and desc.startswith("@"):
                        desc = desc.split(";")[-1].strip() if ";" in desc else desc

                    # Driver version from Class\\{GUID}\\<driver_key>
                    drv_version  = ""
                    drv_provider = ""
                    drv_date     = ""
                    if driver_key:
                        # driver_key looks like "{4D36E97B-E325-11CE-BFC1-08002BE10318}\\0001"
                        # Full path: HKLM\SYSTEM\CCS\Control\Class\{guid}\{index}
                        drv_path = f"{ccs}\\Control\\Class\\{driver_key}"
                        drv_version  = str(_q(sys_hive, drv_path, "DriverVersion",  "") or "")
                        drv_provider = str(_q(sys_hive, drv_path, "ProviderName",   "") or "")
                        drv_date     = str(_q(sys_hive, drv_path, "DriverDate",     "") or "")

                    # Normalise hw_ids to list
                    if isinstance(hw_ids, str):
                        hw_ids = [hw_ids]
                    if isinstance(compat_ids, str):
                        compat_ids = [compat_ids]

                    problem_desc = _CM_PROB.get(int(problem_code), "") if problem_code else ""
                    flagged      = bool(problem_code) or (int(config_flags) & 0x400 != 0)

                    devices.append({
                        "bus":           bus,
                        "device_id":     dev_id,
                        "instance":      inst,
                        "description":   desc.strip(),
                        "class":         class_name,
                        "class_guid":    class_guid,
                        "manufacturer":  mfg,
                        "hardware_ids":  hw_ids[:4],   # keep first 4
                        "driver_version":  drv_version,
                        "driver_provider": drv_provider,
                        "driver_date":     drv_date,
                        "problem_code":  int(problem_code) if problem_code else 0,
                        "problem_desc":  problem_desc,
                        "config_flags":  int(config_flags) if config_flags else 0,
                        "flagged":       flagged,
                    })
                except Exception as exc:
                    _log.debug("Skipping %s\\%s\\%s: %s", bus, dev_id, inst, exc)
                    continue

    return devices


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def _fmt_report(report: dict) -> str:
    devices  = report["devices"]
    flagged  = [d for d in devices if d["flagged"]]
    total    = len(devices)

    lines = [
        "=" * 60,
        "  DEVICE MANAGER (OFFLINE)",
        "=" * 60,
        f"  Total devices : {total}",
        f"  Flagged       : {len(flagged)}",
    ]

    if flagged:
        lines += ["", "  --- Devices with problems ---"]
        for d in sorted(flagged, key=lambda x: x["class"]):
            prob = f"  [Problem {d['problem_code']}: {d['problem_desc']}]" \
                   if d["problem_code"] else "  [disabled/config_flags]"
            lines += [
                f"",
                f"  {d['class']:20s}  {d['description'][:50]}",
                f"    Bus / ID      : {d['bus']}\\{d['device_id']}",
                f"    Driver version: {d['driver_version'] or '(none)'}  "
                f"  Provider: {d['driver_provider'] or '(none)'}",
                f"    Driver date   : {d['driver_date'] or '(none)'}",
                prob,
            ]

    lines += ["", "  --- Device summary by class ---"]
    from collections import Counter
    class_counts: Counter = Counter(d["class"] or "Unknown" for d in devices)
    for cls, cnt in sorted(class_counts.items(), key=lambda x: -x[1]):
        imp = "  *" if cls in _IMPORTANT_CLASSES else ""
        lines.append(f"    {cls:30s} {cnt:4d}{imp}")

    lines.append("=" * 60)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    ap = argparse.ArgumentParser(prog="m27_device_manager", description=DESCRIPTION)
    ap.add_argument("--target", required=False, default=None,
                    help="Mount point of the Windows installation (e.g. /mnt/windows)")
    ap.add_argument("--flagged-only", action="store_true",
                    help="Only report devices with problems")
    args = ap.parse_args(argv)

    if args.target:
        target = Path(args.target)
    else:
        try:
            from toolkit import find_windows_target
            target = find_windows_target()
        except Exception:
            target = None
        if target is None:
            _log.error("Could not auto-detect Windows target. Pass --target.")
            return 1
        print(f"[m27] Auto-detected target: {target}", flush=True)

    if not target.exists():
        _log.error("Target path does not exist: %s", target)
        return 1

    print("[m27] Reading device list from SYSTEM hive Enum tree ...", flush=True)
    devices = collect_devices(target)
    flagged = [d for d in devices if d["flagged"]]
    print(f"[m27] Found {len(devices)} devices, {len(flagged)} flagged", flush=True)

    if args.flagged_only:
        out_devices = flagged
    else:
        out_devices = devices

    report = {
        "target":    str(target),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total":     len(devices),
        "flagged_count": len(flagged),
        "devices":   out_devices,
    }

    print()
    full_report = {"devices": devices, **{k: v for k, v in report.items() if k != "devices"}}
    print(_fmt_report(full_report))

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = root / "logs" / f"device_manager_{ts}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"[m27] Saved → {out_path}", flush=True)
    return 0
