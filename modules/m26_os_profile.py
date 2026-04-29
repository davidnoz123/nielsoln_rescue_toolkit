"""
m26_os_profile.py — Nielsoln Rescue Toolkit: offline Windows OS profile.

Reads the mounted Windows installation (registry SOFTWARE & SYSTEM hives, filesystem)
to collect:
  - OS edition, version, build, service pack
  - OS bitness (32/64-bit) and CPU architecture
  - Registered owner / organisation
  - Install date
  - Installed kernel drivers (.sys files in System32\\drivers\\)
  - Kernel-mode driver services from SYSTEM\\CurrentControlSet\\Services

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m26_os_profile -- --target /mnt/windows

Output:
    Prints a formatted report to stdout.
    Writes JSON to <USB>/logs/os_profile_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import struct
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("m26_os_profile")

DESCRIPTION = (
    "Offline Windows OS profile: edition, bitness, service pack, owner, "
    "install date, and installed kernel drivers"
)

# ---------------------------------------------------------------------------
# Minimal offline registry reader (no external deps)
# ---------------------------------------------------------------------------
# Windows registry hive format is complex; we use a lightweight parser that
# handles the common cases we need (REG_SZ, REG_DWORD, REG_EXPAND_SZ).
# This avoids any dependency on python-registry or hivex.

_REGF_MAGIC = b"regf"
_HBIN_MAGIC = b"hbin"
_NK_MAGIC    = b"nk"
_VK_MAGIC    = b"vk"

_REG_SZ         = 1
_REG_EXPAND_SZ  = 2
_REG_DWORD      = 4
_REG_DWORD_BE   = 5
_REG_MULTI_SZ   = 7
_REG_QWORD      = 11


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _s32(data: bytes, off: int) -> int:
    return struct.unpack_from("<i", data, off)[0]


class _Hive:
    """
    Very small read-only Windows registry hive parser.
    Supports: open key by path, enumerate values, enumerate subkeys.
    Sufficient for reading string + DWORD values from well-formed hives.
    """

    def __init__(self, path: Path):
        self._data = path.read_bytes()
        if self._data[:4] != _REGF_MAGIC:
            raise ValueError(f"Not a registry hive: {path}")
        # Root cell offset is at 0x24 in regf header (relative to first hbin)
        self._root_off = _u32(self._data, 0x24) + 0x1000  # 0x1000 = hive header size

    def _abs(self, rel_off: int) -> int:
        """Convert a relative cell offset to an absolute byte offset."""
        return rel_off + 0x1000

    def _nk_at(self, abs_off: int) -> dict | None:
        """Parse an nk (named key) cell at absolute offset."""
        if self._data[abs_off + 4: abs_off + 6] != _NK_MAGIC:
            return None
        flags        = _u16(self._data, abs_off + 6)
        subkey_count = _u32(self._data, abs_off + 0x18)
        # 0x1C = volatile subkey count; 0x20 = stable subkey list offset
        subkey_list  = _u32(self._data, abs_off + 0x20)
        value_count  = _u32(self._data, abs_off + 0x28)
        value_list   = _u32(self._data, abs_off + 0x2C)
        # 0x4C = key name length (2 bytes); 0x4E = class name length; 0x50 = name
        name_len     = _u16(self._data, abs_off + 0x4C)
        name_bytes   = self._data[abs_off + 0x50: abs_off + 0x50 + name_len]
        # ASCII flag in flags bit 5
        try:
            name = name_bytes.decode("ascii" if flags & 0x20 else "utf-16-le",
                                     errors="replace")
        except Exception:
            name = name_bytes.decode("latin-1", errors="replace")
        return {
            "name": name,
            "abs_off": abs_off,
            "subkey_count": subkey_count,
            "subkey_list": subkey_list,
            "value_count": value_count,
            "value_list": value_list,
        }

    def _iter_subkeys(self, nk: dict):
        """Yield nk dicts for immediate children of *nk*."""
        if nk["subkey_count"] == 0 or nk["subkey_list"] == 0xFFFFFFFF:
            return
        list_abs = self._abs(nk["subkey_list"])
        sig = self._data[list_abs + 4: list_abs + 6]
        if sig in (b"lf", b"lh"):
            count = _u16(self._data, list_abs + 6)
            for i in range(count):
                entry_abs = list_abs + 8 + i * 8
                child_off = _u32(self._data, entry_abs)
                child_abs = self._abs(child_off)
                nk2 = self._nk_at(child_abs)
                if nk2:
                    yield nk2
        elif sig in (b"ri", b"li"):
            count = _u16(self._data, list_abs + 6)
            for i in range(count):
                sub_off = _u32(self._data, list_abs + 8 + i * 4)
                sub_abs = self._abs(sub_off)
                sub_sig = self._data[sub_abs + 4: sub_abs + 6]
                if sub_sig in (b"lf", b"lh"):
                    sub_count = _u16(self._data, sub_abs + 6)
                    for j in range(sub_count):
                        entry_abs = sub_abs + 8 + j * 8
                        child_off = _u32(self._data, entry_abs)
                        child_abs = self._abs(child_off)
                        nk2 = self._nk_at(child_abs)
                        if nk2:
                            yield nk2

    def _open_key(self, nk: dict, parts: list[str]) -> dict | None:
        """Recursively open a subkey path from *nk*."""
        if not parts:
            return nk
        want = parts[0].upper()
        for child in self._iter_subkeys(nk):
            if child["name"].upper() == want:
                return self._open_key(child, parts[1:])
        return None

    def open_key(self, path: str) -> dict | None:
        """Open a key by backslash-separated path, return nk dict or None."""
        root = self._nk_at(self._root_off)
        if root is None:
            return None
        parts = [p for p in path.replace("/", "\\").split("\\") if p]
        if not parts:
            return root
        return self._open_key(root, parts)

    def _vk_at(self, abs_off: int) -> dict | None:
        if self._data[abs_off + 4: abs_off + 6] != _VK_MAGIC:
            return None
        name_len  = _u16(self._data, abs_off + 6)
        data_len  = _u32(self._data, abs_off + 8)
        data_off  = _u32(self._data, abs_off + 0xC)
        data_type = _u32(self._data, abs_off + 0x10)
        name_flag = _u16(self._data, abs_off + 0x14)  # 0x14 = flags (bit 0: ASCII name)
        name_bytes = self._data[abs_off + 0x18: abs_off + 0x18 + name_len]
        try:
            name = name_bytes.decode("ascii" if name_flag & 1 else "utf-16-le",
                                     errors="replace")
        except Exception:
            name = name_bytes.decode("latin-1", errors="replace")
        return {
            "name": name,
            "data_len": data_len,
            "data_off": data_off,
            "data_type": data_type,
        }

    def _read_value_data(self, vk: dict) -> bytes:
        raw_len = vk["data_len"]
        # Small-data flag: if bit 31 set, data is stored in the offset field itself
        if raw_len & 0x80000000:
            actual_len = raw_len & 0x7FFFFFFF
            # Data is in the low bytes of data_off (little-endian)
            raw = struct.pack("<I", vk["data_off"])
            return raw[:actual_len]
        data_abs = self._abs(vk["data_off"])
        # cell size is a signed int32 at data_abs; actual data follows at +4
        cell_size = abs(_s32(self._data, data_abs))
        actual_len = min(raw_len, cell_size - 4)
        return self._data[data_abs + 4: data_abs + 4 + actual_len]

    def query_value(self, nk: dict, name: str) -> str | int | None:
        """Return the decoded value of *name* under *nk*, or None."""
        if nk["value_count"] == 0 or nk["value_list"] == 0xFFFFFFFF:
            return None
        list_abs = self._abs(nk["value_list"])
        for i in range(nk["value_count"]):
            vk_off = _u32(self._data, list_abs + i * 4)
            if vk_off == 0 or vk_off == 0xFFFFFFFF:
                continue
            vk_abs = self._abs(vk_off)
            vk = self._vk_at(vk_abs)
            if vk is None:
                continue
            if vk["name"].upper() == name.upper():
                raw = self._read_value_data(vk)
                return self._decode(vk["data_type"], raw)
        return None

    def _decode(self, dtype: int, raw: bytes):
        if dtype in (_REG_SZ, _REG_EXPAND_SZ):
            try:
                s = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                return s
            except Exception:
                return raw.decode("latin-1", errors="replace").rstrip("\x00")
        if dtype == _REG_MULTI_SZ:
            try:
                return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            except Exception:
                return ""
        if dtype == _REG_DWORD:
            return _u32(raw, 0) if len(raw) >= 4 else 0
        if dtype == _REG_DWORD_BE:
            return struct.unpack_from(">I", raw, 0)[0] if len(raw) >= 4 else 0
        if dtype == _REG_QWORD:
            return struct.unpack_from("<Q", raw, 0)[0] if len(raw) >= 8 else 0
        return raw.hex()

    def iter_subkey_names(self, key_path: str) -> list[str]:
        """Return names of all immediate subkeys of *key_path*."""
        nk = self.open_key(key_path)
        if nk is None:
            return []
        return [child["name"] for child in self._iter_subkeys(nk)]


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def _open_hive(target: Path, relative: str) -> "_Hive | None":
    p = target / relative
    if not p.exists():
        _log.warning("Hive not found: %s", p)
        return None
    try:
        return _Hive(p)
    except Exception as exc:
        _log.warning("Failed to open hive %s: %s", p, exc)
        return None


def _q(hive: "_Hive | None", key_path: str, value_name: str,
        default=None):
    """Safe query: open key and value, return default on any failure."""
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


def collect_os_info(target: Path) -> dict:
    """Read OS details from the SOFTWARE and SYSTEM hives."""
    sw = _open_hive(target, "Windows/System32/config/SOFTWARE")

    key = "Microsoft\\Windows NT\\CurrentVersion"
    product_name  = _q(sw, key, "ProductName",        "unknown")
    build         = _q(sw, key, "CurrentBuildNumber",  "unknown")
    version       = _q(sw, key, "CurrentVersion",      "unknown")
    csd_version   = _q(sw, key, "CSDVersion",          "")     # Service pack string
    owner         = _q(sw, key, "RegisteredOwner",     "")
    org           = _q(sw, key, "RegisteredOrganization", "")
    install_ts    = _q(sw, key, "InstallDate",         0)      # Unix timestamp DWORD

    install_date = ""
    if install_ts and isinstance(install_ts, int) and install_ts > 0:
        try:
            install_date = datetime.fromtimestamp(
                install_ts, tz=timezone.utc).strftime("%Y-%m-%d")
        except (OSError, OverflowError, ValueError):
            install_date = str(install_ts)

    # OS bitness: 64-bit installs have SysWOW64
    syswow64 = (target / "Windows" / "SysWOW64").exists()
    os_bitness = "64-bit" if syswow64 else "32-bit"

    # Computer name — try multiple paths in order of reliability.
    # The ComputerName registry key (Control\ComputerName\ComputerName\ComputerName)
    # can fail to parse on some Vista hives; Tcpip\Parameters\Hostname is more robust.
    computer_name = ""
    sys_hive = _open_hive(target, "Windows/System32/config/SYSTEM")
    if sys_hive is not None:
        for ccs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
            # Primary: Tcpip Parameters (most reliable in offline hive)
            cn = _q(sys_hive, f"{ccs}\\Services\\Tcpip\\Parameters",
                    "Hostname", "")
            if not cn:
                cn = _q(sys_hive, f"{ccs}\\Services\\Tcpip\\Parameters",
                        "NV Hostname", "")
            # Fallback: ComputerName key
            if not cn:
                cn = _q(sys_hive,
                        f"{ccs}\\Control\\ComputerName\\ComputerName",
                        "ComputerName", "")
            if cn and str(cn) not in ("", "unknown"):
                computer_name = str(cn)
                break

    return {
        "product_name":   str(product_name),
        "version":        str(version),
        "build":          str(build),
        "service_pack":   str(csd_version),
        "registered_owner": str(owner),
        "registered_org": str(org),
        "install_date":   install_date,
        "os_bitness":     os_bitness,
        "computer_name":  computer_name,
    }


def collect_drivers(target: Path) -> list[dict]:
    """
    List kernel driver files from Windows\\System32\\drivers\\.
    Returns a list of dicts: name, size_kb, modified (ISO date).
    """
    drivers_dir = target / "Windows" / "System32" / "drivers"
    if not drivers_dir.exists():
        _log.warning("drivers directory not found: %s", drivers_dir)
        return []

    results = []
    for f in sorted(drivers_dir.iterdir()):
        if f.is_file() and f.suffix.lower() == ".sys":
            try:
                st = f.stat()
                results.append({
                    "name":     f.name,
                    "size_kb":  round(st.st_size / 1024, 1),
                    "modified": datetime.fromtimestamp(
                        st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d"),
                })
            except OSError:
                results.append({"name": f.name, "size_kb": 0, "modified": "unknown"})

    return results


def collect_kernel_services(target: Path) -> list[dict]:
    """
    Read kernel-driver services from SYSTEM hive.
    Type=1 = kernel driver, Type=2 = file system driver.
    Returns list of {name, image_path, type}.
    """
    sys_hive = _open_hive(target, "Windows/System32/config/SYSTEM")
    if sys_hive is None:
        return []

    # Try CurrentControlSet first, fall back to ControlSet001
    for ccs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        key_path = f"{ccs}\\Services"
        names = sys_hive.iter_subkey_names(key_path)
        if names:
            break
    else:
        return []

    results = []
    for svc_name in names:
        try:
            svc_key = sys_hive.open_key(f"{key_path}\\{svc_name}")
            if svc_key is None:
                continue
            svc_type = sys_hive.query_value(svc_key, "Type")
            if svc_type not in (1, 2):  # only kernel/fs drivers
                continue
            image_path = sys_hive.query_value(svc_key, "ImagePath") or ""
            results.append({
                "name":       svc_name,
                "type":       "kernel" if svc_type == 1 else "filesystem",
                "image_path": str(image_path),
            })
        except Exception:
            continue

    return sorted(results, key=lambda x: x["name"].lower())


def collect_installed_devices(target: Path) -> list[dict]:
    """
    Read installed device classes from SOFTWARE hive.
    Returns list of {class, device_description, driver_version, provider}.
    """
    sw = _open_hive(target, "Windows/System32/config/SOFTWARE")
    if sw is None:
        return []

    base = "Microsoft\\Windows NT\\CurrentVersion\\DeviceInstall\\InstalledDevices"
    # Try alternative: SYSTEM hive Enum tree (large; skip for now — use INF approach)
    # Instead, enumerate DriverDatabase\DriverPackages from SOFTWARE
    pkg_path = "Microsoft\\Windows\\CurrentVersion\\Setup\\DriverDatabase\\DriverPackages"
    names = sw.iter_subkey_names(pkg_path)
    results = []
    for pkg in names[:200]:  # cap at 200 to avoid huge lists
        try:
            nk = sw.open_key(f"{pkg_path}\\{pkg}")
            if nk is None:
                continue
            provider = sw.query_value(nk, "Provider") or ""
            version  = sw.query_value(nk, "Version")  or ""
            desc     = sw.query_value(nk, "InfSection") or pkg
            results.append({
                "package":  pkg,
                "provider": str(provider),
                "version":  str(version),
                "section":  str(desc),
            })
        except Exception:
            continue
    return results


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def _fmt_report(profile: dict) -> str:
    os_info = profile["os"]
    lines = [
        "=" * 54,
        "  WINDOWS OS PROFILE",
        "=" * 54,
        f"  OS Edition    : {os_info['product_name']}",
        f"  Version       : {os_info['version']}  Build {os_info['build']}",
    ]
    if os_info["service_pack"]:
        lines.append(f"  Service Pack  : {os_info['service_pack']}")
    lines += [
        f"  OS Bitness    : {os_info['os_bitness']}",
        f"  Install date  : {os_info['install_date'] or 'unknown'}",
    ]
    if os_info["registered_owner"]:
        lines.append(f"  Registered to : {os_info['registered_owner']}")
    if os_info["registered_org"]:
        lines.append(f"  Organisation  : {os_info['registered_org']}")
    lines += [
        "",
        f"  Kernel drivers in System32\\drivers\\: {len(profile['drivers'])}",
        f"  Kernel services in registry        : {len(profile['kernel_services'])}",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    ap = argparse.ArgumentParser(
        prog="m26_os_profile",
        description=DESCRIPTION,
    )
    ap.add_argument("--target", required=True,
                    help="Mount point of the Windows installation (e.g. /mnt/windows)")
    ap.add_argument("--no-drivers", action="store_true",
                    help="Skip driver enumeration (faster)")
    args = ap.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        _log.error("Target path does not exist: %s", target)
        return 1

    _log.info("Target: %s", target)

    # Collect
    print("[m26] Collecting OS info from registry ...", flush=True)
    os_info = collect_os_info(target)
    print(f"[m26] OS: {os_info['product_name']}  build={os_info['build']}"
          f"  {os_info['os_bitness']}", flush=True)

    drivers = []
    if not args.no_drivers:
        print("[m26] Enumerating kernel driver files ...", flush=True)
        drivers = collect_drivers(target)
        print(f"[m26] Found {len(drivers)} .sys files in drivers\\", flush=True)

    print("[m26] Reading kernel services from SYSTEM hive ...", flush=True)
    kernel_services = collect_kernel_services(target)
    print(f"[m26] Found {len(kernel_services)} kernel/filesystem driver services",
          flush=True)

    profile = {
        "os":              os_info,
        "drivers":         drivers,
        "kernel_services": kernel_services,
        "target":          str(target),
        "timestamp":       datetime.now(timezone.utc).isoformat(),
    }

    # Print report
    print()
    print(_fmt_report(profile))

    # Save JSON
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = root / "logs" / f"os_profile_{ts}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"[m26] Saved → {out_path}", flush=True)
    return 0
