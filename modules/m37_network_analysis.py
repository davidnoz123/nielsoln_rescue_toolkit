"""m37_network_analysis — Offline Windows network and remote-access exposure analysis.

Reads registry hives to collect:
  - RDP (Remote Desktop) enabled/disabled status
  - Remote Assistance configuration
  - Firewall profile state (Domain/Private/Public)
  - Windows Firewall enabled/disabled per profile
  - Network adapter configurations (static IP, DHCP, DNS)
  - Wi-Fi profiles (SSIDs from wireless profiles)
  - Proxy settings per-user (from NTUSER.DAT)
  - Remote-access related services (RDP, VNC, TeamViewer indicators)
  - Suspicious remote-access software entries in Uninstall keys

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m37_network_analysis -- --target /mnt/windows

Output:
    logs/network_analysis_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DESCRIPTION = (
    "Network analysis: RDP/Remote Assistance state, firewall profiles, "
    "adapter config, Wi-Fi SSIDs, proxy settings, and remote-access software"
)

# ---------------------------------------------------------------------------
# Minimal REGF hive parser (same engine as m07, m33)
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
            abs_name_off = _HIVE_BINS_OFFSET + offset + 4 + 20
            name = self._str_at(abs_name_off, name_length, is_ascii)
        data = self._read_value_data(data_size_raw, data_offset, data_type)
        return (name, data_type, data)

    def _read_value_data(self, size_raw: int, offset: int, dtype: int) -> Any:
        inline = bool(size_raw & 0x80000000)
        size   = size_raw & 0x7FFFFFFF
        if inline:
            raw = struct.pack("<I", offset)[:size] if size <= 4 else b""
        else:
            cell = self._cell(offset)
            if cell is None:
                return None
            raw = bytes(cell[:size])
        if dtype == 1:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if dtype == 2:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if dtype == 4:
            return struct.unpack_from("<I", raw)[0] if len(raw) >= 4 else None
        if dtype == 11:
            return struct.unpack_from("<Q", raw)[0] if len(raw) >= 8 else None
        if dtype == 7:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00").split("\x00")
        return raw.hex()

    def get_value(self, key_offset: int, value_name: str) -> Any:
        vn_lower = value_name.lower()
        for name, dtype, data in self.list_values(key_offset):
            if name.lower() == vn_lower:
                return data
        return None


# ---------------------------------------------------------------------------
# RDP status
# SYSTEM\CurrentControlSet\Control\Terminal Server
#   fDenyTSConnections = 0 means RDP ENABLED
# ---------------------------------------------------------------------------

def _check_rdp(sys_hive: _RegHive) -> dict:
    result = {"enabled": None, "port": 3389, "nla_required": None}
    for cs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        ts_off = sys_hive.get_key_offset(f"{cs}\\Control\\Terminal Server")
        if ts_off is None:
            continue
        deny = sys_hive.get_value(ts_off, "fDenyTSConnections")
        if deny is not None:
            result["enabled"] = (deny == 0)
        # Port override
        port_off = sys_hive.get_key_offset(
            f"{cs}\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
        )
        if port_off is not None:
            port = sys_hive.get_value(port_off, "PortNumber")
            if port:
                result["port"] = port
        # NLA (Network Level Authentication)
        nla_off = sys_hive.get_key_offset(
            f"{cs}\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
        )
        if nla_off is not None:
            nla = sys_hive.get_value(nla_off, "UserAuthentication")
            if nla is not None:
                result["nla_required"] = bool(nla)
        break
    return result


# ---------------------------------------------------------------------------
# Remote Assistance
# SYSTEM\CurrentControlSet\Control\Remote Assistance
# or SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore (fallback)
# ---------------------------------------------------------------------------

def _check_remote_assistance(sys_hive: _RegHive) -> dict:
    result = {"enabled": None}
    for cs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        ra_off = sys_hive.get_key_offset(f"{cs}\\Control\\Remote Assistance")
        if ra_off is None:
            continue
        val = sys_hive.get_value(ra_off, "fAllowToGetHelp")
        if val is not None:
            result["enabled"] = bool(val)
        break
    return result


# ---------------------------------------------------------------------------
# Firewall state
# SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy
# Profiles: DomainProfile, StandardProfile (XP/Vista), PublicProfile (Vista)
# EnableFirewall DWORD: 1=enabled, 0=disabled
# ---------------------------------------------------------------------------

def _check_firewall(sys_hive: _RegHive) -> dict:
    profiles: dict = {}
    for cs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        fw_base = f"{cs}\\Services\\SharedAccess\\Parameters\\FirewallPolicy"
        for profile_name in ("DomainProfile", "StandardProfile", "PublicProfile"):
            prof_off = sys_hive.get_key_offset(f"{fw_base}\\{profile_name}")
            if prof_off is None:
                continue
            enabled = sys_hive.get_value(prof_off, "EnableFirewall")
            profiles[profile_name] = {
                "enabled": bool(enabled) if enabled is not None else None,
            }
        if profiles:
            break
    return {"profiles": profiles}


# ---------------------------------------------------------------------------
# Network adapters
# SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}
# ---------------------------------------------------------------------------

def _load_adapters(sys_hive: _RegHive) -> List[dict]:
    adapters: List[dict] = []
    for cs in ("CurrentControlSet", "ControlSet001", "ControlSet002"):
        iface_off = sys_hive.get_key_offset(
            f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces"
        )
        if iface_off is None:
            continue
        for guid in sys_hive.list_subkey_names(iface_off):
            g_off = sys_hive.get_subkey_offset(iface_off, guid)
            if g_off is None:
                continue
            dhcp_ip   = sys_hive.get_value(g_off, "DhcpIPAddress") or ""
            static_ip = sys_hive.get_value(g_off, "IPAddress")
            dhcp_dns  = sys_hive.get_value(g_off, "DhcpNameServer") or ""
            static_dns = sys_hive.get_value(g_off, "NameServer") or ""
            dhcp_gw   = sys_hive.get_value(g_off, "DhcpDefaultGateway")
            static_gw = sys_hive.get_value(g_off, "DefaultGateway")

            # Skip empty adapters
            if not dhcp_ip and not static_ip and not dhcp_dns and not static_dns:
                continue

            adapter: dict = {
                "guid": guid,
                "dhcp": bool(dhcp_ip),
            }
            if dhcp_ip:
                adapter["ip"] = dhcp_ip
            if static_ip:
                if isinstance(static_ip, list):
                    adapter["ip"] = [ip for ip in static_ip if ip]
                else:
                    adapter["ip"] = static_ip
            if dhcp_dns:
                adapter["dns"] = dhcp_dns
            elif static_dns:
                adapter["dns"] = static_dns
            if dhcp_gw:
                adapter["gateway"] = dhcp_gw if isinstance(dhcp_gw, str) else str(dhcp_gw)
            elif static_gw:
                adapter["gateway"] = static_gw if isinstance(static_gw, str) else str(static_gw)
            adapters.append(adapter)
        break
    return adapters


# ---------------------------------------------------------------------------
# Wi-Fi profiles from filesystem
# Windows\System32\wlan\profiles\Interfaces\{GUID}\{SSID}.xml
# Also check ProgramData\Microsoft\Wlansvc\Profiles
# ---------------------------------------------------------------------------

def _load_wifi_profiles(target: Path) -> Tuple[List[dict], List[str]]:
    limitations: List[str] = []
    profiles: List[dict] = []

    import xml.etree.ElementTree as ET

    search_paths = [
        target / "Windows" / "System32" / "wlan" / "profiles",
        target / "ProgramData" / "Microsoft" / "Wlansvc" / "Profiles" / "Interfaces",
    ]

    for base in search_paths:
        if not base.is_dir():
            continue
        for xml_path in base.rglob("*.xml"):
            try:
                tree = ET.parse(str(xml_path))
                root = tree.getroot()
                # Strip namespace if present
                ns_map = {"wlan": "http://www.microsoft.com/networking/WLAN/profile/v1"}
                ssid_el = root.find(".//wlan:SSID/wlan:name", ns_map)
                if ssid_el is None:
                    # Try without namespace
                    ssid_el = root.find(".//SSID/name")
                if ssid_el is None:
                    ssid_el = root.find(".//{http://www.microsoft.com/networking/WLAN/profile/v1}name")
                ssid = ssid_el.text.strip() if ssid_el is not None and ssid_el.text else xml_path.stem
                auth_el = root.find(".//{http://www.microsoft.com/networking/WLAN/profile/v1}authentication")
                if auth_el is None:
                    auth_el = root.find(".//authentication")
                auth = auth_el.text.strip() if auth_el is not None and auth_el.text else ""
                profiles.append({
                    "ssid": ssid,
                    "authentication": auth,
                    "profile_file": xml_path.name,
                })
            except Exception:
                profiles.append({"ssid": xml_path.stem, "profile_file": xml_path.name})

    if not profiles:
        limitations.append("No Wi-Fi profile XML files found")

    return profiles, limitations


# ---------------------------------------------------------------------------
# Proxy settings from NTUSER.DAT
# HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
# ---------------------------------------------------------------------------

def _load_proxy_settings(ntuser_path: Path) -> Optional[dict]:
    try:
        data = ntuser_path.read_bytes()
        if data[:4] != b"regf":
            return None
        hive = _RegHive(data)
        off = hive.get_key_offset(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
        )
        if off is None:
            return None
        proxy_enabled = hive.get_value(off, "ProxyEnable")
        proxy_server  = hive.get_value(off, "ProxyServer")
        proxy_override = hive.get_value(off, "ProxyOverride")
        auto_config_url = hive.get_value(off, "AutoConfigURL")
        if proxy_enabled is None and not proxy_server:
            return None
        return {
            "proxy_enabled": bool(proxy_enabled) if proxy_enabled is not None else False,
            "proxy_server":   proxy_server or "",
            "proxy_override": proxy_override or "",
            "auto_config_url": auto_config_url or "",
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Suspicious remote-access software from SOFTWARE Uninstall key
# ---------------------------------------------------------------------------

_REMOTE_ACCESS_KEYWORDS = [
    "teamviewer", "vnc", "logmein", "anydesk", "gotomypc", "pcanyplace",
    "remote desktop", "radmin", "ammyy", "dameware", "screenconnect",
    "connectwise", "bomgar", "splashtop", "ultraviewer", "litemanager",
]


def _find_remote_software(sw_hive: _RegHive) -> List[dict]:
    results: List[dict] = []
    uninst_off = sw_hive.get_key_offset(
        "Microsoft\\Windows\\CurrentVersion\\Uninstall"
    )
    if uninst_off is None:
        return results
    for key_name in sw_hive.list_subkey_names(uninst_off):
        key_lower = key_name.lower()
        match = any(kw in key_lower for kw in _REMOTE_ACCESS_KEYWORDS)
        sub_off = sw_hive.get_subkey_offset(uninst_off, key_name)
        if sub_off is None:
            continue
        disp = sw_hive.get_value(sub_off, "DisplayName") or ""
        disp_lower = disp.lower()
        if not match:
            match = any(kw in disp_lower for kw in _REMOTE_ACCESS_KEYWORDS)
        if match:
            version = sw_hive.get_value(sub_off, "DisplayVersion") or ""
            publisher = sw_hive.get_value(sub_off, "Publisher") or ""
            install_date = sw_hive.get_value(sub_off, "InstallDate") or ""
            results.append({
                "name":         disp or key_name,
                "version":      version,
                "publisher":    publisher,
                "install_date": install_date,
            })
    return results


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    limitations: List[str] = []

    sys_hive_path = target / "Windows" / "System32" / "config" / "SYSTEM"
    sw_hive_path  = target / "Windows" / "System32" / "config" / "SOFTWARE"

    rdp: dict = {"enabled": None}
    remote_assist: dict = {"enabled": None}
    firewall: dict = {}
    adapters: List[dict] = []
    remote_software: List[dict] = []
    remote_services: List[str] = []

    # SYSTEM hive
    if not sys_hive_path.exists():
        limitations.append("SYSTEM hive not found; RDP/firewall/adapter data unavailable")
    else:
        try:
            sys_data = sys_hive_path.read_bytes()
            if sys_data[:4] != b"regf":
                limitations.append("SYSTEM hive: invalid signature")
            else:
                sys_hive = _RegHive(sys_data)
                rdp            = _check_rdp(sys_hive)
                remote_assist  = _check_remote_assistance(sys_hive)
                firewall       = _check_firewall(sys_hive)
                adapters       = _load_adapters(sys_hive)
        except Exception as exc:
            limitations.append(f"SYSTEM hive parse error: {exc}")

    # SOFTWARE hive
    if not sw_hive_path.exists():
        limitations.append("SOFTWARE hive not found; remote software scan unavailable")
    else:
        try:
            sw_data = sw_hive_path.read_bytes()
            if sw_data[:4] != b"regf":
                limitations.append("SOFTWARE hive: invalid signature")
            else:
                sw_hive = _RegHive(sw_data)
                remote_software = _find_remote_software(sw_hive)
        except Exception as exc:
            limitations.append(f"SOFTWARE hive parse error: {exc}")

    # Wi-Fi profiles
    wifi_profiles, wifi_lim = _load_wifi_profiles(target)
    limitations.extend(wifi_lim)

    # Proxy settings (first user found)
    proxy_by_user: Dict[str, dict] = {}
    users_dir = target / "Users"
    if users_dir.is_dir():
        for user_dir in sorted(users_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            ntuser = user_dir / "NTUSER.DAT"
            if not ntuser.exists():
                continue
            proxy = _load_proxy_settings(ntuser)
            if proxy:
                proxy_by_user[user_dir.name] = proxy

    # Exposure summary
    rdp_enabled  = rdp.get("enabled")
    ra_enabled   = remote_assist.get("enabled")
    fw_profiles  = firewall.get("profiles", {})
    any_fw_off   = any(
        not p.get("enabled", True) for p in fw_profiles.values()
        if p.get("enabled") is not None
    )

    flags: List[str] = []
    if rdp_enabled:
        flags.append("rdp_enabled")
    if ra_enabled:
        flags.append("remote_assistance_enabled")
    if any_fw_off:
        flags.append("firewall_disabled")
    if remote_software:
        flags.append("remote_software_installed")
    if any(p.get("proxy_enabled") for p in proxy_by_user.values()):
        flags.append("proxy_configured")

    verdict = "OK"
    if flags:
        verdict = "WARNING"
    if "rdp_enabled" in flags and "firewall_disabled" in flags:
        verdict = "SUSPICIOUS"

    summary = {
        "rdp_enabled":                 rdp_enabled,
        "remote_assistance_enabled":   ra_enabled,
        "firewall_any_profile_off":    any_fw_off,
        "remote_software_count":       len(remote_software),
        "wifi_profile_count":          len(wifi_profiles),
        "adapter_count":               len(adapters),
        "exposure_flags":              flags,
    }

    return {
        "scan_status":    "ok",
        "verdict":        verdict,
        "summary":        summary,
        "rdp":            rdp,
        "remote_assistance": remote_assist,
        "firewall":       firewall,
        "adapters":       adapters,
        "wifi_profiles":  wifi_profiles,
        "proxy_settings": proxy_by_user,
        "remote_software": remote_software,
        "limitations":    limitations,
    }


# ---------------------------------------------------------------------------
# Report printing
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    print("\n=== NETWORK ANALYSIS ===")
    print(f"Verdict   : {data.get('verdict', '?')}")
    s = data.get("summary", {})

    rdp = data.get("rdp", {})
    rdp_str = "ENABLED" if rdp.get("enabled") else ("DISABLED" if rdp.get("enabled") is False else "unknown")
    print(f"RDP       : {rdp_str} (port {rdp.get('port', 3389)})")

    ra = data.get("remote_assistance", {})
    ra_str = "ENABLED" if ra.get("enabled") else ("DISABLED" if ra.get("enabled") is False else "unknown")
    print(f"Remote Assistance : {ra_str}")

    fw = data.get("firewall", {}).get("profiles", {})
    if fw:
        for name, prof in fw.items():
            en = prof.get("enabled")
            print(f"Firewall [{name:20}]: {'ON' if en else 'OFF' if en is False else '?'}")

    adapters = data.get("adapters", [])
    if adapters:
        print(f"\nNetwork adapters ({len(adapters)}):")
        for a in adapters:
            ip = a.get("ip", "")
            dns = a.get("dns", "")
            dhcp = "DHCP" if a.get("dhcp") else "static"
            print(f"  {a.get('guid', '?')[:36]}  {dhcp}  IP={ip}  DNS={dns}")

    wifi = data.get("wifi_profiles", [])
    if wifi:
        print(f"\nWi-Fi profiles ({len(wifi)}):")
        for w in wifi:
            print(f"  SSID: {w.get('ssid', '?')}  auth={w.get('authentication', '?')}")

    remote_sw = data.get("remote_software", [])
    if remote_sw:
        print(f"\nRemote-access software ({len(remote_sw)}):")
        for sw in remote_sw:
            print(f"  {sw.get('name', '?')} {sw.get('version', '')}  installed={sw.get('install_date', '?')}")

    proxy = data.get("proxy_settings", {})
    for user, p in proxy.items():
        if p.get("proxy_enabled"):
            print(f"\nProxy [{user}]: {p.get('proxy_server', '?')}")

    flags = s.get("exposure_flags", [])
    if flags:
        print(f"\nExposure flags: {', '.join(flags)}")

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
        prog="m37_network_analysis",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="",
                        help="Path to mounted Windows partition (auto-detect if omitted)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m37] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    import time
    from datetime import datetime as _dt, timezone as _tz

    print(f"[m37] Analysing network configuration in {target_path} ...")
    data = analyse(target_path)
    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"network_analysis_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m37] Log written: {out_path}")

    return 0 if data.get("verdict") == "OK" else 1
