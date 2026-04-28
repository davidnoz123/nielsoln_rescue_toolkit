"""m33_user_account_analysis — Offline Windows local user and group analysis.

Reads the offline SAM and SOFTWARE registry hives plus the Users/profiles
directory to enumerate local user accounts, their enabled/disabled status,
admin membership, last-logon time, and password metadata.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m33_user_account_analysis -- --target /mnt/windows

Output:
    Logs/user_account_analysis_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DESCRIPTION = (
    "User account analysis: enumerates local accounts, admin membership, "
    "last-logon, password metadata, and profile paths from offline SAM/SOFTWARE hives"
)

# ---------------------------------------------------------------------------
# Minimal REGF hive parser (same engine as m07_service_analysis)
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
    if data_type == 3:
        return raw
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
# FILETIME conversion
# ---------------------------------------------------------------------------

_FILETIME_EPOCH = 116444736000000000  # 100-ns ticks from 1601-01-01 to 1970-01-01


def _filetime_to_iso(raw: Any) -> Optional[str]:
    """Convert a Windows FILETIME integer (100-ns ticks since 1601) to ISO 8601 string."""
    if not isinstance(raw, int) or raw <= 0:
        return None
    try:
        epoch_sec = (raw - _FILETIME_EPOCH) / 1e7
        if epoch_sec < 0:
            return None
        dt = datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _filetime_from_bytes(raw: bytes, offset: int) -> Optional[int]:
    if offset + 8 > len(raw):
        return None
    val = struct.unpack_from("<Q", raw, offset)[0]
    return val if val > 0 else None


# ---------------------------------------------------------------------------
# SAM F record parser
# ---------------------------------------------------------------------------
# The F record is stored as REG_BINARY under
# SAM\Domains\Account\Users\<RID_HEX>\F.
#
# Confirmed layout (Vista+):
#   0x00  WORD   version (2)
#   0x02  2      reserved
#   0x04  4      reserved
#   0x08  QWORD  last-logon FILETIME
#   0x10  QWORD  reserved
#   0x18  QWORD  password-last-set FILETIME
#   0x20  QWORD  account-expires FILETIME  (0 = never)
#   0x28  QWORD  password-must-change FILETIME
#   0x30  QWORD  last-bad-password FILETIME
#   0x38  DWORD  RID
#   0x3C  DWORD  account control flags

_ACF_DISABLED         = 0x0001
_ACF_NO_PASSWD_REQ    = 0x0020
_ACF_PASSWD_CANTCHG   = 0x0040
_ACF_PASSWD_NOEXPIRE  = 0x0200
_ACF_LOCKED           = 0x0010


def _parse_f_record(raw: bytes) -> dict:
    result: dict = {
        "last_logon": None,
        "password_last_set": None,
        "account_expires": None,
        "rid": None,
        "disabled": False,
        "locked": False,
        "password_not_required": False,
        "password_no_expire": False,
        "acf_raw": None,
    }
    if not isinstance(raw, bytes) or len(raw) < 0x40:
        return result
    try:
        result["last_logon"]        = _filetime_to_iso(_filetime_from_bytes(raw, 0x08))
        result["password_last_set"] = _filetime_to_iso(_filetime_from_bytes(raw, 0x18))
        _exp_ft = _filetime_from_bytes(raw, 0x20)
        result["account_expires"]   = _filetime_to_iso(_exp_ft) if _exp_ft else None
        if len(raw) >= 0x40:
            result["rid"] = struct.unpack_from("<I", raw, 0x38)[0]
        if len(raw) >= 0x40:
            acf = struct.unpack_from("<I", raw, 0x3C)[0]
            result["acf_raw"]              = acf
            result["disabled"]             = bool(acf & _ACF_DISABLED)
            result["locked"]               = bool(acf & _ACF_LOCKED)
            result["password_not_required"] = bool(acf & _ACF_NO_PASSWD_REQ)
            result["password_no_expire"]   = bool(acf & _ACF_PASSWD_NOEXPIRE)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# SAM V record parser — username, full name, comment
# ---------------------------------------------------------------------------
# V record layout (Vista/Win7):
#   0x00-0x03  version
#   ... (header items at fixed offsets, each: offset[4] + length[4] + type[4])
#   item[0] at 0x0C: username
#   item[1] at 0x18: full name
#   item[2] at 0x24: comment/description
#   item[3] at 0x30: user comment
#   item[4] at 0x3C: home directory
#   data blob starts at byte 0xCC

_V_DATA_START = 0xCC


def _v_get_string(raw: bytes, item_offset: int) -> Optional[str]:
    """Extract a UTF-16-LE string from a V record item slot."""
    if item_offset + 12 > len(raw):
        return None
    try:
        offset = struct.unpack_from("<I", raw, item_offset)[0]
        length = struct.unpack_from("<I", raw, item_offset + 4)[0]
        if length == 0:
            return None
        start = _V_DATA_START + offset
        end   = start + length
        if end > len(raw):
            return None
        return raw[start:end].decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return None


def _parse_v_record(raw: bytes) -> dict:
    return {
        "username":    _v_get_string(raw, 0x0C),
        "full_name":   _v_get_string(raw, 0x18),
        "comment":     _v_get_string(raw, 0x24),
        "home_dir":    _v_get_string(raw, 0x3C),
    }


# ---------------------------------------------------------------------------
# SAM Alias C record — member RID extraction
# Used to find who is in the local Administrators group (RID 0x220)
# ---------------------------------------------------------------------------
# The C record of SAM\Domains\Builtin\Aliases\00000220 lists member SIDs.
# Format:
#   0x00-0x03  version/revision (usually 3)
#   0x04-0x07  reserved
#   0x08-0x0B  reserved
#   ... (header info)
#   member count at a fixed offset, followed by variable-length SIDs
#
# SID structure: revision(1) + subauth_count(1) + authority(6) + subauths(4 each)
# The last sub-authority of a local account SID is the RID.

def _parse_alias_c_members(raw: bytes) -> List[int]:
    """Return list of RIDs from a SAM builtin alias C record."""
    rids: List[int] = []
    if not isinstance(raw, bytes) or len(raw) < 0x30:
        return rids
    try:
        # Member count is at offset 0x28 in most Vista/Win7 alias C records.
        count = struct.unpack_from("<I", raw, 0x28)[0]
        if count == 0 or count > 500:
            return rids
        # Member SID array starts immediately after a header.
        # The header is 0x34 bytes; SIDs follow sequentially.
        pos = 0x34
        for _ in range(count):
            if pos + 2 > len(raw):
                break
            revision    = raw[pos]
            subauth_cnt = raw[pos + 1]
            if revision != 1 or subauth_cnt == 0:
                break
            sid_len = 8 + subauth_cnt * 4
            if pos + sid_len > len(raw):
                break
            # Last sub-authority is the RID for domain/local accounts
            rid_off = pos + 8 + (subauth_cnt - 1) * 4
            rid = struct.unpack_from("<I", raw, rid_off)[0]
            rids.append(rid)
            pos += sid_len
    except Exception:
        pass
    return rids


# ---------------------------------------------------------------------------
# Well-known RIDs
# ---------------------------------------------------------------------------

_BUILTIN_ADMINS_RID = 0x220   # SAM\Domains\Builtin\Aliases\00000220
_RID_ADMIN          = 500     # Built-in Administrator
_RID_GUEST          = 501     # Built-in Guest

_WELL_KNOWN: dict[int, str] = {
    500: "Administrator",
    501: "Guest",
    503: "DefaultAccount",
    504: "WDAGUtilityAccount",
}


# ---------------------------------------------------------------------------
# Profile path from SOFTWARE hive
# ---------------------------------------------------------------------------

def _load_profile_list(target: Path) -> dict:
    """Return {SID_string: profile_path} from SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList."""
    sw_path = target / "Windows" / "System32" / "config" / "SOFTWARE"
    hive = _open_hive(sw_path)
    if hive is None:
        return {}
    key_off = hive.get_key_offset(
        "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    )
    if key_off is None:
        return {}
    result: dict = {}
    for sid_str in hive.list_subkey_names(key_off):
        sub_off = hive.get_subkey_offset(key_off, sid_str)
        if sub_off is None:
            continue
        vals = _values_dict(hive, sub_off)
        profile_path = vals.get("ProfileImagePath")
        if isinstance(profile_path, str) and profile_path:
            result[sid_str] = profile_path
    return result


# ---------------------------------------------------------------------------
# Build SID string for a local account
# ---------------------------------------------------------------------------

def _domain_subauths(sam_hive: _RegHive) -> Optional[List[int]]:
    """Read the domain sub-authorities from SAM\\Domains\\Account."""
    key_off = sam_hive.get_key_offset("Domains\\Account")
    if key_off is None:
        return None
    vals = _values_dict(sam_hive, key_off)
    v_data = vals.get("V")
    if not isinstance(v_data, bytes) or len(v_data) < 0x50:
        return None
    # Domain SID is stored in the V record of the Account key.
    # It starts at offset 0x48 as a standard SID structure.
    try:
        sid_off = 0x48
        rev     = v_data[sid_off]
        sub_cnt = v_data[sid_off + 1]
        if rev != 1 or sub_cnt < 3:
            return None
        subs: List[int] = []
        for i in range(sub_cnt):
            subs.append(struct.unpack_from("<I", v_data, sid_off + 8 + i * 4)[0])
        return subs
    except Exception:
        return None


def _make_local_sid(domain_subs: Optional[List[int]], rid: int) -> Optional[str]:
    if domain_subs is None:
        return None
    return "S-1-5-21-" + "-".join(str(s) for s in domain_subs) + f"-{rid}"


# ---------------------------------------------------------------------------
# Profile directory listing
# ---------------------------------------------------------------------------

def _profile_dirs(target: Path) -> List[str]:
    """Return names of directories under %SystemDrive%\\Users."""
    users_dir = target / "Users"
    if not users_dir.is_dir():
        users_dir = target / "Documents and Settings"
    if not users_dir.is_dir():
        return []
    return [d.name for d in users_dir.iterdir() if d.is_dir()]


# ---------------------------------------------------------------------------
# Suspicious-account heuristics
# ---------------------------------------------------------------------------

_SUSPICIOUS_PREFIXES = ("$", "temp", "test", "admin", "root", "hack", "crack")
_SYSTEM_ACCOUNTS = {"administrator", "guest", "defaultaccount", "wdagutilityaccount",
                    "system", "local service", "network service"}


def _flag_account(account: dict) -> List[str]:
    flags: List[str] = []
    name_lower = (account.get("username") or "").lower()

    if account.get("disabled"):
        flags.append("disabled")
    if account.get("locked"):
        flags.append("locked")
    if account.get("password_not_required"):
        flags.append("no_password_required")
    if account.get("last_logon") is None and not account.get("disabled"):
        flags.append("never_logged_on")
    if account.get("rid") == _RID_ADMIN and not account.get("disabled"):
        flags.append("builtin_admin_active")
    if account.get("rid") == _RID_GUEST and not account.get("disabled"):
        flags.append("guest_account_active")
    if account.get("is_admin") and name_lower not in _SYSTEM_ACCOUNTS:
        if not account.get("disabled"):
            flags.append("local_admin")
    if any(name_lower.startswith(p) for p in _SUSPICIOUS_PREFIXES) and \
            name_lower not in _SYSTEM_ACCOUNTS:
        flags.append("suspicious_name")
    if name_lower not in _SYSTEM_ACCOUNTS and \
            not account.get("profile_path") and \
            account.get("last_logon"):
        flags.append("no_profile_path")

    return flags


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(target: Path) -> dict:
    sam_path = target / "Windows" / "System32" / "config" / "SAM"
    limitations: List[str] = []

    sam = _open_hive(sam_path)
    if sam is None:
        return {
            "scan_status": "error",
            "error": f"Could not open SAM hive at {sam_path}",
            "accounts": [],
            "summary": {},
            "limitations": [f"SAM hive not readable: {sam_path}"],
        }

    # ---- Domain sub-authorities (needed to build SID strings) ----
    domain_subs = _domain_subauths(sam)
    if domain_subs is None:
        limitations.append("Could not read domain SID sub-authorities; SID strings unavailable")

    # ---- Profile list from SOFTWARE hive ----
    profile_list = _load_profile_list(target)

    # ---- Profile directories on disk ----
    on_disk_dirs = set(d.lower() for d in _profile_dirs(target))

    # ---- Determine which RIDs are in local Administrators group ----
    admin_rids: set[int] = set()
    admins_key = sam.get_key_offset("Domains\\Builtin\\Aliases\\00000220")
    if admins_key is not None:
        vals = _values_dict(sam, admins_key)
        c_data = vals.get("C")
        if isinstance(c_data, bytes):
            admin_rids = set(_parse_alias_c_members(c_data))
    else:
        limitations.append("Could not read Builtin\\Administrators alias — admin membership unknown")

    # ---- Enumerate user accounts ----
    names_key = sam.get_key_offset("Domains\\Account\\Users\\Names")
    users_key  = sam.get_key_offset("Domains\\Account\\Users")

    accounts: List[dict] = []

    if names_key is None or users_key is None:
        limitations.append("SAM\\Domains\\Account\\Users not found — no accounts enumerated")
    else:
        for username in sam.list_subkey_names(names_key):
            try:
                name_subkey = sam.get_subkey_offset(names_key, username)
                if name_subkey is None:
                    continue
                # The default value's *type* field encodes the RID for user Names keys
                name_vals = sam.list_values(name_subkey)
                rid: Optional[int] = None
                for vname, dtype, _vdata in name_vals:
                    if vname == "":   # default value
                        rid = dtype   # type field carries the RID
                        break

                f_rec: dict = {}
                v_rec: dict = {}
                if rid is not None:
                    rid_hex = f"{rid:08X}"
                    user_key = sam.get_subkey_offset(users_key, rid_hex)
                    if user_key is not None:
                        uvals = _values_dict(sam, user_key)
                        f_data = uvals.get("F")
                        if isinstance(f_data, bytes):
                            f_rec = _parse_f_record(f_data)
                            # F record RID should match; trust name-derived RID
                            f_rec["rid"] = rid
                        v_data = uvals.get("V")
                        if isinstance(v_data, bytes):
                            v_rec = _parse_v_record(v_data)

                sid_str = _make_local_sid(domain_subs, rid) if rid is not None else None

                # Match profile path from ProfileList
                profile_path: Optional[str] = None
                profile_exists: Optional[bool] = None
                if sid_str and sid_str in profile_list:
                    profile_path = profile_list[sid_str]
                    # Check if profile dir exists on disk
                    profile_dir_name = Path(profile_path.replace("\\", "/")).name
                    profile_exists = profile_dir_name.lower() in on_disk_dirs

                is_admin = (rid in admin_rids) if rid is not None else False
                # Well-known Administrator (RID 500) is always admin
                if rid == _RID_ADMIN:
                    is_admin = True

                account = {
                    "username":             username,
                    "full_name":            v_rec.get("full_name"),
                    "comment":              v_rec.get("comment"),
                    "home_dir":             v_rec.get("home_dir"),
                    "rid":                  rid,
                    "sid":                  sid_str,
                    "is_admin":             is_admin,
                    "disabled":             f_rec.get("disabled", False),
                    "locked":               f_rec.get("locked", False),
                    "password_not_required": f_rec.get("password_not_required", False),
                    "password_no_expire":   f_rec.get("password_no_expire", False),
                    "last_logon":           f_rec.get("last_logon"),
                    "password_last_set":    f_rec.get("password_last_set"),
                    "account_expires":      f_rec.get("account_expires"),
                    "profile_path":         profile_path,
                    "profile_dir_exists":   profile_exists,
                    "flags":                [],
                }
                account["flags"] = _flag_account(account)
                accounts.append(account)

            except Exception as exc:
                accounts.append({
                    "username": username,
                    "parse_error": str(exc),
                    "flags": ["parse_error"],
                })

    # Sort: admins first, then by username
    accounts.sort(key=lambda a: (not a.get("is_admin", False),
                                  (a.get("username") or "").lower()))

    # ---- Summary ----
    total       = len(accounts)
    enabled     = sum(1 for a in accounts if not a.get("disabled") and "parse_error" not in a)
    admins      = sum(1 for a in accounts if a.get("is_admin"))
    active_admins = sum(1 for a in accounts if a.get("is_admin") and not a.get("disabled"))
    never_logon = sum(1 for a in accounts if a.get("last_logon") is None and not a.get("disabled"))
    flagged     = [a for a in accounts if a.get("flags") and a["flags"] != ["disabled"]]

    summary = {
        "total_accounts":   total,
        "enabled_accounts": enabled,
        "admin_accounts":   admins,
        "active_admins":    active_admins,
        "never_logged_on":  never_logon,
        "flagged_accounts": len(flagged),
    }

    # ---- Overall verdict ----
    verdict = "OK"
    if active_admins > 1:
        verdict = "WARNING"   # multiple active admin accounts
    if any("suspicious_name" in (a.get("flags") or []) for a in accounts):
        verdict = "WARNING"
    if any("guest_account_active" in (a.get("flags") or []) for a in accounts):
        verdict = "WARNING"

    return {
        "scan_status": "ok",
        "verdict":     verdict,
        "accounts":    accounts,
        "summary":     summary,
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Report printing
# ---------------------------------------------------------------------------

def _print_report(data: dict) -> None:
    accts = data.get("accounts", [])
    print("\n=== USER ACCOUNT ANALYSIS ===")
    print(f"Verdict : {data.get('verdict', '?')}")
    s = data.get("summary", {})
    print(f"Accounts: {s.get('total_accounts', 0)} total, "
          f"{s.get('enabled_accounts', 0)} enabled, "
          f"{s.get('admin_accounts', 0)} admin, "
          f"{s.get('active_admins', 0)} active-admin")
    print()
    for a in accts:
        if "parse_error" in a:
            print(f"  {a['username']!s:20}  [PARSE ERROR: {a['parse_error']}]")
            continue
        admin_mark = " [ADMIN]"  if a.get("is_admin") else ""
        dis_mark   = " [DISABLED]" if a.get("disabled")  else ""
        lock_mark  = " [LOCKED]"   if a.get("locked")     else ""
        print(f"  {a['username']!s:20}{admin_mark}{dis_mark}{lock_mark}")
        if a.get("full_name"):
            print(f"    Full name: {a['full_name']}")
        if a.get("comment"):
            print(f"    Comment  : {a['comment']}")
        print(f"    RID      : {a.get('rid')}")
        print(f"    Last logon: {a.get('last_logon') or 'never/unknown'}")
        print(f"    Pwd set   : {a.get('password_last_set') or 'unknown'}")
        if a.get("profile_path"):
            exists = "exists" if a.get("profile_dir_exists") else "MISSING"
            print(f"    Profile  : {a['profile_path']}  [{exists}]")
        extra_flags = [f for f in (a.get("flags") or [])
                       if f not in ("disabled", "locked", "local_admin")]
        if extra_flags:
            print(f"    Flags    : {', '.join(extra_flags)}")
        print()

    limits = data.get("limitations", [])
    if limits:
        print("Limitations:")
        for lim in limits:
            print(f"  - {lim}")


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    """
    Run user account analysis against an offline Windows installation.

    root   — USB root (for writing logs)
    argv   — extra CLI args (e.g. ['--target', '/mnt/windows'])
    """
    from toolkit import find_windows_target  # noqa: PLC0415

    parser = argparse.ArgumentParser(
        prog="m33_user_account_analysis",
        description=DESCRIPTION,
    )
    parser.add_argument("--target", default="",
                        help="Path to mounted Windows partition (auto-detect if omitted)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary only, not full account list")
    args = parser.parse_args(argv)

    target_str = args.target.strip()
    if not target_str:
        target_path = find_windows_target()
        if target_path is None:
            print("ERROR: Could not auto-detect Windows installation. Pass --target.")
            return 2
        print(f"[m33] Auto-detected Windows target: {target_path}")
    else:
        target_path = Path(target_str)

    if not target_path.exists():
        print(f"ERROR: Target does not exist: {target_path}")
        return 2

    import time
    from datetime import datetime as _dt, timezone as _tz

    print(f"[m33] Analysing user accounts in {target_path} ...")
    data = analyse(target_path)

    data["generated"] = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["target"]    = str(target_path)

    if not args.summary:
        _print_report(data)

    # Write JSON log
    logs_dir = root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = logs_dir / f"user_account_analysis_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"[m33] Log written: {out_path}")

    # Return non-zero if warning or error
    return 0 if data.get("verdict") in ("OK", None) else 1
