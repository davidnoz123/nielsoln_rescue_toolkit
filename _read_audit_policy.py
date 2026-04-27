"""
Read Windows Vista audit policy from an offline Windows installation.

Sources checked:
  1. SECURITY hive -> Policy\PolAdtEv   (9 classic audit categories)
  2. System32\GroupPolicy\...\audit.csv (Advanced Audit Policy, if configured)

Run via devtools.py: action = "run_remote", remote_script = "_read_audit_policy.py"
"""

import struct
import sys
from pathlib import Path

TARGET = Path("/mnt/windows")

# ---------------------------------------------------------------------------
# Minimal REGF parser (read-only)
# ---------------------------------------------------------------------------
_HIVE_BINS_OFFSET = 0x1000


class _RegHive:
    __slots__ = ("_data", "_root_offset")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._root_offset = struct.unpack_from("<I", data, 0x24)[0]

    def _cell(self, offset):
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

    def _str_at(self, abs_offset, length, is_ascii):
        if abs_offset + length > len(self._data):
            return ""
        raw = bytes(self._data[abs_offset: abs_offset + length])
        enc = "ascii" if is_ascii else "utf-16-le"
        return raw.decode(enc, errors="replace").rstrip("\x00")

    def _nk_info(self, offset):
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

    def _subkey_offsets(self, list_offset):
        if list_offset == 0xFFFFFFFF:
            return []
        cell = self._cell(list_offset)
        if cell is None or len(cell) < 4:
            return []
        sig   = bytes(cell[0:2])
        count = struct.unpack_from("<H", cell, 2)[0]
        offsets = []
        try:
            if sig in (b"lf", b"lh"):
                for i in range(count):
                    pos = 4 + i * 8
                    if pos + 4 > len(cell):
                        break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"li":
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 > len(cell):
                        break
                    offsets.append(struct.unpack_from("<I", cell, pos)[0])
            elif sig == b"ri":
                for i in range(count):
                    pos = 4 + i * 4
                    if pos + 4 > len(cell):
                        break
                    offsets.extend(self._subkey_offsets(struct.unpack_from("<I", cell, pos)[0]))
        except Exception:
            pass
        return offsets

    def _find_subkey_offset(self, parent_offset, name):
        nk = self._nk_info(parent_offset)
        if nk is None:
            return None
        name_lower = name.lower()
        for sub_off in self._subkey_offsets(nk["subkeys_offset"]):
            sub_nk = self._nk_info(sub_off)
            if sub_nk and sub_nk["name"].lower() == name_lower:
                return sub_off
        return None

    def get_key_offset(self, path):
        parts = [p for p in path.split("\\") if p]
        current = self._root_offset
        for part in parts:
            found = self._find_subkey_offset(current, part)
            if found is None:
                return None
            current = found
        return current

    def get_value_raw(self, path, value_name):
        """Return raw bytes of a REG_BINARY value, or None."""
        offset = self.get_key_offset(path)
        if offset is None:
            return None
        nk = self._nk_info(offset)
        if nk is None or nk["values_count"] == 0 or nk["values_list_offset"] == 0xFFFFFFFF:
            return None
        vlist_cell = self._cell(nk["values_list_offset"])
        if vlist_cell is None:
            return None
        vn_lower = value_name.lower()
        for i in range(nk["values_count"]):
            pos = i * 4
            if pos + 4 > len(vlist_cell):
                break
            try:
                vk_off = struct.unpack_from("<I", vlist_cell, pos)[0]
                cell = self._cell(vk_off)
                if cell is None or len(cell) < 0x18 or bytes(cell[0:2]) != b"vk":
                    continue
                name_len     = struct.unpack_from("<H", cell, 2)[0]
                data_size_raw= struct.unpack_from("<I", cell, 4)[0]
                data_offset  = struct.unpack_from("<I", cell, 8)[0]
                flags_vk     = struct.unpack_from("<H", cell, 16)[0]
                is_ascii     = bool(flags_vk & 0x0001)
                if name_len > 0:
                    abs_name = _HIVE_BINS_OFFSET + vk_off + 4 + 0x14
                    vname = self._str_at(abs_name, name_len, is_ascii)
                else:
                    vname = ""
                if vname.lower() != vn_lower:
                    continue
                inline      = bool(data_size_raw & 0x80000000)
                actual_size = data_size_raw & 0x7FFFFFFF
                if inline:
                    return struct.pack("<I", data_offset)[:actual_size]
                data_cell = self._cell(data_offset)
                if data_cell is None:
                    return None
                return bytes(data_cell[:actual_size])
            except Exception:
                pass
        return None


def _open_hive(path):
    try:
        data = path.read_bytes()
        if len(data) < 0x1000 or data[:4] != b"regf":
            return None
        return _RegHive(data)
    except Exception as exc:
        print(f"  [!] Cannot open hive {path}: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Decode PolAdtEv blob
# ---------------------------------------------------------------------------
# Vista uses 9 classic audit categories.  The PolAdtEv value is a binary blob
# of the form:
#   [optional 4-byte header] followed by entries of (success:WORD, failure:WORD)
#   one per category (9 categories = 36 bytes after the header).
#
# Some versions have a 4-byte header (format marker 0x00000002), others skip it.
# We detect by checking total blob length.

_CATEGORY_NAMES = [
    "System",
    "Logon/Logoff",
    "Object Access",
    "Privilege Use",
    "Detailed Tracking",
    "Policy Change",
    "Account Management",
    "Directory Service Access",
    "Account Logon",
]

_FLAG_LABELS = {0: "No Auditing", 1: "Success", 2: "Failure", 3: "Success and Failure"}


def _decode_pol_adt_ev(raw: bytes) -> list:
    """Decode PolAdtEv binary blob into list of (category, success, failure) tuples."""
    if not raw:
        return []

    # Try to find the start of category entries.
    # The blob may have a 4-byte header; category data is 9 pairs of WORDs = 36 bytes.
    # Try with and without 4-byte header.
    results = []
    for skip in (0, 4, 8):
        data = raw[skip:]
        if len(data) < 9 * 4:
            continue
        entries = []
        ok = True
        for i in range(9):
            offset = i * 4
            success = struct.unpack_from("<H", data, offset)[0]
            failure = struct.unpack_from("<H", data, offset + 2)[0]
            # Sanity: values should be 0-3
            if success > 3 or failure > 3:
                ok = False
                break
            entries.append((
                _CATEGORY_NAMES[i],
                bool(success),
                bool(failure),
            ))
        if ok:
            results = entries
            break

    return results


def _print_policy_table(entries: list) -> None:
    col1 = max(len(e[0]) for e in entries) + 2
    header = f"{'Category':<{col1}}  {'Success':^9}  {'Failure':^9}"
    print(header)
    print("-" * len(header))
    for cat, suc, fail in entries:
        s = "YES" if suc else "no"
        f = "YES" if fail else "no"
        marker = ""
        if not suc and not fail:
            marker = "  <-- not audited"
        elif not fail:
            marker = "  <-- failure NOT audited"
        print(f"{cat:<{col1}}  {s:^9}  {f:^9}{marker}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Windows Audit Policy Reader")
    print(f"Target: {TARGET}")
    print("=" * 60)

    # --- 1. SECURITY hive → Policy\PolAdtEv ---
    sec_hive_path = TARGET / "Windows/System32/config/SECURITY"
    print(f"\n[1] SECURITY hive: {sec_hive_path}")
    hive = _open_hive(sec_hive_path)
    if hive:
        raw = hive.get_value_raw("Policy", "PolAdtEv")
        if raw is None:
            print("    PolAdtEv value not found under Policy key.")
        else:
            print(f"    PolAdtEv raw ({len(raw)} bytes): {raw.hex(' ')}")
            entries = _decode_pol_adt_ev(raw)
            if entries:
                print()
                print("    Classic Audit Policy (9 categories):")
                print()
                # indent
                for cat, suc, fail in entries:
                    s = "YES" if suc else "no"
                    f = "YES" if fail else "no"
                    note = ""
                    if not suc and not fail:
                        note = "  ← NOT audited"
                    elif not fail:
                        note = "  ← failure NOT audited"
                    print(f"      {cat:<30}  Success={s:<3}  Failure={f:<3}{note}")
            else:
                print("    Could not decode PolAdtEv blob (unexpected format).")
    else:
        print("    Could not open SECURITY hive.")

    # --- 2. Advanced Audit Policy CSV ---
    print("\n[2] Advanced Audit Policy CSV files:")
    csv_patterns = [
        TARGET / "Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv",
        TARGET / "Windows/SysWOW64/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv",
    ]
    # Also check per-user GP
    gp_user_root = TARGET / "Windows/System32/GroupPolicyUsers"
    if gp_user_root.is_dir():
        for sid_dir in gp_user_root.iterdir():
            p = sid_dir / "Machine/Microsoft/Windows NT/Audit/audit.csv"
            if p not in csv_patterns:
                csv_patterns.append(p)

    found_any_csv = False
    for csv_path in csv_patterns:
        if csv_path.exists():
            found_any_csv = True
            print(f"\n    Found: {csv_path}")
            try:
                text = csv_path.read_text(encoding="utf-8-sig", errors="replace")
                print(text)
            except Exception as exc:
                print(f"    Error reading: {exc}")

    if not found_any_csv:
        print("    No audit.csv found — Advanced Audit Policy not configured via Group Policy.")

    # --- 3. Local Security Policy INF (if exported) ---
    print("\n[3] Checking for exported security policy (security.inf):")
    inf_paths = [
        TARGET / "Windows/security/database/secedit.sdb",  # not text, skip
        TARGET / "Windows/security/templates/setup security.inf",
        TARGET / "Windows/inf/defltbase.inf",
    ]
    # Look for any .inf in Windows/security
    sec_dir = TARGET / "Windows/security"
    if sec_dir.is_dir():
        for p in sec_dir.rglob("*.inf"):
            inf_paths.append(p)

    found_inf = False
    for inf_path in inf_paths:
        if inf_path.exists() and inf_path.suffix.lower() == ".inf":
            found_inf = True
            print(f"\n    Found: {inf_path}")
            try:
                text = inf_path.read_text(encoding="utf-8-sig", errors="replace")
                # Only print the [Event Audit] section if present
                lines = text.splitlines()
                in_section = False
                printed = 0
                for line in lines:
                    if line.strip().lower() == "[event audit]":
                        in_section = True
                        print(f"    {line}")
                        continue
                    if in_section:
                        if line.strip().startswith("[") and line.strip() != "[Event Audit]":
                            break
                        print(f"    {line}")
                        printed += 1
                if not printed and not in_section:
                    print("    (no [Event Audit] section found in this file)")
            except Exception as exc:
                print(f"    Error reading: {exc}")

    if not found_inf:
        print("    No .inf policy files found.")

    print("\n[done]")


main()
