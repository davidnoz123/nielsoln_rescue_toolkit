"""
tests/test_m07_service_analysis.py — Unit tests for m07_service_analysis helpers.

Tests the logic functions directly (no real registry hive or live filesystem
required).  Fixtures create minimal synthetic data or mock the filesystem.

Run:
    pytest tests/test_m07_service_analysis.py -v
"""
import struct
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Make modules/ importable from the repo root when running pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
import modules.m07_service_analysis as m07

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vals(**kw):
    """Build a fake _values_dict return value."""
    return kw


# ---------------------------------------------------------------------------
# 1. _check_unquoted_path
# ---------------------------------------------------------------------------

class TestCheckUnquotedPath:
    def test_quoted_path_is_safe(self):
        assert m07._check_unquoted_path('"C:\\Program Files\\svc\\svc.exe"') is False

    def test_no_spaces_is_safe(self):
        assert m07._check_unquoted_path("C:\\Windows\\System32\\svchost.exe") is False

    def test_unquoted_with_spaces_is_risk(self):
        assert m07._check_unquoted_path("C:\\Program Files\\MyApp\\svc.exe") is True

    def test_svchost_k_pattern_is_safe(self):
        # svchost -k <group> is never a real unquoted path risk
        assert m07._check_unquoted_path(
            "C:\\Windows\\system32\\svchost.exe -k netsvcs"
        ) is False

    def test_quoted_with_spaces_is_safe(self):
        assert m07._check_unquoted_path(
            '"C:\\Program Files\\My App\\service.exe" -arg'
        ) is False

    def test_empty_is_safe(self):
        assert m07._check_unquoted_path("") is False


# ---------------------------------------------------------------------------
# 2. _extract_exe_from_image_path
# ---------------------------------------------------------------------------

class TestExtractExe:
    def test_quoted(self):
        assert m07._extract_exe_from_image_path(
            '"C:\\path\\svc.exe" --arg'
        ) == "C:\\path\\svc.exe"

    def test_unquoted_with_args(self):
        result = m07._extract_exe_from_image_path(
            "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted"
        )
        assert result == "C:\\Windows\\system32\\svchost.exe"

    def test_env_var_path(self):
        result = m07._extract_exe_from_image_path(
            "%SystemRoot%\\system32\\lsass.exe"
        )
        assert result == "%SystemRoot%\\system32\\lsass.exe"

    def test_empty(self):
        assert m07._extract_exe_from_image_path("") == ""


# ---------------------------------------------------------------------------
# 3. _parse_failure_actions
# ---------------------------------------------------------------------------

class TestParseFailureActions:
    def _make_binary(self, reset_period, actions):
        """Build a FailureActions REG_BINARY blob."""
        buf = struct.pack("<IIII", reset_period, 0, 0, len(actions))
        for atype, delay in actions:
            buf += struct.pack("<II", atype, delay)
        return buf

    def test_none_returns_none(self):
        assert m07._parse_failure_actions(None) is None

    def test_too_short_returns_none(self):
        assert m07._parse_failure_actions(b"\x00" * 8) is None

    def test_restart_action(self):
        raw = self._make_binary(86400, [(1, 60000), (1, 120000)])
        result = m07._parse_failure_actions(raw)
        assert result is not None
        assert result["reset_period_sec"] == 86400
        assert len(result["actions"]) == 2
        assert result["actions"][0]["type"] == "RESTART"
        assert result["actions"][0]["delay_ms"] == 60000

    def test_reboot_action(self):
        raw = self._make_binary(0, [(2, 0)])
        result = m07._parse_failure_actions(raw)
        assert result["actions"][0]["type"] == "REBOOT"

    def test_no_actions(self):
        raw = self._make_binary(3600, [])
        result = m07._parse_failure_actions(raw)
        assert result["reset_period_sec"] == 3600
        assert result["actions"] == []

    def test_hex_string_input(self):
        raw  = self._make_binary(86400, [(1, 30000)])
        hexs = raw.hex()
        result = m07._parse_failure_actions(hexs)
        assert result is not None
        assert result["actions"][0]["type"] == "RESTART"


# ---------------------------------------------------------------------------
# 4. _parse_pe_version_strings
# ---------------------------------------------------------------------------

class TestParsePeVersionStrings:
    def _build_string_struct(self, key: str, value: str) -> bytes:
        """Build a minimal VS_VERSION_INFO String struct (with DWORD alignment)."""
        key_bytes   = (key + "\x00").encode("utf-16-le")
        value_bytes = (value + "\x00").encode("utf-16-le")
        # The value is DWORD-aligned from the struct start (6-byte header)
        after_key   = 6 + len(key_bytes)
        aligned_off = (after_key + 3) & ~3
        padding     = aligned_off - after_key
        total_len   = aligned_off + len(value_bytes)
        header      = struct.pack("<HHH", total_len, len(value) + 1, 1)
        return header + key_bytes + b"\x00" * padding + value_bytes

    def test_finds_company_name(self):
        chunk = self._build_string_struct("CompanyName", "ACME Corp")
        # Pad so the struct header is actually at p-6
        data = b"\x00" * 100 + chunk + b"\x00" * 100
        result = m07._parse_pe_version_strings(data)
        assert result.get("CompanyName") == "ACME Corp"

    def test_empty_data_returns_empty(self):
        assert m07._parse_pe_version_strings(b"") == {}

    def test_no_version_info_returns_empty(self):
        assert m07._parse_pe_version_strings(b"\x00" * 1024) == {}


# ---------------------------------------------------------------------------
# 5. _classify_image_path (safe / suspicious / exists)
# ---------------------------------------------------------------------------

class TestClassifyImagePath:
    def _fake_target(self, tmp_path):
        # Create a Windows layout under tmp_path
        sys32 = tmp_path / "Windows" / "System32"
        sys32.mkdir(parents=True)
        return tmp_path

    def test_safe_system32_path(self, tmp_path):
        target = self._fake_target(tmp_path)
        result = m07._classify_image_path(
            "C:\\Windows\\System32\\svchost.exe -k netsvcs", target
        )
        assert result["safe"] is True
        assert result["suspicious_reason"] is None
        assert result["unquoted_path_risk"] is False
        # exists depends on filesystem resolution; just confirm it's not True for
        # a path that doesn't actually exist under tmp_path
        assert result["exists"] is not True

    def test_temp_path_is_suspicious(self, tmp_path):
        result = m07._classify_image_path(
            "C:\\Temp\\evil.exe", tmp_path
        )
        assert result["suspicious_reason"] is not None

    def test_missing_binary(self, tmp_path):
        result = m07._classify_image_path(
            "C:\\Windows\\System32\\missing_xyz_none.exe", tmp_path
        )
        # exists should be False (file absent) or None (path resolution failed)
        assert result["exists"] in (False, None)

    def test_unquoted_path_flagged(self, tmp_path):
        result = m07._classify_image_path(
            "C:\\Program Files\\App\\svc.exe", tmp_path
        )
        assert result["unquoted_path_risk"] is True


# ---------------------------------------------------------------------------
# 6. _build_full_config — dependencies, delayed autostart
# ---------------------------------------------------------------------------

class TestBuildFullConfig:
    def test_dependencies(self):
        vals = _make_vals(
            Start=2,
            Type=0x20,
            DependOnService=["RpcSs", "NTDS"],
            DependOnGroup=["NetworkProvider"],
        )
        cfg = m07._build_full_config(vals)
        assert cfg["depend_on_service"] == ["RpcSs", "NTDS"]
        assert cfg["depend_on_group"]   == ["NetworkProvider"]

    def test_delayed_auto_start(self):
        vals = _make_vals(Start=2, Type=0x20, DelayedAutostart=1)
        cfg  = m07._build_full_config(vals)
        assert cfg["delayed_auto_start"] is True

    def test_kernel_driver(self):
        vals = _make_vals(Start=0, Type=0x01)
        cfg  = m07._build_full_config(vals)
        assert "KERNEL_DRIVER" in cfg["type_flags"]
        assert cfg["start_name"] == "BOOT"

    def test_auto_start_service(self):
        vals = _make_vals(Start=2, Type=0x20, ObjectName="LocalSystem")
        cfg  = m07._build_full_config(vals)
        assert cfg["start_name"] == "AUTO"
        assert "WIN32_SHARE_PROCESS" in cfg["type_flags"]
        assert cfg["object_name"]   == "LocalSystem"


# ---------------------------------------------------------------------------
# 7. _build_flags — flag combinations
# ---------------------------------------------------------------------------

class TestBuildFlags:
    def _dummy_config(self, start="AUTO"):
        return {"start_name": start}

    def test_missing_binary_gets_both_flags(self):
        path_info = {"exists": False, "suspicious_reason": None,
                     "safe": True, "location": "system32",
                     "suspicious_location": False, "unquoted_path_risk": False}
        flags = m07._build_flags(path_info, self._dummy_config(), None,
                                 0x20, "netsvcs", None, "C:\\Windows\\svc.exe")
        assert "MISSING_BINARY" in flags
        assert "DELETED" in flags

    def test_unquoted_path_flag(self):
        path_info = {"exists": True, "suspicious_reason": None,
                     "safe": False, "location": "program_files",
                     "suspicious_location": False, "unquoted_path_risk": True}
        flags = m07._build_flags(path_info, self._dummy_config(), None,
                                 0x10, None, None, "C:\\Program Files\\svc.exe")
        assert "UNQUOTED_PATH" in flags

    def test_has_failure_events_flag(self):
        path_info = {"exists": True, "suspicious_reason": None,
                     "safe": True, "location": "system32",
                     "suspicious_location": False, "unquoted_path_risk": False}
        event_history = {"event_counts": {"7000": 2}, "recent_events": []}
        flags = m07._build_flags(path_info, self._dummy_config(), None,
                                 0x20, "netsvcs", event_history,
                                 "C:\\Windows\\system32\\svchost.exe")
        assert "HAS_FAILURE_EVENTS" in flags

    def test_svchost_no_group_when_group_none(self):
        path_info = {"exists": True, "suspicious_reason": None,
                     "safe": True, "location": "system32",
                     "suspicious_location": False, "unquoted_path_risk": False}
        flags = m07._build_flags(
            path_info, self._dummy_config(), None, 0x20, None, None,
            "C:\\Windows\\system32\\svchost.exe -k unknowngroup"
        )
        assert "SVCHOST_NO_GROUP" in flags

    def test_svchost_with_valid_group_no_flag(self):
        path_info = {"exists": True, "suspicious_reason": None,
                     "safe": True, "location": "system32",
                     "suspicious_location": False, "unquoted_path_risk": False}
        flags = m07._build_flags(
            path_info, self._dummy_config(), None, 0x20, "netsvcs", None,
            "C:\\Windows\\system32\\svchost.exe -k netsvcs"
        )
        assert "SVCHOST_NO_GROUP" not in flags

    def test_missing_service_dll_flag(self):
        path_info = {"exists": True, "suspicious_reason": None,
                     "safe": True, "location": "system32",
                     "suspicious_location": False, "unquoted_path_risk": False}
        dll = {"file_evidence": {"exists": False}}
        flags = m07._build_flags(path_info, self._dummy_config(), dll,
                                 0x20, "netsvcs", None,
                                 "C:\\Windows\\system32\\svchost.exe")
        assert "MISSING_SERVICE_DLL" in flags

    def test_disabled_flag(self):
        path_info = {"exists": True, "suspicious_reason": None,
                     "safe": True, "location": "system32",
                     "suspicious_location": False, "unquoted_path_risk": False}
        flags = m07._build_flags(path_info, self._dummy_config("DISABLED"), None,
                                 0x20, None, None, "C:\\Windows\\svc.exe")
        assert "DISABLED" in flags


# ---------------------------------------------------------------------------
# 8. _summarise — counts and verdict
# ---------------------------------------------------------------------------

class TestSummarise:
    def _make_service(self, name, start="AUTO", flags=None, image_path="C:\\svc.exe"):
        return {
            "name": name, "display_name": name, "start": start,
            "type": "OWN_PROCESS", "image_path": image_path,
            "flags": flags or [],
        }

    def test_clean_verdict(self):
        services = [self._make_service("svcA"), self._make_service("svcB")]
        summary  = m07._summarise(services)
        assert summary["verdict"]  == "CLEAN"
        assert summary["total"]    == 2

    def test_review_verdict_for_missing_binary(self):
        services = [self._make_service("bad", flags=["MISSING_BINARY", "DELETED"])]
        summary  = m07._summarise(services)
        assert summary["verdict"] == "REVIEW"
        assert summary["missing_binaries"] == 1

    def test_suspicious_verdict_threshold(self):
        services = [self._make_service(f"s{i}", flags=["SUSPICIOUS"]) for i in range(3)]
        summary  = m07._summarise(services)
        assert summary["verdict"]          == "SUSPICIOUS"
        assert summary["suspicious_count"] == 3

    def test_unquoted_count(self):
        services = [self._make_service("s", flags=["UNQUOTED_PATH"])]
        summary  = m07._summarise(services)
        assert summary["unquoted_path_risks"] == 1

    def test_driver_counts(self):
        boot  = self._make_service("d1", start="BOOT",   flags=["DRIVER"])
        sys_d = self._make_service("d2", start="SYSTEM", flags=["DRIVER"])
        svc   = self._make_service("s1", start="AUTO",   flags=[])
        summary = m07._summarise([boot, sys_d, svc])
        assert summary["boot_drivers"]   == 1
        assert summary["system_drivers"] == 1

    def test_failure_event_count(self):
        services = [
            self._make_service("bad", flags=["HAS_FAILURE_EVENTS"]),
            self._make_service("good"),
        ]
        summary = m07._summarise(services)
        assert summary["failure_event_count"] == 1
