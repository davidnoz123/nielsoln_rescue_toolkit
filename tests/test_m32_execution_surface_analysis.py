"""
test_m32_execution_surface_analysis.py — Unit tests for m32_execution_surface_analysis.

Run with:
    import runpy ; temp = runpy._run_module_as_main("pytest")
    # or directly:
    pytest tests/test_m32_execution_surface_analysis.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO / "modules"))

import m32_execution_surface_analysis as m32

# ---------------------------------------------------------------------------
# 1. _win_to_linux — Windows path → Linux path under target
# ---------------------------------------------------------------------------

class TestWinToLinux:
    TARGET = Path("/mnt/windows")

    def test_drive_letter_system32(self):
        result = m32._win_to_linux(r"C:\Windows\System32\ntdll.dll", self.TARGET)
        assert result == "/mnt/windows/Windows/System32/ntdll.dll"

    def test_drive_letter_program_files(self):
        result = m32._win_to_linux(r"C:\Program Files\Foo\bar.exe", self.TARGET)
        assert result == "/mnt/windows/Program Files/Foo/bar.exe"

    def test_systemroot_backslash(self):
        result = m32._win_to_linux(r"\SystemRoot\system32\svchost.exe", self.TARGET)
        assert result is not None
        assert result.endswith("Windows/system32/svchost.exe")

    def test_percent_systemroot(self):
        result = m32._win_to_linux(r"%SystemRoot%\System32\foo.exe", self.TARGET)
        assert result is not None
        assert "Windows/System32/foo.exe" in result

    def test_percent_windir(self):
        result = m32._win_to_linux(r"%windir%\System32\bar.exe", self.TARGET)
        assert result is not None
        assert "Windows/System32/bar.exe" in result

    def test_kernel_namespace_prefix(self):
        result = m32._win_to_linux(r"\\??\C:\Windows\System32\ntdll.dll", self.TARGET)
        assert result is not None
        assert "Windows/System32/ntdll.dll" in result

    def test_empty_path_returns_none(self):
        assert m32._win_to_linux("", self.TARGET) is None

    def test_none_like_empty_returns_none(self):
        assert m32._win_to_linux("   ", self.TARGET) is None

    def test_quoted_path(self):
        result = m32._win_to_linux(r'"C:\Windows\System32\svchost.exe" -k netsvcs', self.TARGET)
        # The function strips leading quote and handles quoted paths
        # This is a path with args — it's passed as-is after quote strip
        assert result is not None

    def test_lowercase_drive_letter(self):
        result = m32._win_to_linux(r"c:\windows\system32\foo.exe", self.TARGET)
        assert result is not None
        assert "windows/system32/foo.exe" in result.lower()

    def test_percent_systemdrive(self):
        result = m32._win_to_linux(r"%SystemDrive%\Windows\System32\foo.exe", self.TARGET)
        assert result is not None


# ---------------------------------------------------------------------------
# 2. _relpath_under_windows
# ---------------------------------------------------------------------------

class TestRelpathUnderWindows:
    def test_system32_file(self):
        result = m32._relpath_under_windows(r"C:\Windows\System32\ntdll.dll")
        assert result == "System32/ntdll.dll"

    def test_system32_lowercase(self):
        result = m32._relpath_under_windows(r"c:\windows\system32\ntdll.dll")
        assert result is not None
        assert "system32/ntdll.dll" in result.lower()

    def test_not_under_windows(self):
        result = m32._relpath_under_windows(r"C:\Program Files\Foo\bar.exe")
        assert result is None

    def test_winsxs_path(self):
        result = m32._relpath_under_windows(r"C:\Windows\WinSxS\x86_foo\ntdll.dll")
        assert result is not None
        assert result.startswith("WinSxS")

    def test_empty_string(self):
        result = m32._relpath_under_windows("")
        assert result is None


# ---------------------------------------------------------------------------
# 3. _was_path_scanned — scan coverage lookup
# ---------------------------------------------------------------------------

class TestWasPathScanned:
    def _make_index(self, scanned=None, perm=None, size=None, has_clamav=True):
        return {
            "scanned_dirs": set(scanned or []),
            "perm_denied":  set(perm or []),
            "size_skipped": set(size or []),
            "has_clamav":   has_clamav,
            "scan_status":  "clean" if has_clamav else "no_clamav",
        }

    def test_file_in_scanned_dir(self):
        idx = self._make_index(scanned=["/mnt/windows/windows/system32"])
        result = m32._was_path_scanned("/mnt/windows/Windows/System32/ntdll.dll", idx)
        assert result == "scanned"

    def test_file_under_nested_scanned_dir(self):
        idx = self._make_index(scanned=["/mnt/windows/windows"])
        result = m32._was_path_scanned("/mnt/windows/Windows/System32/ntdll.dll", idx)
        assert result == "scanned"

    def test_file_out_of_scope(self):
        idx = self._make_index(scanned=["/mnt/windows/windows/system32"])
        result = m32._was_path_scanned("/mnt/windows/Users/victim/malware.exe", idx)
        assert result == "out_of_scope"

    def test_file_permission_denied(self):
        idx = self._make_index(
            scanned=["/mnt/windows/windows"],
            perm=["/mnt/windows/windows/system32/secure"],
        )
        result = m32._was_path_scanned("/mnt/windows/Windows/System32/secure/foo.dll", idx)
        assert result == "permission_denied"

    def test_file_size_skipped(self):
        idx = self._make_index(
            scanned=["/mnt/windows/windows/system32"],
            size=["/mnt/windows/windows/system32/huge.dll"],
        )
        result = m32._was_path_scanned("/mnt/windows/Windows/System32/huge.dll", idx)
        assert result == "size_skipped"

    def test_no_clamav(self):
        idx = self._make_index(has_clamav=False)
        idx["scan_status"] = "no_clamav"
        result = m32._was_path_scanned("/mnt/windows/Windows/System32/foo.exe", idx)
        assert result == "no_clamav"

    def test_no_scan_data(self):
        idx = self._make_index(has_clamav=False)
        idx["scan_status"] = "no_data"
        result = m32._was_path_scanned("/mnt/windows/Windows/System32/foo.exe", idx)
        assert result == "no_scan_data"

    def test_none_path(self):
        idx = self._make_index(scanned=["/mnt/windows/windows/system32"])
        result = m32._was_path_scanned(None, idx)
        assert result == "no_scan_data"

    def test_exact_scanned_path_match(self):
        idx = self._make_index(scanned=["/mnt/windows/windows/system32/foo.exe"])
        result = m32._was_path_scanned("/mnt/windows/Windows/System32/foo.exe", idx)
        assert result == "scanned"


# ---------------------------------------------------------------------------
# 4. _integrity_status
# ---------------------------------------------------------------------------

class TestIntegrityStatus:
    def _make_index(self, anomalous=None, missing=None):
        anomalous_relpaths = set()
        anomalous_details  = {}
        missing_relpaths   = set()
        for entry in (anomalous or []):
            key = entry["path"].replace("\\", "/").lower()
            anomalous_relpaths.add(key)
            anomalous_details[key] = entry
        for path in (missing or []):
            missing_relpaths.add(path.replace("\\", "/").lower())
        return {
            "anomalous_relpaths": anomalous_relpaths,
            "anomalous_details":  anomalous_details,
            "missing_relpaths":   missing_relpaths,
        }

    def test_path_in_anomalous(self):
        idx = self._make_index(anomalous=[{
            "path": "System32/ntdll.dll",
            "category": "kernel",
            "anomalies": ["SUSPICIOUS_METADATA"],
        }])
        result = m32._integrity_status("System32/ntdll.dll", idx)
        assert result["in_protected_list"] is True
        assert "SUSPICIOUS_METADATA" in result["anomalies"]
        assert result["missing"] is False

    def test_path_in_missing(self):
        idx = self._make_index(missing=["System32/missing.dll"])
        result = m32._integrity_status("System32/missing.dll", idx)
        assert result["missing"] is True
        assert result["in_protected_list"] is True

    def test_path_not_in_either(self):
        idx = self._make_index()
        result = m32._integrity_status("System32/normal.dll", idx)
        assert result["in_protected_list"] is False
        assert result["anomalies"] == []
        assert result["missing"] is False

    def test_case_insensitive_match(self):
        idx = self._make_index(anomalous=[{
            "path": "system32/ntdll.dll",
            "category": "kernel",
            "anomalies": ["ZERO_BYTE"],
        }])
        result = m32._integrity_status("System32/ntdll.dll", idx)
        assert result["in_protected_list"] is True

    def test_empty_path(self):
        idx = self._make_index()
        result = m32._integrity_status("", idx)
        assert result["in_protected_list"] is False


# ---------------------------------------------------------------------------
# 5. _is_suspicious_location
# ---------------------------------------------------------------------------

class TestIsSuspiciousLocation:
    def test_temp_dir(self):
        assert m32._is_suspicious_location(r"C:\Windows\Temp\malware.exe") is True

    def test_appdata(self):
        assert m32._is_suspicious_location(r"C:\Users\dave\AppData\Local\evil.exe") is True

    def test_desktop(self):
        assert m32._is_suspicious_location(r"C:\Users\dave\Desktop\prog.exe") is True

    def test_downloads(self):
        assert m32._is_suspicious_location(r"C:\Users\dave\Downloads\app.exe") is True

    def test_recycler(self):
        assert m32._is_suspicious_location(r"C:\RECYCLER\malware.exe") is True

    def test_recycle_bin(self):
        assert m32._is_suspicious_location(r"C:\$Recycle.Bin\malware.exe") is True

    def test_system32_is_safe(self):
        assert m32._is_suspicious_location(r"C:\Windows\System32\svchost.exe") is False

    def test_program_files_is_safe(self):
        assert m32._is_suspicious_location(r"C:\Program Files\App\app.exe") is False

    def test_empty_string(self):
        assert m32._is_suspicious_location("") is False

    def test_tmp_variant(self):
        assert m32._is_suspicious_location(r"C:\tmp\payload.exe") is True

    def test_user_dir_not_suspicious(self):
        # A direct path not hitting the suspicious patterns
        assert m32._is_suspicious_location(r"C:\Windows\SysWOW64\foo.dll") is False


# ---------------------------------------------------------------------------
# 6. _score_risk
# ---------------------------------------------------------------------------

class TestScoreRisk:
    def _no_integrity(self):
        return {"anomalies": [], "in_protected_list": False, "missing": False}

    def _anomaly_integrity(self):
        return {"anomalies": ["SUSPICIOUS_METADATA"], "in_protected_list": True, "missing": False}

    def test_demand_clean_is_low(self):
        risk = m32._score_risk(
            "DEMAND", "scanned", True, self._no_integrity(),
            False, [], False, "not_applicable",
        )
        assert risk == "LOW"

    def test_auto_clean_scanned_is_medium(self):
        risk = m32._score_risk(
            "AUTO", "scanned", True, self._no_integrity(),
            False, [], False, "not_applicable",
        )
        assert risk == "MEDIUM"

    def test_auto_not_scanned_is_high(self):
        risk = m32._score_risk(
            "AUTO", "out_of_scope", True, self._no_integrity(),
            False, [], False, "not_applicable",
        )
        assert risk == "HIGH"

    def test_auto_missing_binary_is_critical(self):
        risk = m32._score_risk(
            "AUTO", "scanned", False, self._no_integrity(),
            False, [], False, "not_applicable",
        )
        assert risk == "CRITICAL"

    def test_auto_suspicious_location_is_high(self):
        risk = m32._score_risk(
            "AUTO", "scanned", True, self._no_integrity(),
            True, [], False, "not_applicable",
        )
        assert risk == "HIGH"

    def test_auto_unscanned_plus_suspicious_is_critical(self):
        risk = m32._score_risk(
            "AUTO", "out_of_scope", True, self._no_integrity(),
            True, [], False, "not_applicable",
        )
        assert risk == "CRITICAL"

    def test_auto_m07_suspicious_flag_is_high(self):
        risk = m32._score_risk(
            "AUTO", "scanned", True, self._no_integrity(),
            False, ["SUSPICIOUS"], False, "not_applicable",
        )
        assert risk == "HIGH"

    def test_boot_missing_binary_is_critical(self):
        risk = m32._score_risk(
            "BOOT", "scanned", False, self._no_integrity(),
            False, [], False, "not_applicable",
        )
        assert risk == "CRITICAL"

    def test_auto_anomaly_is_high(self):
        risk = m32._score_risk(
            "AUTO", "scanned", True, self._anomaly_integrity(),
            False, [], False, "not_applicable",
        )
        assert risk == "HIGH"

    def test_auto_unscanned_plus_anomaly_is_critical(self):
        risk = m32._score_risk(
            "AUTO", "out_of_scope", True, self._anomaly_integrity(),
            False, [], False, "not_applicable",
        )
        assert risk == "CRITICAL"

    def test_svchost_dll_unchecked_auto_is_critical(self):
        risk = m32._score_risk(
            "AUTO", "scanned", True, self._no_integrity(),
            False, [], True, "out_of_scope",
        )
        assert risk == "CRITICAL"

    def test_disabled_service_is_low(self):
        risk = m32._score_risk(
            "DISABLED", "out_of_scope", True, self._no_integrity(),
            False, [], False, "not_applicable",
        )
        assert risk == "LOW"


# ---------------------------------------------------------------------------
# 7. _compute_flags
# ---------------------------------------------------------------------------

class TestComputeFlags:
    def _no_integrity(self):
        return {"anomalies": [], "in_protected_list": False, "missing": False}

    def _anomaly_integrity(self):
        return {"anomalies": ["SUSPICIOUS_METADATA"], "in_protected_list": True, "missing": False}

    def test_no_flags_for_clean_service(self):
        flags = m32._compute_flags(
            "AUTO", "scanned", "not_applicable",
            True, False, self._no_integrity(),
            [], False, "MEDIUM",
        )
        assert flags == []

    def test_executable_not_scanned_flag(self):
        flags = m32._compute_flags(
            "AUTO", "out_of_scope", "not_applicable",
            True, False, self._no_integrity(),
            [], False, "HIGH",
        )
        assert "executable_not_scanned" in flags

    def test_executable_missing_flag(self):
        flags = m32._compute_flags(
            "AUTO", "scanned", "not_applicable",
            False, False, self._no_integrity(),
            [], False, "CRITICAL",
        )
        assert "executable_missing" in flags

    def test_executable_untrusted_flag(self):
        flags = m32._compute_flags(
            "AUTO", "scanned", "not_applicable",
            True, True, self._no_integrity(),
            [], False, "HIGH",
        )
        assert "executable_untrusted" in flags

    def test_suspicious_path_from_m07_suspicious(self):
        flags = m32._compute_flags(
            "AUTO", "scanned", "not_applicable",
            True, False, self._no_integrity(),
            ["SUSPICIOUS"], False, "HIGH",
        )
        assert "suspicious_path" in flags

    def test_suspicious_path_from_m07_unquoted(self):
        flags = m32._compute_flags(
            "AUTO", "scanned", "not_applicable",
            True, False, self._no_integrity(),
            ["UNQUOTED_PATH"], False, "HIGH",
        )
        assert "suspicious_path" in flags

    def test_svchost_dll_unchecked(self):
        flags = m32._compute_flags(
            "AUTO", "scanned", "out_of_scope",
            True, False, self._no_integrity(),
            [], True, "CRITICAL",
        )
        assert "svchost_dll_unchecked" in flags

    def test_svchost_dll_checked_no_flag(self):
        flags = m32._compute_flags(
            "AUTO", "scanned", "scanned",
            True, False, self._no_integrity(),
            [], True, "MEDIUM",
        )
        assert "svchost_dll_unchecked" not in flags

    def test_system_file_anomaly(self):
        flags = m32._compute_flags(
            "AUTO", "scanned", "not_applicable",
            True, False, self._anomaly_integrity(),
            [], False, "HIGH",
        )
        assert "system_file_anomaly" in flags

    def test_high_risk_autostart_for_auto_high(self):
        flags = m32._compute_flags(
            "AUTO", "scanned", "not_applicable",
            True, True, self._no_integrity(),
            [], False, "HIGH",
        )
        assert "high_risk_autostart" in flags

    def test_high_risk_autostart_not_for_demand(self):
        flags = m32._compute_flags(
            "DEMAND", "scanned", "not_applicable",
            True, True, self._no_integrity(),
            [], False, "HIGH",
        )
        assert "high_risk_autostart" not in flags

    def test_no_scan_data_counts_as_not_scanned(self):
        flags = m32._compute_flags(
            "AUTO", "no_scan_data", "not_applicable",
            True, False, self._no_integrity(),
            [], False, "HIGH",
        )
        assert "executable_not_scanned" in flags


# ---------------------------------------------------------------------------
# 8. _build_scan_index
# ---------------------------------------------------------------------------

class TestBuildScanIndex:
    def test_no_clamav_data(self):
        idx = m32._build_scan_index(None)
        assert idx["has_clamav"] is False
        assert idx["scanned_dirs"] == set()

    def test_no_clamav_status(self):
        idx = m32._build_scan_index({"scan_status": "no_clamav"})
        assert idx["has_clamav"] is False

    def test_analyze_only_not_counted_as_clamav(self):
        idx = m32._build_scan_index({"scan_status": "analyze_only"})
        assert idx["has_clamav"] is False

    def test_clean_scan_has_clamav(self):
        idx = m32._build_scan_index({
            "scan_status": "clean",
            "scan_scope": {"paths_scanned": ["/mnt/windows/Windows/System32"]},
            "scan_gaps": {},
        })
        assert idx["has_clamav"] is True
        assert "/mnt/windows/windows/system32" in idx["scanned_dirs"]

    def test_paths_normalised_lowercase(self):
        idx = m32._build_scan_index({
            "scan_status": "clean",
            "scan_scope": {"paths_scanned": ["/mnt/windows/Windows/SYSTEM32/"]},
            "scan_gaps": {},
        })
        assert "/mnt/windows/windows/system32" in idx["scanned_dirs"]

    def test_permission_denied_populated(self):
        idx = m32._build_scan_index({
            "scan_status": "partial",
            "scan_scope": {"paths_scanned": []},
            "scan_gaps": {"permission_denied": ["/mnt/windows/Windows/System32/secure"]},
        })
        assert "/mnt/windows/windows/system32/secure" in idx["perm_denied"]

    def test_size_skipped_populated(self):
        idx = m32._build_scan_index({
            "scan_status": "partial",
            "scan_scope": {"paths_scanned": []},
            "scan_gaps": {"size_limited_files": ["/mnt/windows/big.vhd"]},
        })
        assert "/mnt/windows/big.vhd" in idx["size_skipped"]


# ---------------------------------------------------------------------------
# 9. _build_integrity_index
# ---------------------------------------------------------------------------

class TestBuildIntegrityIndex:
    def test_none_data(self):
        idx = m32._build_integrity_index(None)
        assert len(idx["anomalous_relpaths"]) == 0
        assert len(idx["missing_relpaths"]) == 0

    def test_anomalous_files_indexed(self):
        data = {
            "anomalous_files": [
                {"path": "System32/ntdll.dll", "category": "kernel", "anomalies": ["ZERO_BYTE"]}
            ],
            "missing_files": [],
        }
        idx = m32._build_integrity_index(data)
        assert "system32/ntdll.dll" in idx["anomalous_relpaths"]

    def test_missing_files_indexed(self):
        data = {
            "anomalous_files": [],
            "missing_files": [{"path": "System32/hal.dll", "category": "kernel"}],
        }
        idx = m32._build_integrity_index(data)
        assert "system32/hal.dll" in idx["missing_relpaths"]

    def test_anomaly_details_retrievable(self):
        data = {
            "anomalous_files": [
                {"path": "System32/ntdll.dll", "anomalies": ["SUSPICIOUS_METADATA"]}
            ],
            "missing_files": [],
        }
        idx = m32._build_integrity_index(data)
        details = idx["anomalous_details"].get("system32/ntdll.dll")
        assert details is not None
        assert "SUSPICIOUS_METADATA" in details["anomalies"]


# ---------------------------------------------------------------------------
# 10. _compute_summary
# ---------------------------------------------------------------------------

class TestComputeSummary:
    def _make_service(self, risk="LOW", flags=None):
        return {"name": "testsvc", "risk": risk, "flags": flags or [], "start_type": "AUTO"}

    def test_empty_list(self):
        s = m32._compute_summary([])
        assert s["total_services"] == 0
        assert s["critical_risk"] == 0

    def test_counts_critical(self):
        services = [
            self._make_service("CRITICAL", ["executable_not_scanned"]),
            self._make_service("HIGH", ["system_file_anomaly"]),
            self._make_service("LOW"),
        ]
        s = m32._compute_summary(services)
        assert s["total_services"] == 3
        assert s["critical_risk"] == 1
        assert s["high_risk"] == 1

    def test_counts_not_scanned(self):
        services = [
            self._make_service("HIGH", ["executable_not_scanned"]),
            self._make_service("HIGH", ["executable_not_scanned", "high_risk_autostart"]),
            self._make_service("LOW"),
        ]
        s = m32._compute_summary(services)
        assert s["not_scanned"] == 2

    def test_counts_untrusted(self):
        services = [
            self._make_service("HIGH", ["executable_untrusted"]),
            self._make_service("LOW"),
        ]
        s = m32._compute_summary(services)
        assert s["untrusted"] == 1


# ---------------------------------------------------------------------------
# 11. _compute_risk_distribution
# ---------------------------------------------------------------------------

class TestComputeRiskDistribution:
    def test_empty(self):
        dist = m32._compute_risk_distribution([])
        assert dist == {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    def test_counts_all_levels(self):
        services = [
            {"risk": "CRITICAL"}, {"risk": "HIGH"}, {"risk": "HIGH"},
            {"risk": "MEDIUM"}, {"risk": "LOW"}, {"risk": "LOW"}, {"risk": "LOW"},
        ]
        dist = m32._compute_risk_distribution(services)
        assert dist["CRITICAL"] == 1
        assert dist["HIGH"] == 2
        assert dist["MEDIUM"] == 1
        assert dist["LOW"] == 3


# ---------------------------------------------------------------------------
# 12. _compute_recommendations
# ---------------------------------------------------------------------------

class TestComputeRecommendations:
    def test_no_issues_no_recs(self):
        summary = {"critical_risk": 0, "not_scanned": 0, "untrusted": 0, "high_risk": 0}
        recs = m32._compute_recommendations(summary, [])
        assert recs == []

    def test_critical_generates_rec(self):
        summary = {"critical_risk": 1, "not_scanned": 0, "untrusted": 0, "high_risk": 0}
        services = [{"name": "evil", "risk": "CRITICAL", "flags": []}]
        recs = m32._compute_recommendations(summary, services)
        assert any("CRITICAL" in r for r in recs)
        assert any("evil" in r for r in recs)

    def test_not_scanned_generates_rec(self):
        summary = {"critical_risk": 0, "not_scanned": 3, "untrusted": 0, "high_risk": 0}
        recs = m32._compute_recommendations(summary, [])
        assert any("not scanned" in r.lower() for r in recs)

    def test_untrusted_generates_rec(self):
        summary = {"critical_risk": 0, "not_scanned": 0, "untrusted": 2, "high_risk": 0}
        recs = m32._compute_recommendations(summary, [])
        assert any("suspicious" in r.lower() for r in recs)

    def test_svchost_unchecked_generates_rec(self):
        summary = {"critical_risk": 0, "not_scanned": 0, "untrusted": 0, "high_risk": 1}
        services = [{"name": "svcsomething", "risk": "HIGH", "flags": ["svchost_dll_unchecked"]}]
        recs = m32._compute_recommendations(summary, services)
        assert any("svchost" in r.lower() for r in recs)


# ---------------------------------------------------------------------------
# 13. Fixture test
# ---------------------------------------------------------------------------

class TestFixture:
    FIXTURE = Path(__file__).parent / "fixtures" / "execution_surface_sample.json"

    def test_fixture_loads(self):
        assert self.FIXTURE.exists(), f"Fixture not found: {self.FIXTURE}"
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_fixture_has_required_fields(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        assert "generated" in data
        assert "target" in data
        assert "services_analysed" in data
        assert "summary" in data
        assert "risk_distribution" in data

    def test_fixture_services_have_required_fields(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        for svc in data["services_analysed"]:
            assert "name" in svc
            assert "start_type" in svc
            assert "scan_result" in svc
            assert "risk" in svc
            assert "flags" in svc

    def test_fixture_risk_levels_valid(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        valid_risks = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for svc in data["services_analysed"]:
            assert svc["risk"] in valid_risks, f"Invalid risk: {svc['risk']}"

    def test_fixture_summary_counts_correct(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        s = data["summary"]
        assert s["total_services"] == len(data["services_analysed"])
        assert s["critical_risk"] == sum(
            1 for svc in data["services_analysed"] if svc["risk"] == "CRITICAL"
        )

    def test_fixture_has_critical_and_clean_services(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        risks = {svc["risk"] for svc in data["services_analysed"]}
        assert "CRITICAL" in risks
        assert "LOW" in risks

    def test_fixture_recommendations_are_strings(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        for rec in data.get("recommendations", []):
            assert isinstance(rec, str)


# ---------------------------------------------------------------------------
# 14. Integration-level: _analyse_service with mock data
# ---------------------------------------------------------------------------

class TestAnalyseServiceIntegration:
    TARGET = Path("/mnt/windows")

    def _make_scan_index(self, scanned=None):
        return {
            "scanned_dirs": set(scanned or ["/mnt/windows/windows/system32"]),
            "perm_denied":  set(),
            "size_skipped": set(),
            "has_clamav":   True,
            "scan_status":  "clean",
        }

    def _make_integrity_index(self):
        return {
            "anomalous_relpaths": set(),
            "anomalous_details":  {},
            "missing_relpaths":   set(),
        }

    def test_clean_system32_service_is_low_or_medium(self):
        svc = {
            "name": "Spooler",
            "display_name": "Print Spooler",
            "start": "AUTO",
            "image_path": r"C:\Windows\System32\spoolsv.exe",
            "resolved_path": r"C:\Windows\System32\spoolsv.exe",
            "flags": [],
            "file_evidence": {"exists": True, "suspicious_location": False},
            "dll_details": None,
            "svchost_group": None,
            "config": {"start_raw": 2},
        }
        result = m32._analyse_service(svc, self.TARGET, self._make_scan_index(), self._make_integrity_index())
        assert result["risk"] in ("LOW", "MEDIUM")
        assert result["flags"] == []

    def test_suspicious_location_auto_service_is_high_or_critical(self):
        svc = {
            "name": "EvilSvc",
            "display_name": "Evil Service",
            "start": "AUTO",
            "image_path": r"C:\Users\victim\AppData\Local\Temp\evil.exe",
            "resolved_path": r"C:\Users\victim\AppData\Local\Temp\evil.exe",
            "flags": ["SUSPICIOUS"],
            "file_evidence": {"exists": True, "suspicious_location": True},
            "dll_details": None,
            "svchost_group": None,
            "config": {"start_raw": 2},
        }
        result = m32._analyse_service(svc, self.TARGET, self._make_scan_index([]), self._make_integrity_index())
        assert result["risk"] in ("HIGH", "CRITICAL")
        assert "executable_untrusted" in result["flags"]

    def test_missing_binary_auto_is_critical(self):
        svc = {
            "name": "GhostSvc",
            "display_name": "Ghost",
            "start": "AUTO",
            "image_path": r"C:\Windows\System32\ghost.exe",
            "resolved_path": r"C:\Windows\System32\ghost.exe",
            "flags": ["MISSING_BINARY"],
            "file_evidence": {"exists": False, "suspicious_location": False},
            "dll_details": None,
            "svchost_group": None,
            "config": {"start_raw": 2},
        }
        result = m32._analyse_service(svc, self.TARGET, self._make_scan_index(), self._make_integrity_index())
        assert result["risk"] == "CRITICAL"
        assert "executable_missing" in result["flags"]

    def test_svchost_service_includes_dll_field(self):
        svc = {
            "name": "wuauserv",
            "display_name": "Windows Update",
            "start": "AUTO",
            "image_path": r"%SystemRoot%\system32\svchost.exe -k netsvcs",
            "resolved_path": r"C:\Windows\system32\svchost.exe",
            "flags": [],
            "file_evidence": {"exists": True, "suspicious_location": False},
            "dll_details": {
                "ServiceDll": r"C:\Windows\System32\wuaueng.dll",
                "resolved_path": r"C:\Windows\System32\wuaueng.dll",
                "file_evidence": {"exists": True, "suspicious_location": False},
            },
            "svchost_group": "netsvcs",
            "config": {"start_raw": 2},
        }
        result = m32._analyse_service(svc, self.TARGET, self._make_scan_index(), self._make_integrity_index())
        assert result["is_svchost"] is True
        assert "service_dll" in result
        assert result["service_dll"]["path"] == r"C:\Windows\System32\wuaueng.dll"

    def test_demand_service_is_low(self):
        svc = {
            "name": "ClipSvc",
            "display_name": "Clipboard Service",
            "start": "DEMAND",
            "image_path": r"C:\Windows\System32\svchost.exe -k UnistackSvcGroup",
            "resolved_path": r"C:\Windows\System32\svchost.exe",
            "flags": [],
            "file_evidence": {"exists": True, "suspicious_location": False},
            "dll_details": None,
            "svchost_group": None,
            "config": {"start_raw": 3},
        }
        result = m32._analyse_service(svc, self.TARGET, self._make_scan_index(), self._make_integrity_index())
        assert result["risk"] == "LOW"
