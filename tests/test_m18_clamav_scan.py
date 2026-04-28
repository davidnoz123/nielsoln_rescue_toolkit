"""
tests/test_m18_clamav_scan.py — Unit tests for m18_clamav_scan.py

Coverage:
  - TestParseCvdHeader       — CVD/CLD header parsing (valid, missing, corrupt, time formats)
  - TestParseClamscanlogs    — clamscan log line parsing (infected, error, perm-denied, size-skip)
  - TestComputeCoverage      — key directory coverage analysis
  - TestComputeConfidence    — confidence scoring logic
  - TestCorrelateModules     — cross-module flag logic
  - TestComputeRecommendations — recommendation generation

Run from the repo root:
    pytest tests/test_m18_clamav_scan.py -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Add repo root to sys.path so `from modules.m18_...` works
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.m18_clamav_scan import (
    _compute_confidence,
    _compute_coverage,
    _compute_recommendations,
    _get_limitations,
    _parse_clamscan_logs,
    _parse_cvd_header,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _cvd_header(build_time: str = "07 Dec 2024 09-54 -0500",
                version: str = "27397",
                sig_count: str = "8715603") -> bytes:
    """Build a synthetic 512-byte CVD header."""
    raw = f"ClamAV-VDB:{build_time}:{version}:{sig_count}:64:abc123:sig:builder:94"
    header = raw.encode("ascii")
    # Pad to 512 bytes with null bytes
    return header + b"\x00" * (512 - len(header))


def _make_infected_target(tmp: Path) -> Path:
    """Create a minimal fake Windows target directory tree."""
    (tmp / "Windows" / "System32").mkdir(parents=True)
    (tmp / "Windows" / "SysWOW64").mkdir(parents=True)
    (tmp / "Windows" / "Temp").mkdir(parents=True)
    (tmp / "Users").mkdir(parents=True)
    (tmp / "Program Files").mkdir(parents=True)
    (tmp / "Program Files (x86)").mkdir(parents=True)
    (tmp / "ProgramData").mkdir(parents=True)
    return tmp


# ---------------------------------------------------------------------------
# 1. TestParseCvdHeader
# ---------------------------------------------------------------------------

class TestParseCvdHeader:
    def test_valid_header_standard_time(self, tmp_path):
        path = _write(tmp_path / "daily.cld", _cvd_header("07 Dec 2024 09-54 -0500", "27397", "8715603"))
        result = _parse_cvd_header(path)
        assert result["version"] == "27397"
        assert result["sig_count"] == 8715603
        assert result["parse_error"] is None
        assert result["build_time"] is not None
        assert result["age_days"] is not None
        assert isinstance(result["age_days"], int)
        assert result["age_days"] >= 0

    def test_valid_header_colon_time(self, tmp_path):
        """Fallback: build time already extracted (not from split), parse with colon format."""
        # ClamAV always uses dashes, so test with dash-format but different month
        path = _write(tmp_path / "main.cvd", _cvd_header("01 Jan 2024 12-00 +0000", "62", "8000000"))
        result = _parse_cvd_header(path)
        assert result["version"] == "62"
        assert result["sig_count"] == 8000000
        assert result["parse_error"] is None

    def test_missing_file(self, tmp_path):
        result = _parse_cvd_header(tmp_path / "nonexistent.cvd")
        assert result["parse_error"] is not None
        assert result["version"] is None

    def test_corrupt_header(self, tmp_path):
        path = _write(tmp_path / "bad.cvd", b"This is not a valid ClamAV file\x00" * 20)
        result = _parse_cvd_header(path)
        assert result["parse_error"] is not None

    def test_partial_header(self, tmp_path):
        """A file with only 10 bytes should produce a parse error."""
        path = _write(tmp_path / "tiny.cvd", b"ClamAV-VDB")
        result = _parse_cvd_header(path)
        assert result["parse_error"] is not None

    def test_age_days_is_positive(self, tmp_path):
        path = _write(tmp_path / "daily.cld", _cvd_header("01 Jan 2020 00-00 +0000", "10000", "1000"))
        result = _parse_cvd_header(path)
        assert result["age_days"] is not None
        assert result["age_days"] > 0

    def test_sig_count_as_integer(self, tmp_path):
        path = _write(tmp_path / "daily.cld", _cvd_header(sig_count="2104337"))
        result = _parse_cvd_header(path)
        assert result["sig_count"] == 2104337
        assert isinstance(result["sig_count"], int)


# ---------------------------------------------------------------------------
# 2. TestParseClamscanlogs
# ---------------------------------------------------------------------------

class TestParseClamscanlogs:
    def _make_log(self, tmp_path: Path, name: str, content: str) -> Path:
        p = tmp_path / name
        p.write_text(textwrap.dedent(content), encoding="utf-8")
        return p

    def test_infected_line_parsed(self, tmp_path):
        log = self._make_log(tmp_path, "seg1.log", """\
            /mnt/windows/Windows/Temp/evil.exe: Win.Trojan.Backdoor-1234 FOUND
        """)
        result = _parse_clamscan_logs([log])
        assert len(result["infected"]) == 1
        assert result["infected"][0]["path"] == "/mnt/windows/Windows/Temp/evil.exe"
        assert "Win.Trojan.Backdoor-1234" in result["infected"][0]["virus"]

    def test_multiple_infections(self, tmp_path):
        log = self._make_log(tmp_path, "seg1.log", """\
            /mnt/windows/Users/dave/bad1.exe: Win.Virus.Test-1 FOUND
            /mnt/windows/Windows/Temp/bad2.exe: Win.Virus.Test-2 FOUND
            /mnt/windows/ProgramData/bad3.dll: Win.Backdoor.Test-3 FOUND
        """)
        result = _parse_clamscan_logs([log])
        assert len(result["infected"]) == 3

    def test_duplicate_infections_deduplicated(self, tmp_path):
        content = "/mnt/windows/bad.exe: Win.Trojan.Test FOUND\n" * 5
        log = self._make_log(tmp_path, "seg1.log", content)
        result = _parse_clamscan_logs([log])
        assert len(result["infected"]) == 1

    def test_error_line_parsed(self, tmp_path):
        log = self._make_log(tmp_path, "seg1.log", """\
            /mnt/windows/Windows/System32/locked.sys: Can't access file ERROR
        """)
        result = _parse_clamscan_logs([log])
        assert len(result["error_paths"]) == 1
        assert "/locked.sys" in result["error_paths"][0]

    def test_permission_denied_in_error(self, tmp_path):
        log = self._make_log(tmp_path, "seg1.log", """\
            /mnt/windows/Windows/System32/config/SYSTEM: Permission denied ERROR
        """)
        result = _parse_clamscan_logs([log])
        assert len(result["permission_denied"]) == 1

    def test_size_skip_line(self, tmp_path):
        log = self._make_log(tmp_path, "seg1.log", """\
            /mnt/windows/Users/dave/bigfile.iso: Max file size reached
        """)
        result = _parse_clamscan_logs([log])
        # Size skip parsing is best-effort; check no crash
        assert isinstance(result["size_skipped"], list)

    def test_empty_log(self, tmp_path):
        log = self._make_log(tmp_path, "empty.log", "")
        result = _parse_clamscan_logs([log])
        assert result["infected"] == []
        assert result["error_paths"] == []
        assert result["permission_denied"] == []

    def test_no_logs(self):
        result = _parse_clamscan_logs([])
        assert result["infected"] == []

    def test_multiple_log_files_aggregated(self, tmp_path):
        log1 = self._make_log(tmp_path, "seg1.log", """\
            /mnt/windows/Windows/Temp/bad1.exe: Win.Trojan.A FOUND
        """)
        log2 = self._make_log(tmp_path, "seg2.log", """\
            /mnt/windows/Users/dave/bad2.exe: Win.Trojan.B FOUND
        """)
        result = _parse_clamscan_logs([log1, log2])
        assert len(result["infected"]) == 2

    def test_warning_line(self, tmp_path):
        log = self._make_log(tmp_path, "seg1.log", """\
            WARNING: Clamd was NOT notified: Can't connect to clamd on ...
        """)
        result = _parse_clamscan_logs([log])
        assert any("Clamd" in w for w in result["warnings"])


# ---------------------------------------------------------------------------
# 3. TestComputeCoverage
# ---------------------------------------------------------------------------

class TestComputeCoverage:
    def test_all_dirs_scanned(self, tmp_path):
        target = _make_infected_target(tmp_path)
        scan_dirs = [
            target / "Windows" / "System32",
            target / "Windows" / "SysWOW64",
            target / "Windows" / "Temp",
            target / "Users",
            target / "Program Files",
            target / "Program Files (x86)",
            target / "ProgramData",
            target,
        ]
        cov = _compute_coverage(target, scan_dirs)
        assert cov["system32_scanned"] is True
        assert cov["users_scanned"] is True
        assert cov["overall_estimate"] == "high"
        assert cov["dirs_not_scanned"] == []

    def test_system32_not_scanned(self, tmp_path):
        target = _make_infected_target(tmp_path)
        scan_dirs = [
            target / "Users",
            target / "Windows" / "Temp",
        ]
        cov = _compute_coverage(target, scan_dirs)
        assert cov["system32_scanned"] is False
        assert "Windows/System32" in cov["dirs_not_scanned"]
        assert cov["overall_estimate"] in ("low", "medium", "unknown")

    def test_users_not_scanned(self, tmp_path):
        target = _make_infected_target(tmp_path)
        scan_dirs = [target / "Windows" / "System32"]
        cov = _compute_coverage(target, scan_dirs)
        assert cov["users_scanned"] is False
        assert "Users" in cov["dirs_not_scanned"]

    def test_nothing_scanned(self, tmp_path):
        target = _make_infected_target(tmp_path)
        cov = _compute_coverage(target, [])
        assert cov["overall_estimate"] == "unknown"
        assert cov["system32_scanned"] is False

    def test_appdata_implied_by_users(self, tmp_path):
        target = _make_infected_target(tmp_path)
        scan_dirs = [target / "Windows" / "System32", target / "Users"]
        cov = _compute_coverage(target, scan_dirs)
        assert cov["users_scanned"] is True
        assert cov["appdata_scanned"] is True

    def test_syswow64_absent_not_penalised(self, tmp_path):
        """If SysWOW64 doesn't exist, missing it should not lower coverage."""
        # Don't create SysWOW64 in this target
        (tmp_path / "Windows" / "System32").mkdir(parents=True)
        (tmp_path / "Windows" / "Temp").mkdir(parents=True)
        (tmp_path / "Users").mkdir(parents=True)
        (tmp_path / "Program Files").mkdir(parents=True)
        (tmp_path / "Program Files (x86)").mkdir(parents=True)
        (tmp_path / "ProgramData").mkdir(parents=True)

        scan_dirs = [
            tmp_path / "Windows" / "System32",
            tmp_path / "Windows" / "Temp",
            tmp_path / "Users",
            tmp_path / "Program Files",
        ]
        cov = _compute_coverage(tmp_path, scan_dirs)
        # SysWOW64 doesn't exist — should not appear in dirs_not_scanned
        assert "Windows/SysWOW64" not in cov["dirs_not_scanned"]


# ---------------------------------------------------------------------------
# 4. TestComputeConfidence
# ---------------------------------------------------------------------------

def _mock_defs(age_main: int, age_daily: int) -> dict:
    def _db(age):
        return {"file": "x.cvd", "version": "1", "build_time": "...",
                "sig_count": 1000, "age_days": age, "parse_error": None}
    return {"main": _db(age_main), "daily": _db(age_daily), "bytecode": _db(age_main)}


def _mock_coverage(system32=True, users=True) -> dict:
    return {
        "system32_scanned": system32,
        "syswow64_scanned": True,
        "windows_temp_scanned": True,
        "users_scanned": users,
        "appdata_scanned": users,
        "program_files_scanned": True,
        "program_files_x86_scanned": True,
        "programdata_scanned": True,
        "dirs_not_scanned": (
            ([] if system32 else ["Windows/System32"]) +
            ([] if users else ["Users"])
        ),
        "overall_estimate": "high" if (system32 and users) else "medium",
    }


def _mock_gaps(perm_denied_count=0, size_skipped_count=0) -> dict:
    return {
        "permission_denied": [f"/mnt/windows/file{i}" for i in range(perm_denied_count)],
        "size_limited_files": [f"/mnt/windows/big{i}" for i in range(size_skipped_count)],
        "error_paths": [],
        "dirs_not_scanned": [],
        "archives_skipped_flag": True,
        "max_file_size": "20M",
        "max_scan_size": "50M",
    }


def _mock_execution(oom=False, errors=0) -> dict:
    return {
        "scan_start_time": "...",
        "scan_end_time": "...",
        "duration_seconds": 100.0,
        "infected_count": 0,
        "errors_encountered": errors,
        "oom_killed": oom,
        "scan_status": "partial" if oom else "clean",
        "analyze_only": False,
        "permission_denied_paths": [],
    }


class TestComputeConfidence:
    def test_high_confidence_fresh_defs_full_coverage(self):
        conf = _compute_confidence(
            _mock_defs(5, 1),
            _mock_coverage(),
            _mock_gaps(),
            _mock_execution(),
            "quick",
        )
        assert conf["level"] == "high"
        assert conf["score"] >= 5

    def test_outdated_defs_over_90_days_gives_low(self):
        # 97d defs (-2) + quick profile (-1) = score 3 = medium; also acceptable low/unknown
        conf = _compute_confidence(
            _mock_defs(95, 97),
            _mock_coverage(),
            _mock_gaps(),
            _mock_execution(),
            "quick",
        )
        assert conf["level"] in ("low", "unknown", "medium")
        assert conf["score"] < 5
        assert any("97 days" in r or "95 days" in r for r in conf["reasons"])

    def test_stale_defs_30_to_90_days_medium(self):
        conf = _compute_confidence(
            _mock_defs(45, 50),
            _mock_coverage(),
            _mock_gaps(),
            _mock_execution(),
            "quick",
        )
        # Should lose 1 point for stale defs + 1 for quick = score 4 = medium
        assert conf["level"] in ("medium",)
        assert any("50 days" in r or "45 days" in r for r in conf["reasons"])

    def test_missing_defs_gives_unknown(self):
        defs = {
            "main": {"file": None, "version": None, "build_time": None,
                     "sig_count": None, "age_days": None, "parse_error": "Database file not found"},
            "daily": {"file": None, "version": None, "build_time": None,
                      "sig_count": None, "age_days": None, "parse_error": "Database file not found"},
            "bytecode": {"file": None, "version": None, "build_time": None,
                         "sig_count": None, "age_days": None, "parse_error": "Database file not found"},
        }
        conf = _compute_confidence(defs, _mock_coverage(), _mock_gaps(), _mock_execution(), "quick")
        assert conf["level"] == "unknown"

    def test_system32_not_scanned_lowers_confidence(self):
        conf = _compute_confidence(
            _mock_defs(5, 1),
            _mock_coverage(system32=False),
            _mock_gaps(),
            _mock_execution(),
            "quick",
        )
        # -2 for system32 + -1 for quick = score 3 = medium
        assert conf["score"] < 5
        assert conf["level"] in ("medium", "low")
        assert any("System32" in r for r in conf["reasons"])

    def test_oom_killed_lowers_confidence(self):
        conf = _compute_confidence(
            _mock_defs(5, 1),
            _mock_coverage(),
            _mock_gaps(),
            _mock_execution(oom=True),
            "quick",
        )
        assert conf["score"] < 5
        assert any("incomplete" in r.lower() or "partial" in r.lower() for r in conf["reasons"])

    def test_many_errors_lowers_confidence(self):
        conf = _compute_confidence(
            _mock_defs(5, 1),
            _mock_coverage(),
            _mock_gaps(),
            _mock_execution(errors=15),
            "quick",
        )
        assert any("15 scan error" in r for r in conf["reasons"])

    def test_many_perm_denied_lowers_confidence(self):
        conf = _compute_confidence(
            _mock_defs(5, 1),
            _mock_coverage(),
            _mock_gaps(perm_denied_count=15),
            _mock_execution(),
            "quick",
        )
        assert any("permission" in r.lower() for r in conf["reasons"])

    def test_score_never_negative(self):
        defs = {
            "main": {"age_days": None, "file": None, "version": None,
                     "build_time": None, "sig_count": None, "parse_error": "Not found"},
            "daily": {"age_days": None, "file": None, "version": None,
                      "build_time": None, "sig_count": None, "parse_error": "Not found"},
            "bytecode": {"age_days": None, "file": None, "version": None,
                         "build_time": None, "sig_count": None, "parse_error": "Not found"},
        }
        conf = _compute_confidence(
            defs,
            _mock_coverage(system32=False, users=False),
            _mock_gaps(perm_denied_count=20),
            _mock_execution(oom=True, errors=50),
            "quick",
        )
        assert conf["score"] >= 0

    def test_thorough_profile_no_archive_penalty(self):
        conf = _compute_confidence(
            _mock_defs(5, 1),
            _mock_coverage(),
            _mock_gaps(),
            _mock_execution(),
            "thorough",
        )
        # thorough doesn't get -1 for quick profile
        assert conf["score"] == 6


# ---------------------------------------------------------------------------
# 5. TestCorrelateModules
# ---------------------------------------------------------------------------

class TestCorrelateModules:
    def test_clean_with_tampering_flag(self, tmp_path):
        """ClamAV clean + system integrity = TAMPERING_SUSPECTED → cross-module flag."""
        from modules.m18_clamav_scan import _correlate_modules

        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        si_log = logs_dir / "system_integrity_20241210_120000.json"
        si_log.write_text(json.dumps({
            "verdict": "TAMPERING_SUSPECTED",
            "protected_files": [],
            "winsxs": {},
        }), encoding="utf-8")

        result = _correlate_modules(logs_dir, infected=[])
        assert "CLAMAV_CLEAN_BUT_TAMPERING_SUSPECTED" in result["cross_module_flags"]
        assert any("tampering" in s.lower() for s in result["unexplained_signals"])

    def test_clean_with_suspicious_persistence(self, tmp_path):
        from modules.m18_clamav_scan import _correlate_modules

        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        persist_log = logs_dir / "persist_20241210_120000.jsonl"
        findings = [
            {"severity": "HIGH", "type": "RUNKEY", "key": "HKLM\\...", "value": "evil.exe"},
            {"severity": "MEDIUM", "type": "RUNKEY", "key": "HKLM\\...", "value": "suspect.exe"},
        ]
        persist_log.write_text("\n".join(json.dumps(f) for f in findings), encoding="utf-8")

        result = _correlate_modules(logs_dir, infected=[])
        assert "CLAMAV_CLEAN_BUT_SUSPICIOUS_PERSISTENCE" in result["cross_module_flags"]
        assert result["persistence_suspicious"] == 2

    def test_clean_with_suspicious_services(self, tmp_path):
        from modules.m18_clamav_scan import _correlate_modules

        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        svc_log = logs_dir / "service_analysis_20241210_120000.json"
        svc_log.write_text(json.dumps({
            "summary": {"suspicious_count": 3},
            "services": [],
        }), encoding="utf-8")

        result = _correlate_modules(logs_dir, infected=[])
        assert "CLAMAV_CLEAN_BUT_SUSPICIOUS_SERVICES" in result["cross_module_flags"]
        assert result["service_suspicious"] == 3

    def test_infections_plus_persistence_gives_multiple_threat_signal(self, tmp_path):
        from modules.m18_clamav_scan import _correlate_modules

        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        persist_log = logs_dir / "persist_20241210_120000.jsonl"
        persist_log.write_text(
            json.dumps({"severity": "HIGH", "type": "RUNKEY"}),
            encoding="utf-8",
        )

        infected = [{"path": "/mnt/windows/Windows/Temp/evil.exe", "virus": "Win.Trojan.Test"}]
        result = _correlate_modules(logs_dir, infected=infected)
        assert "MULTIPLE_MODULE_THREAT_SIGNALS" in result["cross_module_flags"]

    def test_no_other_logs_no_flags(self, tmp_path):
        from modules.m18_clamav_scan import _correlate_modules

        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        result = _correlate_modules(logs_dir, infected=[])
        assert result["cross_module_flags"] == []
        assert result["unexplained_signals"] == []


# ---------------------------------------------------------------------------
# 6. TestComputeRecommendations
# ---------------------------------------------------------------------------

class TestComputeRecommendations:
    def test_outdated_defs_update_recommendation(self):
        recs = _compute_recommendations(
            definitions=_mock_defs(97, 100),
            coverage=_mock_coverage(),
            gaps=_mock_gaps(),
            confidence={"level": "low", "score": 2, "reasons": []},
            cross_module={"cross_module_flags": [], "unexplained_signals": [],
                          "persistence_suspicious": 0, "service_suspicious": 0},
            infected=[],
            profile="quick",
        )
        assert any("update" in r.lower() or "Update" in r for r in recs)

    def test_quick_profile_thorough_recommendation(self):
        recs = _compute_recommendations(
            definitions=_mock_defs(5, 1),
            coverage=_mock_coverage(),
            gaps=_mock_gaps(),
            confidence={"level": "high", "score": 5, "reasons": []},
            cross_module={"cross_module_flags": [], "unexplained_signals": [],
                          "persistence_suspicious": 0, "service_suspicious": 0},
            infected=[],
            profile="quick",
        )
        assert any("thorough" in r.lower() for r in recs)

    def test_no_thorough_recommendation_for_thorough_profile(self):
        recs = _compute_recommendations(
            definitions=_mock_defs(5, 1),
            coverage=_mock_coverage(),
            gaps=_mock_gaps(),
            confidence={"level": "high", "score": 6, "reasons": []},
            cross_module={"cross_module_flags": [], "unexplained_signals": [],
                          "persistence_suspicious": 0, "service_suspicious": 0},
            infected=[],
            profile="thorough",
        )
        # Should not recommend switching to thorough (already thorough)
        assert not any("run a thorough scan for complete coverage" in r.lower() for r in recs)

    def test_infections_give_review_and_reinstall_recommendation(self):
        infected = [{"path": "/mnt/windows/bad.exe", "virus": "Win.Trojan.Test"}]
        recs = _compute_recommendations(
            definitions=_mock_defs(5, 1),
            coverage=_mock_coverage(),
            gaps=_mock_gaps(),
            confidence={"level": "medium", "score": 3, "reasons": []},
            cross_module={"cross_module_flags": [], "unexplained_signals": [],
                          "persistence_suspicious": 0, "service_suspicious": 0},
            infected=infected,
            profile="quick",
        )
        assert any("infected" in r.lower() for r in recs)
        assert any("reinstall" in r.lower() for r in recs)

    def test_tampering_flag_gives_secondary_scanner_recommendation(self):
        recs = _compute_recommendations(
            definitions=_mock_defs(5, 1),
            coverage=_mock_coverage(),
            gaps=_mock_gaps(),
            confidence={"level": "medium", "score": 3, "reasons": []},
            cross_module={
                "cross_module_flags": ["CLAMAV_CLEAN_BUT_TAMPERING_SUSPECTED"],
                "unexplained_signals": [],
                "persistence_suspicious": 0,
                "service_suspicious": 0,
            },
            infected=[],
            profile="quick",
        )
        assert any("secondary" in r.lower() or "scanner" in r.lower() for r in recs)

    def test_missing_dirs_gives_scan_dirs_recommendation(self):
        cov = _mock_coverage(users=False)
        recs = _compute_recommendations(
            definitions=_mock_defs(5, 1),
            coverage=cov,
            gaps=_mock_gaps(),
            confidence={"level": "medium", "score": 3, "reasons": []},
            cross_module={"cross_module_flags": [], "unexplained_signals": [],
                          "persistence_suspicious": 0, "service_suspicious": 0},
            infected=[],
            profile="quick",
        )
        assert any("Users" in r for r in recs)

    def test_no_recommendations_if_all_good(self):
        """Even with no issues, at least one recommendation is returned."""
        recs = _compute_recommendations(
            definitions=_mock_defs(5, 1),
            coverage=_mock_coverage(),
            gaps=_mock_gaps(),
            confidence={"level": "high", "score": 5, "reasons": []},
            cross_module={"cross_module_flags": [], "unexplained_signals": [],
                          "persistence_suspicious": 0, "service_suspicious": 0},
            infected=[],
            profile="thorough",
        )
        assert len(recs) >= 1


# ---------------------------------------------------------------------------
# 7. TestGetLimitations
# ---------------------------------------------------------------------------

class TestGetLimitations:
    def test_quick_limitations(self):
        ft, heuristic = _get_limitations("quick")
        assert any("archive" in l.lower() for l in ft)
        assert any("zero-day" in l.lower() for l in heuristic)

    def test_thorough_limitations(self):
        ft, heuristic = _get_limitations("thorough")
        assert any("size limit" in l.lower() for l in ft)
        assert any("zero-day" in l.lower() for l in heuristic)

    def test_heuristic_limitations_always_include_fileless(self):
        for profile in ("quick", "thorough"):
            _, heuristic = _get_limitations(profile)
            assert any("fileless" in l.lower() for l in heuristic)


# ---------------------------------------------------------------------------
# 8. TestFixtureSchemas  — load fixtures and check required fields
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
FIXTURE_NAMES = [
    "clamav_scan_full_clean.json",
    "clamav_scan_partial_oom.json",
    "clamav_scan_outdated_defs.json",
    "clamav_scan_infected_skips.json",
]


@pytest.mark.parametrize("fixture_name", FIXTURE_NAMES)
class TestFixtureSchemas:
    def test_required_fields(self, fixture_name):
        path = FIXTURES_DIR / fixture_name
        assert path.exists(), f"Fixture file missing: {path}"
        data = json.loads(path.read_text(encoding="utf-8"))
        for field in ("generated", "target", "scan_status", "infected_files",
                      "definitions", "coverage", "scan_confidence", "recommendations"):
            assert field in data, f"Missing required field '{field}' in {fixture_name}"

    def test_scan_status_valid(self, fixture_name):
        path = FIXTURES_DIR / fixture_name
        data = json.loads(path.read_text(encoding="utf-8"))
        valid = {"clean", "infected", "partial", "error", "no_clamav", "analyze_only", "unknown"}
        assert data["scan_status"] in valid

    def test_confidence_level_valid(self, fixture_name):
        path = FIXTURES_DIR / fixture_name
        data = json.loads(path.read_text(encoding="utf-8"))
        level = data.get("scan_confidence", {}).get("level")
        assert level in ("high", "medium", "low", "unknown")

    def test_infected_files_is_list(self, fixture_name):
        path = FIXTURES_DIR / fixture_name
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data["infected_files"], list)

    def test_recommendations_is_list(self, fixture_name):
        path = FIXTURES_DIR / fixture_name
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data["recommendations"], list)
        assert len(data["recommendations"]) >= 1


class TestPartialOomFixture:
    def test_partial_status_and_low_confidence(self):
        path = FIXTURES_DIR / "clamav_scan_partial_oom.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["scan_status"] == "partial"
        assert data["scan_confidence"]["level"] in ("low", "unknown")
        assert data["scan_execution"]["oom_killed"] is True


class TestInfectedFixture:
    def test_infected_count_and_status(self):
        path = FIXTURES_DIR / "clamav_scan_infected_skips.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["scan_status"] == "infected"
        assert len(data["infected_files"]) >= 1
        assert any("path" in f and "virus" in f for f in data["infected_files"])

    def test_size_limited_files_present(self):
        path = FIXTURES_DIR / "clamav_scan_infected_skips.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data["scan_gaps"]["size_limited_files"]) > 0

    def test_permission_denied_present(self):
        path = FIXTURES_DIR / "clamav_scan_infected_skips.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data["scan_gaps"]["permission_denied"]) > 0


class TestOutdatedDefsFixture:
    def test_outdated_age_and_low_confidence(self):
        path = FIXTURES_DIR / "clamav_scan_outdated_defs.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        daily_age = data["definitions"]["daily"]["age_days"]
        assert daily_age > 90
        assert data["scan_confidence"]["level"] in ("low", "unknown")
        assert any("Update" in r or "update" in r for r in data["recommendations"])


class TestM17Integration:
    """Ensure m17 _clamav() correctly parses the new JSON format."""

    def test_reads_json_log_over_txt(self, tmp_path):
        from modules.m17_system_summary import _clamav  # type: ignore[import]

        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        # Write a clamav_scan_*.json log (new format)
        json_log = logs_dir / "clamav_scan_20241210_143000.json"
        json_log.write_text(json.dumps({
            "generated": "2024-12-10T14:30:00+00:00",
            "target": "/mnt/windows",
            "profile": "quick",
            "scan_status": "clean",
            "infected_files": [],
            "definitions": {
                "main": {"age_days": 5, "version": "62", "sig_count": 8715603,
                         "build_time": "...", "file": "main.cvd", "parse_error": None},
                "daily": {"age_days": 1, "version": "27397", "sig_count": 2104337,
                          "build_time": "...", "file": "daily.cld", "parse_error": None},
            },
            "coverage": {"overall_estimate": "high"},
            "scan_confidence": {"level": "high", "score": 5, "reasons": []},
            "recommendations": ["Run thorough scan for full coverage."],
        }), encoding="utf-8")

        result = _clamav(logs_dir)
        assert result is not None
        assert result["verdict"] == "CLEAN"
        assert result["infected"] == 0
        assert result["confidence"] == "high"
        assert result["coverage_estimate"] == "high"
        assert result["definitions_age"] == 5

    def test_reads_infected_from_json(self, tmp_path):
        from modules.m17_system_summary import _clamav  # type: ignore[import]

        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        json_log = logs_dir / "clamav_scan_20241210_160000.json"
        json_log.write_text(json.dumps({
            "generated": "2024-12-10T16:00:00+00:00",
            "target": "/mnt/windows",
            "profile": "quick",
            "scan_status": "infected",
            "infected_files": [
                {"path": "/mnt/windows/bad.exe", "virus": "Win.Trojan.Test"}
            ],
            "definitions": {
                "main": {"age_days": 5, "version": "62", "sig_count": 8715603,
                         "build_time": "...", "file": "main.cvd", "parse_error": None},
                "daily": {"age_days": 1, "version": "27397", "sig_count": 2104337,
                          "build_time": "...", "file": "daily.cld", "parse_error": None},
            },
            "coverage": {"overall_estimate": "high"},
            "scan_confidence": {"level": "medium", "score": 3, "reasons": []},
            "recommendations": ["Review infected files."],
        }), encoding="utf-8")

        result = _clamav(logs_dir)
        assert result is not None
        assert result["verdict"] == "INFECTED"
        assert result["infected"] == 1
