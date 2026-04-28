"""
tests/test_m31_system_integrity_audit.py — Unit tests for m31_system_integrity_audit.

Run with:
    pytest tests/test_m31_system_integrity_audit.py -v
"""
from __future__ import annotations

import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

_MODULES_DIR = Path(__file__).parent.parent / "modules"
_M31_PATH    = _MODULES_DIR / "m31_system_integrity_audit.py"

def _load_m31():
    spec = importlib.util.spec_from_file_location("m31_system_integrity_audit", _M31_PATH)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

m31 = _load_m31()


# ---------------------------------------------------------------------------
# Helpers to build minimal PE bytes with version info
# ---------------------------------------------------------------------------

def _build_version_info(company: str = "Microsoft Corporation",
                        internal_name: str = "ntdll.dll") -> bytes:
    """Construct a minimal VS_VERSION_INFO block embedded in PE stub bytes.

    Returns raw bytes that look like the start of a PE file (MZ header present).
    """

    def _enc(s: str) -> bytes:
        return (s + "\x00").encode("utf-16-le")

    def _align4(n: int) -> int:
        return (n + 3) & ~3

    def _string_struct(key: str, value: str) -> bytes:
        # StringStruct: wLength(2) wValueLength(2) wType=1(2) szKey(UTF-16) padding value(UTF-16)
        key_enc   = _enc(key)
        val_enc   = _enc(value)
        after_key = 6 + len(key_enc)
        padding   = _align4(after_key) - after_key
        body      = key_enc + bytes(padding) + val_enc
        w_len     = 6 + len(body)
        w_val_len = len(val_enc) // 2
        hdr       = struct.pack("<HHH", w_len, w_val_len, 1)
        return hdr + body

    pieces = _string_struct("CompanyName",   company)
    pieces += _string_struct("InternalName", internal_name)

    # Prepend a small MZ stub so the parser sees an MZ header
    mz_stub = b"MZ" + bytes(510)
    return mz_stub + pieces


# ---------------------------------------------------------------------------
# TestCollectFileEvidence
# ---------------------------------------------------------------------------

class TestCollectFileEvidence:
    def test_missing_file_returns_exists_false(self, tmp_path):
        path = tmp_path / "nonexistent.dll"
        ev   = m31._collect_file_evidence(path)
        assert ev["exists"] is False
        assert ev["sha256"] is None

    def test_existing_file_returns_metadata(self, tmp_path):
        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        ev = m31._collect_file_evidence(f)
        assert ev["exists"] is True
        assert ev["size_bytes"] == 102
        assert ev["sha256"] is not None
        assert len(ev["sha256"]) == 64

    def test_zero_byte_file(self, tmp_path):
        f = tmp_path / "empty.dll"
        f.write_bytes(b"")
        ev = m31._collect_file_evidence(f)
        assert ev["exists"] is True
        assert ev["size_bytes"] == 0

    def test_version_info_extracted(self, tmp_path):
        f   = tmp_path / "test.exe"
        raw = _build_version_info("Microsoft Corporation", "ntdll.dll")
        f.write_bytes(raw)
        ev = m31._collect_file_evidence(f)
        assert ev["exists"] is True
        vi = ev.get("version_info") or {}
        assert "CompanyName" in vi
        assert vi["CompanyName"] == "Microsoft Corporation"


# ---------------------------------------------------------------------------
# TestCheckFileAnomalies
# ---------------------------------------------------------------------------

class TestCheckFileAnomalies:
    def _make_ev(self, company="Microsoft Corporation", size=100000,
                 mtime="2010-06-15T08:00:00Z", internal_name="ntdll.dll"):
        return {
            "exists":       True,
            "size_bytes":   size,
            "modified":     mtime,
            "version_info": {"CompanyName": company, "InternalName": internal_name},
        }

    def test_ms_company_no_anomaly(self):
        ev      = self._make_ev(company="Microsoft Corporation")
        anomalies = m31._check_file_anomalies(ev, "System32/ntdll.dll", "runtime")
        assert "SUSPICIOUS_METADATA" not in anomalies

    def test_non_ms_company_flagged(self):
        ev        = self._make_ev(company="ACME Hack Corp")
        anomalies = m31._check_file_anomalies(ev, "System32/ntdll.dll", "runtime")
        assert "SUSPICIOUS_METADATA" in anomalies

    def test_zero_byte_flagged(self):
        ev        = self._make_ev(size=0)
        anomalies = m31._check_file_anomalies(ev, "System32/ntdll.dll", "runtime")
        assert "ZERO_BYTE" in anomalies

    def test_future_timestamp_flagged(self):
        ev        = self._make_ev(mtime="2099-01-01T00:00:00Z")
        anomalies = m31._check_file_anomalies(ev, "System32/ntdll.dll", "runtime")
        assert "TIMESTAMP_FUTURE" in anomalies

    def test_ancient_timestamp_flagged(self):
        ev        = self._make_ev(mtime="1995-01-01T00:00:00Z")
        anomalies = m31._check_file_anomalies(ev, "System32/ntdll.dll", "runtime")
        assert "TIMESTAMP_TOO_OLD" in anomalies

    def test_missing_file_no_anomalies(self):
        ev = {"exists": False, "size_bytes": None, "modified": None, "version_info": {}}
        anomalies = m31._check_file_anomalies(ev, "System32/ntdll.dll", "runtime")
        assert anomalies == []

    def test_internal_name_mismatch_flagged(self):
        ev = self._make_ev(company="Microsoft Corporation", internal_name="evildll")
        # ntdll.dll with internal name "evildll" should flag INTERNAL_NAME_MISMATCH
        anomalies = m31._check_file_anomalies(ev, "System32/ntdll.dll", "runtime")
        assert "INTERNAL_NAME_MISMATCH" in anomalies


# ---------------------------------------------------------------------------
# TestParseCbsLog
# ---------------------------------------------------------------------------

class TestParseCbsLog:
    _CORRUPTION_TEXT = """\
2026-04-15 10:22:13, Info           CBS  Initializing.
2026-04-15 10:22:15, Error          CBS  Cannot repair member file [l:34]"ntdll.dll"
2026-04-15 10:22:16, Error          CBS  CORRUPTION: checksum mismatch on kernel32.dll
2026-04-15 10:22:17, Info           CBS  Repairing file kernel32.dll
2026-04-15 10:22:18, Error          CBS  Could not repair kernel32.dll — access denied
"""

    def test_detects_corruption_indicators(self):
        result = m31._parse_cbs_log(self._CORRUPTION_TEXT)
        assert len(result["corruption_indicators"]) >= 1

    def test_counts_repair_attempts(self):
        result = m31._parse_cbs_log(self._CORRUPTION_TEXT)
        assert result["repair_attempts"] >= 1

    def test_counts_failed_repairs(self):
        result = m31._parse_cbs_log(self._CORRUPTION_TEXT)
        assert result["failed_repairs"] >= 1

    def test_counts_errors(self):
        result = m31._parse_cbs_log(self._CORRUPTION_TEXT)
        assert result["error_count"] >= 3

    def test_clean_log_no_corruption(self):
        clean_text = """\
2026-04-15 10:00:00, Info  CBS  Starting.
2026-04-15 10:00:01, Info  CBS  Component store healthy.
2026-04-15 10:00:02, Info  CBS  Done.
"""
        result = m31._parse_cbs_log(clean_text)
        assert result["corruption_indicators"] == []
        assert result["failed_repairs"] == 0


# ---------------------------------------------------------------------------
# TestCheckPendingXml
# ---------------------------------------------------------------------------

class TestCheckPendingXml:
    _PENDING_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<Pending>
  <POQ>
    <HardLink source="C:\\old.dll" destination="C:\\new.dll" />
    <MoveFile source="C:\\temp\\foo.tmp" destination="C:\\Windows\\foo.dll" />
    <MoveFile source="C:\\temp\\bar.tmp" destination="C:\\Windows\\bar.dll" />
  </POQ>
</Pending>
"""

    def test_finds_pending_operations(self, tmp_path):
        winsxs = tmp_path / "Windows" / "WinSxS"
        winsxs.mkdir(parents=True)
        (winsxs / "pending.xml").write_text(self._PENDING_XML, encoding="utf-8")

        win_root = tmp_path / "Windows"
        result   = m31._check_pending_xml(win_root)
        assert result["found"] is True
        assert result["pending_operations"] >= 2

    def test_no_pending_xml(self, tmp_path):
        win_root = tmp_path / "Windows"
        win_root.mkdir(parents=True)
        result   = m31._check_pending_xml(win_root)
        assert result["found"] is False
        assert result["pending_operations"] == 0

    def test_corrupt_xml_sets_parse_error(self, tmp_path):
        winsxs = tmp_path / "Windows" / "WinSxS"
        winsxs.mkdir(parents=True)
        (winsxs / "pending.xml").write_text("<Pending><Unclosed>", encoding="utf-8")
        win_root = tmp_path / "Windows"
        result   = m31._check_pending_xml(win_root)
        assert result["found"] is True
        assert result["parse_error"] is not None


# ---------------------------------------------------------------------------
# TestComputeVerdict
# ---------------------------------------------------------------------------

class TestComputeVerdict:
    def _make_sections(self, missing=0, anomalous=0, cbs_corrupt=False,
                       disk_io_errors=0, suspicious_metadata=False,
                       disk_related=False):
        pf_flags = []
        if missing >= 5:
            pf_flags.append("MANY_PROTECTED_FILES_MISSING")
        elif missing >= 1:
            pf_flags.append("PROTECTED_FILES_MISSING")
        if suspicious_metadata:
            pf_flags.append("SUSPICIOUS_METADATA_IN_SYSTEM_DIR")

        svc_flags = []
        if cbs_corrupt:
            svc_flags.append("CBS_CORRUPTION_INDICATOR")
            svc_flags.append("CBS_FAILED_REPAIRS")

        evts_flags = []
        if disk_io_errors > 5:
            evts_flags.append("DISK_IO_ERRORS")

        cross_flags = []
        if disk_related:
            cross_flags.append("DISK_RELATED_CORRUPTION_SUSPECTED")

        return {
            "protected_files": {
                "checked": 60,
                "missing":  [{"path": f"f{i}", "category": "runtime"} for i in range(missing)],
                "anomalous": [{"path": "f0", "category": "runtime",
                               "anomalies": ["SUSPICIOUS_METADATA"],
                               "version_info": {"CompanyName": "ACME"},
                               "sha256": None, "size_bytes": 1000, "modified": "2010Z"}
                              ] * anomalous,
                "flags": pf_flags,
            },
            "servicing": {
                "cbs_log_found":        cbs_corrupt,
                "corruption_indicators": ["Cannot repair member file foo.dll"] if cbs_corrupt else [],
                "repair_attempts":      1 if cbs_corrupt else 0,
                "failed_repairs":       1 if cbs_corrupt else 0,
                "flags":                svc_flags,
            },
            "events": {
                "evtx_available": True,
                "disk_io_errors": disk_io_errors,
                "controller_resets": 0,
                "driver_failures":   0,
                "flags":             evts_flags,
            },
            "cross_module": {
                "disk_health_verdict": "CAUTION" if disk_related else None,
                "disk_errors_found":   disk_related,
                "flags":               cross_flags,
            },
            "driver_integrity": {"missing_driver_files": [], "suspicious_paths": [], "flags": []},
            "boot":             {"flags": []},
            "winsxs":           {"flags": []},
            "pending":          {"flags": []},
        }

    def test_clean_verdict(self):
        sections = self._make_sections()
        verdict, confidence, limitations, recs = m31._compute_verdict(sections)
        assert verdict == "CLEAN"

    def test_minor_issues_one_missing(self):
        sections = self._make_sections(missing=1)
        verdict, _, _, _ = m31._compute_verdict(sections)
        assert verdict == "MINOR_ISSUES"

    def test_corruption_many_missing(self):
        sections = self._make_sections(missing=5)
        verdict, _, _, _ = m31._compute_verdict(sections)
        assert verdict == "CORRUPTION_SUSPECTED"

    def test_tampering_suspicious_metadata(self):
        sections = self._make_sections(suspicious_metadata=True)
        verdict, _, _, _ = m31._compute_verdict(sections)
        assert verdict == "TAMPERING_SUSPECTED"

    def test_disk_related_corruption(self):
        sections = self._make_sections(missing=2, cbs_corrupt=True, disk_related=True)
        verdict, _, _, _ = m31._compute_verdict(sections)
        assert verdict == "DISK_RELATED_CORRUPTION_SUSPECTED"

    def test_corruption_cbs_plus_missing(self):
        sections = self._make_sections(missing=2, cbs_corrupt=True)
        verdict, _, _, _ = m31._compute_verdict(sections)
        assert verdict == "CORRUPTION_SUSPECTED"

    def test_recommendations_contain_sfc(self):
        sections = self._make_sections(missing=3)
        _, _, _, recs = m31._compute_verdict(sections)
        assert any("SFC" in r for r in recs)

    def test_recommendations_contain_chkdsk(self):
        sections = self._make_sections(disk_io_errors=8)
        _, _, _, recs = m31._compute_verdict(sections)
        assert any("CHKDSK" in r for r in recs)


# ---------------------------------------------------------------------------
# TestScanProtectedFiles
# ---------------------------------------------------------------------------

class TestScanProtectedFiles:
    def test_detects_missing_required_file(self, tmp_path):
        """Protected files are missing because we gave it a skeleton win_root."""
        win_root = tmp_path / "Windows"
        win_root.mkdir()
        (win_root / "System32").mkdir()
        # Leave almost all files absent — several required ones should be missing
        result = m31._scan_protected_files(win_root)
        assert result["checked"] > 0
        required_missing = result["missing"]
        assert len(required_missing) > 0

    def test_existing_file_not_in_missing(self, tmp_path):
        """A present ntdll.dll should NOT appear in missing."""
        win_root = tmp_path / "Windows"
        (win_root / "System32").mkdir(parents=True)
        # Create ntdll.dll with valid MZ stub + Microsoft metadata
        raw = _build_version_info("Microsoft Corporation", "ntdll.dll")
        (win_root / "System32" / "ntdll.dll").write_bytes(raw)
        result = m31._scan_protected_files(win_root)
        missing_paths = [m["path"] for m in result["missing"]]
        assert "System32/ntdll.dll" not in missing_paths

    def test_suspicious_metadata_in_anomalous(self, tmp_path):
        """ntdll.dll with non-Microsoft company → anomalous, with SUSPICIOUS_METADATA."""
        win_root = tmp_path / "Windows"
        (win_root / "System32").mkdir(parents=True)
        raw = _build_version_info("ACME Hack Corp", "ntdll.dll")
        (win_root / "System32" / "ntdll.dll").write_bytes(raw)
        result = m31._scan_protected_files(win_root)
        anom_paths = [a["path"] for a in result["anomalous"]]
        assert "System32/ntdll.dll" in anom_paths
        ntdll_anoms = next(a["anomalies"] for a in result["anomalous"]
                           if a["path"] == "System32/ntdll.dll")
        assert "SUSPICIOUS_METADATA" in ntdll_anoms


# ---------------------------------------------------------------------------
# TestCheckServicing
# ---------------------------------------------------------------------------

class TestCheckServicing:
    def test_missing_cbs_log(self, tmp_path):
        win_root = tmp_path / "Windows"
        win_root.mkdir()
        result   = m31._check_servicing(win_root)
        assert result["cbs_log_found"] is False

    def test_cbs_log_with_corruption(self, tmp_path):
        cbs_dir = tmp_path / "Windows" / "Logs" / "CBS"
        cbs_dir.mkdir(parents=True)
        (cbs_dir / "CBS.log").write_text(
            "2026-01-01 Error CBS Cannot repair member file ntdll.dll\n"
            "2026-01-01 Error CBS Could not repair ntdll.dll\n",
            encoding="utf-8",
        )
        win_root = tmp_path / "Windows"
        result   = m31._check_servicing(win_root)
        assert result["cbs_log_found"] is True
        assert len(result["corruption_indicators"]) >= 1
        assert "CBS_CORRUPTION_INDICATOR" in result["flags"]
        assert "CBS_FAILED_REPAIRS" in result["flags"]


# ---------------------------------------------------------------------------
# TestCorrelateOtherModules
# ---------------------------------------------------------------------------

class TestCorrelateOtherModules:
    def test_no_logs_returns_defaults(self, tmp_path):
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        result   = m31._correlate_other_modules(logs_dir)
        assert result["disk_health_log"] is None
        assert result["service_suspicious"] == 0

    def test_disk_health_caution_plus_disk_errors(self, tmp_path):
        """Disk health CAUTION + disk integrity errors → DISK_RELATED_CORRUPTION_SUSPECTED flag."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        # Write a minimal disk_health log
        dh_log = [{"model": "Test Drive", "verdict": "CAUTION", "flags": ["REALLOCATED_SECTORS"]}]
        (logs_dir / "disk_health_20260428_120000.json").write_text(
            json.dumps(dh_log), encoding="utf-8"
        )

        # Write a minimal disk_integrity log with errors
        di_log = {"io_error_events": {"disk_errors": 10}, "dirty_bit": {"dirty": True}}
        (logs_dir / "disk_integrity_20260428_120000.json").write_text(
            json.dumps(di_log), encoding="utf-8"
        )

        result = m31._correlate_other_modules(logs_dir)
        assert result["disk_health_verdict"] == "CAUTION"
        assert result["disk_errors_found"] is True
        assert "DISK_RELATED_CORRUPTION_SUSPECTED" in result["flags"]

    def test_persistence_and_service_signals_tampering(self, tmp_path):
        """Both persistence (HIGH) and suspicious services → CROSS_MODULE_TAMPERING_SIGNAL."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        # Persistence JSONL with one HIGH finding
        (logs_dir / "persist_20260428_120000.jsonl").write_text(
            json.dumps({"severity": "HIGH", "category": "run_key",
                        "path": "HKLM\\Software\\Run\\evil"}) + "\n",
            encoding="utf-8",
        )

        # Service analysis with suspicious count
        sa = {"summary": {"suspicious_count": 2, "verdict": "SUSPICIOUS"}}
        (logs_dir / "service_analysis_20260428_120000.json").write_text(
            json.dumps(sa), encoding="utf-8"
        )

        result = m31._correlate_other_modules(logs_dir)
        assert result["persistence_suspicious"] == 1
        assert result["service_suspicious"] == 2
        assert "CROSS_MODULE_TAMPERING_SIGNAL" in result["flags"]
