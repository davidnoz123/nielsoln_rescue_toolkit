"""
tests/test_triage.py — Unit tests for toolkit.triage.

Run from repo root:
    python -m pytest
"""

import csv
import sys
from pathlib import Path

import pytest

# Ensure repo root is on sys.path so toolkit imports resolve
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from toolkit.triage import interesting, run_triage  # noqa: E402


# ---------------------------------------------------------------------------
# interesting() tests
# ---------------------------------------------------------------------------

class TestInteresting:
    def test_exe_extension(self):
        assert interesting(Path("/mnt/vista/Windows/notepad.exe"))

    def test_dll_extension(self):
        assert interesting(Path("/mnt/vista/Windows/System32/kernel32.dll"))

    def test_ps1_extension(self):
        assert interesting(Path("/mnt/vista/Users/Bob/script.ps1"))

    def test_txt_not_interesting(self):
        assert not interesting(Path("/mnt/vista/Users/Bob/readme.txt"))

    def test_jpg_not_interesting(self):
        assert not interesting(Path("/mnt/vista/Users/Bob/photo.jpg"))

    def test_appdata_roaming_hint(self):
        # A file without a suspicious extension but in a suspicious path
        assert interesting(Path("/mnt/vista/Users/Bob/AppData/Roaming/something.log"))

    def test_temp_path_hint(self):
        assert interesting(Path("/mnt/vista/Temp/dropper.txt"))

    def test_startup_path_hint(self):
        assert interesting(Path("/mnt/vista/Windows/Startup/mystery"))

    def test_case_insensitive_extension(self):
        assert interesting(Path("/mnt/vista/foo/VIRUS.EXE"))

    def test_case_insensitive_path(self):
        assert interesting(Path("/mnt/vista/Users/Bob/APPDATA/ROAMING/thing.dat"))


# ---------------------------------------------------------------------------
# run_triage() integration tests (using a temporary fake Windows folder)
# ---------------------------------------------------------------------------

class TestRunTriage:
    def _make_fake_target(self, tmp_path: Path) -> Path:
        target = tmp_path / "fake_vista"
        # Interesting file
        roaming = target / "Users" / "Test" / "AppData" / "Roaming"
        roaming.mkdir(parents=True)
        (roaming / "suspicious.exe").write_bytes(b"\x4d\x5a" + b"\x00" * 64)

        # Non-interesting file
        docs = target / "Users" / "Test" / "Documents"
        docs.mkdir(parents=True)
        (docs / "notes.txt").write_text("hello world", encoding="utf-8")

        return target

    def test_creates_report(self, tmp_path: Path):
        target = self._make_fake_target(tmp_path)
        root = tmp_path / "usb_root"
        (root / "reports").mkdir(parents=True)
        (root / "logs").mkdir(parents=True)

        import logging
        logging.basicConfig(level=logging.WARNING)

        result = run_triage(root, target)
        assert result == 0

        report = root / "reports" / "triage_report.csv"
        assert report.exists(), "triage_report.csv should be created"

        with report.open(encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))

        # Header + at least one data row
        assert len(rows) >= 2, "Report should contain at least one flagged file"
        header = rows[0]
        assert "path" in header
        assert "sha256" in header

    def test_flags_exe_in_roaming(self, tmp_path: Path):
        target = self._make_fake_target(tmp_path)
        root = tmp_path / "usb_root"
        (root / "reports").mkdir(parents=True)
        (root / "logs").mkdir(parents=True)

        import logging
        logging.basicConfig(level=logging.WARNING)

        run_triage(root, target)
        report = root / "reports" / "triage_report.csv"

        with report.open(encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))

        paths = [row[0] for row in rows[1:]]
        assert any("suspicious.exe" in p for p in paths)

    def test_does_not_flag_txt(self, tmp_path: Path):
        target = self._make_fake_target(tmp_path)
        root = tmp_path / "usb_root"
        (root / "reports").mkdir(parents=True)
        (root / "logs").mkdir(parents=True)

        import logging
        logging.basicConfig(level=logging.WARNING)

        run_triage(root, target)
        report = root / "reports" / "triage_report.csv"

        with report.open(encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))

        paths = [row[0] for row in rows[1:]]
        assert not any("notes.txt" in p for p in paths)

    def test_missing_target_returns_2(self, tmp_path: Path):
        root = tmp_path / "usb_root"
        (root / "reports").mkdir(parents=True)
        (root / "logs").mkdir(parents=True)

        import logging
        logging.basicConfig(level=logging.WARNING)

        result = run_triage(root, tmp_path / "nonexistent")
        assert result == 2
