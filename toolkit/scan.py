"""
toolkit/scan.py — ClamAV orchestration.

Run from repo root:
    import runpy ; temp = runpy._run_module_as_main("toolkit.scan")
"""

import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


def run_scan(root: Path, target: Path) -> int:
    if not target.exists():
        log.error("Target does not exist: %s", target)
        print("Target does not exist:", target)
        return 2

    clamscan = shutil.which("clamscan")
    if clamscan is None:
        msg = (
            "clamscan not found. "
            "ClamAV is not installed or not on PATH. "
            "Run 'triage' for a Python-only scan instead."
        )
        log.warning(msg)
        print(msg)
        return 3

    log_path = root / "logs" / "clamav_scan.log"

    cmd = [
        clamscan,
        "--recursive",
        "--infected",
        f"--log={log_path}",
        str(target),
    ]

    log.info("Running ClamAV: %s", " ".join(cmd))
    print("Running:", " ".join(cmd))

    result = subprocess.run(cmd)  # noqa: S603 — clamscan path verified by shutil.which

    log.info("ClamAV finished with exit code %d. Log: %s", result.returncode, log_path)
    print("ClamAV log:", log_path)

    # clamscan exit codes: 0=clean, 1=infected found, 2=error
    if result.returncode == 1:
        log.warning("ClamAV found infected files — see log for details.")
        return 4  # toolkit exit code: suspicious/infected found

    return result.returncode
