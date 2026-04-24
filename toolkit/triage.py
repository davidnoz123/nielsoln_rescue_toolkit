"""
toolkit/triage.py — Python-only suspicious file triage.

Run from repo root:
    import runpy ; temp = runpy._run_module_as_main("toolkit.triage")
"""

import csv
import hashlib
import logging
import os
import time
from pathlib import Path

log = logging.getLogger(__name__)

SUSPICIOUS_EXTS = {
    ".exe", ".dll", ".sys", ".scr",
    ".bat", ".cmd", ".vbs", ".js", ".ps1",
    ".hta", ".wsf", ".pif",
}

SUSPICIOUS_PATH_HINTS = [
    "/appdata/roaming/",
    "/appdata/local/temp/",
    "/temp/",
    "/startup/",
    "/windows/temp/",
    "/recycler/",
    "/$recycle.bin/",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def interesting(path: Path, relative_to: Path = None) -> bool:
    if relative_to is not None:
        try:
            text = str(path.relative_to(relative_to)).replace("\\", "/").lower()
        except ValueError:
            text = str(path).replace("\\", "/").lower()
    else:
        text = str(path).replace("\\", "/").lower()
    if path.suffix.lower() in SUSPICIOUS_EXTS:
        return True
    return any(hint in text for hint in SUSPICIOUS_PATH_HINTS)


def run_triage(root: Path, target: Path) -> int:
    if not target.exists():
        log.error("Target does not exist: %s", target)
        print("Target does not exist:", target)
        return 2

    report_path = root / "reports" / "triage_report.csv"
    log.info("Starting triage: target=%s", target)

    count = 0
    errors = 0

    with report_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "size_bytes", "modified_time", "sha256", "reason", "error"])

        for dirpath, _dirnames, filenames in os.walk(str(target)):
            for name in filenames:
                path = Path(dirpath) / name

                if not interesting(path, relative_to=target):
                    continue

                try:
                    st = path.stat()
                    mtime = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)
                    )
                    digest = sha256_file(path)
                    writer.writerow([
                        str(path),
                        st.st_size,
                        mtime,
                        digest,
                        "suspicious extension or path",
                        "",
                    ])
                    count += 1
                except Exception as exc:
                    writer.writerow([str(path), "", "", "", "", str(exc)])
                    errors += 1
                    log.debug("Could not read %s: %s", path, exc)

    log.info("Triage complete: %d files flagged, %d errors. Report: %s", count, errors, report_path)
    print(f"Triage complete: {count} file(s) flagged, {errors} error(s).")
    print("Report:", report_path)
    return 0
