"""
toolkit/mount_detect.py — Detect likely Windows installations.

Run from repo root:
    import runpy ; temp = runpy._run_module_as_main("toolkit.mount_detect")
"""

import logging
from pathlib import Path

log = logging.getLogger(__name__)

SEARCH_BASES = [Path("/mnt"), Path("/media")]
WINDOWS_MARKER = "Windows/System32"


def find_windows_installations() -> list:
    candidates = []

    for base in SEARCH_BASES:
        if not base.exists():
            continue
        try:
            for marker in base.rglob(WINDOWS_MARKER):
                # marker is e.g. /mnt/sda1/Windows/System32
                candidate = marker.parents[1]
                if candidate not in candidates:
                    candidates.append(candidate)
        except PermissionError as exc:
            log.debug("Permission error scanning %s: %s", base, exc)

    return candidates


def run_detect(root: Path) -> int:
    log.info("Scanning for Windows installations under %s", SEARCH_BASES)
    candidates = find_windows_installations()

    if not candidates:
        msg = "No likely Windows installations found under /mnt or /media."
        log.info(msg)
        print(msg)
        return 1

    print("Likely Windows installations:")
    for path in candidates:
        print("  " + str(path))
        log.info("Found: %s", path)

    return 0
