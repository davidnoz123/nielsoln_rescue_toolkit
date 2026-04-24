"""
toolkit/updater.py — Staged self-update logic.

Run from repo root:
    import runpy ; temp = runpy._run_module_as_main("toolkit.updater")

Update stages
-------------
1. Download latest ZIP from cache/repo (or network if available).
2. Extract to a staging area (cache/update_staging/).
3. Run a basic smoke-test against the staged copy.
4. If tests pass, promote by replacing toolkit/ with the staged copy.
5. Write a version record to cache/version.txt.

In v1 this module stubs the network fetch and only demonstrates
the staging/promotion logic safely.
"""

import logging
import shutil
from pathlib import Path

log = logging.getLogger(__name__)

VERSION_FILE = "cache/version.txt"


def current_version(root: Path) -> str:
    vf = root / VERSION_FILE
    if vf.exists():
        return vf.read_text(encoding="utf-8").strip()
    return "unknown"


def run_update(root: Path) -> int:
    log.info("Update requested. Current version: %s", current_version(root))
    print(f"Current version: {current_version(root)}")

    # v1: network update not yet implemented — offline/USB-copy workflow only.
    msg = (
        "Automatic network update is not yet implemented in v1.\n"
        "To update the toolkit, copy a new version of the toolkit/ folder\n"
        "to this USB drive manually, then re-run your command."
    )
    log.info(msg)
    print(msg)
    return 0
