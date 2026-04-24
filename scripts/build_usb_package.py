"""
scripts/build_usb_package.py — Build dist/NIELSOLN_RESCUE_USB.

Run from repo root:
    import runpy ; temp = runpy._run_module_as_main("scripts.build_usb_package")

Steps
-----
1. Remove old dist/NIELSOLN_RESCUE_USB if it exists.
2. Create fresh dist/NIELSOLN_RESCUE_USB.
3. Copy bootstrap.sh.
4. Copy toolkit/.
5. Create cache/, logs/, reports/, quarantine/.
6. Create runtime placeholder directories.
7. chmod bootstrap.sh executable (Linux/macOS only).
"""

import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "NIELSOLN_RESCUE_USB"


def main() -> None:
    print(f"Building USB package into: {DIST}")

    if DIST.exists():
        print("Removing existing dist folder...")
        shutil.rmtree(DIST)

    DIST.mkdir(parents=True)

    # Core files
    shutil.copy2(ROOT / "bootstrap.sh", DIST / "bootstrap.sh")
    shutil.copytree(ROOT / "toolkit", DIST / "toolkit")

    # Working directories
    for name in [
        "cache/downloads",
        "cache/wheels",
        "cache/repo",
        "logs",
        "reports",
        "quarantine",
    ]:
        (DIST / name).mkdir(parents=True, exist_ok=True)
        (DIST / name / ".gitkeep").touch()

    # Runtime placeholder directories
    for runtime in ["linux-x86_64", "macos-x86_64", "macos-arm64"]:
        path = DIST / "runtimes" / runtime
        path.mkdir(parents=True, exist_ok=True)
        (path / "README.txt").write_text(
            f"Place the portable Python 3 runtime for {runtime} here.\n"
            "Expected layout:\n"
            "  python/\n"
            "    bin/\n"
            "      python3\n",
            encoding="utf-8",
        )

    # Make bootstrap.sh executable on Unix-like systems
    try:
        os.chmod(DIST / "bootstrap.sh", 0o755)
    except (AttributeError, NotImplementedError):
        pass  # Windows — permissions handled when copied to USB

    print(f"Done. USB package: {DIST}")
    print()
    print("Contents:")
    for path in sorted(DIST.rglob("*")):
        rel = path.relative_to(DIST)
        indent = "  " * (len(rel.parts) - 1)
        label = str(rel.name) + ("/" if path.is_dir() else "")
        print(f"  {indent}{label}")


if __name__ == "__main__":
    main()
