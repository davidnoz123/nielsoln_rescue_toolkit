"""
toolkit/env.py — Platform detection and path helpers.

Run from repo root:
    import runpy ; temp = runpy._run_module_as_main("toolkit.env")
"""

import platform
import sys
from pathlib import Path


def get_platform() -> str:
    """Return a short platform tag, e.g. 'linux-x86_64'."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalise common variants
    if machine in ("amd64", "x86_64"):
        machine = "x86_64"
    elif machine in ("aarch64", "arm64"):
        machine = "arm64"

    return f"{system}-{machine}"


def get_python_executable(root: Path) -> Path:
    """Return path to bundled Python for the current platform, if present."""
    tag = get_platform()
    candidate = root / "runtimes" / tag / "python" / "bin" / "python3"
    return candidate


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_macos() -> bool:
    return platform.system().lower() == "darwin"


def is_windows() -> bool:
    return platform.system().lower() == "windows"


if __name__ == "__main__":
    tag = get_platform()
    print("Platform:", tag)
    print("Python:", sys.version)
