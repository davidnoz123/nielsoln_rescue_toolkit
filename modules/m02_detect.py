"""
m02_detect.py — Nielsoln Rescue Toolkit: detect mounted Windows installations.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m02_detect
"""

from pathlib import Path

DESCRIPTION = "Detect likely Windows installations under /mnt or /media"


def run(root: Path, argv: list) -> int:
    """Module protocol entry point — called by `bootstrap run m02_detect`."""
    from toolkit import run_detect
    return run_detect(root)
