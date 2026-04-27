"""
m03_triage.py — Nielsoln Rescue Toolkit: Python-only suspicious file triage.

Walks the target Windows installation and flags all files with suspicious
extensions or paths. Outputs a CSV report (no ClamAV required).

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m03_triage -- --target /mnt/windows
"""

from pathlib import Path

DESCRIPTION = (
    "Python-only suspicious file triage: flags interesting files by extension "
    "and path, outputs CSV report with SHA256 (no ClamAV required)"
)


def run(root: Path, argv: list) -> int:
    """Module protocol entry point — called by `bootstrap run m03_triage`."""
    import argparse
    from toolkit import run_triage
    p = argparse.ArgumentParser(
        prog="bootstrap run m03_triage",
        description=DESCRIPTION,
    )
    p.add_argument("--target", required=True,
                   help="Path to mounted Windows installation (e.g. /mnt/windows)")
    args = p.parse_args(argv)
    return run_triage(root, Path(args.target))
