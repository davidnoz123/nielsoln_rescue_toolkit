"""
m18_clamav_scan.py — Nielsoln Rescue Toolkit: ClamAV scan against a target.

Runs clamscan with OOM-safe memory limits, resume support, and scan profiles.
Requires ClamAV to be installed or bundled (bootstrap clamav --install).

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m18_clamav_scan -- --target /mnt/windows [--profile thorough]
"""

from pathlib import Path

DESCRIPTION = (
    "ClamAV scan against a target Windows installation with OOM-safe memory "
    "limits and resume support (requires: bootstrap clamav --install)"
)


def run(root: Path, argv: list) -> int:
    """Module protocol entry point — called by `bootstrap run m18_clamav_scan`."""
    import argparse
    from toolkit import run_scan
    p = argparse.ArgumentParser(
        prog="bootstrap run m18_clamav_scan",
        description=DESCRIPTION,
    )
    p.add_argument("--target", required=True,
                   help="Path to mounted Windows installation (e.g. /mnt/windows)")
    p.add_argument("--profile", choices=["quick", "thorough"], default="quick",
                   help="quick=exe/script types only (~350 MB RAM)  "
                        "thorough=all files+archives (~600 MB RAM). Default: quick")
    p.add_argument("--no-swap", action="store_true",
                   help="Skip automatic swap file creation (not recommended on low-RAM systems)")
    p.add_argument("--no-resume", action="store_true",
                   help="Ignore any existing checkpoint and restart from the beginning")
    p.add_argument("--verbose", action="store_true",
                   help="Print each clamscan command line")
    args = p.parse_args(argv)
    return run_scan(
        root,
        Path(args.target),
        profile=args.profile,
        no_swap=args.no_swap,
        resume=not args.no_resume,
        verbose=args.verbose,
    )
