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
    from toolkit import run_scan, find_windows_target
    p = argparse.ArgumentParser(
        prog="bootstrap run m18_clamav_scan",
        description=DESCRIPTION,
    )
    p.add_argument("--target",
                   help="Path to mounted Windows installation. "
                        "Auto-detected from NTFS mounts if omitted.")
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

    if args.target:
        target = Path(args.target)
    else:
        target = find_windows_target()
        if target is None:
            print("ERROR: Could not auto-detect a Windows installation on any NTFS mount.")
            print("       Pass --target explicitly, or check mounts with: findmnt -t ntfs,fuseblk")
            return 2
        print(f"[m18] Auto-detected Windows target: {target}")

    return run_scan(
        root,
        target,
        profile=args.profile,
        no_swap=args.no_swap,
        resume=not args.no_resume,
        verbose=args.verbose,
    )
