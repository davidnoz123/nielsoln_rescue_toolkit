"""
Nielsoln Rescue Toolkit — CLI entrypoint.

Run from repo root:
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
"""

import argparse
import logging
import sys
from pathlib import Path


def find_usb_root() -> Path:
    return Path(__file__).resolve().parent


def setup_logging(root: Path, verbose: bool) -> None:
    log_path = root / "logs" / "toolkit.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def main() -> int:
    root = find_usb_root()

    parser = argparse.ArgumentParser(
        prog="bootstrap",
        description="Nielsoln Rescue Toolkit",
    )
    parser.add_argument("--no-update", action="store_true", help="Skip update check")
    parser.add_argument("--offline", action="store_true", help="Disable network access")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Run ClamAV scan against target")
    p_scan.add_argument("--target", required=True, help="Path to mounted Windows installation")

    p_triage = sub.add_parser("triage", help="Python-only suspicious file triage")
    p_triage.add_argument("--target", required=True, help="Path to mounted Windows installation")

    sub.add_parser("detect", help="Detect likely Windows installations under /mnt or /media")
    sub.add_parser("update", help="Pull latest toolkit from repository")

    p_runtime = sub.add_parser(
        "runtime",
        help="Install or update the bundled Python runtime on this USB",
    )
    p_runtime.add_argument(
        "--platform", default=None,
        help="Platform tag, e.g. linux-x86_64 (default: current platform)",
    )
    p_runtime.add_argument(
        "--mode", default="update",
        choices=["full", "update", "check", "prune"],
        help=(
            "full=wipe+re-extract  update=incremental (default)  "
            "check=dry-run  prune=update+delete-extras"
        ),
    )
    p_runtime.add_argument(
        "--verbosity", type=int, default=2, choices=[0, 1, 2],
        help="0=silent  1=actions only  2=actions+decisions (default)",
    )

    args = parser.parse_args()

    setup_logging(root, getattr(args, "verbose", False))
    log = logging.getLogger(__name__)
    log.debug("USB root: %s", root)
    log.debug("Command: %s", args.command)

    # Fire background auto-update unless suppressed or running the explicit
    # update/runtime commands (which provide their own foreground output).
    if not args.no_update and not args.offline and args.command not in ("update", "runtime"):
        from toolkit import start_background_update
        start_background_update(root)

    if args.command == "scan":
        from toolkit import run_scan
        return run_scan(root, Path(args.target))

    if args.command == "triage":
        from toolkit import run_triage
        return run_triage(root, Path(args.target))

    if args.command == "detect":
        from toolkit import run_detect
        return run_detect(root)

    if args.command == "update":
        from toolkit import run_update
        return run_update(root, offline=args.offline)

    if args.command == "runtime":
        from toolkit import run_install_runtime
        return run_install_runtime(
            root,
            platform_tag=args.platform,
            mode=args.mode,
            verbosity=args.verbosity,
        )

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
