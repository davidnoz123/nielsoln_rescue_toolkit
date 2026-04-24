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


def ensure_dirs(root: Path) -> None:
    for name in ["logs", "reports", "cache/downloads", "cache/wheels", "cache/repo", "quarantine"]:
        (root / name).mkdir(parents=True, exist_ok=True)


def setup_logging(root: Path, verbose: bool) -> None:
    log_path = root / "logs" / "toolkit.log"
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
    ensure_dirs(root)

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

    args = parser.parse_args()

    setup_logging(root, getattr(args, "verbose", False))
    log = logging.getLogger(__name__)
    log.debug("USB root: %s", root)
    log.debug("Command: %s", args.command)

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
        return run_update(root)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
