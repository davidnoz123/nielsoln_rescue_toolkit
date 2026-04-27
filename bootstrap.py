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
    p_scan.add_argument(
        "--profile", choices=["quick", "thorough"], default="quick",
        help="Scan profile: quick (exe/script types, no archives) or thorough (all files, archives bounded). Default: quick",
    )
    p_scan.add_argument(
        "--no-swap", action="store_true",
        help="Skip automatic swap file creation (not recommended on low-RAM systems)",
    )
    p_scan.add_argument(
        "--no-resume", action="store_true",
        help="Ignore any existing checkpoint and restart the scan from the beginning",
    )

    p_triage = sub.add_parser("triage", help="Python-only suspicious file triage")
    p_triage.add_argument("--target", required=True, help="Path to mounted Windows installation")

    p_persist = sub.add_parser(
        "persist",
        help="Scan for persistence mechanisms (startup, tasks, services, registry autoruns)",
    )
    p_persist.add_argument(
        "--target", required=True,
        help="Path to mounted Windows installation (e.g. /mnt/windows)",
    )
    p_persist.add_argument(
        "--summary", action="store_true",
        help="Print a sorted human-readable summary after scanning",
    )
    p_persist.add_argument("--no-startup",  action="store_true", help="Skip startup folder scan")
    p_persist.add_argument("--no-tasks",    action="store_true", help="Skip scheduled task scan")
    p_persist.add_argument("--no-services", action="store_true", help="Skip service scan")
    p_persist.add_argument("--no-registry", action="store_true", help="Skip registry autorun scan")

    sub.add_parser("detect", help="Detect likely Windows installations under /mnt or /media")
    sub.add_parser("update", help="Pull latest toolkit from repository")

    p_exec = sub.add_parser(
        "exec",
        help="Execute an ad-hoc Python script payload (base64+gzip encoded) on this machine.",
    )
    p_exec.add_argument(
        "--payload",
        default="",
        metavar="B64GZ",
        help="Base64+gzip-encoded Python source.  If omitted, read from stdin.",
    )

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

    p_clamav = sub.add_parser(
        "clamav",
        help="Download, install, or update the bundled ClamAV antivirus scanner.",
    )
    p_clamav.add_argument(
        "--download",
        action="store_true",
        help="Download the ClamAV .deb to the local cache (clamav/linux-x86_64/).",
    )
    p_clamav.add_argument(
        "--install",
        action="store_true",
        help="Extract the bundled ClamAV .deb into clamav/linux-x86_64/extracted/.",
    )
    p_clamav.add_argument(
        "--update-db",
        action="store_true",
        help="Run freshclam to download/update the virus database (requires internet).",
    )
    p_clamav.add_argument(
        "--verbosity", type=int, default=2, choices=[0, 1, 2],
        metavar="N",
        help="0=silent  1=actions only  2=actions+decisions (default: 2).",
    )

    sub.add_parser(
        "dropbear",
        help="Download the dropbear SSH server binary to _tools/dropbear on this USB.",
    )

    p_push = sub.add_parser(
        "push",
        help="Push local source files to a running RescueZilla over SSH (bypasses GitHub).",
    )
    p_push.add_argument(
        "--host", required=True,
        help="IP or hostname of the RescueZilla machine.",
    )
    p_push.add_argument(
        "--port", type=int, default=22,
        help="SSH port (default: 22).",
    )
    p_push.add_argument(
        "--key", default="",
        metavar="PATH",
        help="Path to SSH private key (default: system default).",
    )
    p_push.add_argument(
        "--remote-root", default="",
        metavar="PATH",
        help="Path to toolkit root on remote (auto-detected if omitted).",
    )

    p_ssh = sub.add_parser(
        "ssh",
        help="Start an SSH server (openssh/dropbear) for remote VS Code access.",
    )
    p_ssh.add_argument(
        "--port", type=int, default=22,
        help="Port to listen on (default: 22).",
    )
    p_ssh.add_argument(
        "--pubkey", default="",
        metavar="KEY",
        help="Additional SSH public key string to install (in addition to the bundled key).",
    )
    p_ssh.add_argument(
        "--password", default="",
        metavar="PW",
        help="Set a temporary root password (less secure than key auth).",
    )

    args = parser.parse_args()

    setup_logging(root, getattr(args, "verbose", False))
    log = logging.getLogger(__name__)
    log.debug("USB root: %s", root)
    log.debug("Command: %s", args.command)

    # Fire background auto-update unless suppressed or running the explicit
    # update/runtime/clamav commands (which provide their own foreground output).
    if not args.no_update and not args.offline and args.command not in ("update", "runtime", "clamav"):
        from toolkit import start_background_update
        start_background_update(root)

    if args.command == "scan":
        from toolkit import run_scan
        return run_scan(
            root,
            Path(args.target),
            profile=args.profile,
            no_swap=args.no_swap,
            resume=not args.no_resume,
            verbose=args.verbose,
        )

    if args.command == "triage":
        from toolkit import run_triage
        return run_triage(root, Path(args.target))

    if args.command == "persist":
        from persistence_scan import run_persistence_scan
        return run_persistence_scan(
            root,
            Path(args.target),
            summary=args.summary,
            no_startup=args.no_startup,
            no_tasks=args.no_tasks,
            no_services=args.no_services,
            no_registry=args.no_registry,
        )

    if args.command == "exec":
        import base64, gzip, traceback
        try:
            raw = args.payload or sys.stdin.read().strip()
            code = gzip.decompress(base64.b64decode(raw)).decode("utf-8")
        except Exception as exc:
            print(f"exec: failed to decode payload: {exc}", file=sys.stderr)
            return 1
        globs = {"root": root, "Path": Path, "__name__": "__remote_exec__"}
        try:
            exec(compile(code, "<remote-exec>", "exec"), globs)  # noqa: S102
        except SystemExit as exc:
            return exc.code or 0
        except Exception:
            traceback.print_exc()
            return 1
        return 0

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

    if args.command == "clamav":
        from toolkit import download_clamav, run_install_clamav, run_clamav_update_db
        if not args.download and not args.install and not args.update_db:
            p_clamav.print_help()
            return 0
        rc = 0
        if args.download:
            try:
                download_clamav(root, verbosity=args.verbosity)
            except RuntimeError as exc:
                print(f"ERROR: {exc}")
                rc = 1
        if args.install and rc == 0:
            rc = run_install_clamav(root, verbosity=args.verbosity)
        elif args.install:
            print("Skipping --install because --download failed.")
        if args.update_db:
            rc = run_clamav_update_db(root, verbosity=args.verbosity) or rc
        return rc

    if args.command == "dropbear":
        from toolkit import download_dropbear
        try:
            download_dropbear(root, verbosity=2)
        except RuntimeError as exc:
            print(f"ERROR: {exc}")
            return 1
        return 0

    if args.command == "push":
        from toolkit import run_push
        return run_push(
            root,
            host=args.host,
            port=args.port,
            key=args.key,
            remote_root=args.remote_root,
            verbosity=2,
        )

    if args.command == "ssh":
        from toolkit import run_ssh
        return run_ssh(
            root,
            extra_pubkey=args.pubkey,
            password=args.password,
            port=args.port,
        )

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
