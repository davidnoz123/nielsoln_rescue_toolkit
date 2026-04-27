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

    p_run = sub.add_parser(
        "run",
        help="Run a scan module by name (e.g. bootstrap run m01_persistence_scan -- --target /mnt/windows)",
    )
    p_run.add_argument(
        "name",
        help="Module name without .py extension (e.g. m01_persistence_scan)",
    )
    p_run.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments passed directly to the module (use -- to separate)",
    )

    p_load = sub.add_parser(
        "load",
        help="Install a module from a base64+gzip encoded payload onto this USB",
    )
    p_load.add_argument(
        "--name", required=True,
        help="Module filename without .py (e.g. m02_disk_overview)",
    )
    p_load.add_argument(
        "--payload", default="",
        metavar="B64GZ",
        help="Base64+gzip-encoded Python source.  If omitted, read from stdin.",
    )

    sub.add_parser("status", help="Show SHA256 and presence of all core files and modules on this USB")
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

    # Fire background auto-update unless suppressed or running lifecycle commands.
    if not args.no_update and not args.offline and args.command not in (
        "update", "runtime", "clamav", "load", "status",
    ):
        from toolkit import start_background_update
        start_background_update(root)

    if args.command == "run":
        from toolkit import load_module, acquire_run_lock, release_run_lock
        module_argv = args.args
        # Strip a leading '--' separator if the user wrote: bootstrap run <name> -- --flag
        if module_argv and module_argv[0] == "--":
            module_argv = module_argv[1:]
        try:
            acquire_run_lock(root, f"run {args.name}")
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        try:
            try:
                mod = load_module(root, args.name)
            except (FileNotFoundError, ImportError) as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1
            return mod.run(root, module_argv)
        finally:
            release_run_lock(root)

    if args.command == "load":
        import base64, gzip
        try:
            raw = args.payload or sys.stdin.read().strip()
            source = gzip.decompress(base64.b64decode(raw))
        except Exception as exc:
            print(f"load: failed to decode payload: {exc}", file=sys.stderr)
            return 1
        modules_dir = root / "modules"
        modules_dir.mkdir(parents=True, exist_ok=True)
        dest = modules_dir / f"{args.name}.py"
        dest.write_bytes(source)
        print(f"Installed: {dest}")
        return 0

    if args.command == "status":
        from toolkit import status_report
        return status_report(root)

    if args.command == "exec":
        import base64, gzip, traceback
        from toolkit import acquire_run_lock, release_run_lock
        try:
            acquire_run_lock(root, "exec")
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        try:
            raw = args.payload or sys.stdin.read().strip()
            try:
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
        finally:
            release_run_lock(root)

    if args.command == "update":
        from toolkit import run_update, acquire_run_lock, release_run_lock
        try:
            acquire_run_lock(root, "update")
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        try:
            return run_update(root, offline=args.offline)
        finally:
            release_run_lock(root)

    if args.command == "runtime":
        from toolkit import run_install_runtime
        return run_install_runtime(
            root,
            platform_tag=args.platform,
            mode=args.mode,
            verbosity=args.verbosity,
        )

    if args.command == "clamav":
        from toolkit import download_clamav, run_install_clamav, run_clamav_update_db, acquire_run_lock, release_run_lock
        if not args.download and not args.install and not args.update_db:
            p_clamav.print_help()
            return 0
        try:
            acquire_run_lock(root, "clamav")
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        try:
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
        finally:
            release_run_lock(root)

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
