"""
m29_storage_usage.py — Nielsoln Rescue Toolkit: storage usage on the offline Windows partition.

Reports disk free space, partition sizes, largest directories, and temp/cache
bloat visible in the offline Windows filesystem.  Read-only, no tools required
beyond Python standard library.

Usage (REPL):
    import runpy ; temp = runpy._run_module_as_main("bootstrap")
    # Then: bootstrap run m29_storage_usage -- --target /mnt/windows

Output:
    Prints a formatted report to stdout.
    Writes JSON to <USB>/logs/storage_usage_<timestamp>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("m29_storage_usage")

DESCRIPTION = (
    "Storage usage: free space, largest directories, and temp/cache bloat "
    "on the offline Windows partition — requires --target /mnt/windows"
)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

_DISK_WARN_PCT   = 85   # warn if usage >= 85%
_DISK_CRIT_PCT   = 95   # critical if usage >= 95%
_TEMP_WARN_MB    = 500  # warn if combined temp/cache exceeds 500 MB
_DIR_TOP_N       = 15   # number of largest dirs to report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _du_tree(path: Path, max_depth: int = 2) -> list[tuple[int, Path]]:
    """
    Walk *path* up to *max_depth* levels, return list of (total_bytes, subpath)
    for each immediate child directory.  Skips unreadable entries silently.
    """
    results: list[tuple[int, Path]] = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                total = _dir_size(Path(entry.path))
                results.append((total, Path(entry.path)))
    except PermissionError:
        pass
    return results


def _dir_size(path: Path) -> int:
    """Recursively sum file sizes under *path*.  Ignores errors."""
    total = 0
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                    elif entry.is_dir(follow_symlinks=False):
                        total += _dir_size(Path(entry.path))
                except (PermissionError, OSError):
                    pass
    except (PermissionError, OSError):
        pass
    return total


def _mb(n: int) -> float:
    return round(n / (1024 * 1024), 1)


def _gb(n: int) -> float:
    return round(n / (1024 ** 3), 2)


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def collect_partition_stats(target: Path) -> dict:
    """statvfs on the mounted Windows partition."""
    try:
        sv = os.statvfs(target)
        total_bytes = sv.f_frsize * sv.f_blocks
        free_bytes  = sv.f_frsize * sv.f_bfree
        used_bytes  = total_bytes - free_bytes
        used_pct    = round(used_bytes / total_bytes * 100, 1) if total_bytes else 0.0
        return {
            "total_gb":  _gb(total_bytes),
            "used_gb":   _gb(used_bytes),
            "free_gb":   _gb(free_bytes),
            "used_pct":  used_pct,
        }
    except Exception as exc:
        _log.warning("statvfs failed: %s", exc)
        return {"total_gb": None, "used_gb": None, "free_gb": None, "used_pct": None}


def collect_top_dirs(target: Path) -> list[dict]:
    """Return the _DIR_TOP_N largest first-level directories under target."""
    win_root = target / "Windows"
    users_root = target / "Users"
    prog_root  = target / "Program Files"
    prog86     = target / "Program Files (x86)"

    dirs_to_scan = [target]
    # Also go one level deeper in these important directories
    for subroot in (win_root, users_root, prog_root, prog86):
        if subroot.exists():
            dirs_to_scan.append(subroot)

    seen: set[Path] = set()
    all_dirs: list[tuple[int, Path]] = []
    for root in dirs_to_scan:
        for size, subdir in _du_tree(root):
            if subdir not in seen:
                seen.add(subdir)
                all_dirs.append((size, subdir))

    all_dirs.sort(reverse=True, key=lambda t: t[0])
    results = []
    for size, d in all_dirs[:_DIR_TOP_N]:
        results.append({
            "path":    str(d.relative_to(target)),
            "size_mb": _mb(size),
        })
    return results


_TEMP_DIRS = [
    "Windows/Temp",
    "Windows/SoftwareDistribution/Download",
    "Windows/Prefetch",
    "Users/*/AppData/Local/Temp",
    "Users/*/AppData/Local/Microsoft/Windows/Temporary Internet Files",
    "Users/*/AppData/LocalLow/Temp",
]


def collect_temp_usage(target: Path) -> list[dict]:
    """Measure known temp/cache directories."""
    results = []
    for pattern in _TEMP_DIRS:
        if "*" in pattern:
            # Expand user wildcard
            parts = pattern.split("/", 2)
            users_dir = target / parts[0]
            rest = "/".join(parts[2:]) if len(parts) > 2 else ""
            if users_dir.exists():
                try:
                    for user in users_dir.iterdir():
                        if not user.is_dir():
                            continue
                        candidate = user / rest if rest else user
                        if candidate.exists():
                            size = _dir_size(candidate)
                            results.append({
                                "path":    str(candidate.relative_to(target)),
                                "size_mb": _mb(size),
                            })
                except (PermissionError, OSError):
                    pass
        else:
            candidate = target / pattern
            if candidate.exists():
                size = _dir_size(candidate)
                results.append({
                    "path":    pattern,
                    "size_mb": _mb(size),
                })
    return results


def _derive_verdict(stats: dict, temp_mb: float) -> str:
    pct = stats.get("used_pct")
    if pct is None:
        return "UNKNOWN"
    if pct >= _DISK_CRIT_PCT:
        return "CRITICAL"
    if pct >= _DISK_WARN_PCT:
        return "WARNING"
    if temp_mb >= _TEMP_WARN_MB:
        return "TEMP_BLOAT"
    return "OK"


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def _fmt_report(report: dict) -> str:
    stats   = report["partition"]
    top     = report["top_dirs"]
    temps   = report["temp_dirs"]
    verdict = report["verdict"]

    lines = [
        "=" * 56,
        "  STORAGE USAGE",
        "=" * 56,
    ]

    if stats["total_gb"] is not None:
        lines += [
            f"  Total   : {stats['total_gb']:7.2f} GB",
            f"  Used    : {stats['used_gb']:7.2f} GB  ({stats['used_pct']}%)",
            f"  Free    : {stats['free_gb']:7.2f} GB",
            f"  Verdict : {verdict}",
        ]
    else:
        lines.append("  Partition stats unavailable.")

    lines += ["", "  Largest directories:"]
    for d in top[:10]:
        lines.append(f"    {d['size_mb']:8.1f} MB   {d['path']}")

    total_temp_mb = sum(d["size_mb"] for d in temps)
    lines += [
        "",
        f"  Temp / cache directories  (total: {total_temp_mb:.1f} MB):",
    ]
    for d in sorted(temps, key=lambda x: x["size_mb"], reverse=True):
        lines.append(f"    {d['size_mb']:8.1f} MB   {d['path']}")

    lines.append("=" * 56)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    ap = argparse.ArgumentParser(prog="m29_storage_usage", description=DESCRIPTION)
    ap.add_argument("--target", required=False, default=None,
                    help="Mount point of the Windows installation")
    args = ap.parse_args(argv)

    if args.target:
        target = Path(args.target)
    else:
        try:
            from toolkit import find_windows_target
            target = find_windows_target()
        except Exception:
            target = None
        if target is None:
            _log.error("Could not auto-detect Windows target. Pass --target.")
            return 1
        print(f"[m29] Auto-detected target: {target}", flush=True)

    if not target.exists():
        _log.error("Target path does not exist: %s", target)
        return 1

    print("[m29] Collecting partition stats ...", flush=True)
    stats = collect_partition_stats(target)
    if stats["total_gb"] is not None:
        print(f"[m29] {stats['used_gb']} / {stats['total_gb']} GB used "
              f"({stats['used_pct']}%)", flush=True)

    print("[m29] Scanning largest directories (this may take a minute) ...",
          flush=True)
    top_dirs = collect_top_dirs(target)

    print("[m29] Measuring temp/cache directories ...", flush=True)
    temp_dirs = collect_temp_usage(target)
    total_temp_mb = sum(d["size_mb"] for d in temp_dirs)

    verdict = _derive_verdict(stats, total_temp_mb)

    report = {
        "target":    str(target),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "partition": stats,
        "verdict":   verdict,
        "top_dirs":  top_dirs,
        "temp_dirs": temp_dirs,
        "total_temp_mb": total_temp_mb,
    }

    print()
    print(_fmt_report(report))

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = root / "logs" / f"storage_usage_{ts}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"[m29] Saved → {out_path}", flush=True)
    return 0
