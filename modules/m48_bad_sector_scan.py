"""
m48_bad_sector_scan.py — Read-only bad-sector and slow-read test.

Scans the block device backing the mounted Windows partition using direct
Python file I/O (no external tools required).  Defaults to a sampled scan
(~30 zones × 4 blocks = ~120 × 512 KB = ~60 MB read, ~1-3 min on HDD).
A full sequential scan is available with --profile full but takes hours.

Run via runpy (from modules/ folder):
    import runpy; temp = runpy._run_module_as_main("m48_bad_sector_scan")

Or via bootstrap on RescueZilla:
    python3 bootstrap.py run m48_bad_sector_scan -- --target /mnt/windows

Or push-and-run via devtools:
    action = "run_module"
    module_name = "m48_bad_sector_scan"
    module_args = ["--target", "/mnt/windows"]
"""

import argparse
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

DESCRIPTION = "Read-only bad-sector and slow-read scan via direct block device I/O"
LOG_PREFIX   = "bad_sector_scan"

_log = logging.getLogger("m48")

# ── Default scan parameters ──────────────────────────────────────────────────
DEFAULT_BLOCK_SIZE       = 512 * 1024   # 512 KB per read
DEFAULT_SLOW_MS          = 500          # flag reads slower than this (ms)
DEFAULT_TIME_LIMIT_S     = 300          # 5 min wall-clock limit
DEFAULT_N_ZONES          = 30           # divide device range into N zones
DEFAULT_BLOCKS_PER_ZONE  = 4            # read this many blocks per zone


# ── Device discovery helpers ─────────────────────────────────────────────────

def _find_partition_device(target: Path):
    """Return the block-device source for *target* (e.g. /dev/sda2), or None."""
    # 1. findmnt (most reliable)
    try:
        out = subprocess.check_output(
            ["findmnt", "-n", "-o", "SOURCE", str(target)],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
        if out and not out.startswith("//"):
            return out
    except Exception:
        pass

    # 2. /proc/mounts fallback
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == str(target):
                    return parts[0]
    except Exception:
        pass

    return None


def _physical_device(dev: str) -> str:
    """Strip partition suffix: /dev/sda2 → /dev/sda, /dev/nvme0n1p3 → /dev/nvme0n1."""
    name = Path(dev).name
    m = re.match(r"(nvme\d+n\d+)p\d+$", name)
    if m:
        return str(Path(dev).parent / m.group(1))
    m = re.match(r"([a-z]+\d*[a-z]+)\d+$", name)  # sda2, hda1, mmcblk0p1 handled below
    if m:
        return str(Path(dev).parent / m.group(1))
    # mmcblk0p2 → mmcblk0
    m = re.match(r"(mmcblk\d+)p\d+$", name)
    if m:
        return str(Path(dev).parent / m.group(1))
    return dev


def _read_sys(path: str):
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except Exception:
        return None


def _device_size_bytes(dev: str) -> int:
    """Return device size in bytes via /sys or blockdev."""
    name = Path(dev).name
    # /sys/class/block/<name>/size = 512-byte sectors
    v = _read_sys(f"/sys/class/block/{name}/size")
    if v is not None:
        return v * 512
    # blockdev fallback
    try:
        out = subprocess.check_output(
            ["blockdev", "--getsize64", dev],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
        return int(out)
    except Exception:
        pass
    return 0


def _sector_size(dev: str) -> int:
    """Return physical sector size in bytes (usually 512 or 4096)."""
    name = Path(dev).name
    for suffix in [
        f"/sys/class/block/{name}/queue/physical_block_size",
        f"/sys/block/{name}/queue/physical_block_size",
    ]:
        v = _read_sys(suffix)
        if v is not None:
            return v
    return 512


def _partition_offset_lba(partition_dev: str) -> int:
    """LBA start of the partition (512-byte units) from /sys, or 0."""
    name = Path(partition_dev).name
    v = _read_sys(f"/sys/class/block/{name}/start")
    return v if v is not None else 0


# ── Range accumulator ────────────────────────────────────────────────────────

def _add_range(ranges: list, lba: int, count: int, **extra):
    """Append a new range or extend the last entry if contiguous."""
    if ranges:
        last = ranges[-1]
        if last["lba_end"] + 1 >= lba:
            last["lba_end"] = max(last["lba_end"], lba + count - 1)
            last["sector_count"] = last["lba_end"] - last["lba_start"] + 1
            for k, v in extra.items():
                if k not in last:
                    last[k] = v
            return
    entry = {"lba_start": lba, "lba_end": lba + count - 1, "sector_count": count}
    entry.update(extra)
    ranges.append(entry)


# ── Core scan loop ───────────────────────────────────────────────────────────

def _scan(
    device: str,
    size_bytes: int,
    sector_size: int,
    block_size: int,
    time_limit_s: float,
    slow_threshold_ms: float,
    n_zones: int,
    blocks_per_zone: int,
) -> dict:
    """
    Open *device* read-only and perform a sampled sequential scan.
    Returns a partial report dict ready to be merged into the full report.
    """
    if size_bytes <= 0:
        return {
            "scan_status": "error",
            "interrupted_reason": "device_size_unknown",
            "sectors_attempted": 0,
            "sectors_read_ok": 0,
            "sectors_failed": 0,
            "sectors_slow": 0,
            "bad_ranges": [],
            "slow_read_ranges": [],
            "duration_seconds": 0.0,
            "stop_reasons": [],
            "_sampled_fraction": 0.0,
            "_full_scan": False,
        }

    blocks_total = size_bytes // block_size
    if blocks_total == 0:
        blocks_total = 1

    # Build sample offsets: spread n_zones evenly, blocks_per_zone per zone
    zone_size = max(1, blocks_total // n_zones)
    offsets = []
    for z in range(n_zones):
        zone_start = z * zone_size
        step = max(1, zone_size // max(1, blocks_per_zone))
        for b in range(blocks_per_zone):
            blk = zone_start + b * step
            if blk < blocks_total:
                offsets.append(blk * block_size)
    # Remove duplicates while preserving order
    seen = set()
    offsets = [o for o in offsets if not (o in seen or seen.add(o))]

    sectors_per_block = max(1, block_size // sector_size)

    attempted = ok_count = fail_count = slow_count = 0
    bad_ranges: list  = []
    slow_ranges: list = []
    stop_reasons: list = []
    scan_complete = True
    interrupted_reason = None

    now_iso = lambda: datetime.now(timezone.utc).isoformat()

    t_start = time.monotonic()

    try:
        with open(device, "rb", buffering=0) as fh:
            for byte_off in offsets:
                elapsed_wall = time.monotonic() - t_start
                if elapsed_wall >= time_limit_s:
                    scan_complete = False
                    stop_reasons.append("time_limit_reached")
                    interrupted_reason = "time_limit_reached"
                    _log.info("Time limit %.0fs reached after %d attempts", time_limit_s, attempted)
                    break

                lba = byte_off // sector_size

                try:
                    fh.seek(byte_off)
                    t0 = time.monotonic()
                    data = fh.read(block_size)
                    elapsed_ms = (time.monotonic() - t0) * 1000
                    attempted += 1

                    if len(data) == 0:
                        _log.debug("EOF at offset %d", byte_off)
                        break

                    if elapsed_ms > slow_threshold_ms:
                        slow_count += 1
                        _add_range(
                            slow_ranges, lba, sectors_per_block,
                            avg_latency_ms=round(elapsed_ms, 1),
                            max_latency_ms=round(elapsed_ms, 1),
                        )
                        _log.debug("SLOW  lba=%d  %.0f ms", lba, elapsed_ms)
                    else:
                        ok_count += 1
                        _log.debug("OK    lba=%d  %.0f ms", lba, elapsed_ms)

                except OSError as exc:
                    fail_count += 1
                    attempted += 1
                    _add_range(
                        bad_ranges, lba, sectors_per_block,
                        first_seen=now_iso(),
                        error_code=str(exc.errno),
                        error_msg=str(exc),
                    )
                    _log.warning("BAD   lba=%d  errno=%s  %s", lba, exc.errno, exc)

    except PermissionError as exc:
        return {
            "scan_status": "error",
            "interrupted_reason": f"permission_denied: {exc}",
            "sectors_attempted": 0, "sectors_read_ok": 0,
            "sectors_failed": 0, "sectors_slow": 0,
            "bad_ranges": [], "slow_read_ranges": [],
            "duration_seconds": 0.0, "stop_reasons": ["permission_denied"],
            "_sampled_fraction": 0.0, "_full_scan": False,
        }
    except Exception as exc:
        scan_complete = False
        interrupted_reason = f"{type(exc).__name__}: {exc}"
        _log.error("Scan error: %s", exc)

    duration = time.monotonic() - t_start
    sampled_fraction = round(attempted / max(1, len(offsets)), 4)

    # ── Determine verdict ────────────────────────────────────────────────────
    if fail_count > 0:
        verdict = "BAD_SECTORS_FOUND"
    elif slow_count > max(1, attempted) * 0.05:
        verdict = "SLOW_READS"
    elif not scan_complete and attempted < len(offsets) * 0.5:
        verdict = "SCAN_INCOMPLETE"
    else:
        verdict = "OK"

    # Confidence depends on coverage and completeness
    if scan_complete and attempted >= len(offsets) * 0.9:
        confidence = "high"
    elif attempted >= len(offsets) * 0.5:
        confidence = "medium"
    else:
        confidence = "low"

    limitations = []
    if not scan_complete:
        limitations.append("scan_incomplete_time_limit")
    limitations.append("sampled_scan_not_exhaustive")
    limitations.append("mounted_partition_os_buffering_may_mask_errors")

    return {
        "scan_status": "completed" if scan_complete else "interrupted",
        "interrupted_reason": interrupted_reason,
        "sectors_attempted": attempted * sectors_per_block,
        "sectors_read_ok":   ok_count  * sectors_per_block,
        "sectors_failed":    fail_count * sectors_per_block,
        "sectors_slow":      slow_count * sectors_per_block,
        "bad_ranges":        bad_ranges,
        "slow_read_ranges":  slow_ranges,
        "duration_seconds":  round(duration, 1),
        "verdict":           verdict,
        "risk_status":       verdict,
        "confidence":        confidence,
        "limitations":       limitations,
        "stop_reasons":      stop_reasons,
        "_sampled_fraction": sampled_fraction,
        "_full_scan":        sampled_fraction >= 0.999,
    }


# ── Module entry point ───────────────────────────────────────────────────────

def run(root: Path, argv: list) -> int:
    ap = argparse.ArgumentParser(prog="m48_bad_sector_scan", description=DESCRIPTION)
    ap.add_argument("--target", required=True, help="Mounted Windows path (e.g. /mnt/windows)")
    ap.add_argument(
        "--profile", choices=["quick", "full"], default="quick",
        help="quick=sampled 5-min scan (default); full=exhaustive scan (hours)",
    )
    ap.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE,
                    help=f"Read block size in bytes (default {DEFAULT_BLOCK_SIZE})")
    ap.add_argument("--time-limit", type=int, default=None,
                    help="Max seconds to scan (default: 300 for quick, 7200 for full)")
    ap.add_argument("--slow-ms", type=float, default=DEFAULT_SLOW_MS,
                    help=f"Slow-read threshold in ms (default {DEFAULT_SLOW_MS})")
    args = ap.parse_args(argv)

    target    = Path(args.target)
    block_sz  = args.block_size

    if args.profile == "full":
        n_zones         = 5000
        blocks_per_zone = 500
        time_limit_s    = float(args.time_limit or 7200)
    else:
        n_zones         = DEFAULT_N_ZONES
        blocks_per_zone = DEFAULT_BLOCKS_PER_ZONE
        time_limit_s    = float(args.time_limit or DEFAULT_TIME_LIMIT_S)

    _log.info("Profile: %s  zones=%d  blocks/zone=%d  time_limit=%.0fs",
              args.profile, n_zones, blocks_per_zone, time_limit_s)

    # ── Device discovery ─────────────────────────────────────────────────────
    partition_dev  = _find_partition_device(target)
    if partition_dev:
        _log.info("Partition device: %s", partition_dev)
        physical_dev       = _physical_device(partition_dev)
        part_offset_lba    = _partition_offset_lba(partition_dev)
        scan_device        = partition_dev
        size_bytes         = _device_size_bytes(scan_device)
        sector_sz          = _sector_size(physical_dev)
        _log.info("Physical device:  %s  partition_offset_lba=%d", physical_dev, part_offset_lba)
        _log.info("Device size:      %d bytes  sector_size=%d", size_bytes, sector_sz)
    else:
        _log.error("Cannot determine block device for %s", target)
        physical_dev    = None
        part_offset_lba = None
        scan_device     = None
        size_bytes      = 0
        sector_sz       = 512

    # ── Scan ─────────────────────────────────────────────────────────────────
    if scan_device:
        _log.info("Starting scan of %s …", scan_device)
        result = _scan(
            device           = scan_device,
            size_bytes       = size_bytes,
            sector_size      = sector_sz,
            block_size       = block_sz,
            time_limit_s     = time_limit_s,
            slow_threshold_ms= args.slow_ms,
            n_zones          = n_zones,
            blocks_per_zone  = blocks_per_zone,
        )
    else:
        result = {
            "scan_status": "error",
            "interrupted_reason": "device_not_found",
            "sectors_attempted": 0, "sectors_read_ok": 0,
            "sectors_failed": 0, "sectors_slow": 0,
            "bad_ranges": [], "slow_read_ranges": [],
            "duration_seconds": 0.0, "stop_reasons": ["device_not_found"],
            "_sampled_fraction": 0.0, "_full_scan": False,
            "verdict": "UNKNOWN", "risk_status": "UNKNOWN",
            "confidence": "none", "limitations": ["device_not_found"],
        }

    # ── Assemble report ───────────────────────────────────────────────────────
    now = datetime.now(timezone.utc)
    sampled_frac = result.pop("_sampled_fraction", 0.0)
    full_scan    = result.pop("_full_scan", False)
    stop_reasons = result.pop("stop_reasons", [])

    verdict = result.get("verdict", "UNKNOWN")
    clone_recommended = verdict in ("BAD_SECTORS_FOUND", "FAILING", "CRITICAL")

    ddrescue_cmd = None
    if clone_recommended and physical_dev:
        ddrescue_cmd = (
            f"ddrescue -d -r3 {physical_dev} /path/to/image.img /path/to/map.log"
        )

    recommendations: list = []
    warnings:        list = []

    if verdict == "BAD_SECTORS_FOUND":
        recommendations.append(
            "Bad sectors detected — clone the drive with ddrescue before further use."
        )
        recommendations.append(
            "Do not write to or repair this drive until it has been imaged."
        )
    elif verdict == "SLOW_READS":
        recommendations.append(
            "Slow sectors detected — drive may have early-stage wear.  Consider cloning."
        )
    elif verdict == "SCAN_INCOMPLETE":
        warnings.append("Scan did not complete — results may not be representative.")
    elif verdict == "UNKNOWN":
        warnings.append("Block device could not be found — no scan performed.")

    report = {
        "report_type":              "BAD_SECTOR_SCAN",
        "generated":                now.isoformat(),
        "target":                   str(target),
        "physical_device":          physical_dev,
        "partition_device":         partition_dev,
        "device":                   partition_dev,          # legacy alias
        "partition_offset_lba":     part_offset_lba,
        "windows_volume":           "C:",
        "filesystem":               "ntfs",
        "scan_mode":                "sampled",
        "block_size_bytes":         block_sz,
        "slow_read_threshold_ms":   args.slow_ms,
        "scan_scope": {
            "device_size_bytes":    size_bytes if scan_device else None,
            "sector_size_bytes":    sector_sz,
            "start_lba":            0,
            "end_lba":              (size_bytes // sector_sz - 1) if sector_sz and size_bytes else None,
            "total_lba_count":      size_bytes // sector_sz if sector_sz and size_bytes else None,
            "sampled_fraction":     sampled_frac,
            "full_scan":            full_scan,
        },
        "safety": {
            "read_only":            True,
            "destructive":          False,
            "write_test_performed": False,
            "stop_reasons":         stop_reasons,
        },
        "clone_recommended":        clone_recommended,
        "ddrescue_command":         ddrescue_cmd,
        "recommendations":          recommendations,
        "warnings":                 warnings,
    }
    report.update(result)

    # ── Write log ─────────────────────────────────────────────────────────────
    usb_logs = root / "logs"
    usb_logs.mkdir(exist_ok=True)
    ts       = now.strftime("%Y%m%d_%H%M%S")
    out_path = usb_logs / f"{LOG_PREFIX}_{ts}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _log.info("Saved → %s", out_path)

    # ── Console summary ───────────────────────────────────────────────────────
    print()
    print("=" * 56)
    print("  BAD SECTOR SCAN RESULTS")
    print("=" * 56)
    print(f"  Device:         {partition_dev or 'NOT FOUND'}")
    print(f"  Physical disk:  {physical_dev  or 'NOT FOUND'}")
    print(f"  Scan status:    {report.get('scan_status', '?').upper()}")
    print(f"  Verdict:        {verdict}")
    print(f"  Sectors failed: {report.get('sectors_failed', 0)}")
    print(f"  Sectors slow:   {report.get('sectors_slow',  0)}")
    print(f"  Bad ranges:     {len(report.get('bad_ranges', []))}")
    print(f"  Duration:       {report.get('duration_seconds', 0):.1f}s")
    print(f"  Coverage:       {sampled_frac * 100:.2f}% of partition")
    print(f"  Confidence:     {report.get('confidence', '?')}")
    for rec in recommendations:
        print(f"  → {rec}")
    for warn in warnings:
        print(f"  ⚠ {warn}")
    print("=" * 56)
    print(f"\nLog written to: {out_path}")

    return 0


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    idx = sys.argv.index("--") + 1 if "--" in sys.argv else 1
    sys.exit(run(Path("."), sys.argv[idx:]))
