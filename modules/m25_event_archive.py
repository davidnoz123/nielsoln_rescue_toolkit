"""m25_event_archive — Incremental Windows Event Log archive.

Reads .evtx files from an offline Windows installation and appends new records
to a JSONL chunk archive on the USB.  Re-runnable and safe: only records with a
RecordId greater than the last checkpoint are written.  Anomalies (log clears,
gaps, timestamp regressions) are detected and logged inline.

Archive layout on USB:
    event_archive/
    └── <machine_id>/          # sha256(hostname|serial|bios_date)[:16]
        ├── machine.json       # machine identity metadata
        └── channels/
            └── Security/
                ├── checkpoint.json
                ├── checkpoint.tmp     (staging; safe to delete if found)
                └── chunks/
                    └── 20260427_063510.jsonl

Each .jsonl file contains one JSON object per line.  Line types:
    {"type": "chunk_header", ...}   — first line of every chunk
    {"type": "event", ...}          — one Windows event record
    {"type": "anomaly", ...}        — gap / clear / regression detected

Usage:
    bootstrap run m25_event_archive -- --target /mnt/windows
    bootstrap run m25_event_archive -- --target /mnt/windows --channels Security System
    bootstrap run m25_event_archive -- --target /mnt/windows --summary
"""

from __future__ import annotations

import argparse
import datetime
import glob
import hashlib
import importlib.util
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

DESCRIPTION = "Incremental Windows Event Log archive — appends new events to USB JSONL chunks"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_CHANNELS = ["Security", "System", "Application"]
_EVTX_BASE = "Windows/System32/winevt/Logs"
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Warn (but continue) if a gap exceeds this many RecordIds.
_GAP_WARN_THRESHOLD = 100


# ---------------------------------------------------------------------------
# python-evtx bootstrap — borrow from m23 (always deployed alongside m25)
# ---------------------------------------------------------------------------

def _ensure_evtx() -> bool:
    """Load python-evtx.  Tries sys.path first, then borrows from m23's bundled wheel.

    m23_logon_audit.py is always deployed alongside m25 (both are in
    _UPDATE_FILES).  Re-using its wheel avoids duplicating 450 lines of
    base64 in this file.
    """
    try:
        import Evtx.Evtx  # noqa: F401
        return True
    except ImportError:
        pass

    # Borrow the bundled wheel from m23
    try:
        m23_path = Path(__file__).parent / "m23_logon_audit.py"
        if not m23_path.exists():
            print("[m25] m23_logon_audit.py not found — cannot load python-evtx wheel.")
            return False
        spec = importlib.util.spec_from_file_location("_m23_evtx_loader", m23_path)
        m23 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m23)
        ok = m23._ensure_evtx()
        if ok:
            print("[m25] python-evtx loaded via m23 bundled wheel.")
        return ok
    except Exception as exc:
        print(f"[m25] Failed to load python-evtx from m23 wheel: {exc}")
        return False


# ---------------------------------------------------------------------------
# Machine identity
# ---------------------------------------------------------------------------

def _dmidecode_field(dmi_type: int, field: str) -> str:
    """Return a trimmed field value from dmidecode output, or ''."""
    try:
        import subprocess
        out = subprocess.run(
            ["dmidecode", f"-t{dmi_type}"],
            capture_output=True, text=True, timeout=10,
        ).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith(field + ":"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def _get_machine_info(root: Path) -> dict:
    """Return {hostname, serial, bios_date} from hardware_profile log or dmidecode."""
    # Try hardware_profile log first (already computed)
    log_dir = root / "logs"
    hw_logs = sorted(glob.glob(str(log_dir / "hardware_profile_*.json")))
    if hw_logs:
        try:
            data = json.loads(Path(hw_logs[-1]).read_text(encoding="utf-8"))
            hostname   = data.get("system", {}).get("hostname", "")
            serial     = data.get("system", {}).get("serial_number", "")
            bios_date  = data.get("bios", {}).get("release_date", "")
            if hostname or serial:
                return {"hostname": hostname, "serial": serial, "bios_date": bios_date}
        except Exception:
            pass

    # Fall back to dmidecode
    hostname  = _dmidecode_field(1, "Product Name") or os.uname().nodename
    serial    = _dmidecode_field(1, "Serial Number")
    bios_date = _dmidecode_field(0, "Release Date")
    return {"hostname": hostname, "serial": serial, "bios_date": bios_date}


def _make_machine_id(info: dict) -> str:
    raw = f"{info['hostname']}|{info['serial']}|{info['bios_date']}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Checkpoint helpers
# ---------------------------------------------------------------------------

def _checkpoint_path(channel_dir: Path) -> Path:
    return channel_dir / "checkpoint.json"


def _load_checkpoint(channel_dir: Path) -> dict:
    """Return checkpoint dict; empty dict if none exists."""
    p = _checkpoint_path(channel_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_checkpoint(channel_dir: Path, checkpoint: dict) -> None:
    """Atomically write checkpoint.json via a .tmp staging file."""
    tmp_path = channel_dir / "checkpoint.tmp"
    final_path = _checkpoint_path(channel_dir)
    tmp_path.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")
    os.replace(str(tmp_path), str(final_path))


# ---------------------------------------------------------------------------
# EVTX parsing
# ---------------------------------------------------------------------------

def _tag(local: str) -> str:
    return f"{{{_NS}}}{local}"


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _parse_evtx(evtx_path: Path, after_id: int | None = None) -> list[dict]:
    """Parse records from *evtx_path*, returning those with record_id > after_id.

    When *after_id* is set, records up to and including it are skipped cheaply
    (header read only — no XML decode).  This makes incremental runs fast.
    Returns list sorted by RecordId asc.

    Each record dict:
        record_id   int
        timestamp   str  (ISO-8601 from SystemTime attribute)
        event_id    int
        provider    str
        computer    str
        data        dict[str, str]  (EventData Name/value pairs)
        raw_xml     str
        raw_sha256  str  (sha256 of raw XML bytes)
    """
    import Evtx.Evtx as evtx

    records = []
    with evtx.Evtx(str(evtx_path)) as log:
        for record in log.records():
            try:
                # Cheap header-only check: skip records we've already archived.
                # record.record_num() reads the 8-byte EVTX record header only;
                # record.xml() is the expensive full binary decode + serialisation.
                if after_id is not None:
                    try:
                        if record.record_num() <= after_id:
                            continue
                    except Exception:
                        pass  # fall through to full parse if header read fails

                raw_xml = record.xml()
                if isinstance(raw_xml, bytes):
                    raw_bytes = raw_xml
                    raw_xml = raw_xml.decode("utf-8", errors="replace")
                else:
                    raw_bytes = raw_xml.encode("utf-8", errors="replace")

                raw_sha = _sha256_bytes(raw_bytes)
                root_el = ET.fromstring(raw_xml)
                sys_el  = root_el.find(_tag("System"))
                if sys_el is None:
                    continue

                eid_el = sys_el.find(_tag("EventID"))
                if eid_el is None or not (eid_el.text or "").strip().isdigit():
                    continue
                event_id = int(eid_el.text.strip())

                rid_el = sys_el.find(_tag("EventRecordID"))
                if rid_el is None or not (rid_el.text or "").strip().isdigit():
                    continue
                record_id = int(rid_el.text.strip())

                time_el = sys_el.find(_tag("TimeCreated"))
                timestamp = time_el.get("SystemTime", "") if time_el is not None else ""

                prov_el  = sys_el.find(_tag("Provider"))
                provider = prov_el.get("Name", "") if prov_el is not None else ""

                comp_el  = sys_el.find(_tag("Computer"))
                computer = (comp_el.text or "").strip() if comp_el is not None else ""

                data: dict[str, str] = {}
                ed = root_el.find(_tag("EventData"))
                if ed is not None:
                    for item in ed:
                        name = item.get("Name", "")
                        if name:
                            data[name] = (item.text or "").strip()

                records.append({
                    "record_id": record_id,
                    "timestamp": timestamp,
                    "event_id":  event_id,
                    "provider":  provider,
                    "computer":  computer,
                    "data":      data,
                    "raw_xml":   raw_xml,
                    "raw_sha256": raw_sha,
                })
            except Exception:
                continue

    records.sort(key=lambda r: r["record_id"])
    return records


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def _detect_anomalies(
    new_records: list[dict],
    checkpoint: dict,
    channel: str,
    machine_id: str,
    evtx_path: Path,
) -> list[dict]:
    """Return a list of anomaly dicts to prepend to the chunk.

    *new_records* must already be filtered to records after the last checkpoint.
    Old records are not needed — any anomalies in them were detected on prior runs.
    """
    anomalies = []
    now = datetime.datetime.utcnow().isoformat() + "Z"

    def _anomaly(kind: str, detail: str) -> dict:
        return {
            "type":       "anomaly",
            "anomaly":    kind,
            "machine_id": machine_id,
            "channel":    channel,
            "detected":   now,
            "detail":     detail,
        }

    if not new_records:
        return anomalies

    last_id = checkpoint.get("last_record_id")
    last_ts = checkpoint.get("last_timestamp")
    last_sz = checkpoint.get("source_file_size")

    # Source file size shrank → log was replaced or cleared
    try:
        current_sz = evtx_path.stat().st_size
    except OSError:
        current_sz = None

    if last_sz is not None and current_sz is not None and current_sz < last_sz:
        anomalies.append(_anomaly(
            "SOURCE_REPLACED",
            f"evtx file size shrank from {last_sz} to {current_sz} bytes — "
            "log may have been replaced or cleared.",
        ))

    # Check for 1102 (Security log cleared) or 104 (System log cleared)
    clear_ids = {1102, 104}
    for rec in new_records:
        if rec["event_id"] in clear_ids:
            anomalies.append(_anomaly(
                "LOG_CLEARED",
                f"EventID {rec['event_id']} at {rec['timestamp']} — "
                "Windows audit log was cleared.",
            ))

    # Gap since last checkpoint
    if last_id is not None:
        expected_next = last_id + 1
        if new_records:
            actual_next = new_records[0]["record_id"]
            gap = actual_next - expected_next
            if gap > _GAP_WARN_THRESHOLD:
                anomalies.append(_anomaly(
                    "GAP_DETECTED",
                    f"RecordId gap: expected {expected_next}, got {actual_next} "
                    f"(gap of {gap} records) — events may have been deleted or log wrapped.",
                ))

    # Timestamp regression in new records
    if last_ts:
        for rec in new_records:
            if rec["timestamp"] and rec["timestamp"] < last_ts:
                anomalies.append(_anomaly(
                    "TIMESTAMP_REGRESSION",
                    f"RecordId {rec['record_id']} has timestamp {rec['timestamp']} "
                    f"which is earlier than last checkpoint timestamp {last_ts}.",
                ))
                break  # warn once

    return anomalies


# ---------------------------------------------------------------------------
# Per-channel archive logic
# ---------------------------------------------------------------------------

def _run_channel(
    root: Path,
    target: Path,
    channel: str,
    machine_id: str,
    archive_dir: Path,
    summary_only: bool = False,
) -> dict:
    """Archive one event log channel.  Returns a result dict."""
    result = {
        "channel":      channel,
        "status":       "ok",
        "new_events":   0,
        "anomalies":    0,
        "chunk_file":   None,
        "error":        None,
    }

    evtx_path = target / _EVTX_BASE / f"{channel}.evtx"
    if not evtx_path.exists():
        result["status"] = "missing"
        result["error"]  = f"Not found: {evtx_path}"
        print(f"  [{channel}] SKIP — {evtx_path} not found.")
        return result

    channel_dir = archive_dir / "channels" / channel
    channel_dir.mkdir(parents=True, exist_ok=True)
    chunks_dir  = channel_dir / "chunks"
    chunks_dir.mkdir(exist_ok=True)

    # Clean up any leftover .tmp checkpoint from a previous crash
    tmp_path = channel_dir / "checkpoint.tmp"
    if tmp_path.exists():
        print(f"  [{channel}] Removing stale checkpoint.tmp from previous run.")
        tmp_path.unlink(missing_ok=True)

    checkpoint = _load_checkpoint(channel_dir)
    last_id    = checkpoint.get("last_record_id")
    last_ts    = checkpoint.get("last_timestamp")
    last_sz    = checkpoint.get("source_file_size")

    try:
        current_sz = evtx_path.stat().st_size
    except OSError:
        current_sz = None

    print(f"  [{channel}] Parsing {evtx_path} ({(current_sz or 0) // 1024} KB) "
          f"(after_id={last_id}) ...")
    try:
        new_records = _parse_evtx(evtx_path, after_id=last_id)
    except Exception as exc:
        result["status"] = "error"
        result["error"]  = str(exc)
        print(f"  [{channel}] ERROR parsing evtx: {exc}")
        return result

    anomalies = _detect_anomalies(
        new_records, checkpoint, channel, machine_id, evtx_path
    )

    result["new_events"] = len(new_records)
    result["anomalies"]  = len(anomalies)

    if anomalies:
        for a in anomalies:
            print(f"  [{channel}] ANOMALY {a['anomaly']}: {a['detail']}")

    if not new_records and not anomalies:
        print(f"  [{channel}] No new events since last run (last RecordId={last_id}).")
        # Still update file size in checkpoint if it changed
        if current_sz != last_sz and last_id is not None:
            checkpoint["source_file_size"] = current_sz
            _save_checkpoint(channel_dir, checkpoint)
        return result

    if summary_only:
        print(f"  [{channel}] {len(new_records)} new event(s), {len(anomalies)} anomaly(ies) "
              f"(--summary: not written).")
        return result

    # Write chunk file
    ts_str = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    chunk_path = chunks_dir / f"{ts_str}.jsonl"
    result["chunk_file"] = str(chunk_path)

    last_new_id = last_id
    last_new_ts = last_ts

    with chunk_path.open("w", encoding="utf-8") as f:
        # Header line
        header = {
            "type":               "chunk_header",
            "machine_id":         machine_id,
            "channel":            channel,
            "created":            ts_str,
            "new_event_count":    len(new_records),
            "anomaly_count":      len(anomalies),
            "prev_last_record_id": last_id,
        }
        f.write(json.dumps(header) + "\n")

        # Anomaly lines first
        for a in anomalies:
            f.write(json.dumps(a) + "\n")

        # Event lines
        for rec in new_records:
            line = {
                "type":       "event",
                "machine_id": machine_id,
                "channel":    channel,
                "record_id":  rec["record_id"],
                "timestamp":  rec["timestamp"],
                "event_id":   rec["event_id"],
                "provider":   rec["provider"],
                "computer":   rec["computer"],
                "data":       rec["data"],
                "raw_xml":    rec["raw_xml"],
                "raw_sha256": rec["raw_sha256"],
            }
            f.write(json.dumps(line) + "\n")
            last_new_id = rec["record_id"]
            last_new_ts = rec["timestamp"]

    print(f"  [{channel}] Wrote {len(new_records)} event(s) → {chunk_path.name}")

    # Atomic checkpoint update
    new_checkpoint = {
        "last_record_id":   last_new_id,
        "last_timestamp":   last_new_ts,
        "source_file_size": current_sz,
        "last_run":         ts_str,
    }
    _save_checkpoint(channel_dir, new_checkpoint)

    return result


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(root: Path, argv: list) -> int:
    """Archive Windows Event Log channels to USB JSONL chunks.

    Args:
        --target <path>     Mounted Windows root (default: /)
        --channels <names>  Space-separated channel names (default: Security System Application)
        --machine-id <hex>  Override auto-detected machine ID
        --summary           Detect and print new events without writing them
    """
    parser = argparse.ArgumentParser(
        prog="m25_event_archive",
        description="Incremental Windows Event Log archive",
    )
    parser.add_argument("--target",     default="/",
                        help="Mounted Windows root path")
    parser.add_argument("--channels",   nargs="+", default=_DEFAULT_CHANNELS,
                        help="Channel names to archive")
    parser.add_argument("--machine-id", default="",
                        help="Override machine ID (16 hex chars)")
    parser.add_argument("--summary",    action="store_true",
                        help="Detect new events but do not write them")
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        print(f"[m25] Target not found: {target}")
        return 1

    # ---- python-evtx ----
    print("[m25] Checking python-evtx dependency ...")
    if not _ensure_evtx():
        print("[m25] Cannot continue without python-evtx.")
        print("[m25] Ensure m23_logon_audit.py is present alongside this module.")
        return 1

    # ---- machine identity ----
    if args.machine_id:
        machine_id = args.machine_id[:16]
        machine_info = {}
        print(f"[m25] Using supplied machine ID: {machine_id}")
    else:
        print("[m25] Determining machine identity ...")
        machine_info = _get_machine_info(root)
        machine_id   = _make_machine_id(machine_info)
        print(f"[m25] Machine ID : {machine_id}")
        print(f"[m25] Hostname   : {machine_info.get('hostname', '?')}")
        print(f"[m25] Serial     : {machine_info.get('serial', '?')}")
        print(f"[m25] BIOS date  : {machine_info.get('bios_date', '?')}")

    # ---- archive root ----
    archive_root = root / "event_archive" / machine_id
    archive_root.mkdir(parents=True, exist_ok=True)

    # Write / refresh machine.json
    machine_json = archive_root / "machine.json"
    machine_doc = {
        "machine_id":   machine_id,
        "hostname":     machine_info.get("hostname", ""),
        "serial":       machine_info.get("serial", ""),
        "bios_date":    machine_info.get("bios_date", ""),
        "last_updated": datetime.datetime.utcnow().isoformat() + "Z",
    }
    machine_json.write_text(json.dumps(machine_doc, indent=2), encoding="utf-8")

    if args.summary:
        print("\n[m25] Summary mode — events will be detected but NOT written.\n")
    else:
        print(f"\n[m25] Archive root: {archive_root}\n")

    # ---- per-channel ----
    channels = args.channels
    print(f"[m25] Channels: {', '.join(channels)}\n")

    results = []
    rc = 0
    for ch in channels:
        r = _run_channel(
            root=root,
            target=target,
            channel=ch,
            machine_id=machine_id,
            archive_dir=archive_root,
            summary_only=args.summary,
        )
        results.append(r)
        if r["status"] == "error":
            rc = 1

    # ---- summary ----
    print("\n" + "=" * 60)
    print("  m25_event_archive — RUN SUMMARY")
    print("=" * 60)
    total_new      = sum(r["new_events"] for r in results)
    total_anomalies= sum(r["anomalies"]  for r in results)
    for r in results:
        status_str = (
            f"{r['new_events']} new, {r['anomalies']} anomaly(ies)"
            if r["status"] == "ok"
            else r["status"].upper()
        )
        print(f"  {r['channel']:<20s} {status_str}")
    print(f"\n  Total new events : {total_new}")
    print(f"  Total anomalies  : {total_anomalies}")
    if total_anomalies:
        print("\n  *** ANOMALIES DETECTED — review chunk files for details ***")
    print("=" * 60)

    # Write a run log entry
    if not args.summary:
        log_dir = root / "logs"
        log_dir.mkdir(exist_ok=True)
        ts_str = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        log_path = log_dir / f"event_archive_{ts_str}.json"
        log_doc = {
            "machine_id":      machine_id,
            "run_time":        ts_str,
            "target":          str(target),
            "channels":        channels,
            "total_new_events": total_new,
            "total_anomalies":  total_anomalies,
            "results":          results,
        }
        log_path.write_text(json.dumps(log_doc, indent=2), encoding="utf-8")
        print(f"\n[m25] Run log → {log_path}")

    return rc
