# SP13 — TIMELINE_BUILD

**Status:** 📋 Planned
**Phase:** 3 — Deeper forensics
**Priority:** 13

## Goal

Create a unified chronological activity timeline from filesystem timestamps,
Prefetch execution records, event log timestamps, and persistence installation
dates.

## Why after SP04, SP07, SP12

TIMELINE_BUILD is an aggregation module — it consumes findings from other
modules and adds chronological context.  It has little value until at least
SP04 (Prefetch) and SP07 (Event Logs) are available to contribute execution
timestamps.

## Scope

1. **Timestamp sources** (each source needs a driver module to be implemented):
   - Filesystem `mtime`/`ctime` from SP12 RECENT_ACTIVITY findings
   - Prefetch last-run timestamps from SP04 findings
   - Event log timestamps from SP07 findings
   - Service/task creation timestamps from SP01 findings (where available)
   - Browser history timestamps from SP05 findings

2. **Timeline construction** — merge all events sorted by timestamp.  Each
   timeline entry:

   ```json
   {
     "ts":     "<ISO-8601>",
     "source": "PREFETCH",
     "event":  "Executed POWERSHELL.EXE",
     "path":   "C:\\Windows\\System32\\...",
     "score":  55,
     "risk":   "MEDIUM"
   }
   ```

3. **Activity windows** — identify dense time windows (> 5 events in 30 minutes)
   and flag them as suspected infection/compromise events.

4. **Narrative summary** — produce a short human-readable narrative:
   _"On 2026-01-15 around 14:30, 12 events were observed including a new
   service installation and execution of a script from AppData."_

## Output

JSONL timeline to `logs/timeline_<ts>.jsonl`; narrative summary appended to
`logs/timeline_<ts>_summary.txt`

## Dependencies

- SP04 PREFETCH_ANALYSIS (recommended)
- SP07 WINDOWS_EVENT_LOGS (recommended)
- SP12 RECENT_ACTIVITY (recommended)
- SP01 PERSISTENCE_SCAN (recommended)
- Runs meaningfully with any subset of the above.

## Constraints

- Standard library only
- Read-only; never write to target volume

## Acceptance criteria

- [ ] Merges at least two different timestamp sources correctly
- [ ] Identifies a 30-minute activity cluster as a potential event
- [ ] Produces a human-readable narrative with no technical jargon
