# SP19 — CROSS_MACHINE_INTEL

**Status:** 📋 Planned
**Phase:** 4 — Orchestration
**Priority:** 19

## Goal

Build a local threat intelligence database on the USB from hashes, filenames,
and findings observed across multiple client machines.

## Why valuable

If the same suspicious hash appears on three different client machines, that
is a strong signal — especially if none of those hashes match the known-bad
list.  The technician becomes their own threat intel source.

## Scope

1. **Intel database** — `intel/cross_machine_intel.json` on the USB (writable,
   not on the target volume).  Schema:

   ```json
   {
     "hashes": {
       "<sha256>": {
         "machines": ["Garnet-PC", "Smith-PC"],
         "paths":    ["C:\\Users\\..."],
         "risk":     "HIGH",
         "notes":    "Seen on 2 machines; no AV match"
       }
     },
     "filenames": {
       "svch0st.exe": { "machines": [...], "count": 3 }
     },
     "domains": {
       "update.bad-domain.ru": { "machines": [...], "source": "browser_audit" }
     }
   }
   ```

2. **Ingestion** — after each scan run, merge new findings from all JSONL logs
   into the intel DB.  Extract hashes (from SP09), filenames, and URLs/domains
   (from SP05).

3. **Query** — when running a new scan, check all file hashes and filenames
   against the intel DB before scoring; apply a cross-machine bonus if seen
   elsewhere.

4. **Export** — allow the intel DB to be exported as a `known_bad_hashes.txt`
   for use in SP09, or as a report.

## Risk scoring impact

| Signal | Score delta |
|---|---|
| Hash seen on ≥ 2 machines | +20 |
| Hash seen on ≥ 4 machines | +35 |
| Filename seen on ≥ 2 machines (not hash match) | +15 |
| Domain seen on ≥ 2 machines | +20 |

## Output

Updates `intel/cross_machine_intel.json`.  Emits JSONL to
`logs/cross_intel_<ts>.jsonl` for new cross-machine matches found.

## Dependencies

- SP09 HASH_TRACKING (hash inputs)
- SP05 BROWSER_AUDIT (domain inputs)

## Constraints

- Standard library only
- Never write to target volume; only writes to USB intel directory

## Acceptance criteria

- [ ] Correctly accumulates findings across two simulated scan runs
- [ ] Applies cross-machine bonus when hash seen on multiple machines
- [ ] Intel DB survives across separate invocations (persistent JSON)
