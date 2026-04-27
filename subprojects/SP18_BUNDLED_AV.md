# SP18 — BUNDLED_AV

**Status:** 📋 Planned
**Phase:** 4 — Orchestration
**Priority:** 18

## Goal

Integrate ClamAV (already partially sketched in `toolkit.py`) as a bundled
scanner engine, with offline signature databases on the USB.

## Current state

`toolkit.py` already has a skeleton for downloading and running ClamAV.
`bootstrap.py` can run a ClamAV scan.  This subproject formalises the
integration and makes it a proper scan module.

## Scope

1. **ClamAV binary** — bundled in `_tools/clamav/` on the USB.  Downloaded via
   `toolkit.py download_clamav()` during `bootstrap update`.

2. **Signature database** — `main.cvd` + `daily.cvd` bundled offline on the
   USB.  Updated via `bootstrap update` when network is available.

3. **Scan execution** — run `clamscan --recursive --no-summary --infected
   --stdout <target_path>` and capture output.

4. **Output parsing** — parse ClamAV stdout to extract infected file path and
   signature name.  Emit one JSONL finding per infected file.

5. **Scope** — scan the target Windows volume.  Allow a configurable scope
   (e.g. just `Users\` first, then full volume).

6. **No quarantine / deletion** — report only.  Never pass `--move` or
   `--remove` to ClamAV.

7. **Fallback** — if ClamAV binary is missing, emit informational finding and
   continue.

## Risk scoring

| Signal | Score delta |
|---|---|
| ClamAV signature match | +70 |
| Match in Temp/AppData | +10 (additive) |
| Match in System32 | +20 (additive, unusual location) |

## Output

JSONL findings to `logs/clamav_<ts>.jsonl`

## Dependencies

- `_tools/clamav/` binary and signature files on USB (download via toolkit.py)

## Constraints

- ClamAV must be a static or portable binary compatible with RescueZilla
  (Ubuntu 24.10 x86_64)
- Never pass destructive flags to ClamAV
- Standard library only for the wrapper; ClamAV itself is the engine

## Acceptance criteria

- [ ] Runs ClamAV with no internet connection using bundled signatures
- [ ] Emits JSONL finding for each infected file reported by ClamAV
- [ ] Graceful fallback if binary or signatures are missing
