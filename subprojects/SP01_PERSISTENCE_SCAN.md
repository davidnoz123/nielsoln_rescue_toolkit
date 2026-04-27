# SP01 — PERSISTENCE_SCAN

**Status:** ✅ Done (`persistence_scan.py`, commit `8c1fd10`)
**Phase:** 1 — Core scanning
**Priority:** 1

## Goal

Detect Windows autorun and persistence mechanisms from an offline Windows filesystem.

## What was implemented

- Startup folders (system-wide and per-user)
- Scheduled tasks (modern XML and legacy `.job` formats)
- Services (offline registry, SYSTEM hive)
- Registry autoruns (Run, RunOnce, Winlogon, IFEO, policies, per-user NTUSER.DAT)
- Pure-Python REGF hive parser (no external dependencies)
- JSONL output with risk score + human-readable reasons per finding
- Deduplication of NTFS junction-linked hive paths (Vista `Documents and Settings` → `Users`)

## Known limitations / future work

- IFEO (Image File Execution Options) hijacks only partially covered
- `AppInit_DLLs`, `LSA` providers, `BootExecute`, `KnownDLLs` not yet scanned
- WMI event subscriptions not scanned — Vista WMI repository is binary format;
  Win10/11 WMI string scanning is handled in SP29 MODERN_WINDOWS_ARTEFACTS
- Does not parse `.lnk` shortcut binary format — target paths may be unresolved
- Win10/11-specific persistence: COM object hijacking, Defender exclusions,
  Windows scheduled tasks with new XML fields — see SP29
- `AppCertDLLs`, `AppInit_DLLs` in 64-bit context not verified
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
  full enumeration not implemented (only targeted keys checked)

## Acceptance criteria

✅ Runs read-only on a mounted offline Vista installation
✅ Produces JSONL findings to `logs/persist_<ts>.jsonl`
✅ Zero errors on Garnet-PC (235 findings, 0 errors, 7H/161M/67L)
