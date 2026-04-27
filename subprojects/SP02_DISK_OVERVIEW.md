# SP02 — DISK_OVERVIEW

**Status:** 📋 Planned
**Phase:** 1 — Core scanning
**Priority:** 2

> **Not in ChatGPT's list.** This should run first on every engagement — before
> any scan module — to establish machine identity and context.

## Goal

Produce a concise machine identity and health overview from the offline Windows
filesystem.  Every other module's findings become more meaningful once you know
whose machine it is, what Windows version it is, and when it was last used.

## Scope

1. **Machine identity** — hostname, domain, Windows version, edition, build,
   install date; read from `SOFTWARE` hive
   (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`).

2. **Users** — list all user profiles with SID, username, last-login hint,
   profile path.  Read from `SOFTWARE` hive profile list and directory listing.

3. **Disk / filesystem** — total and approximate used space on the scanned
   partition, last mount time (from NTFS `$Boot` / `$Volume` if accessible,
   otherwise stat fallback).

4. **Last activity hint** — most-recently-modified file in `System32`,
   `Users`, and `Windows\Prefetch` as a rough upper bound on last use date.

5. **Installed products** — top-20 software entries from
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (name + version
   only).  Useful for spotting old/cracked software.

6. **AV / security tools present** — check for known AV/EDR product keys in
   the registry or known executable paths.

## Output

JSONL findings to `logs/overview_<ts>.jsonl` plus a single human-readable
summary printed to stdout.

## Dependencies

- SP01 REGF parser (extract from `persistence_scan.py` into `core.py`)

## Constraints

- Standard library only
- Read-only; never write to the target volume

## Acceptance criteria

- [ ] Prints hostname, OS version, and user list in under 5 seconds
- [ ] Produces a `logs/overview_<ts>.jsonl` file
- [ ] Handles missing or corrupt hives gracefully
