# SP24 — SCAN_PROFILE_OS

**Status:** 📋 Planned (future — after Windows coverage is solid)
**Phase:** 6 — OS expansion
**Priority:** 24

## Goal

Select and configure OS-specific scan profiles so the tool can handle Windows,
macOS, and other future platforms without hard-coding OS assumptions into every
module.

## Note on MAC_LIMITATIONS (merged here)

The original ChatGPT list included a separate `MAC_LIMITATIONS` module.
That is not a scan module — it is documentation and runtime reporting.
Its content is folded into this subproject: the OS profile should report its
own limitations as informational findings.

## Scope

1. **OS detection** — from the mounted filesystem:
   - Windows: presence of `Windows\System32\ntoskrnl.exe`, registry hives
   - macOS: presence of `System/Library/CoreServices/SystemVersion.plist`
   - Unknown: report and use minimal safe profile

2. **Profile structure** — each OS profile provides:
   - Which scan modules are applicable
   - Root paths to scan (e.g. `/mnt/windows/Users` vs `/mnt/macos/Users`)
   - Known-safe path exclusions
   - OS version detection
   - Known limitations (reported as informational findings)

3. **Windows profiles** — per-version adjustments:
   - XP: no Prefetch v23, no EVTX (uses .evt), different registry paths
   - Vista/7: Prefetch v23/26, EVTX, BCD
   - 8/10/11: WMI subscriptions, AMSI, ETW artefacts

4. **macOS limitations reported at runtime:**
   - FileVault-encrypted volumes cannot be scanned offline
   - T2 / Apple Silicon: SSD is hardware-encrypted; standard mount not possible
   - APFS snapshots not automatically accessible from Linux
   - `codesign` and Gatekeeper metadata not verifiable offline
   - `xattr` / quarantine flags accessible via `getfattr` if tools available

## Output

No JSONL findings of its own — feeds configuration to other modules.
Emits informational findings for any detected limitations.

## Dependencies

- None (runs first, before other modules)

## Constraints

- Standard library only

## Acceptance criteria

- [ ] Correctly identifies Vista vs Windows 10 from filesystem layout
- [ ] Reports macOS scanning limitations as informational findings
- [ ] Unknown OS falls back to a safe minimal profile
