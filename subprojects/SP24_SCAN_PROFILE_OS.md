# SP24 — SCAN_PROFILE_OS

**Status:** 📋 Planned
**Phase:** 2 — Engineering foundations (promoted from Phase 6)
**Priority:** 8c (implement alongside SP08–SP11; needed before any non-Vista machine is scanned)

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

   | OS | Prefetch | Event logs | BCD/UEFI | Amcache | WMI subs | Defender | BitLocker risk |
   |---|---|---|---|---|---|---|---|
   | XP | v17 | .evt (binary) | boot.ini | ❌ | ❌ | ❌ | None |
   | Vista/7 | v23/26 | EVTX | BCD, BIOS | ❌ | ❌ | ❌ | Low |
   | Win8 | v26 | EVTX | BCD, UEFI | ✅ | ⚠️ | ✅ | Medium |
   | Win10 | v30 (may be disabled on SSD) | EVTX | BCD, UEFI, Secure Boot | ✅ | ✅ | ✅ | High |
   | Win11 | v30 (disabled if no HDD) | EVTX | BCD, UEFI, Secure Boot required | ✅ | ✅ | ✅ | Very high |

   Key per-profile differences:
   - **XP:** no EVTX, no Amcache, no UEFI; `.evt` parsing needed for SP07
   - **Vista/7:** primary current target; all SP01–SP16 applicable
   - **Win8:** adds Amcache, UEFI; Defender exclusions become relevant
   - **Win10/11:** Prefetch may be disabled on SSD; Amcache is primary execution
     history; BitLocker high probability; UEFI Secure Boot; all SP29 artefacts
     applicable; PSReadLine history present

4. **BitLocker detection** — run before any scan module on Win8+ machines.
   If detected, report as CRITICAL informational and halt that volume's scan.
   See SP29 MODERN_WINDOWS_ARTEFACTS for detection method.

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
