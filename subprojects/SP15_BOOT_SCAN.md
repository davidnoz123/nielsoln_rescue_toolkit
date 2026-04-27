# SP15 — BOOT_SCAN

**Status:** 📋 Planned
**Phase:** 3 — Deeper forensics
**Priority:** 15

## Goal

Inspect boot-related areas for suspicious changes: MBR, VBR, BCD store,
boot-time drivers, EFI partition contents, and UEFI environment state.

## Scope

1. **MBR (Master Boot Record)** — read the first 512 bytes of the disk device
   (`/dev/sdX`).  Requires knowing the device, which should be detectable from
   the mount point.  Check for:
   - Non-standard MBR code (compare hash against known-good Vista/Win7 MBR)
   - Presence of rootkit signatures in the first 512 bytes

2. **VBR (Volume Boot Record)** — first sector of the NTFS partition.  Similar
   hash check.

3. **BCD store** — `C:\Boot\BCD` (Vista UEFI) or `\Boot\BCD` on the system
   partition.  Parse as a REGF hive to extract boot entries.  Flag:
   - Non-standard bootloaders
   - Extra boot entries pointing to unusual paths
   - `boot.ini` modifications (XP-era; Vista uses BCD)

4. **Boot-critical files** — check that standard Vista boot files exist and
   are not obviously replaced:
   - `bootmgr`
   - `C:\Windows\System32\winload.exe`
   - `C:\Windows\System32\ntoskrnl.exe`

5. **Early-launch drivers** — from SP01 PERSISTENCE_SCAN services phase
   (BOOT_START / type=0 services).  Flag any boot-start driver not in
   `C:\Windows\System32\drivers\`.

6. **UEFI / Secure Boot state** (modern machines — Win8+):  
   Detect from the rescue Linux environment:
   - `/sys/firmware/efi/` exists → machine booted UEFI (note: this reflects
     the *rescue* system's boot mode, not the target's; infer target mode from
     EFI partition presence instead)
   - **EFI partition** — look for a FAT32 partition mounted at `/boot/efi` or
     listed in `/proc/mounts` with type `vfat`.  If found, list its contents
     for unexpected bootloaders (`\EFI\` subdirectory listing).
   - **Secure Boot state** — read from `\EFI\Microsoft\Boot\bootmgfw.efi`
     presence and the BCD store's `bootems` and `ems` settings.  Cannot verify
     whether Secure Boot is actually enforced without UEFI variable access.
   - **Unexpected EFI entries** — any `\EFI\` subdirectory that is not
     `Microsoft`, `BOOT`, or a known OEM vendor is suspicious.
   - **UEFI rootkit indicators** — files in the EFI partition that are not
     standard Windows boot files (e.g. `\EFI\Microsoft\Boot\` should contain
     only well-known files like `bootmgfw.efi`, `bootmgr.efi`, `memtest.efi`).

7. **BitLocker detection** (Win8+ — also checked in SP29):  
   If `C:\Windows\System32\winload.exe` is accessible but the `Users\` folder
   is not, or the hive files are missing/truncated, BitLocker may be active.
   Also check: `HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus`
   and presence of `C:\$BitLocker Recovery Key*.txt`.
   Report as an informational CRITICAL finding if detected.

## Risk scoring

| Signal | Score delta |
|---|---|
| MBR hash does not match any known-good | +50 |
| Extra BCD boot entry | +35 |
| `winload.exe` or `ntoskrnl.exe` missing/replaced | +60 |
| Boot-start driver from non-system path | +55 |
| Unexpected file in `\EFI\` partition | +45 |
| Non-Microsoft EFI subdirectory (unknown vendor) | +30 |
| BitLocker detected | Informational CRITICAL |
| Standard Vista MBR hash confirmed | −10 |

## Notes

- Reading raw disk sectors requires root (which RescueZilla always has).
- The disk device path must be inferred from `/proc/mounts` or passed as an
  argument.  Do not hardcode `/dev/sda`.

## Output

JSONL findings to `logs/boot_scan_<ts>.jsonl`

## Dependencies

- Raw disk device path (auto-detect from mount point using `/proc/mounts`)
- SP01 PERSISTENCE_SCAN findings (for early-launch drivers)

## Constraints

- Standard library only (struct, hashlib)
- Read-only on target; reads raw device sectors (root required)

## Acceptance criteria

- [ ] Reads MBR without crashing even on a GPT disk
- [ ] Correctly identifies a Vista MBR as a non-suspicious finding
- [ ] Detects a non-system boot-start driver from SP01 findings
