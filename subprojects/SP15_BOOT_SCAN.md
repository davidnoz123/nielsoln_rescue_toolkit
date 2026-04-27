# SP15 — BOOT_SCAN

**Status:** 📋 Planned
**Phase:** 3 — Deeper forensics
**Priority:** 15

## Goal

Inspect boot-related areas for suspicious changes: MBR, VBR, BCD store,
boot-time drivers, and EFI partition contents.

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

## Risk scoring

| Signal | Score delta |
|---|---|
| MBR hash does not match any known-good | +50 |
| Extra BCD boot entry | +35 |
| `winload.exe` or `ntoskrnl.exe` missing/replaced | +60 |
| Boot-start driver from non-system path | +55 |
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
