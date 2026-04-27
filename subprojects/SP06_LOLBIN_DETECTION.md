# SP06 — LOLBIN_DETECTION

**Status:** 📋 Planned
**Phase:** 1 — Core scanning
**Priority:** 6

## Goal

Detect suspicious use of legitimate Windows built-in tools (LOLBins — Living
Off the Land Binaries) that are commonly abused by malware.

## Why here in the ordering

SP01 PERSISTENCE_SCAN already collects registry autoruns and service
command-lines.  LOLBIN_DETECTION can be partially implemented as a second-pass
scoring layer over the existing persistence findings, plus new evidence sources
(Prefetch, scheduled tasks).  The LOLBin list also feeds SP04 PREFETCH_ANALYSIS
and SP07 WINDOWS_EVENT_LOGS.

## Scope

1. **Known LOLBin list** — hardcoded catalogue of commonly abused binaries with
   typical abuse patterns.  Minimum set for Vista:

   | Binary | Abuse pattern |
   |---|---|
   | `powershell.exe` | `-enc`, `-w hidden`, `IEX`, `DownloadString` |
   | `cmd.exe` | Long command lines, `^` obfuscation, `%COMSPEC%` aliases |
   | `mshta.exe` | Running `.hta` files, remote URLs |
   | `wscript.exe` / `cscript.exe` | Scripts in Temp/AppData |
   | `rundll32.exe` | Non-system DLL paths, JavaScript: URIs |
   | `regsvr32.exe` | Remote `.sct` files, non-system DLLs |
   | `certutil.exe` | `-decode`, `-urlcache` |
   | `bitsadmin.exe` | Download jobs |
   | `schtasks.exe` | Created from non-system locations |
   | `wmic.exe` | `process call create`, `os get` with suspicious args |

2. **Evidence sources** to scan:
   - Registry autorun values (from SP01 PERSISTENCE_SCAN JSONL)
   - Scheduled task XML command-lines (from SP01)
   - Prefetch entries (from SP04 PREFETCH_ANALYSIS JSONL) — if available
   - Shortcut (`.lnk`) files in startup folders

3. **Command-line analysis** — parse arguments for known abuse patterns
   (encoded payloads, URL fetches, unusual flags).

## Output

JSONL findings to `logs/lolbin_<ts>.jsonl`

## Dependencies

- Can run standalone, but enriched by SP01 and SP04 JSONL output.

## Constraints

- Standard library only
- Read-only; never write to target volume

## Acceptance criteria

- [ ] Flags PowerShell `-enc` and `-w hidden` usage in any evidence source
- [ ] Does not false-positive on `C:\Windows\System32\cmd.exe` without arguments
- [ ] Works standalone without SP01/SP04 output present
