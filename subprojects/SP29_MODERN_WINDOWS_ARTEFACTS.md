# SP29 — MODERN_WINDOWS_ARTEFACTS

**Status:** 📋 Planned
**Phase:** 2 — Engineering foundations
**Priority:** 8b (implement alongside SP08–SP11; insert between SP11 and SP12)

> **Not in ChatGPT's list.** Added because Windows 10/11 has entirely different
> forensic artefacts from Vista. Without this module, the toolkit is
> significantly less useful on modern machines.

## Goal

Scan Windows 10/11-specific artefacts that either do not exist on Vista or
behave very differently: Amcache, Shimcache, WMI event subscriptions,
PowerShell execution artefacts, Windows Defender exclusions, and the Windows
Timeline database.

## Critical constraint — BitLocker

**If the target drive is BitLocker-encrypted, offline scanning is not possible
without the recovery key.**  Detect BitLocker before attempting any scan:

- Check for `C:\Windows\System32\winload.exe` being accessible.
- Check registry hive `SYSTEM` key:
  `HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus`
- Look for `$BitLocker Recovery Key` and `.bek` files in the root and on the
  EFI partition.
- If BitLocker is detected, emit a CRITICAL informational finding and stop
  scanning that volume.  Report the recovery key location (recovery partition,
  Microsoft account, or AD/AAD) so the technician knows where to look.

## Scope

### 1. Amcache.hve (Win8+, primary on Win10/11)

`C:\Windows\AppCompat\Programs\Amcache.hve`

A REGF hive.  Contains every executable ever run on the machine — more
comprehensive than Prefetch, and **not disabled on SSDs**.  Key paths:

- `Root\InventoryApplicationFile` — per-file records with SHA-1 hash,
  file path, publisher, PE link date, and last-modified timestamp.
- `Root\File` (older format, Win8) — similar records.

This is the single most important modern artefact.  Even if a file has been
deleted, its entry may remain.  Cross-reference entries against:
- SP09 known-bad hash list
- SP19 cross-machine intel DB
- Suspicious paths (AppData, Temp, Downloads)

### 2. Shimcache / AppCompatCache (all Windows versions, XP+)

Registry key:
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache`

Binary blob — format varies by OS version.  Contains a list of executables
that have been run (or in some cases just touched) on the system.  Parse
the binary format for each version:

| OS | Cache format |
|---|---|
| XP | 32-bit, 96-byte entries |
| Vista/7 | 32/64-bit, with timestamp and file size |
| Win8 | Updated format with execution flag |
| Win10 | Updated again; execution flag removed |

The data is raw binary in the registry value.  Use `struct` to parse.

### 3. WMI Event Subscriptions (Win7+, major malware vector on Win10/11)

`C:\Windows\System32\wbem\Repository\`

The WMI repository is a proprietary binary database.  Full parsing is complex.
Approach:

**Option A (recommended):** use `strings`-style byte scanning of the
`OBJECTS.DATA` file for suspicious patterns:
- Executable paths in AppData/Temp
- PowerShell `-enc` or `DownloadString` patterns
- VBScript or JScript content

**Option B:** If `wbemtest` or `wmic` is available on the rescue system
(unlikely), run a query.  Do not depend on this.

Emit an informational finding noting whether full WMI parsing was possible.
Even partial string scanning of `OBJECTS.DATA` catches most commodity malware.

Known WMI persistence patterns to search for:
- `ActiveScriptEventConsumer` — runs a VBScript/JScript
- `CommandLineEventConsumer` — runs a command line
- `FilterToConsumerBinding` — links the trigger to the action

### 4. PowerShell Artefacts (Win10/11)

**PSReadLine history:**
`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

Plain text — one command per line.  Read and scan for:
- `-enc` (encoded commands)
- `DownloadString`, `Invoke-Expression`, `IEX`
- `Start-Process` with unusual paths
- Credential-related cmdlets (`Get-Credential`, `ConvertTo-SecureString`)
- `Set-MpPreference` (Defender exclusion commands)

**PowerShell ScriptBlock logging** (requires Win10 configured to log):
`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
If enabled, logs go to the Windows event log (EVTX, covered in SP07).
Check whether logging is enabled or has been disabled by policy (a suspicious
configuration change).

**Transcripts:** check `%USERPROFILE%\Documents\` for `.txt` files with
PowerShell transcript content.

### 5. Windows Defender Exclusions

Registry keys (read from SOFTWARE hive):
```
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes
```

Any exclusion that points to a Temp, AppData, or unusual path is a strong
indicator that malware disabled its own detection.  Cross-reference exclusion
paths against SP03 SUSPICIOUS_PATHS and SP01 PERSISTENCE_SCAN findings.

### 6. Windows Timeline (Win10 1803+)

`%LOCALAPPDATA%\ConnectedDevicesPlatform\<user_id>\ActivitiesCache.db`

SQLite database.  Contains a record of user activity including application
launches, document opens, and browser visits — with full timestamps.

If `sqlite3` stdlib module is available:
- Query `Activity` table for `AppActivityType=5` (application launch) entries
- Extract `AppId`, `StartTime`, `EndTime`, `Payload` (JSON)
- Flag suspicious app paths in the activity log

Graceful fallback if SQLite not available.

### 7. Prefetch on Win10/11 (supplement to SP04)

On Win10/11:
- Format version is **v30** (MAM-compressed, like v26 from Win8)
- Prefetch is **disabled by default on SSDs with no ReadyBoot** — check
  `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\
   PrefetchParameters\EnablePrefetcher` registry value:
  - 0 = disabled, 1 = app only, 2 = boot only, 3 = both
- If Prefetch is disabled, emit an informational finding; Amcache (above)
  is the primary execution history source instead.

## Risk scoring

| Signal | Score delta |
|---|---|
| BitLocker detected | Informational CRITICAL — stop and report |
| Amcache entry from Temp/AppData/Downloads | +35 |
| Amcache entry for a file that no longer exists | +25 |
| Amcache SHA-1 matches known-bad list | +65 |
| Shimcache entry from suspicious path | +30 |
| WMI string match: DownloadString/IEX in OBJECTS.DATA | +55 |
| WMI string match: ActiveScriptEventConsumer pattern | +50 |
| PowerShell history: `-enc` or `DownloadString` | +45 |
| Defender exclusion pointing to Temp/AppData | +50 |
| Defender exclusion matches a persistence finding | +60 |
| ScriptBlock logging disabled by policy | +20 |

## Output

JSONL findings to `logs/modern_windows_<ts>.jsonl`

## Dependencies

- SP08 RISK_SCORING / `core.py` (for consistent schema)
- SP01 PERSISTENCE_SCAN JSONL (for Defender exclusion cross-reference)
- SP03 SUSPICIOUS_PATHS JSONL (for path cross-reference)
- SP09 HASH_TRACKING (for Amcache SHA-1 known-bad match)
- `sqlite3` stdlib module (optional, for Windows Timeline)

## Constraints

- Standard library only (struct, hashlib, json; sqlite3 optional)
- **Never** write to the target volume
- Amcache SHA-1 is SHA-1, not SHA-256 — do not confuse with SP09's SHA-256

## Compatibility matrix

| Feature | XP | Vista/7 | Win8 | Win10 | Win11 |
|---|---|---|---|---|---|
| Amcache | ❌ | ❌ | ✅ | ✅ | ✅ |
| Shimcache | ✅ | ✅ | ✅ | ✅ | ✅ |
| WMI subscriptions | ⚠️ limited | ⚠️ limited | ✅ | ✅ | ✅ |
| PSReadLine history | ❌ | ❌ | ❌ | ✅ | ✅ |
| Defender exclusions | ❌ | ❌ | ✅ | ✅ | ✅ |
| Windows Timeline | ❌ | ❌ | ❌ | ✅ (1803+) | ✅ |
| BitLocker risk | Low | Low | Medium | High | High |

## Acceptance criteria

- [ ] Detects BitLocker and reports clearly before attempting any scan
- [ ] Parses Amcache.hve using the existing REGF parser from `persistence_scan.py`
- [ ] Parses Shimcache binary blob from SYSTEM hive for Vista, Win7, and Win10 formats
- [ ] String-scans WMI OBJECTS.DATA for at least `DownloadString`, `IEX`, and `ActiveScriptEventConsumer`
- [ ] Reads PSReadLine history and flags encoded command use
- [ ] Reports Defender exclusions that overlap with persistence findings
- [ ] Handles missing artefacts on Vista (where most of these don't exist) gracefully
