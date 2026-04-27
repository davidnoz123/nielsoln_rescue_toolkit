# Subproject Ordering and Analysis

This document defines the implementation order for all subprojects, explains
where this ordering diverges from the original ChatGPT suggestion, flags
subprojects that should be reconsidered, and notes additions not in the
original list.

---

## Current state (as of 2026-04-27)

| Module | Status | Notes |
|---|---|---|
| SP01 PERSISTENCE_SCAN | ✅ Done | `persistence_scan.py`, commit `8c1fd10` |
| STRUCTURED_LOGS | ✅ Done (inline) | JSONL output baked into persistence_scan.py |
| ERROR_HARDENING | ✅ Done (inline) | Graceful error handling baked into all modules |
| BUNDLED_AV (ClamAV) | 🔄 Partial | Skeleton in `toolkit.py`; not a formal module yet |

---

## Recommended implementation order

### Phase 1 — Core Windows scanning (do these next)

These are the highest-value, lowest-effort additions.  All are pure Python,
standard library only, and can be run standalone on the existing Vista machine.

| # | Subproject | Why here |
|---|---|---|
| 1 | ✅ SP01 PERSISTENCE_SCAN | Done |
| 2 | SP02 DISK_OVERVIEW | Should run first on every engagement — machine identity and context |
| 3 | SP03 SUSPICIOUS_PATHS | Highest-signal scan after persistence; no deps, very fast |
| 4 | SP04 PREFETCH_ANALYSIS | Vista Prefetch is gold — execution history including deleted files |
| 5 | SP05 BROWSER_AUDIT | Most common Vista infection vector; high client-visible impact |
| 6 | SP06 LOLBIN_DETECTION | Partially a second-pass over SP01 findings; easy to build |
| 7 | SP07 WINDOWS_EVENT_LOGS | Not in ChatGPT's list; critical forensic source; do not skip |

### Phase 2 — Engineering foundations

Build these once Phase 1 has 3+ modules, before they each invent their own
conventions.

| # | Subproject | Why here |
|---|---|---|
| 8 | SP08 RISK_SCORING | Shared `core.py` library; extract from persistence_scan.py |
| 8b | SP29 MODERN_WINDOWS_ARTEFACTS | Amcache, Shimcache, WMI, PowerShell, Defender exclusions; needed for any Win10/11 machine |
| 8c | SP24 SCAN_PROFILE_OS | Promoted from Phase 6; needed before scanning any non-Vista machine |
| 9 | SP09 HASH_TRACKING | Scoped to suspect files only — not full-partition hash |
| 10 | SP10 ENTROPY_CHECK | Pure Python, no deps; high value for packed malware |
| 11 | SP11 INCREMENTAL_SCAN | Depends on SP09; makes repeat scans practical |

### Phase 3 — Deeper forensics

| # | Subproject | Why here |
|---|---|---|
| 12 | SP12 RECENT_ACTIVITY | Pure Python; good for clustering infection events |
| 13 | SP13 TIMELINE_BUILD | Aggregation; needs SP04, SP07, SP12 first |
| 14 | SP14 ADS_DETECTION | Flagged — see note below; best-effort only |
| 15 | SP15 BOOT_SCAN | High value for rootkits; needs raw disk access (root OK) |
| 16 | SP16 MEMORY_ARTEFACTS | Narrow offline scope; mostly minidump counting |

### Phase 4 — Orchestration and advanced features

| # | Subproject | Why here |
|---|---|---|
| 17 | SP17 MULTI_ENGINE | Orchestration layer; only useful when 4+ modules exist |
| 18 | SP18 BUNDLED_AV | Formalise existing ClamAV sketch into a proper module |
| 19 | SP19 CROSS_MACHINE_INTEL | USB-local threat intel DB; very valuable for repeat clients |
| 20 | SP20 YARA_RULES | Flagged — see note below |

### Phase 5 — Reporting

| # | Subproject | Why here |
|---|---|---|
| 21 | SP21 TECH_SUMMARY | Needs multiple modules' findings to be meaningful |
| 22 | SP22 CLIENT_REPORT | Depends on SP21 |
| 23 | SP23 ACTION_SUGGESTIONS | Depends on SP21 + SP18 (confirmed vs suspected) |

### Phase 6 — OS expansion (macOS; only after Win10/11 coverage is solid)

| # | Subproject | Why here |
|---|---|---|
| 25 | SP25 MAC_LAUNCH_AGENTS | macOS persistence equivalent of SP01 |
| 26 | SP26 MAC_APP_SCAN | macOS suspicious files equivalent of SP03 |
| 27 | SP27 MAC_QUARANTINE | macOS-specific; no Windows equivalent |
| 28 | SP28 MAC_BROWSER | macOS browser audit; shares logic with SP05 |

---

## Where this ordering diverges from ChatGPT

| Module | ChatGPT rank | This ordering | Reason |
|---|---|---|---|
| SP29 MODERN_WINDOWS_ARTEFACTS | Not listed | 8b | Amcache, Shimcache, WMI subscriptions, PowerShell history, Defender exclusions — essential for Win10/11 |
| SP24 SCAN_PROFILE_OS | Not listed | 8c (was 24) | Promoted from Phase 6; needed before the first non-Vista machine is scanned |
| SP07 WINDOWS_EVENT_LOGS | Not listed | 7 | Critical forensic source; Vista EVTX is very informative; inexplicable omission |
| SP02 DISK_OVERVIEW | Not listed | 2 | Machine identity should be established before any scan |
| SP08 RISK_SCORING | 21 | 8 | Build the shared library while there are still only 2–3 modules; at #21 the debt is already unmanageable |
| SP04 PREFETCH_ANALYSIS | 6 | 4 | Vista Prefetch is enabled by default; execution history of deleted malware is high-value; should come before browser audit |
| SP17 MULTI_ENGINE | 5 | 17 | An orchestration layer built before 3+ modules exist is a stub that needs constant rework; move to after Phase 1–2 |
| SP11 INCREMENTAL_SCAN | 17 | 11 | Depends on SP09 HASH_TRACKING; keep them together in Phase 2 |
| SP20 YARA_RULES | 4 | 20 | Flagged — has a dependency conflict (see below); should not be #4 |

---

## Flagged subprojects ⚠️

### BitLocker (critical constraint for modern machines)

**If the target drive is BitLocker-encrypted, offline scanning is not possible
without the recovery key.**  This is common on corporate Win10/11 laptops and
increasingly on consumer Win11 devices (which enable device encryption by
default if the machine has a TPM and a Microsoft account).

BitLocker detection must run before any scan module on Win8+ machines.
SP29 and SP15 both implement detection.  SP24 SCAN_PROFILE_OS should check
for BitLocker as part of OS profiling.  If detected:
- Report as CRITICAL informational finding
- Tell the technician where the recovery key is likely stored:
  - **Consumer Win11:** Microsoft account recovery key at account.microsoft.com
  - **Corporate:** Active Directory / Azure AD
  - **Self-managed:** `.bek` file or printed/written key
- Do not attempt to scan the encrypted volume.

### SP14 ADS_DETECTION
Reading NTFS Alternate Data Streams from Linux requires `ntfs-3g` extended
attribute support (`getfattr`) or `ntfscat`.  These tools may not be present on
RescueZilla.  The module **must** implement graceful fallback (report limitation
and continue) rather than being a hard dependency.

### SP20 YARA_RULES
Full YARA requires `yara-python`, which is not in the standard library.
**Do not use `pip install` on the rescue machine.**  Two acceptable approaches:
1. Bundle a static `yara` binary in `_tools/yara/` (same pattern as `dropbear`)
   and wrap it via `subprocess`
2. Implement a minimal pure-Python fallback for basic string/regex matching

Before implementing, decide which approach and add the binary download to
`toolkit.py download_yara()` and to `run_update()`.

### PARALLEL_SCAN (removed from subprojects list — not recommended)
See note below.

---

## Merged/removed subprojects

### STRUCTURED_LOGS — merged into SP08 RISK_SCORING / `core.py`
Not a standalone module.  Consistent JSONL output format and field schema is
a shared convention implemented in `core.py`.  `persistence_scan.py` already
emits valid JSONL.  When SP08 is implemented, extract the writer into `core.py`
and have all modules use it.

### ERROR_HARDENING — not a standalone module
Cross-cutting concern.  The approach (try/except around each file read, always
continue, emit informational finding on error) is already implemented in
`persistence_scan.py`.  Document the pattern in `core.py` as a shared
`safe_read()` / `safe_walk()` utility rather than a separate module.

### MAC_LIMITATIONS — merged into SP24 SCAN_PROFILE_OS
Not a scan module — it is documentation and runtime disclaimers.  The OS
profile module reports limitations as informational findings at scan start.

### PARALLEL_SCAN — recommended to ditch (or defer indefinitely)
The primary target is a rotational HDD laptop booted over USB.  Parallel reads
on a single spinning HDD are counterproductive — they add random seek overhead
and typically make things **slower**, not faster.  The correct optimisation for
this scenario is SP11 INCREMENTAL_SCAN (skip unchanged files) and scoping
(only hash/check suspect files, not the whole partition).

If parallelism is ever added, it should be limited to CPU-bound work (entropy
calculation, hash computation) on already-read file data — not concurrent disk
I/O.

---

## New additions (not in ChatGPT's list)

### SP02 DISK_OVERVIEW (Priority 2)
Machine identity, users, OS version, installed software, and last activity hint.
Should run before any scan module to establish context.  Findings from other
modules become much more useful when you know the machine's history.

### SP07 WINDOWS_EVENT_LOGS (Priority 7)
Windows event logs are one of the most valuable offline forensic sources and
were completely absent from the ChatGPT list.  Vista introduced the EVTX binary
format.  Security log: failed logins, privilege escalation, new accounts.
System log: service installs, crashes.  A cleared Security log is itself a
high-confidence indicator of cover-up.

### SP29 MODERN_WINDOWS_ARTEFACTS (Priority 8b)
Triggered by the decision to support modern Windows (10/11) as well as Vista.
Covers artefacts that simply do not exist on Vista: Amcache.hve (primary
execution history on SSDs where Prefetch is disabled), Shimcache (all versions),
WMI event subscription string scanning, PowerShell PSReadLine history,
Windows Defender exclusions (a direct malware self-protection signal), and
Windows Timeline.  Also handles BitLocker detection for modern machines.

### SP24 SCAN_PROFILE_OS (Promoted from Priority 24 → 8c)
Originally deferred to Phase 6 on the assumption Vista was the only target.
Promoted to Phase 2 now that the tool must also handle Win10/11 (and eventually
macOS).  Without an OS profile layer, every module would need its own
version-detection logic — that debt compounds quickly.  Must be implemented
before the first non-Vista machine is tested.
