# SP30 — Report Enhancements: OS, BIOS, Drivers, ChatGPT Context

## Background

Extend the customer-facing `customer_report.md` with richer technical detail that
is currently either missing or only partially surfaced.

---

## Tasks

### ✅ T1 — Logging in event capture (`m25_event_archive.py`)

**Status: DONE**

Progress logging was added in the previous session:
- Progress printed every 5,000 records with counts of `scanned / skipped / new`
- Elapsed time shown at each progress line and at end of each channel
- Incremental run confirmed working: already-seen records skip in ~1 s per 40 k records

---

### ✅ T2 — SSH deploy directive in `AGENTS.md`

**Status: DONE**

Section added: _"CRITICAL: Deploy via SSH/SCP — NEVER use `bootstrap update` from the dev machine"_.  
Contains the deployment table and all rules.

---

### T3 — OS profile module (`modules/m26_os_profile.py`)

**Status: TODO**

Create a new module that reads the offline Windows installation and collects:

| Field | Source |
|---|---|
| OS edition / product name | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` → `ProductName` |
| OS build & version | `CurrentBuildNumber`, `CurrentVersion` |
| OS bitness (32/64-bit) | Presence of `Windows\SysWOW64\` — if exists → 64-bit install |
| CPU architecture | From `m04` hardware profile (already: `cpu.architecture`) |
| Service pack | `CSDVersion` registry value |
| Registered owner | `RegisteredOwner`, `RegisteredOrganization` |
| Install date | `InstallDate` (Unix timestamp) |
| Installed drivers | List `.sys` files under `Windows\System32\drivers\` |
| Kernel driver services | Registry `SYSTEM\CurrentControlSet\Services` — Type=1 (kernel) |

Output: `logs/os_profile_<timestamp>.json`

Module arg: `--target <windows_mount>`

---

### T4 — BIOS & system info in report (`report_gen.py`)

**Status: TODO**

`m04_hardware_profile` already collects `bios.vendor`, `bios.version`, `bios.date`, and
`boot_mode` (UEFI vs Legacy).  The current `section_hardware()` only shows `bios.date`.

Changes needed:
- Show full BIOS row: vendor + version + date + boot mode
- Show CPU architecture (32/64-bit) in the hardware table
- Show CPU cores/threads using correct field names from `m04` JSON
  (`cpu.physical_cores` / `cpu.logical_cores`)
- Show RAM type and speed (already collected, not shown in report)
- Show RAM slot detail (`slots_populated / slots_total`)

---

### T5 — OS details section in report (`report_gen.py`)

**Status: TODO** (depends on T3)

Add `section_os_profile()` between Hardware and Disk Health:

| Field | Source |
|---|---|
| OS Edition | `os_profile.product_name` |
| Version / Build | `os_profile.version` / `os_profile.build` |
| OS bitness | `os_profile.os_bitness` |
| CPU bitness | `hardware.cpu.architecture` |
| Service Pack | `os_profile.service_pack` |
| Registered owner | `os_profile.registered_owner` |
| Install date | `os_profile.install_date` |

---

### T6 — Driver information section in report (`report_gen.py`)

**Status: TODO** (depends on T3)

Add `section_drivers()`:
- Table: driver `.sys` filename, size, modified date
- Flag any drivers **not** in `System32\drivers\` (non-standard location)
- Flag any drivers with a very old or very new date relative to install date
- Collapse full list in a `<details>` block; surface only flagged drivers above the fold

---

### T7 — ChatGPT hardware context section (`report_gen.py`)

**Status: TODO**

Add `section_chatgpt_context()` at the **end** of the report, clearly delimited with
`---`.  Purpose: a plain-text block the customer can paste into ChatGPT (or similar)
to get an independent assessment of the hardware's tier and historical value.

Format:

```
---
## Hardware Context (paste into ChatGPT)

Please analyse the following hardware specifications for a laptop.
Tell me:
1. What performance tier was this laptop when it was released (budget / mid-range / high-end)?
2. How does each component compare to what was typical at the time of release?
3. What tasks was this machine well-suited for when new?
4. Is it still usable today, and for what?

**Estimated release year:** YYYY  (inferred from BIOS date)
**Manufacturer / Model:** ...
**CPU:** ...
**RAM:** ... GiB ... type
**Storage:** ... GB HDD/SSD
**GPU:** ...
**OS installed:** Windows Vista (32/64-bit)
**Form factor:** laptop/desktop
```

The estimated release year is derived from `bios.date` (strip to year, or use OS install
date as a cross-check).

---

### T8 — Release, deploy, run report

**Status: TODO** (depends on T3–T7)

1. `devtools release` — compile-check + git push
2. `push_module m26_os_profile` — deploy new module
3. `run_module m26_os_profile --target /mnt/windows` — collect OS profile
4. `run_remote report_gen.py` — regenerate report
5. `scp` download `customer_report.md` to dev machine

---

## Order of work

```
T3 → T4 → T5 → T6 → T7 → T8
```

T1 and T2 are complete.  T3–T7 are pure local code changes.  T8 is the deploy+run step.
