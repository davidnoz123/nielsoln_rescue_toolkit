# Nielsoln Rescue Toolkit — Data Collection Inventory

A reference of every category of information the toolkit collects, what data
fields are captured, which Python tool produces them, and where the output is
written on the USB.

---

## 1. OS & Windows Identity

**Tool:** `modules/m26_os_profile.py`  
**Output:** `logs/os_profile_<timestamp>.json`

| Field | Description |
|---|---|
| edition | Windows edition (e.g. Home Premium, Ultimate) |
| version / build | NT version + build number (e.g. 6.0.6001) |
| service_pack | Service Pack level |
| install_date | Date the OS was installed |
| installed_owner | Registered owner name |
| registered_organization | Registered organisation |
| bitness | 32-bit or 64-bit |
| cpu_architecture | Processor architecture |
| driver_list | All .sys kernel driver files in System32\drivers\ |

---

## 2. Hardware Profile

**Tool:** `modules/m04_hardware_profile.py`  
**Output:** `logs/hardware_profile_<timestamp>.json`

| Category | Fields |
|---|---|
| System | manufacturer, product_name, product_version, serial_number, chassis_type, form_factor |
| BIOS | vendor, version, release_date |
| CPU | name, cores, threads, architecture, frequency_mhz |
| RAM | total_mb, total_gib, type, speed_mhz, slots_populated, slots_total, per-DIMM modules list |
| Storage | model, size_gb, device path, interface_type, media_type, removable, smart_available |
| Network | interface name, mac_address, speed_mbps, driver |
| GPU | name, driver, vram_mb |
| Boot mode | UEFI or Legacy BIOS |

---

## 3. Disk Health (S.M.A.R.T.)

**Tool:** `modules/m05_disk_health.py`  
**Output:** `logs/disk_health_<timestamp>.json`

| Field | Description |
|---|---|
| device / model / size_gb | Drive identity |
| media_type | HDD or SSD |
| overall_health / verdict | HEALTHY, CAUTION, CRITICAL, NO_SMART |
| reallocated_sectors | Count of remapped bad sectors (key failure indicator) |
| pending_sectors | Sectors waiting to be reallocated |
| uncorrectable_errors | Read errors that could not be recovered |
| spin_retry_count | HDD spinup retry count |
| command_timeouts | Drive command timeout count |
| power_on_hours | Lifetime run time |
| temperature_c | Current drive temperature |
| ssd_wear_level | SSD wear indicator (0–100%) |
| available_reserved_space | SSD spare block reserve |
| warnings / flags | reallocated, pending, uncorrectable, high_temp, ssd_wear_critical |

---

## 4. Clone Readiness

**Tool:** `modules/m13_clone_ready.py`  
**Output:** `logs/clone_ready_<timestamp>.json`

| Field | Description |
|---|---|
| verdict | CLONE_NOW, CLONE_SOON, CLONE_OK, CANNOT_ASSESS |
| issues | Human-readable list of disk problems found |
| smart metrics | hours, reallocated, pending, uncorrectable, spin_retry |

*Derived from the most-recent disk_health log — no additional scan required.*

---

## 5. Memory Health

**Tool:** `modules/m11_memory_health.py`  
**Output:** `logs/memory_health_<timestamp>.json`

| Field | Description |
|---|---|
| MemTotal_kb / MemAvailable_kb | Live system RAM amounts |
| SwapTotal_kb / SwapFree_kb | Swap space |
| DIMM info | manufacturer, size_mb, speed_mhz, form_factor, serial, locator, ecc_errors |
| kernel_dump_present | Whether a full kernel dump file exists |
| minidump_count | Number of Windows minidump files |
| minidump_list | Paths of minidump files found |
| bugcheck_events | BSODs recorded in System.evtx |
| verdict | HEALTHY, SUSPECT, DEGRADED, LOW_RAM |

---

## 6. Thermal Health

**Tool:** `modules/m09_thermal_health.py`  
**Output:** `logs/thermal_health_<timestamp>.json`

| Field | Description |
|---|---|
| hwmon sensors | chip_name, label, temperature_c, high_threshold_c, crit_threshold_c |
| fan sensors | label, rpm |
| thermal zones | zone_name, temperature_c, mode, trip_points |
| CPU throttle | current_freq_mhz, max_freq_mhz, throttle_event_count |
| verdict | normal, caution, critical |
| recommendations | maintenance_needed, thermal_service_recommended |

---

## 7. Battery Health

**Tool:** `modules/m10_battery_health.py`  
**Output:** `logs/battery_health_<timestamp>.json`

| Field | Description |
|---|---|
| status | Charging, Discharging, Full |
| capacity_percent | Current charge level (%) |
| wear_percent | Battery degradation relative to design capacity |
| charge_now_mah / charge_full_mah / charge_design_mah | Actual capacity values |
| cycle_count | Charge cycle count |
| manufacturer / model_name / technology | Battery identity |
| voltage_mv / serial | Electrical specs and serial |
| verdict | HEALTHY, DEGRADED, WORN, CRITICAL, NOT_FOUND |

---

## 8. Software Inventory

**Tool:** `modules/m06_software_inventory.py`  
**Output:** `logs/software_inventory_<timestamp>.json`  
*Reads offline Windows registry — no Windows boot required.*

| Field | Description |
|---|---|
| name / publisher / version | Application identity |
| install_date / install_year | When the software was installed |
| category | Security, Browser, Office, Driver, OS Component, Java/Runtime, Media, Productivity, Game, Toolbar/BHO, Other |
| flags | suspicious, bloat, legacy-publisher, legacy-install-date |
| summary | total_installed, flagged_count, categories breakdown |

---

## 9. Services & Drivers

**Tool:** `modules/m07_service_analysis.py`  
**Output:** `logs/service_analysis_<timestamp>.json`  
*Reads offline Windows SYSTEM registry hive.*

| Field | Description |
|---|---|
| name / display_name | Service identity |
| type | Win32OwnProcess, Win32ShareProcess, KernelDriver, FileSystemDriver, etc. |
| start_type | Boot, System, Automatic, Manual, Disabled |
| image_path | Executable / driver path |
| object_name | Account the service runs as |
| description | Service description text |
| flags | suspicious, third-party, driver, disabled, deleted |
| summary | total_services, flagged_count, by_start_type, by_type |

---

## 10. Persistence Mechanisms

**Tool:** `modules/m01_persistence_scan.py`  
**Output:** `logs/persist_<timestamp>.jsonl`  
*Each line is one finding.*

| Field | Description |
|---|---|
| type | startup, task, service, registry |
| source | File path or registry key where entry was found |
| command | Executable or full command string being launched |
| user | Associated username (null = system-wide) |
| score | 0–100 risk score |
| risk | low, medium, high |
| reasons | Human-readable explanations of what raised the score |

**Locations scanned:**
- Startup folders (All Users + per-user)
- Scheduled Tasks (XML task definitions)
- Services (SYSTEM hive)
- Registry autorun keys (Run, RunOnce, RunServices, Winlogon, etc.)

---

## 11. Logon & Security Events

**Tool:** `modules/m23_logon_audit.py`  
**Output:** `logs/logon_audit_<timestamp>.json`  
**TSV export:** `logon_events.tsv` (via `report_gen.py`)  
*Reads Security.evtx offline.*

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon (wrong password / unknown user / locked out) |
| 4634 | Logoff |
| 4648 | Logon with explicit credentials (pass-the-hash indicator) |
| 4720–4726 | Account creation, deletion, enabled/disabled |
| 4740 | Account lockout |
| 4767 | Account unlock |
| 4723 | User-initiated password change |
| 4724 | Administrator password reset |

Additional fields: SubStatus code breakdown (wrong password, unknown user, account disabled, etc.), verdict (normal, suspicious, concerning).

> **Vista Home note:** Failure auditing is disabled by default on Windows Vista Home Premium, so absence of 4625 events does NOT confirm no failed attempts occurred.

---

## 12. Event Log Archive

**Tool:** `modules/m25_event_archive.py`  
**Output:** `logs/event_archive/` (JSONL chunks, one file per channel per session)

| Field | Description |
|---|---|
| channel | Windows event channel (System, Application, Security, etc.) |
| record_id | Monotonically increasing event record number |
| timestamp | ISO-8601 event timestamp |
| event_id | Windows Event ID |
| provider | Source provider name |
| computer | Machine name |
| data | EventData key/value pairs (varies by event) |
| raw_sha256 | Hash of raw XML record |
| anomalies | gap, clear, regression detection |
| machine.json | hostname, serial_number, bios_date, sha256 identity |

---

## 13. Malware Scan (ClamAV)

**Tool:** `modules/m18_clamav_scan.py`  
**Output:** `logs/scan_report_quick_<timestamp>.txt`, `logs/clamav_quick_<timestamp>_NN.log`

| Field | Description |
|---|---|
| profile | quick (exe/scripts, ~350 MB RAM) or thorough (all files + archives, ~600 MB RAM) |
| status | COMPLETE, INTERRUPTED, PARTIAL |
| infected | Count of segments containing threats |
| scanned | Units completed / total |
| findings | File path + signature name for any infected files |
| definitions | main.cvd + daily.cld version dates |

*Quick profile scans: .exe, .dll, .sys, .bat, .cmd, .vbs, .js, .ps1, .msi, .scr, .com, .pif, .reg*

---

## 14. Upgrade Recommendations

**Tool:** `modules/m15_upgrade_advisor.py`  
**Output:** `logs/upgrade_advisor_<timestamp>.json`  
*Synthesises hardware_profile, disk_health, and thermal data.*

| Component | Fields |
|---|---|
| SSD upgrade | benefit, urgency, description, estimated_cost_usd |
| RAM upgrade | benefit, urgency, description, estimated_cost_usd |
| Thermal service | benefit, urgency, description |
| Battery replacement | benefit, urgency, description, estimated_cost_usd |
| OS upgrade | benefit, urgency, description |

Benefit ratings: critical, high, medium, low, none  
Urgency ratings: immediate, soon, when_budget_allows, optional, not_needed

---

## 15. System Summary (consolidated one-pager)

**Tool:** `modules/m17_system_summary.py`  
**Output:** `logs/system_summary_<timestamp>.json`

Consolidates results from all other modules into a single JSON with an overall
verdict and recommended next action. No new scans are run.

---

## 16. Customer Report

**Tool:** `report_gen.py`  
**Output:** `customer_report.md`, `logon_events.tsv`

A formatted Markdown document for the customer covering:
1. Machine identity & overall assessment
2. Hardware summary
3. OS profile
4. Disk health
5. Software inventory (counts, flagged apps)
6. Services (flagged entries)
7. Thermal & battery health
8. Logon activity (with Vista Home audit policy caveat)
9. Event archive summary
10. Persistence findings
11. Antivirus results
12. Upgrade recommendations
13. Next steps
14. ChatGPT context block (raw data dump for AI-assisted analysis)

---

## Output File Summary

| File pattern | Producer | Format |
|---|---|---|
| `logs/os_profile_*.json` | m26 | JSON |
| `logs/hardware_profile_*.json` | m04 | JSON |
| `logs/disk_health_*.json` | m05 | JSON |
| `logs/clone_ready_*.json` | m13 | JSON |
| `logs/memory_health_*.json` | m11 | JSON |
| `logs/thermal_health_*.json` | m09 | JSON |
| `logs/battery_health_*.json` | m10 | JSON |
| `logs/software_inventory_*.json` | m06 | JSON |
| `logs/service_analysis_*.json` | m07 | JSON |
| `logs/persist_*.jsonl` | m01 | JSONL (one finding per line) |
| `logs/logon_audit_*.json` | m23 | JSON |
| `logs/event_archive_*.json` | m25 | JSONL chunks |
| `logs/scan_report_quick_*.txt` | m18 | Plain text |
| `logs/clamav_quick_*.log` | m18 | ClamAV raw log |
| `logs/upgrade_advisor_*.json` | m15 | JSON |
| `logs/system_summary_*.json` | m17 | JSON |
| `customer_report.md` | report_gen | Markdown |
| `logon_events.tsv` | report_gen | TSV |
| `logs/toolkit.log` | all modules | Append-only operational log |
