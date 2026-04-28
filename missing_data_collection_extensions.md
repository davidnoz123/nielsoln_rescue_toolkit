# Nielsoln Rescue Toolkit — Missing Data Collection Extensions

Design and implement additional data collection modules to fill gaps in the current system inventory.

Context:
- The toolkit runs from a Linux environment (RescueZilla) and inspects an offline Windows installation.
- The system already collects hardware, disk SMART, software, services, persistence, event logs, etc.
- These extensions should add *new information not already captured*.
- All collection must be read-only and safe.

Goal:
Extend the toolkit to capture deeper diagnostics in the following areas:

---

## 1. Device Manager / Driver Health

### Purpose
Identify hardware devices with driver issues or misconfiguration.

### Data to collect
- All detected devices from Windows registry / driver database
- For each device:
  - device name / description
  - hardware ID(s)
  - driver file(s)
  - driver version
  - driver provider
  - driver install date
  - device class

### Problem detection
Flag devices where:
- driver missing
- device disabled
- device has error code
- driver is extremely old
- multiple drivers bound inconsistently

Output: logs/device_manager_<timestamp>.json

---

## 2. Advanced Disk Integrity

### Purpose
Detect real-world disk reliability issues not visible in SMART alone.

### Data to collect
- NTFS dirty bit
- CHKDSK logs
- fragmentation estimate
- disk usage
- large directories/files

### Event log correlation
- disk errors
- controller resets
- I/O failures

Output: logs/disk_integrity_<timestamp>.json

---

## 3. Battery Health (extended)

### Data to collect
- charge behaviour
- discharge rate
- abnormal voltage
- time estimates

### Derived indicators
- normal / rapid discharge / charging issue

Output: logs/battery_analysis_<timestamp>.json

---

## 4. CMOS Battery Health

### Indicators
- time anomalies
- BIOS vs OS time mismatch
- repeated time resets

### Verdict
- HEALTHY / SUSPECT / LIKELY_DEAD

Output: logs/cmos_health_<timestamp>.json

---

## 5. Storage Usage

### Data
- total / free space
- usage %
- largest directories
- temp/cache size

### Flags
- nearly full disk
- large profiles
- excessive temp files

Output: logs/storage_usage_<timestamp>.json

---

## 6. Upgradeable Hardware

### Data
- RAM slots + max capacity
- storage interfaces
- CPU socket (if available)

### Derived
- RAM upgrade possible
- SSD compatible
- extra storage possible
- CPU upgrade feasibility

Output: logs/hardware_upgrade_options_<timestamp>.json

---

## 7. Driver & Firmware Risk

### Data
- BIOS age
- driver age

### Flags
- very old BIOS
- legacy drivers

Output: logs/firmware_driver_risk_<timestamp>.json

---

## 8. Boot Diagnostics

### Data
- boot event logs
- startup programs count

### Flags
- slow boot
- excessive startup items
- repeated failures

Output: logs/boot_analysis_<timestamp>.json

---

## General Requirements

- Read-only
- Works offline
- Handles missing data
- Consistent JSON output

---

## Deliverable

Modules that improve insight into:
- hardware reliability
- disk integrity
- driver issues
- upgrade potential
