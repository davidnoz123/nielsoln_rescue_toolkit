# DISK_HEALTH

```text
Implement a module called DISK_HEALTH for a RescueZilla/Linux-based system triage tool.

Context:
- The tool runs from RescueZilla/Linux, often over SSH.
- It inspects internal disks before malware scanning, cloning, or upgrade work.
- It must be safe and read-only by default.

Goal:
Assess HDD/SSD health and identify failing drives before data loss.

Scope:
- Identify all storage devices.
- Collect SMART health where available.
- Highlight reallocated sectors, pending sectors, uncorrectable errors, power-on hours, temperature, and SSD wear indicators.
- Identify drives that should be cloned immediately.
- Optionally support a read-only surface scan mode for bad-block suspicion.

Output:
- Structured drive findings with severity, evidence, and recommended action.
- Technician/client summary: healthy, caution, failing, or unknown.

Design expectations:
- Read-only by default.
- Warn clearly before any long-running scan.
- Integrate naturally with RescueZilla cloning recommendations.
```
