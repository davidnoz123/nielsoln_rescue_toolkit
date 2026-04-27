# HARDWARE_PROFILE

```text
Implement a module called HARDWARE_PROFILE for a system triage and upgrade advisor.

Goal:
Create a clear hardware profile of the target computer.

Scope:
- Identify manufacturer, model, serial/service tag where available.
- Identify CPU, RAM, storage devices, GPU, network devices, BIOS/UEFI version, boot mode, and architecture.
- Detect whether the machine is desktop/laptop where possible.
- Detect storage interface and likely upgrade path: SATA HDD, SATA SSD, NVMe, eMMC, etc.

Output:
- Structured hardware inventory.
- Human-readable summary suitable for the front page of a report.

Design expectations:
- Read-only.
- Graceful fallback when DMI/SMBIOS data is incomplete.
- Designed to feed UPGRADE_ADVISOR and SYSTEM_LIFESPAN.
```
