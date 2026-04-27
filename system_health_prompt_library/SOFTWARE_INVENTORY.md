# SOFTWARE_INVENTORY

```text
Implement a module called SOFTWARE_INVENTORY for an offline Windows/system triage tool.

Goal:
Report installed software and categorize it for cleanup, migration, and support planning.

Scope:
- Detect installed Windows applications from offline registry hives and known install locations.
- Include name, version, publisher, install date, uninstall command where available.
- Categorize software: operating system component, driver/vendor tool, productivity, browser, security, legacy, unknown.
- Flag very old, unsupported, duplicated, suspicious, or unnecessary software.

Output:
- Structured software inventory.
- Summary grouped by category and risk/usefulness.

Design expectations:
- Read-only.
- Graceful if registry parsing is unavailable.
- Designed to feed BLOAT_DETECTION, OFFICE_MIGRATION, and SYSTEM_LIFESPAN.
```
