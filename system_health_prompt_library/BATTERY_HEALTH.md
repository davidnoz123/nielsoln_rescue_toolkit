# BATTERY_HEALTH

```text
Implement a module called BATTERY_HEALTH for a RescueZilla/Linux-based system triage tool.

Context:
- The tool runs from a Linux live environment, often remotely over SSH.
- It may inspect the live Linux hardware environment and/or a mounted offline Windows installation.
- The scan must be read-only and safe.

Goal:
Assess laptop battery condition and produce practical repair/replacement advice.

Scope:
- Detect whether a battery is present.
- Report design capacity, full charge capacity, current charge, cycle count where available.
- Estimate battery wear and remaining usable capacity.
- Detect not-charging, missing, degraded, or critically worn batteries.
- Distinguish between unavailable data and healthy results.

Output:
- Structured findings with score, severity, evidence, and recommendation.
- Human-readable summary suitable for a technician/client report.

Design expectations:
- Modular scanner, scorer, and reporter.
- Graceful fallback when battery telemetry is unavailable.
- Never modify system settings.
```
