# THERMAL_HEALTH

```text
Implement a module called THERMAL_HEALTH for a system triage tool.

Goal:
Assess overheating risk and likely maintenance needs.

Scope:
- Collect available temperature sensors, fan data, CPU throttling indicators, and thermal zones.
- Detect high idle temperatures, missing fan reports, thermal throttling, or abnormal sensor readings.
- Produce practical recommendations: clean fans, check vents, replace thermal paste, avoid heavy load until serviced.

Output:
- Structured severity findings and a short technician/client summary.

Design expectations:
- Work gracefully when sensor data is unavailable.
- Clearly separate observed facts from inferred maintenance advice.
```
