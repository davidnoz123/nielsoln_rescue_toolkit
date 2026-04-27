# CMOS_HEALTH

```text
Implement a module called CMOS_HEALTH for a system triage tool.

Goal:
Detect likely CMOS/RTC battery issues using indirect evidence.

Scope:
- Compare system clock, filesystem timestamps, BIOS/RTC clues where available.
- Detect suspicious dates such as 2000/2001/1970 or large time drift.
- Identify symptoms consistent with flat CMOS battery: reset time, lost BIOS settings, boot warnings where available.
- Distinguish likely CMOS failure from normal incorrect Linux live environment time.

Output:
- Confidence-rated finding: likely, possible, unlikely, unknown.
- Recommendation: replace CMOS battery, verify BIOS clock, or ignore.

Design expectations:
- Avoid false certainty.
- Do not modify system clock unless explicitly requested by a separate tool.
```
