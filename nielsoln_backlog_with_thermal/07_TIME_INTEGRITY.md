# TIME_INTEGRITY

Implement time and clock trust analysis.

Collect:
- timezone configuration
- NTP/time service configuration
- event log time-change events
- timestamp discontinuities
- CMOS/time reset indicators
- inconsistencies between file timestamps and event logs

Output:
- `logs/time_integrity_<timestamp>.json`

Purpose:
- improve confidence in event timelines
- support CMOS battery diagnosis
- warn when log timing may be unreliable
