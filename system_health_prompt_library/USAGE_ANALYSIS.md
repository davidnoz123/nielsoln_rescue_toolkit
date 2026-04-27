# USAGE_ANALYSIS

```text
Implement a module called USAGE_ANALYSIS for an offline Windows triage tool.

Goal:
Estimate how often installed software has actually been used.

Scope:
- Use available offline evidence such as Prefetch, recent files, shortcuts, timestamps, jump lists where practical.
- Associate usage evidence with installed applications when possible.
- Identify software apparently unused for months/years.
- Distinguish weak evidence from strong evidence.

Output:
- Per-application usage estimate: active, occasional, stale, unknown.
- Evidence and confidence for each estimate.

Design expectations:
- Avoid claiming exact user behaviour.
- Treat last-access times cautiously.
- Complement SOFTWARE_INVENTORY and BLOAT_DETECTION.
```
