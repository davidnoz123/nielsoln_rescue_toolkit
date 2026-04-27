# SYSTEM_SUMMARY

```text
Implement a module called SYSTEM_SUMMARY for a full system triage report.

Goal:
Combine malware, hardware, software, and upgrade findings into a concise professional report.

Scope:
- Summarize overall condition: security, storage, battery, memory, performance, software, upgrade value.
- Highlight urgent risks first.
- Include recommended actions grouped by priority.
- Produce technician-facing and client-facing summaries.

Output:
- One-page summary plus structured machine-readable summary.
- Clear categories: urgent, recommended, optional, informational.

Design expectations:
- Consume findings from other modules; do not duplicate scanning logic.
- Avoid alarmist wording unless evidence is strong.
```
