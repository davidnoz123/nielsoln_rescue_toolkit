# ACTION_PLAN

```text
Implement a module called ACTION_PLAN for a system triage/advisory report.

Goal:
Turn scan findings into a practical ordered action plan.

Scope:
- Prioritise actions by risk, value, dependency, and cost.
- Examples: clone failing drive, replace SSD, upgrade RAM, remove bloatware, replace CMOS battery, migrate Office.
- Separate urgent safety/data-loss actions from optional performance improvements.
- Include operator notes and client-friendly wording.

Output:
- Ordered action list with rationale, estimated effort, risk if ignored, and expected benefit.

Design expectations:
- Consume findings from other modules.
- Do not perform actions; recommend only.
```
