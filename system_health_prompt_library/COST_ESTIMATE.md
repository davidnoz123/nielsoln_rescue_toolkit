# COST_ESTIMATE

```text
Implement a module called COST_ESTIMATE for a system triage/advisory tool.

Goal:
Produce ballpark cost ranges for recommended repairs/upgrades.

Scope:
- Estimate costs for SSD upgrades, RAM upgrades, battery replacement, CMOS battery replacement, labour, data migration, and Office/Microsoft 365 migration.
- Support NZ context and web-fed current prices through ONLINE_LOOKUPS.
- Include low/typical/high estimates and assumptions.

Output:
- Structured cost estimate and client-facing summary.

Design expectations:
- Do not hardcode exact prices as permanent truth.
- Make assumptions and pricing date visible.
- Keep pricing separate from technical findings.
```
