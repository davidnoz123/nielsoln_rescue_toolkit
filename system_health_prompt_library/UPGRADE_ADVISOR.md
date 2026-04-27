# UPGRADE_ADVISOR

```text
Implement a module called UPGRADE_ADVISOR for a system triage tool.

Goal:
Recommend practical hardware upgrades based on detected hardware and client value.

Scope:
- Use hardware profile, disk health, RAM status, OS version, and current storage type.
- Recommend upgrades such as HDD-to-SSD, RAM increase, battery replacement, cleaning/thermal service.
- Estimate benefit: high, medium, low.
- Identify cases where replacement is better than upgrade.
- Include confidence levels and assumptions.

Output:
- Prioritised upgrade recommendations with rationale.
- Technician/client-friendly action list.

Design expectations:
- Separate evidence from recommendation.
- Support NZ-relevant price estimates through a separate pricing/lookup module rather than hardcoding.
```
