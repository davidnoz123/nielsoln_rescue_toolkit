# SYSTEM_LIFESPAN

```text
Implement a module called SYSTEM_LIFESPAN for a hardware/software triage tool.

Goal:
Estimate whether the computer is worth repairing/upgrading and how long it is likely to remain useful.

Scope:
- Use hardware age, CPU class, RAM, storage type, disk health, battery health, OS support status, and user workload assumptions.
- Produce verdicts such as: good as-is, upgrade recommended, repair only if cheap, replace recommended.
- Estimate lifespan after recommended upgrades.

Output:
- Plain-English recommendation with confidence and supporting evidence.
- Prioritised options: do nothing, low-cost tune-up, SSD/RAM upgrade, replace.

Design expectations:
- Be conservative and transparent.
- Avoid pretending exact future lifespan is known.
```
