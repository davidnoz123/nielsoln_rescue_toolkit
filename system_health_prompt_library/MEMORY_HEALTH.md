# MEMORY_HEALTH

```text
Implement a module called MEMORY_HEALTH for a system triage tool.

Goal:
Assess installed RAM health, adequacy, and upgrade potential.

Scope:
- Report installed RAM, usable RAM, memory type/speed where available, slot population where available.
- Detect low RAM for modern usage.
- Flag mismatched memory configurations if detectable.
- Support recommendations such as upgrade to 8GB/16GB/32GB depending on machine age and use case.
- Optionally integrate with memory test results if available.

Output:
- Structured findings and practical upgrade recommendation.

Design expectations:
- Distinguish known facts from unknown slot/capacity limits.
- Avoid overclaiming maximum supported RAM unless confidently detected.
```
