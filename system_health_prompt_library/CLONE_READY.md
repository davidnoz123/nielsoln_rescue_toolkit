# CLONE_READY

```text
Implement a module called CLONE_READY for a RescueZilla-based triage tool.

Goal:
Assess whether the current disk is suitable for cloning and what cloning strategy should be used.

Scope:
- Use disk health, partition layout, filesystem detectability, used space, and target disk size if known.
- Detect high-risk situations: failing source disk, unreadable partitions, encrypted volumes, suspicious SMART data.
- Recommend full disk clone, partition clone, image backup, file-level recovery, or clone ASAP.
- Identify whether SSD upgrade cloning is practical.

Output:
- Clear clone readiness status: ready, caution, urgent, blocked, unknown.
- Recommendations and risks.

Design expectations:
- Read-only assessment only.
- Do not initiate cloning; produce instructions/recommendations for the operator.
```
