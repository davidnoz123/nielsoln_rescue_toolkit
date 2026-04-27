# OFFICE_MIGRATION

```text
Implement a module called OFFICE_MIGRATION for a system triage and client advisory report.

Goal:
Assess current Microsoft Office/office-suite situation and recommend migration options.

Scope:
- Detect installed Office versions and common alternatives where possible.
- Identify unsupported or legacy Office versions.
- Report likely risks: compatibility, security updates, activation/licensing uncertainty.
- Recommend options: keep current, upgrade perpetual Office, migrate to Microsoft 365, use free alternatives.
- Support web-based pricing lookup as a separate step so current NZ pricing can be added to the report.

Output:
- Structured assessment and plain-English recommendation.
- Include assumptions and confidence.

Design expectations:
- Do not hardcode stale pricing.
- Design so current pricing can be injected from ONLINE_LOOKUPS.
```
