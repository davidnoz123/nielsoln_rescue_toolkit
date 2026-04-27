# SERVICE_ANALYSIS

```text
Implement a module called SERVICE_ANALYSIS for an offline Windows triage tool.

Goal:
Assess Windows services for performance, security, and cleanup relevance.

Scope:
- Enumerate services from offline configuration where possible.
- Report service name, display name, startup mode, executable path, account, and related DLL where available.
- Identify suspicious services, unnecessary auto-start services, obsolete vendor services, and services running from unusual locations.
- Separate malware-style findings from performance-cleanup recommendations.

Output:
- Structured service findings with severity, reasons, and recommendation.

Design expectations:
- Read-only.
- Designed to integrate with PERSISTENCE_SCAN, BLOAT_DETECTION, and SYSTEM_SUMMARY.
```
