# BLOAT_DETECTION

```text
Implement a module called BLOAT_DETECTION for a Windows triage and cleanup advisor.

Goal:
Identify likely unnecessary, obsolete, duplicated, or performance-draining software.

Scope:
- Use software inventory, usage analysis, startup/persistence findings, services, and known vendor/OEM patterns.
- Flag trialware, toolbars, redundant updaters, obsolete runtimes, abandoned utilities, duplicate browsers/security tools, and OEM bundles.
- Distinguish safe cleanup candidates from software that requires human review.

Output:
- Prioritised cleanup candidates with confidence, rationale, and caution notes.
- Do not uninstall anything; report only.

Design expectations:
- Conservative recommendations.
- Explain why something is likely bloat.
- Allow allowlists/denylists to be maintained separately.
```
