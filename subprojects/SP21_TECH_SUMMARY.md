# SP21 — TECH_SUMMARY

**Status:** 📋 Planned
**Phase:** 5 — Reporting
**Priority:** 21

## Goal

Generate a technician-focused summary of all findings: what was found, how
confident we are, what is unexplained, and recommended next steps.

## Audience

The technician running the scan — someone who understands Windows, malware, and
forensics but may not have time to read 200+ JSONL findings.

## Scope

1. **Input** — all `logs/findings_<ts>.jsonl` from SP17 MULTI_ENGINE (or
   individual module JSONL files if orchestration is not yet implemented).

2. **Executive stats:**
   - Modules run and any that failed
   - Total findings by risk level (CRITICAL/HIGH/MEDIUM/LOW)
   - Scan duration and timestamp
   - Machine identity (from SP02 if available)

3. **Top findings** — top 10 highest-scoring findings with a one-line
   description each.

4. **Unexplained items** — findings flagged HIGH/CRITICAL with no corroborating
   evidence from a second module (possible false positives to investigate).

5. **Noteworthy negatives** — modules that ran and found nothing (reassurance).

6. **Recommended next steps** — short bullet list keyed to risk level:
   - CRITICAL: "Confirm finding manually before any remediation"
   - HIGH: "Investigate these specific files/keys"
   - MEDIUM: "Note for follow-up"
   - LOW: "Probably benign; log for reference"

## Output

`logs/tech_summary_<ts>.txt` — plain text, 1–2 pages.

## Dependencies

- SP17 MULTI_ENGINE (preferred) or any module JSONL output
- SP02 DISK_OVERVIEW (for machine identity)

## Constraints

- Standard library only
- No jargon the technician won't understand

## Acceptance criteria

- [ ] Produces a < 2-page summary from 200+ findings in < 5 seconds
- [ ] Clearly distinguishes CRITICAL from LOW findings
- [ ] Lists recommended next steps without overclaiming
