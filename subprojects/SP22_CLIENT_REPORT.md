# SP22 — CLIENT_REPORT

**Status:** 📋 Planned
**Phase:** 5 — Reporting
**Priority:** 22

## Goal

Generate a plain-English report for the client (machine owner) that explains
what was found without overclaiming certainty or using technical jargon.

## Audience

A non-technical client — someone who uses their laptop for email and browsing
and wants to know "is my computer safe?"

## Principles

- Never say "infected" — say "suspicious activity was found" or "some files
  need further investigation"
- Never claim certainty about malware unless ClamAV (SP18) or a known-bad hash
  (SP09) found a confirmed match
- Always explain what each finding *could* mean, not what it *definitely* means
- Keep it under one page
- Include a "what happens next" section

## Scope

1. **Input** — tech summary from SP21.
2. **Report sections:**
   - What we scanned (machine name, date, scan duration)
   - Summary verdict (Clean / Some concerns / Suspicious activity found /
     Confirmed threat — based on highest risk level found)
   - What we found (plain English, grouped by category — not by module)
   - What this might mean
   - What we recommend (general: backup, Windows reinstall, monitor for
     symptoms — never specific file operations)
   - What we did not check (honestly list limitations)

3. **Calibrated language:** map risk levels to plain-English descriptions:
   - CRITICAL → "A file was found that matches known malware"
   - HIGH → "Some unusual activity was found that is worth investigating"
   - MEDIUM → "Some items were found that are worth noting"
   - LOW → "A few minor items were found that are probably not a concern"
   - CLEAN → "No suspicious activity was found in the areas we checked"

## Output

`logs/client_report_<ts>.txt` — plain text, 1 page max.

## Dependencies

- SP21 TECH_SUMMARY

## Constraints

- No technical jargon
- Never recommend deleting specific files (report-only tool)

## Acceptance criteria

- [ ] A non-technical reader understands the verdict without help
- [ ] Does not use words like "heuristic", "entropy", "JSONL", "LOLBin"
- [ ] Clearly states what was NOT checked
