# SP23 — ACTION_SUGGESTIONS

**Status:** 📋 Planned
**Phase:** 5 — Reporting
**Priority:** 23

## Goal

Recommend safe, appropriate follow-up actions based on the findings and
confidence level — for the technician, not the client.

## Scope

1. **Input** — SP21 TECH_SUMMARY + SP17 merged findings.

2. **Action categories** (ranked by severity):

   | Condition | Suggested action |
   |---|---|
   | ClamAV / known-bad hash match | Advise backup + clean reinstall; do not attempt selective removal |
   | CRITICAL finding (no AV confirm) | Manual verification of specific file before any action |
   | Multiple HIGH persistence entries | Enumerate all persistence and boot components before touching anything |
   | Suspicious browser extensions | Document, note for client; advise browser reset if reinstall not done |
   | HIGH-entropy packed executable in AppData | Hash and submit to VirusTotal when online; hold remediation |
   | Only LOW/MEDIUM findings | Note for file; advise client to monitor for symptoms |
   | Clean scan | Advise routine maintenance and backup |

3. **Safe action principles** — all suggested actions must be consistent with
   v1 constraints:
   - Never suggest deleting files
   - Never suggest modifying the registry
   - Prefer "investigate further", "backup first", "advise client"
   - Flag any action that would require v2 (write-access) capabilities

4. **Output format** — numbered action list with priority, rationale, and
   required access level (offline read-only / online / write-access v2).

## Output

`logs/action_suggestions_<ts>.txt`

## Dependencies

- SP21 TECH_SUMMARY
- SP18 BUNDLED_AV (to distinguish confirmed vs suspected findings)

## Constraints

- Standard library only
- Never suggest irreversible actions without explicit confirmation requirement
- All suggestions must be consistent with v1 (read-only) constraints

## Acceptance criteria

- [ ] Produces appropriate actions for a CRITICAL finding
- [ ] Produces appropriate actions for a fully clean scan
- [ ] Never suggests writing to the target volume in v1
