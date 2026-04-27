# SP07 — WINDOWS_EVENT_LOGS

**Status:** 📋 Planned
**Phase:** 1 — Core scanning
**Priority:** 7

> **Not in ChatGPT's list.**  Added because Windows event logs are one of the
> most valuable forensic sources on Vista and were completely omitted.

## Goal

Parse offline Windows event logs to surface security-relevant events: failed
logins, new service installations, privilege escalation, account changes, and
suspicious process activity.

## Why this was missing

Event logs (`*.evtx`) are the closest thing to a security audit trail on Vista.
They can confirm that malware ran, show lateral movement attempts, and reveal
when a service was installed.  Vista introduced the new binary EVTX format.
A pure-Python EVTX parser is non-trivial but feasible.

## Scope

1. **Log files** — `C:\Windows\System32\winevt\Logs\*.evtx`

2. **Priority logs and event IDs:**

   | Log | Event ID | Description |
   |---|---|---|
   | Security | 4625 | Failed login |
   | Security | 4624 | Successful login |
   | Security | 4720 | New user account created |
   | Security | 4728/4732 | User added to admin group |
   | Security | 4698/4702 | Scheduled task created/modified |
   | System | 7045 | New service installed |
   | System | 7034/7035 | Service crashed / started |
   | Application | 1000/1001 | Application crash / hang |

3. **EVTX parsing** — the EVTX binary format uses a BinXML encoding.
   Implement a minimal parser for the record header and BinXML substitution
   table to extract the fields above without a full XML parser.
   If parsing fails for a record, skip and continue.

4. **Log rotation evidence** — note if logs appear to have been cleared
   (Security log empty despite the machine being old is suspicious).

## Risk scoring

| Signal | Score delta |
|---|---|
| Multiple failed logins (> 5) in same session | +30 |
| New admin-group addition | +40 |
| New service installed | +25 |
| Scheduled task created from non-system path | +35 |
| Security log appears cleared | +45 |
| Login from unusual hour (01:00–05:00 local) | +10 |

## Output

JSONL findings to `logs/evtlogs_<ts>.jsonl`

## Dependencies

None (standalone pure-Python EVTX parser).

## Constraints

- Standard library only (struct, io)
- Read-only; never write to target volume
- EVTX parser must fail gracefully on corrupt records

## Acceptance criteria

- [ ] Parses Vista EVTX format without external libraries
- [ ] Extracts at least event IDs 4625, 4624, 7045 from Security/System logs
- [ ] Reports cleared/empty Security log as a finding
- [ ] Handles corrupt records without crashing
