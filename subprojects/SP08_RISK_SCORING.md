# SP08 — RISK_SCORING (shared library)

**Status:** 📋 Planned
**Phase:** 2 — Engineering foundations
**Priority:** 8

## Goal

Extract the scoring and finding schema into a shared `core.py` module so all
scan modules use consistent score bands, risk labels, and JSONL output format.

## Why this ordering

ChatGPT placed this at #21.  That was wrong.  Once SP03–SP07 are being built
simultaneously, the risk of each module inventing its own score thresholds and
field names becomes real.  Implement the shared core while there are still only
2-3 modules, before the debt accumulates.

## Scope

1. **Finding dataclass / dict schema:**

   ```python
   {
     "ts":        "<ISO-8601>",       # when the finding was generated
     "module":    "PERSISTENCE_SCAN", # which module produced it
     "type":      "registry",         # finding sub-type
     "source":    "/mnt/windows/...", # path or hive key
     "target":    "...",              # command/value/path found
     "user":      "Garnet",           # associated user or null
     "score":     65,                 # 0–100
     "risk":      "MEDIUM",           # LOW / MEDIUM / HIGH / CRITICAL
     "reasons":   ["..."]             # list of human-readable strings
   }
   ```

2. **Score-to-risk mapping** (single source of truth):
   - 0–29 → LOW
   - 30–59 → MEDIUM
   - 60–84 → HIGH
   - 85–100 → CRITICAL

3. **`score_finding(base, adjustments)` function** — takes a list of
   `(delta, reason_string)` tuples, clamps to 0–100, returns score + reasons.

4. **`write_jsonl(path, finding)` function** — appends one finding as a JSON
   line; creates file and parent dirs if needed.

5. **`summarise_findings(findings)` function** — returns count by risk level,
   top-5 highest-scoring findings, and any CRITICAL findings.

## Refactoring required

`persistence_scan.py` contains its own inline scoring — refactor it to use
`core.py` after this module is implemented.  The JSONL schema is already close;
just needs field normalisation.

## Output

`core.py` in the repo root (alongside `persistence_scan.py`).  Not a scan
module — no JSONL output of its own.

## Dependencies

None.

## Acceptance criteria

- [ ] `persistence_scan.py` refactored to use `core.py` with no behaviour change
- [ ] Score bands documented and consistent across all modules
- [ ] `py_compile` passes
