# SP17 — MULTI_ENGINE (scan orchestration)

**Status:** 📋 Planned
**Phase:** 4 — Orchestration
**Priority:** 17

## Goal

Coordinate all scan modules and merge their findings into a single consolidated
report with deduplication, cross-module correlation, and a unified risk summary.

## Why not #5 (ChatGPT's rank)

An orchestration layer is only useful when there are multiple modules to
orchestrate.  Building it at #5, before most modules exist, means maintaining
it as a stub that does nothing.  Build it after Phase 1–2 modules are ready.

## Scope

1. **Module registry** — a manifest of available scan modules and their output
   log paths.  Each module registers via a simple convention: the module exposes
   a `run(root, log_dir)` function and a `MODULE_NAME` constant.

2. **Sequential execution** — run all enabled modules in dependency order.
   (PARALLEL_SCAN is demoted — see SP_PARALLEL_SCAN note.)

3. **Finding aggregation** — read all `logs/*_<ts>.jsonl` files from the
   current scan run and merge into a single `logs/findings_<ts>.jsonl`.

4. **Cross-module correlation:**
   - File appears in SP01 (persistence) AND SP03 (suspicious path) AND SP09
     (hash matches known-bad) → CRITICAL escalation
   - LOLBin execution in SP06 AND SP04 Prefetch execution AND SP07 event log
     entry → HIGH escalation
   - Apply a correlation bonus: `+15` per additional corroborating module

5. **Deduplication** — findings with the same `source` path and `type` from
   different modules are merged (keep the highest score, combine reasons).

6. **Summary stats** — total findings by risk level, top-10 findings, number
   of modules run, scan duration.

## Output

`logs/findings_<ts>.jsonl` — merged, deduplicated, correlated findings
`logs/scan_summary_<ts>.json` — summary stats

## Dependencies

- All Phase 1–2 modules
- SP08 RISK_SCORING / core.py (for consistent schema)

## Constraints

- Standard library only
- Must work with any subset of modules available

## Acceptance criteria

- [ ] Merges findings from at least 3 modules into one file
- [ ] Applies cross-module correlation bonus correctly
- [ ] Runs modules in dependency order without circular loops
