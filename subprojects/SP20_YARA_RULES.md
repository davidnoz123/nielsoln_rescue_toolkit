# SP20 — YARA_RULES

**Status:** ⚠️ Flagged — dependency conflict with standard-library constraint
**Phase:** 4 — Orchestration
**Priority:** 20

## Goal

Add YARA-based rule scanning to detect known malware patterns and suspicious
content using community and custom rules.

## Constraint flag

Full YARA requires the `yara-python` binding, which is **not** in the standard
library.  Two options:

### Option A — Bundled static `yara` binary (recommended)
Bundle a static `yara` CLI binary in `_tools/yara/` on the USB.  Download via
`toolkit.py download_yara()` during `bootstrap update`.  Run via `subprocess`
from Python.  The binary must be:
- Statically compiled for `x86_64-linux`
- Compatible with RescueZilla (Ubuntu 24.10)
- Sourced from the official VirusTotal/YARA GitHub releases

**Stable URL:** `https://github.com/VirusTotal/yara/releases/latest`

### Option B — Pure-Python pseudo-YARA (fallback)
Implement a minimal subset of YARA matching (string search, regex, byte
patterns) in pure Python.  Accept a simplified rule format and run offline.
Lower detection coverage but no binary dependency.

**Recommendation:** implement Option B as the fallback, and support Option A
when the binary is available.

## Scope

1. **Rule library** — bundled `rules/` directory on the USB with:
   - A curated subset of community rules from YARA-Rules project (Windows PE,
     common malware families, LOLBins)
   - Custom rules for Vista-era malware (Conficker, Sality, ZeroAccess etc.)
   - Rules are text files — can be updated without a binary update

2. **Scan targets** — all `.exe`, `.dll`, `.sys`, `.scr` in suspect paths
   (from SP03/SP09), not the full partition.

3. **Output** — one finding per rule match, including rule name, matched file,
   and matched strings.

## Output

JSONL findings to `logs/yara_<ts>.jsonl`

## Dependencies

- `_tools/yara/` static binary (optional; falls back to pure-Python)
- SP03 SUSPICIOUS_PATHS or SP09 HASH_TRACKING to scope file list

## Acceptance criteria

- [ ] Runs pure-Python fallback without any external binary
- [ ] Detects a test string match using the fallback engine
- [ ] Emits informational finding explaining coverage limitations when in
     fallback mode
