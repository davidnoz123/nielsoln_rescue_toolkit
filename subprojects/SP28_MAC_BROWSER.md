# SP28 — MAC_BROWSER

**Status:** 📋 Planned (Phase 6 — macOS expansion)
**Phase:** 6 — OS expansion
**Priority:** 28

## Goal

Audit macOS browser profiles for suspicious extensions, homepage hijacks, and
download history artefacts.  Mirrors SP05 BROWSER_AUDIT for macOS paths.

## Scope

1. **Safari** — `~/Library/Safari/`:
   - `Bookmarks.plist` — suspicious bookmarks
   - `Extensions/` directory — installed extensions
   - `Downloads.plist` — download history
   - `History.db` (SQLite)

2. **Chrome / Chromium** — `~/Library/Application Support/Google/Chrome/Default/`:
   - `Preferences` (JSON) — extensions, startup pages, homepage
   - `Extensions/` directory listing

3. **Firefox** — `~/Library/Application Support/Firefox/Profiles/*/`:
   - `extensions.json`
   - `prefs.js`

4. **Arc, Brave, Edge** — check for their profile directories; scan
   `Preferences` JSON using the same Chromium logic.

## Notes

Much of the logic is shared with SP05 BROWSER_AUDIT (Windows).  Consider
extracting a shared `browser_common.py` utility rather than duplicating.

## Output

JSONL findings to `logs/mac_browser_<ts>.jsonl`

## Dependencies

- SP24 SCAN_PROFILE_OS (macOS profile active)
- Shared logic with SP05 BROWSER_AUDIT

## Constraints

- Standard library only (json, sqlite3 optional)
- Graceful fallback for binary plists and absent SQLite
