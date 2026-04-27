# SP05 — BROWSER_AUDIT

**Status:** 📋 Planned
**Phase:** 1 — Core scanning
**Priority:** 5

## Goal

Inspect browser profiles for suspicious extensions, hijacked settings,
suspicious downloads history, and persistence-like artefacts.

## Why here in the ordering

Browser hijacking and adware are the most common infection vectors on old
Vista machines.  IE, Firefox, and early Chrome profiles are trivially readable
offline.  High client-visible impact — findings translate directly to symptoms
the user noticed (wrong homepage, extra toolbars, weird search engine).

## Scope

1. **Internet Explorer** (primary target for Vista):
   - `HKCU\Software\Microsoft\Internet Explorer\Main` — homepage, search
     provider; read from NTUSER.DAT hives
   - BHOs (Browser Helper Objects) — `HKLM\SOFTWARE\Microsoft\Windows\
     CurrentVersion\Explorer\Browser Helper Objects`
   - Toolbars and extensions in the registry
   - Typed URL history: `HKCU\Software\Microsoft\Internet Explorer\TypedURLs`

2. **Firefox** — `%APPDATA%\Mozilla\Firefox\Profiles\*`:
   - `extensions.json` — list of installed add-ons
   - `prefs.js` — homepage, startup URLs, proxy settings
   - `places.sqlite` — download history (limited parsing without `sqlite3`
     module; use line scanning on the raw file)

3. **Chrome / Chromium** — `%LOCALAPPDATA%\Google\Chrome\User Data\Default`:
   - `Preferences` (JSON) — extensions, homepage, startup pages
   - `Extensions\` directory listing — flag non-webstore IDs

4. **Common signals** across browsers:
   - Hijacked homepage or search engine
   - Extensions with no name or unknown IDs
   - Download of executable files to suspicious paths
   - Proxy settings overrides

## Notes

- `sqlite3` is part of the Python standard library but requires the SQLite
  shared library to be present on the rescue system.  Check availability at
  runtime and fall back to raw binary scanning if absent.

## Output

JSONL findings to `logs/browser_<ts>.jsonl`

## Dependencies

None required (sqlite3 optional, graceful fallback).

## Constraints

- Standard library only (sqlite3 if available)
- Read-only; never write to target volume

## Acceptance criteria

- [ ] Reads IE home page and BHOs from NTUSER.DAT without external tools
- [ ] Reports Firefox extensions from `extensions.json` if present
- [ ] Falls back cleanly if SQLite is unavailable
