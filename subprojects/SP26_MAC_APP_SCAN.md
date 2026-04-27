# SP26 — MAC_APP_SCAN

**Status:** 📋 Planned (Phase 6 — macOS expansion)
**Phase:** 6 — OS expansion
**Priority:** 26

## Goal

Identify suspicious macOS applications, packages, disk images, scripts, and
binaries on an offline macOS installation.

## Scope

1. **Installed applications** — `/Applications/`, `~/Applications/`:
   - Parse `Info.plist` for bundle identifier, version, and executable path
   - Flag bundles with no Apple/known-vendor code signature markers
   - Flag recently added apps (mtime within 90 days)

2. **Suspicious file types:**
   - `.pkg` installer packages outside App Store patterns
   - `.dmg` disk images in unusual locations
   - `.command`, `.sh`, `.py` files in `~/Desktop`, `~/Downloads`, `~/Library`
   - Universal binaries or arm64 binaries with no bundle context

3. **Known bad indicators:**
   - Apps in `~/Library/Application Support/` masquerading as system services
   - Apps with generic names (System Preferences Helper, Update Assistant)

4. **Crontab** — `crontab -l` equivalent: read `var/at/jobs/` and
   `/usr/lib/cron/tabs/` for scheduled commands

## Output

JSONL findings to `logs/mac_app_scan_<ts>.jsonl`

## Dependencies

- SP24 SCAN_PROFILE_OS (macOS profile active)

## Constraints

- Standard library only
- Graceful fallback for binary plists
