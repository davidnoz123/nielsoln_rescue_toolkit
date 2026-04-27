# SP25 — MAC_LAUNCH_AGENTS

**Status:** 📋 Planned (Phase 6 — macOS expansion)
**Phase:** 6 — OS expansion
**Priority:** 25

## Goal

Detect macOS LaunchAgents and LaunchDaemons used for persistence, scanning an
offline macOS installation mounted under a Linux environment.

## Scope

1. **LaunchAgents locations:**
   - `/Library/LaunchAgents/`
   - `/Library/LaunchDaemons/`
   - `~/Library/LaunchAgents/` (per-user)

2. **Parsing** — `.plist` files (XML format for older macOS; binary format for
   newer).  Parse XML plists with `xml.etree.ElementTree` (stdlib).  For binary
   plists, implement a minimal parser or skip with a warning.

3. **Key fields to extract:**
   - `Label` — unique identifier
   - `ProgramArguments` — command and arguments
   - `RunAtLoad`, `KeepAlive`, `StartInterval`
   - `WorkingDirectory`, `EnvironmentVariables`

4. **Risk signals:**
   - `RunAtLoad=true` with unusual `ProgramArguments`
   - Commands in `~/Library/`, `/tmp/`, or unusual paths
   - Shell scripts as the program
   - Unknown vendor labels (not Apple, not a known app)

## Risk scoring

| Signal | Score delta |
|---|---|
| RunAtLoad command from tmp/home Library | +40 |
| Shell script as LaunchAgent program | +25 |
| Unknown label format | +15 |
| Apple system label (com.apple.*) | −20 |

## Dependency

- SP24 SCAN_PROFILE_OS (macOS profile active)

## Output

JSONL findings to `logs/mac_launch_agents_<ts>.jsonl`

## Constraints

- Standard library only (xml.etree.ElementTree for XML plists)
- Graceful fallback for binary plists
