# USER_ACCOUNT_ANALYSIS

Implement extraction of local Windows users, groups, account status, profile mappings, and password/account metadata from an offline Windows installation.

Context:
- Runs from RescueZilla/Linux.
- Reads offline registry hives and Windows profile directories.
- Read-only only.

Collect:
- local user accounts
- disabled/enabled status
- admin vs standard users
- group membership
- profile path
- last logon where available
- password last set / expiry indicators where available
- blank password indicators if safely inferable
- stale accounts
- suspicious or unexpected accounts

Output:
- `logs/user_account_analysis_<timestamp>.json`

Include:
- summary
- accounts
- groups
- flagged accounts
- limitations
