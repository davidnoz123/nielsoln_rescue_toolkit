# EXECUTION_HISTORY

Implement offline application execution history analysis.

Collect:
- Windows Prefetch entries where available
- recent files / shortcuts where available
- RunMRU / typed paths where available
- last executed binaries
- execution timeline summary

Use cases:
- what ran recently?
- what changed before the problem?
- did a suspicious executable run?

Output:
- `logs/execution_history_<timestamp>.json`
