# RECENT_CHANGE_ANALYSIS

Implement recent change analysis.

Goal:
Identify what changed before the reported problem.

Correlate:
- installed software dates
- driver install dates
- Windows update events
- event log timeline
- file modification times
- prefetch/execution history
- service/task creation or modification

Output:
- timeline of recent changes
- likely relevant changes
- confidence and limitations

Output:
- `logs/recent_change_analysis_<timestamp>.json`
