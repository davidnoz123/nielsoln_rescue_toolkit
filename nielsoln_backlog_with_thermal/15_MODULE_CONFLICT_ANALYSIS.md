# MODULE_CONFLICT_ANALYSIS

Implement cross-module contradiction/conflict analysis.

Examples:
- ClamAV clean but suspicious persistence exists
- service references missing binary but disk integrity is clean
- device manager says driver OK but service driver file missing
- system integrity flags a file that ClamAV did not scan
- logon audit clean but auditing is disabled/limited

Output:
- conflicts
- affected modules
- severity
- explanation
- recommended follow-up

Output:
- `logs/module_conflict_analysis_<timestamp>.json`
