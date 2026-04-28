# TASK_SCHEDULER_ANALYSIS

Implement deeper scheduled task analysis beyond basic persistence scanning.

Collect:
- all scheduled tasks
- task path/name
- enabled/disabled state
- hidden flag
- triggers
- actions
- command and arguments
- run-as user
- working directory
- author/description
- last run result if available
- suspicious task flags

Flag:
- hidden tasks
- tasks running from AppData/Temp/Downloads/Public
- PowerShell/mshta/wscript/cscript/rundll32/regsvr32 usage
- encoded commands
- missing targets

Output:
- `logs/task_scheduler_analysis_<timestamp>.json`
