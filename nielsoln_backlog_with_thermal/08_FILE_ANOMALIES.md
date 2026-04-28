# FILE_ANOMALIES

Implement suspicious file anomaly detection.

Detect:
- executables/scripts in user-writable locations
- duplicate system binaries in unusual places
- double extensions
- misleading filenames
- random-looking names
- recently modified executables
- hidden/system attribute abuse where detectable
- unusual executable files without extensions

Output:
- `logs/file_anomalies_<timestamp>.json`
