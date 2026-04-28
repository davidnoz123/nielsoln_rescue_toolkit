# DRIVER_STORE_ANALYSIS

Implement DriverStore and installed driver package analysis.

Collect:
- driver packages in DriverStore/FileRepository
- INF files
- provider
- class
- version/date where available
- duplicate packages
- orphaned driver packages
- old drivers
- suspicious driver locations
- correlation to device_manager and service_analysis

Output:
- `logs/driver_store_analysis_<timestamp>.json`
