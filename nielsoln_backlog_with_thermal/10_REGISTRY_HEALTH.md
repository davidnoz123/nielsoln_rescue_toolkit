# REGISTRY_HEALTH

Implement registry health and anomaly analysis.

Collect:
- hive availability
- hive parse errors
- suspicious malformed keys/values
- orphaned service/driver references
- autorun registry anomalies not already covered
- pending rename/update markers where relevant

Output:
- `logs/registry_health_<timestamp>.json`
