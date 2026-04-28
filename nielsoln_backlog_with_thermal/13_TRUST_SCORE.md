# TRUST_SCORE

Implement a unified machine trust/risk score.

Combine:
- ClamAV result and confidence
- persistence findings
- service execution surface
- system integrity
- device/driver anomalies
- suspicious files
- event log security indicators
- module limitations

Output:
- overall trust score
- category scores
- top contributing risks
- confidence
- limitations
- recommended next actions

Output file:
- `logs/trust_score_<timestamp>.json`
