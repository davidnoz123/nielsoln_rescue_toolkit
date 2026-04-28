# NETWORK_ANALYSIS

Implement offline network and remote-access exposure analysis.

Collect:
- RDP enabled/disabled
- Remote Assistance indicators
- firewall profile state where available
- saved network profiles
- WiFi profile metadata where available
- proxy settings
- remote-related services
- network adapter configuration
- suspicious remote-access software indicators

Output:
- `logs/network_analysis_<timestamp>.json`

Include:
- exposure summary
- remote access status
- network profiles
- proxy settings
- recommendations
