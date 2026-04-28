# WINDOWS_UPDATE_ANALYSIS

Implement offline Windows Update and patch-state analysis.

Collect:
- installed updates / hotfixes
- failed update indicators
- pending updates
- pending reboot/update state
- Windows Update log indicators
- servicing package metadata where available
- OS support status if known locally or via external report layer

Output:
- `logs/windows_update_analysis_<timestamp>.json`
