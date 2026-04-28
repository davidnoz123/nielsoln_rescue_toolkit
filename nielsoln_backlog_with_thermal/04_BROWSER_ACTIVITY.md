# BROWSER_ACTIVITY

Implement offline browser activity and browser-risk analysis.

Collect where available:
- browser profiles
- installed extensions
- download history
- recent history summary
- suspicious extension indicators
- obsolete browser versions
- saved credential indicators without extracting secrets

Browsers:
- Chrome
- Edge
- Firefox
- Internet Explorer where relevant for Vista/old Windows

Output:
- `logs/browser_activity_<timestamp>.json`

Safety:
- Do not extract or expose passwords.
- Treat browsing history as customer-sensitive.
