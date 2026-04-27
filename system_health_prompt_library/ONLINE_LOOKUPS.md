# ONLINE_LOOKUPS

```text
Implement a module called ONLINE_LOOKUPS for a system triage/advisory workflow.

Goal:
Fetch current internet-based reference information needed for recommendations.

Scope:
- Look up current NZ-relevant pricing and availability for RAM, SSDs, laptop batteries, Microsoft 365/Office plans, and replacement machines when requested.
- Keep lookup results separate from offline scan data.
- Record source, date/time, price, vendor, and assumptions.
- Support manual override/cached results for offline use.

Output:
- Structured pricing/reference data that other modules can cite.

Design expectations:
- Do not scrape aggressively.
- Clearly separate current web findings from tool-generated hardware analysis.
- Make stale cached pricing obvious.
```
