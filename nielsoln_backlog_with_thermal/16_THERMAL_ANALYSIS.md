# THERMAL_ANALYSIS

Implement first-class thermal analysis for the Nielsoln Rescue Toolkit.

## Context

- The toolkit runs from RescueZilla/Linux on a customer laptop.
- The target Windows installation is offline.
- Thermal analysis is different from most other modules because it measures live hardware behaviour from the rescue environment.
- Results are indicative, not definitive, because OEM Windows thermal drivers/software may not be running.
- The goal is to detect cooling problems, throttling, dust/fan issues, and thermal behaviour that may explain slowness or instability.

## Goal

Create a thermal diagnostic module that answers:

- Is the machine hot at idle?
- Are thermal sensors available?
- Is the fan visible and responding?
- Does the CPU heat up too quickly under light load?
- Does the CPU throttle under load?
- Does temperature recover after load is removed?
- Should the machine be cleaned, serviced, or have thermal paste replaced?

## Module name

Use:

```text
THERMAL_ANALYSIS
```

Suggested output:

```text
logs/thermal_analysis_<timestamp>.json
```

It may also replace or extend the existing `thermal_health` module, but preserve backward compatibility if that module already exists.

---

## 1. Passive thermal snapshot

Collect live sensor data without applying load.

Collect where available:

- CPU temperature
- GPU temperature
- disk temperature if exposed
- ACPI thermal zones
- hwmon sensor readings
- fan RPM
- fan sensor availability
- CPU current frequency
- CPU max frequency
- CPU governor/scaling mode
- CPU throttling indicators where available

Record:

- sensors available: yes/no
- missing sensor limitations
- idle temperature readings
- hottest observed component
- fan readings
- CPU frequency state

Flag:

- high idle temperature
- missing fan data
- missing thermal sensors
- CPU already frequency-limited at idle
- suspiciously hot disk if available

---

## 2. Short thermal response test

Perform a short, safe CPU load test.

This is not a long stress test.

Suggested behaviour:

- measure idle baseline first
- apply moderate CPU load for a short period
- monitor temperature repeatedly during load
- monitor CPU frequency during load
- stop immediately if temperature exceeds a safe threshold
- monitor cooldown/recovery after load is removed

Collect:

- test duration requested
- test duration completed
- idle temperature
- peak temperature
- temperature rise
- time to peak
- recovery temperature
- recovery time
- CPU frequency before/during/after
- throttling detected yes/no
- emergency stop yes/no
- reason for early stop

Important:
- Do not run an aggressive or long stress test on old hardware.
- The default should be conservative.
- The test should be skippable.
- If no sensors are available, do not run the load test unless explicitly configured.

---

## 3. Thermal behaviour interpretation

Classify cooling response.

Suggested verdicts:

```text
GOOD
FAIR
POOR
CRITICAL
UNKNOWN
SKIPPED
```

Consider:

- idle temperature
- peak temperature
- speed of temperature rise
- recovery speed
- CPU throttling
- fan response
- sensor availability
- test completeness

Examples:

- GOOD: moderate idle temp, safe peak, quick recovery, no throttling
- FAIR: warm but controlled, no emergency condition
- POOR: rapid heat rise, high peak, slow recovery, throttling
- CRITICAL: unsafe peak, emergency stop, severe throttling
- UNKNOWN: insufficient sensor data
- SKIPPED: test not run

---

## 4. Correlation with other modules

Correlate thermal analysis with:

- hardware_profile
- disk_health
- storage_usage
- performance_diagnosis
- event_archive
- system_summary

Look for:

- CPU throttling explaining poor performance
- unexpected shutdown events that may be heat-related
- disk temperature concerns
- old laptop age increasing likelihood of dust/thermal paste degradation
- fan data unavailable but thermal zones hot

---

## 5. Customer-facing recommendations

Generate practical recommendations such as:

- clean vents and fan
- inspect fan operation
- replace thermal paste
- avoid heavy workloads until serviced
- use on a hard flat surface
- consider replacement if thermal behaviour remains poor after cleaning

Recommendations should include:

- priority
- reason
- confidence
- estimated benefit

---

## 6. Safety requirements

- Read-only with respect to disks and system configuration.
- Conservative CPU load only.
- Short default duration.
- Hard stop on high temperature.
- Do not run load test if no temperature sensor is available unless explicitly configured.
- Clearly label results as rescue-environment indicative, not OEM-certified.
- Handle missing sensors gracefully.
- Do not crash if thermal sysfs/hwmon paths are absent.

---

## 7. Output structure

Include:

- timestamp
- target
- scan_status
- passive_snapshot
- sensors
- fans
- cpu_frequency
- thermal_zones
- response_test
- verdict
- confidence
- warnings
- recommendations
- limitations
- correlation_refs

Suggested high-level shape:

```json
{
  "timestamp": "...",
  "target": "...",
  "scan_status": "ok|partial|skipped|error",
  "passive_snapshot": {
    "sensors_available": true,
    "idle_temp_c": 55,
    "hottest_component": "CPU",
    "fan_data_available": false
  },
  "response_test": {
    "enabled": true,
    "completed": true,
    "duration_seconds": 20,
    "idle_temp_c": 55,
    "peak_temp_c": 88,
    "recovery_temp_c": 63,
    "temperature_rise_c": 33,
    "throttling_detected": true,
    "emergency_stop": false
  },
  "verdict": "POOR",
  "confidence": "medium",
  "warnings": [
    "CPU temperature rose rapidly under short load",
    "CPU throttling detected"
  ],
  "recommendations": [
    "Clean vents and fan",
    "Replace thermal paste if overheating continues"
  ],
  "limitations": [
    "Measured from RescueZilla/Linux, not the installed Windows environment",
    "Fan sensor not exposed"
  ]
}
```

---

## 8. Schema and integration

Deliver:

- `thermal_analysis.schema.json`
- update schema index
- update system summary integration
- update customer report generation
- add explanation hooks for:
  - high idle temperature
  - throttling
  - poor cooling response
  - missing sensor data
  - rescue-environment limitation

---

## 9. Tests / fixtures

Include tests or sample fixtures for:

- no sensors available
- normal idle temperature
- high idle temperature
- successful response test
- throttling detected
- emergency stop condition
- fan data unavailable
- partial scan
- skipped load test

## Deliverable

A robust thermal analysis module that gives practical, safe, customer-useful insight into whether the laptop’s cooling system is healthy and whether overheating may be contributing to slowness or instability.
