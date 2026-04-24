# Test Plan

## Local tests

From the repository root:

```bash
python -m pytest
```

## Build USB package

```bash
python scripts/build_usb_package.py
```

Expected output:

```text
dist/NIELSOLN_RESCUE_USB
```

## Test help

```bash
bash dist/NIELSOLN_RESCUE_USB/bootstrap.sh --help
```

## Test triage against fake Windows folder

Create fake target:

```bash
mkdir -p /tmp/fake_vista/Users/Test/AppData/Roaming
echo test > /tmp/fake_vista/Users/Test/AppData/Roaming/suspicious.exe
```

Run:

```bash
bash dist/NIELSOLN_RESCUE_USB/bootstrap.sh triage --target /tmp/fake_vista
```

Expected:

```text
dist/NIELSOLN_RESCUE_USB/reports/triage_report.csv
```

## Test ClamAV missing behavior

If `clamscan` is not installed:

```bash
bash dist/NIELSOLN_RESCUE_USB/bootstrap.sh scan --target /tmp/fake_vista
```

Expected: a clean message saying `clamscan not found`.
