# Repository Layout

Create this repository:

```text
nielsoln-rescue-toolkit/
  README.md
  AGENTS.md
  LICENSE
  .gitignore
  bootstrap.sh
  toolkit/
    __init__.py
    bootstrap.py
    env.py
    updater.py
    scan.py
    triage.py
    report.py
    mount_detect.py
    config.json
  scripts/
    build_usb_package.py
    download_portable_python.py
  tests/
    test_triage.py
```

## File responsibilities

- `bootstrap.sh`: tiny launcher only
- `toolkit/bootstrap.py`: CLI entrypoint
- `toolkit/env.py`: platform detection and path handling
- `toolkit/updater.py`: staged update logic
- `toolkit/scan.py`: ClamAV orchestration
- `toolkit/triage.py`: Python-only suspicious file triage
- `toolkit/report.py`: CSV/HTML report generation
- `toolkit/mount_detect.py`: detect likely Windows installations
- `scripts/build_usb_package.py`: builds `dist/NIELSOLN_RESCUE_USB`
- `scripts/download_portable_python.py`: downloads portable Python runtimes
