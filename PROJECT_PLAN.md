# Project Plan

## Phase 0 — Repository creation

Create a local repo with this structure:

```text
nielsoln-rescue-toolkit/
  README.md
  AGENTS.md
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

Then create the GitHub repository using `gh`.

## Phase 1 — Local USB package build

Build this staged USB folder:

```text
dist/NIELSOLN_RESCUE_USB/
  bootstrap.sh
  toolkit/
  runtimes/
    linux-x86_64/
      python/
    macos-x86_64/
      python/
    macos-arm64/
      python/
  cache/
    downloads/
    wheels/
    repo/
  logs/
  reports/
  quarantine/
```

Initially, it is acceptable for the `runtimes/` directories to contain placeholder README files rather than full Python runtimes.

## Phase 2 — Minimal working command

Make this work:

```bash
bash bootstrap.sh triage --target /mnt/vista
```

It should produce:

```text
reports/triage_report.csv
logs/toolkit.log
```

## Phase 3 — ClamAV integration

Make this work if `clamscan` exists:

```bash
bash bootstrap.sh scan --target /mnt/vista
```

If `clamscan` is unavailable, print a useful message and still offer triage.

## Phase 4 — Self-update

Add update support:

```bash
bash bootstrap.sh update
bash bootstrap.sh --no-update scan --target /mnt/vista
```

Update must be staged, tested, and promoted only after validation.

## Phase 5 — Auto-detect Windows partitions

Add:

```bash
bash bootstrap.sh detect
```

This should list likely mounted Windows installations.

Do not auto-mount disks in v1 unless explicitly requested.
