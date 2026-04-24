# USB Package Specification

## USB folder name

```text
NIELSOLN_RESCUE_USB
```

## Top-level layout

```text
NIELSOLN_RESCUE_USB/
  bootstrap.sh
  toolkit/
  runtimes/
  cache/
  logs/
  reports/
  quarantine/
```

## bootstrap.sh

Responsibilities:

1. Find its own directory.
2. Prefer system `python3`.
3. Fall back to bundled Python runtime if available.
4. Execute `toolkit/bootstrap.py`.

It should not contain business logic.

## runtimes/

Portable Python runtimes may be placed here:

```text
runtimes/linux-x86_64/python/
runtimes/macos-x86_64/python/
runtimes/macos-arm64/python/
```

## cache/

Used for downloaded assets, GitHub ZIP fallbacks, package wheels, and version records.

## logs/

All command logs go here.

## reports/

CSV and HTML reports go here.

## quarantine/

Reserved for future use. Do not use by default in v1.
