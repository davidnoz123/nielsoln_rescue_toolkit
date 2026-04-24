# Download Portable Python Runtimes

## Recommended source

Use `python-build-standalone` releases where practical.

## Priority order

1. Use system `python3` if available.
2. Use bundled portable Python if available.
3. Fail with a clear message.

## Runtime directories

```text
runtimes/linux-x86_64/python/
runtimes/macos-x86_64/python/
runtimes/macos-arm64/python/
```

## First version

For v1, it is acceptable to create placeholder runtime directories with README files, then add real downloads later.

## Later version

`scripts/download_portable_python.py` should:

1. Detect desired platform.
2. Download archive into `cache/downloads`.
3. Verify checksum if provided.
4. Extract into matching `runtimes/.../python`.
5. Make executables executable.
6. Run `python --version` to validate.
