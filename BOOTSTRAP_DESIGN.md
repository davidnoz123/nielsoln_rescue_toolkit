# Bootstrap Design

## Principle

Use shell only to find Python. Use Python for everything else.

## bootstrap.sh logic

```text
1. ROOT = directory containing bootstrap.sh
2. If python3 exists:
      exec python3 ROOT/toolkit/bootstrap.py "$@"
3. Else detect OS and architecture
4. Try matching bundled runtime
5. Else fail with clear message
```

## Commands

```bash
bash bootstrap.sh --help
bash bootstrap.sh triage --target /mnt/vista
bash bootstrap.sh scan --target /mnt/vista
bash bootstrap.sh detect
bash bootstrap.sh update
```

## Flags

```bash
--no-update
--offline
--verbose
```

## Exit codes

```text
0 success
1 general failure
2 invalid argument or missing target
3 external tool unavailable
4 suspicious/infected files found
```
