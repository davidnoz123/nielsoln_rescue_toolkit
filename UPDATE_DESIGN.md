# Self-Update Design

## Rule

Never update in-place blindly.

## Desired directories

```text
cache/repo_current/
cache/repo_next/
cache/repo_previous/
```

## Basic flow

```text
1. Check internet
2. Check whether git exists
3. If git exists:
      fetch remote
      compare current commit
   Else:
      download GitHub zip
4. Stage update into repo_next
5. Run smoke test:
      python toolkit/bootstrap.py --help
6. If smoke test passes:
      move current to previous
      move next to current
7. If anything fails:
      keep current
```

## v1 simplification

For the first version, update can simply print:

```text
Update feature not implemented yet.
```

but the file and command should exist.
