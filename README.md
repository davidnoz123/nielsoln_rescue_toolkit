# Nielsoln Rescue Toolkit Instruction Pack

This pack is intended for Claude in VS Code.

Create a GitHub repository named:

```text
nielsoln-rescue-toolkit
```

Build a USB-ready rescue toolkit that can run from a Linux terminal in RescueZilla or a similar live Linux environment.

Version 1 should be conservative:

- read-only scanning
- report generation
- no deletion
- no automatic repair
- no quarantine unless explicitly enabled later

## Intended workflow

Claude should:

1. Read `AGENTS.md`
2. Follow `PROJECT_PLAN.md`
3. Create the local repository
4. Use `gh` to create the GitHub repo
5. Build the USB package into `dist/NIELSOLN_RESCUE_USB`
6. Test the bootstrap command locally
7. Only copy to the real USB drive when explicitly instructed

## First working target

```bash
bash bootstrap.sh triage --target /mnt/vista
```
