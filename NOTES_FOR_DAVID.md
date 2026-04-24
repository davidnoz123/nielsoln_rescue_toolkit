# Notes for David

## Recommended first Claude instruction

Open `CLAUDE_TASK_PROMPT.md` and paste it into Claude in VS Code.

## Suggested local folder

Extract this instruction pack somewhere like:

```text
C:\Users\david\projects\nielsoln-rescue-toolkit-instruction-pack
```

Then ask Claude to create the actual repo beside it.

## USB safety

Do not point Claude at the real USB drive initially.

Let it build:

```text
dist/NIELSOLN_RESCUE_USB
```

Then manually inspect before copying.

## GitHub visibility

The prompt uses `--private`.

You can change it later:

```bash
gh repo edit nielsoln-rescue-toolkit --visibility public
```

## First real field command in RescueZilla

After copying to USB and mounting the Vista disk:

```bash
bash /media/ubuntu/NIELSOLN_RESCUE_USB/bootstrap.sh detect
bash /media/ubuntu/NIELSOLN_RESCUE_USB/bootstrap.sh triage --target /mnt/vista
```
