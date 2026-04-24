# Prompt to Give Claude in VS Code

You are working in VS Code. Please read all markdown files in this instruction pack before writing code.

Your task is to create a new project called:

```text
nielsoln-rescue-toolkit
```

The project is a USB-based rescue toolkit for scanning offline Windows installations from RescueZilla or another Linux live environment.

Please do the following:

1. Create the repository structure described in `REPO_LAYOUT.md`.
2. Implement the initial code from `INITIAL_CODE_SKETCHES.md`.
3. Add a `scripts/build_usb_package.py` script based on `BUILD_USB_PACKAGE_SKETCH.md`.
4. Add placeholder portable Python runtime directories with README files.
5. Add a basic pytest test for the triage path filtering.
6. Run tests.
7. Build the USB package.
8. Test:

```bash
bash dist/NIELSOLN_RESCUE_USB/bootstrap.sh --help
```

9. Create a GitHub repository using `gh`:

```bash
gh repo create nielsoln-rescue-toolkit --private --source=. --remote=origin --push
```

If `gh` is not authenticated, stop and tell me exactly what command I need to run.

Important safety constraints:

- Do not modify a real USB drive yet.
- Do not delete or quarantine files.
- Do not mount any Windows partition read-write.
- Version 1 is report-only.
