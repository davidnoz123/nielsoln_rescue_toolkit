# Initial Code Sketches

These are starter sketches. Claude should turn them into real files.

## bootstrap.sh

```bash
#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    exec python3 "$ROOT/toolkit/bootstrap.py" "$@"
fi

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" = "Linux" ] && [ "$ARCH" = "x86_64" ]; then
    PY="$ROOT/runtimes/linux-x86_64/python/bin/python3"
    if [ -x "$PY" ]; then
        exec "$PY" "$ROOT/toolkit/bootstrap.py" "$@"
    fi
fi

echo "No compatible Python found."
exit 1
```

## toolkit/bootstrap.py

```python
import argparse
import sys
from pathlib import Path

def find_usb_root():
    return Path(__file__).resolve().parents[1]

def ensure_dirs(root):
    for name in ["logs", "reports", "cache", "quarantine"]:
        (root / name).mkdir(exist_ok=True)

def main():
    root = find_usb_root()
    ensure_dirs(root)

    parser = argparse.ArgumentParser(description="Nielsoln Rescue Toolkit")
    parser.add_argument("--no-update", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--verbose", action="store_true")

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan")
    scan.add_argument("--target", required=True)

    triage = sub.add_parser("triage")
    triage.add_argument("--target", required=True)

    sub.add_parser("detect")
    sub.add_parser("update")

    args = parser.parse_args()

    if args.command == "scan":
        from toolkit.scan import run_scan
        return run_scan(root, Path(args.target))

    if args.command == "triage":
        from toolkit.triage import run_triage
        return run_triage(root, Path(args.target))

    if args.command == "detect":
        from toolkit.mount_detect import run_detect
        return run_detect(root)

    if args.command == "update":
        from toolkit.updater import run_update
        return run_update(root)

    parser.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

## toolkit/scan.py

```python
import shutil
import subprocess

def run_scan(root, target):
    if not target.exists():
        print("Target does not exist:", target)
        return 2

    clamscan = shutil.which("clamscan")
    if clamscan is None:
        print("clamscan not found. Install ClamAV or run triage only.")
        return 3

    log_path = root / "logs" / "clamav_scan.log"

    cmd = [
        clamscan,
        "-r",
        str(target),
        "-i",
        "--log=" + str(log_path),
    ]

    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd)
    print("ClamAV log:", log_path)
    return result.returncode
```

## toolkit/triage.py

```python
import csv
import hashlib
import os
import time
from pathlib import Path

SUSPICIOUS_EXTS = {
    ".exe", ".dll", ".sys", ".scr",
    ".bat", ".cmd", ".vbs", ".js", ".ps1",
}

SUSPICIOUS_PATH_HINTS = [
    "/appdata/roaming/",
    "/appdata/local/temp/",
    "/temp/",
    "/startup/",
]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def interesting(path):
    text = str(path).replace("\\", "/").lower()
    if Path(path).suffix.lower() in SUSPICIOUS_EXTS:
        return True
    return any(hint in text for hint in SUSPICIOUS_PATH_HINTS)

def run_triage(root, target):
    if not target.exists():
        print("Target does not exist:", target)
        return 2

    report_path = root / "reports" / "triage_report.csv"

    with report_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "size", "modified_time", "sha256", "reason", "error"])

        for dirpath, dirnames, filenames in os.walk(str(target)):
            for name in filenames:
                path = Path(dirpath) / name
                if not interesting(path):
                    continue

                try:
                    st = path.stat()
                    mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
                    writer.writerow([
                        str(path),
                        st.st_size,
                        mtime,
                        sha256_file(path),
                        "interesting extension/path",
                        "",
                    ])
                except Exception as e:
                    writer.writerow([str(path), "", "", "", "", str(e)])

    print("Triage report:", report_path)
    return 0
```

## toolkit/mount_detect.py

```python
from pathlib import Path

def run_detect(root):
    candidates = []

    for base in [Path("/mnt"), Path("/media")]:
        if not base.exists():
            continue

        for path in base.rglob("Windows/System32"):
            candidates.append(path.parents[1])

    if not candidates:
        print("No likely Windows installations found under /mnt or /media.")
        return 1

    print("Likely Windows installations:")
    for item in candidates:
        print("  " + str(item))

    return 0
```
