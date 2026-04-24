# build_usb_package.py Sketch

Claude should create `scripts/build_usb_package.py`.

Required behavior:

```text
1. Remove old dist/NIELSOLN_RESCUE_USB if it exists.
2. Create fresh dist/NIELSOLN_RESCUE_USB.
3. Copy bootstrap.sh.
4. Copy toolkit/.
5. Create cache/, logs/, reports/, quarantine/.
6. Create runtime placeholder directories.
7. chmod bootstrap.sh executable on Unix-like systems.
```

Sketch:

```python
from pathlib import Path
import shutil
import os

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "NIELSOLN_RESCUE_USB"

def main():
    if DIST.exists():
        shutil.rmtree(DIST)

    DIST.mkdir(parents=True)
    shutil.copy2(ROOT / "bootstrap.sh", DIST / "bootstrap.sh")
    shutil.copytree(ROOT / "toolkit", DIST / "toolkit")

    for name in ["cache/downloads", "cache/wheels", "cache/repo", "logs", "reports", "quarantine"]:
        (DIST / name).mkdir(parents=True, exist_ok=True)

    for runtime in ["linux-x86_64", "macos-x86_64", "macos-arm64"]:
        path = DIST / "runtimes" / runtime
        path.mkdir(parents=True, exist_ok=True)
        (path / "README.txt").write_text("Portable Python runtime goes here.\n", encoding="utf-8")

    try:
        os.chmod(DIST / "bootstrap.sh", 0o755)
    except Exception:
        pass

    print("Built", DIST)

if __name__ == "__main__":
    main()
```
