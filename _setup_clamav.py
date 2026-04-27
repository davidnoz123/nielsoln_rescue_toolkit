"""
Setup and update ClamAV: download .deb, install it, then run freshclam
to fetch the latest definitions.

Run via: devtools.py action = "run_remote", remote_script = "_setup_clamav.py"
"""
import sys
import time
from pathlib import Path

# bootstrap.py sets cwd to the USB root before exec'ing us
root = Path.cwd()
sys.path.insert(0, str(root))

from toolkit import download_clamav, run_install_clamav, run_clamav_update_db


def _phase(n, total, label):
    print(f"\n[{n}/{total}] {label} ...", flush=True)
    return time.monotonic()


def _done(t0):
    elapsed = time.monotonic() - t0
    print(f"      done ({elapsed:.0f}s)", flush=True)


print("=" * 60)
print("ClamAV Setup & Definition Update")
print(f"USB root: {root}")
print("=" * 60)

# Step 1: Download .deb
t = _phase(1, 3, "Downloading ClamAV .deb (skip if already cached)")
try:
    deb_path = download_clamav(root, verbosity=2)
    print(f"      OK: {deb_path.name}", flush=True)
    _done(t)
except RuntimeError as exc:
    print(f"      FAILED: {exc}", flush=True)
    sys.exit(1)

# Step 2: Install (extract .deb)
t = _phase(2, 3, "Installing ClamAV (extract .deb to USB)")
rc = run_install_clamav(root, verbosity=2)
if rc != 0:
    print("      FAILED", flush=True)
    sys.exit(rc)
_done(t)

# Step 3: Update virus definitions via freshclam
t = _phase(3, 3, "Downloading latest virus definitions via freshclam (this may take several minutes)")
rc = run_clamav_update_db(root, verbosity=2)
if rc != 0:
    print(f"      freshclam exited {rc}", flush=True)
    sys.exit(rc)
_done(t)

print("\n[done] ClamAV ready.  Run m18_clamav_scan to scan.", flush=True)
