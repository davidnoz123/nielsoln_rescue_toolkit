"""
scripts/download_portable_python.py — Download portable Python runtimes.

Run from repo root:
    import runpy ; temp = runpy._run_module_as_main("scripts.download_portable_python")

NOTE: This script requires internet access. Do not run on the rescue USB itself.

In v1 this is a stub that prints the download URLs and target paths.
Full download logic will be added in a later phase.

Portable Python sources considered:
  - python-build-standalone (indygreg releases on GitHub)
    https://github.com/indygreg/python-build-standalone/releases
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# python-build-standalone release base URL (adjust tag as needed)
BASE_URL = (
    "https://github.com/indygreg/python-build-standalone/releases/download"
    "/20240415"
)

TARGETS = [
    {
        "platform": "linux-x86_64",
        "filename": "cpython-3.12.3+20240415-x86_64-unknown-linux-gnu-install_only.tar.gz",
    },
    {
        "platform": "macos-x86_64",
        "filename": "cpython-3.12.3+20240415-x86_64-apple-darwin-install_only.tar.gz",
    },
    {
        "platform": "macos-arm64",
        "filename": "cpython-3.12.3+20240415-aarch64-apple-darwin-install_only.tar.gz",
    },
]


def main() -> None:
    print("Portable Python download plan")
    print("=" * 60)
    for t in TARGETS:
        url = f"{BASE_URL}/{t['filename']}"
        dest = ROOT / "dist" / "NIELSOLN_RESCUE_USB" / "runtimes" / t["platform"]
        print(f"\nPlatform : {t['platform']}")
        print(f"URL      : {url}")
        print(f"Dest     : {dest}")

    print()
    print("Full download not yet implemented in v1.")
    print("Download each archive manually, extract, and place under:")
    print("  dist/NIELSOLN_RESCUE_USB/runtimes/<platform>/python/")


if __name__ == "__main__":
    main()
