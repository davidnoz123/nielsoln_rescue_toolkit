"""Fetch the dropbear SSH server binary from Ubuntu packages and stage it on the USB build.

Dropbear is a lightweight SSH server (~200 KB). Bundling it on the USB means
bootstrap.sh can start an SSH server on RescueZilla without any network access
or apt-get.

Run from the repo root:
    import runpy; runpy._run_module_as_main("scripts.fetch_dropbear")

Or:
    python scripts/fetch_dropbear.py

Output:
    dist/NIELSOLN_RESCUE_USB/_tools/dropbear   (Linux x86_64 ELF binary)
"""

import io
import pathlib
import sys
import tarfile
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEST = pathlib.Path("dist/NIELSOLN_RESCUE_USB/_tools/dropbear")

# Ubuntu 22.04 LTS (jammy) — stable LTS, binary works on any modern Linux kernel.
# To find the current filename: https://packages.ubuntu.com/jammy/amd64/dropbear-bin/download
_JAMMY_BASE = "http://security.ubuntu.com/ubuntu/pool/universe/d/dropbear/"
_PACKAGE_CANDIDATES = [
    _JAMMY_BASE + "dropbear-bin_2020.81-5ubuntu0.1_amd64.deb",
    # Fallback: try archive mirror
    "http://archive.ubuntu.com/ubuntu/pool/universe/d/dropbear/dropbear-bin_2020.81-5_amd64.deb",
]


# ---------------------------------------------------------------------------
# ar archive parser (stdlib only — no external tools needed)
# ---------------------------------------------------------------------------

def _iter_ar(data: bytes):
    """Yield (name: str, content: bytes) for each entry in an ar archive."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("Not an ar archive (missing !<arch> header)")
    pos = 8
    while pos + 60 <= len(data):
        name = data[pos : pos + 16].rstrip().decode("latin-1")
        size = int(data[pos + 48 : pos + 58].strip())
        pos += 60
        content = data[pos : pos + size]
        pos += size
        if pos % 2:
            pos += 1  # ar entries are padded to even offsets
        yield name, content


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if DEST.exists():
        print(f"Already present: {DEST}  ({DEST.stat().st_size:,} bytes) — nothing to do.")
        return

    DEST.parent.mkdir(parents=True, exist_ok=True)

    # --- Download .deb -------------------------------------------------------
    deb_data: bytes | None = None
    for url in _PACKAGE_CANDIDATES:
        print(f"Trying {url} ...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "rescue-toolkit/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                deb_data = resp.read()
            print(f"  Downloaded {len(deb_data):,} bytes")
            break
        except Exception as exc:
            print(f"  Failed: {exc}")

    if deb_data is None:
        print()
        print("ERROR: All download URLs failed.")
        print("Manual fallback:")
        print("  1. Visit https://packages.ubuntu.com/jammy/amd64/dropbear-bin/download")
        print("  2. Download the .deb and place it in the current directory as dropbear-bin.deb")
        print("  3. Re-run this script — it will detect and use the local file.")
        _try_local_deb()
        return

    _extract_and_save(deb_data)


def _try_local_deb() -> None:
    """Fallback: look for a manually downloaded .deb in the current directory."""
    candidates = sorted(pathlib.Path(".").glob("dropbear-bin*.deb"))
    if not candidates:
        sys.exit(1)
    path = candidates[-1]
    print(f"Found local .deb: {path}")
    _extract_and_save(path.read_bytes())


def _extract_and_save(deb_data: bytes) -> None:
    """Parse the .deb, extract the dropbear binary, write to DEST."""
    # .deb is an ar archive containing control.tar.* and data.tar.*
    data_entry: tuple[str, bytes] | None = None
    for name, content in _iter_ar(deb_data):
        if name.startswith("data.tar"):
            data_entry = (name, content)
            break

    if data_entry is None:
        print("ERROR: No data.tar.* found inside .deb archive.")
        sys.exit(1)

    ar_name, tar_bytes = data_entry
    print(f"  Extracting from {ar_name} ...")

    # Decompress zstd if needed (Ubuntu 21.10+ packages data.tar.zst)
    if ar_name.endswith(".zst"):
        try:
            import zstandard  # type: ignore
        except ImportError:
            print("ERROR: zstandard package is required to extract this .deb.")
            print("Run:  pip install zstandard")
            sys.exit(1)
        dctx = zstandard.ZstdDecompressor()
        tar_bytes = dctx.decompress(tar_bytes, max_output_size=20 * 1024 * 1024)

    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        for member in tf.getmembers():
            # The binary is at ./usr/sbin/dropbear inside the tarball
            if member.name.endswith("/dropbear") and "sbin" in member.name:
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                DEST.write_bytes(fobj.read())
                size = DEST.stat().st_size
                print(f"  Saved: {DEST}  ({size:,} bytes)")
                print()
                print("Done. The binary will be included when you run the USB package build.")
                print(f"Path on USB:  _tools/dropbear")
                return

    print("ERROR: Could not find 'dropbear' binary inside data tarball.")
    print("Members found:")
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        for m in tf.getmembers():
            print(f"  {m.name}")
    sys.exit(1)


if __name__ == "__main__":
    main()
