#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Special case: 'ssh' subcommand
#
# SSH connectivity is the recovery path if Python automation breaks.
# Install openssh-server and start sshd here in pure bash — before Python —
# so the daemon is up regardless of Python's state.
# Python is still called afterward to install the authorised key and print
# the VS Code connection snippet.
# ---------------------------------------------------------------------------
if [ "$1" = "ssh" ]; then
    PORT=22
    for arg in "$@"; do
        case "$arg" in --port=*) PORT="${arg#--port=}" ;; esac
    done

    # Dropbear is bundled on the USB — no apt-get, no network needed.
    # FAT32 has no execute bit, so copy to /tmp (tmpfs) before running.
    DROPBEAR_SRC="$ROOT/_tools/dropbear"
    if [ ! -f "$DROPBEAR_SRC" ]; then
        echo "ERROR: _tools/dropbear not found on USB."
        echo "Run: sudo bash bootstrap.sh update    (requires network)"
        exit 1
    fi
    DROPBEAR=/tmp/dropbear_rescue
    # Kill any previous instance before overwriting the binary (avoids "Text
    # file busy" error when the executable is still mapped into memory).
    if [ -f "$DROPBEAR" ]; then
        pkill -x dropbear_rescue 2>/dev/null || true
        sleep 0.3
        rm -f "$DROPBEAR"
    fi
    cp "$DROPBEAR_SRC" "$DROPBEAR"
    chmod +x "$DROPBEAR"

    # Copy bundled shared libraries (.so files) to /tmp as well.
    # dropbear links against libatomic, libtomcrypt, libtommath, libgmp — all
    # bundled in _tools/ alongside the binary.  We set LD_LIBRARY_PATH so the
    # dynamic linker finds them without any apt-get install.
    # (FAT32 has no execute bit, so we copy to /tmp which is tmpfs.)
    LIB_DIR=/tmp/dropbear_libs
    # Wipe and recreate so stale .so files never cause "Text file busy".
    rm -rf "$LIB_DIR"
    mkdir -p "$LIB_DIR"
    for SO in "$ROOT/_tools/"*.so.*; do
        [ -f "$SO" ] && cp "$SO" "$LIB_DIR/"
    done

    # Install bundled developer key from toolkit.py into authorized_keys.
    TOOLKIT_PY="$ROOT/toolkit.py"
    if [ -f "$TOOLKIT_PY" ]; then
        BUNDLED_KEY=$(
            grep '_SSH_BUNDLED_PUBKEY = ' "$TOOLKIT_PY" \
            | sed 's/.*"\(ssh-[^"]*\)".*/\1/'
        )
    fi
    if [ -n "$BUNDLED_KEY" ]; then
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        KEY_MATERIAL=$(echo "$BUNDLED_KEY" | awk '{print $2}')
        if ! grep -qF "$KEY_MATERIAL" /root/.ssh/authorized_keys 2>/dev/null; then
            echo "$BUNDLED_KEY" >> /root/.ssh/authorized_keys
            echo "[bootstrap.sh] Developer key installed."
        fi
        chmod 600 /root/.ssh/authorized_keys
    else
        echo "[bootstrap.sh] WARNING: could not extract bundled key from toolkit.py"
    fi

    # Start dropbear.
    # -R  auto-generate host keys (stored in /etc/dropbear)
    # -s  disable password auth (key-only)
    # -p  listen port
    # LD_LIBRARY_PATH points at the bundled .so files — no apt-get needed.
    echo "[bootstrap.sh] Starting dropbear SSH on port ${PORT} ..."
    LD_LIBRARY_PATH="$LIB_DIR" "$DROPBEAR" -R -s -p "$PORT"
    echo "[bootstrap.sh] dropbear started. Connect as: ssh root@<ip> -p ${PORT}"
fi
# ---------------------------------------------------------------------------
# End SSH special case — fall through to Python for key install + info print
# ---------------------------------------------------------------------------

if command -v python3 >/dev/null 2>&1; then
    exec python3 "$ROOT/bootstrap.py" "$@"
fi

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" = "Linux" ] && [ "$ARCH" = "x86_64" ]; then
    PY="$ROOT/runtimes/linux-x86_64/python/bin/python3"
    if [ -x "$PY" ]; then
        exec "$PY" "$ROOT/bootstrap.py" "$@"
    fi
fi

if [ "$OS" = "Darwin" ] && [ "$ARCH" = "x86_64" ]; then
    PY="$ROOT/runtimes/macos-x86_64/python/bin/python3"
    if [ -x "$PY" ]; then
        exec "$PY" "$ROOT/bootstrap.py" "$@"
    fi
fi

if [ "$OS" = "Darwin" ] && [ "$ARCH" = "arm64" ]; then
    PY="$ROOT/runtimes/macos-arm64/python/bin/python3"
    if [ -x "$PY" ]; then
        exec "$PY" "$ROOT/bootstrap.py" "$@"
    fi
fi

echo "No compatible Python found. Install python3 or add a bundled runtime to runtimes/."
exit 1
