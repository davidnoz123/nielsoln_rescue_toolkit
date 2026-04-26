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
    DEBUG_MODE=0
    for arg in "$@"; do
        case "$arg" in
            --port=*) PORT="${arg#--port=}" ;;
            --debug)  DEBUG_MODE=1 ;;
        esac
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
    if pgrep -x dropbear_rescue >/dev/null 2>&1; then
        echo "[bootstrap.sh] Stopping existing dropbear_rescue (PID $(pgrep -x dropbear_rescue)) ..."
        pkill -x dropbear_rescue 2>/dev/null || true
        sleep 0.5
        if pgrep -x dropbear_rescue >/dev/null 2>&1; then
            echo "[bootstrap.sh] WARNING: dropbear_rescue still running after SIGTERM — sending SIGKILL ..."
            pkill -9 -x dropbear_rescue 2>/dev/null || true
            sleep 0.3
        fi
        echo "[bootstrap.sh] dropbear_rescue stopped."
    else
        echo "[bootstrap.sh] No existing dropbear_rescue process found."
    fi
    rm -f "$DROPBEAR"
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

    # Install all bundled developer keys from toolkit.py into authorized_keys.
    # _SSH_BUNDLED_PUBKEYS is a Python list — extract every ssh-* line from it.
    TOOLKIT_PY="$ROOT/toolkit.py"
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    KEYS_INSTALLED=0
    if [ -f "$TOOLKIT_PY" ]; then
        # Pull every quoted ssh-... value out of the _SSH_BUNDLED_PUBKEYS block.
        while IFS= read -r BUNDLED_KEY; do
            [ -z "$BUNDLED_KEY" ] && continue
            KEY_MATERIAL=$(echo "$BUNDLED_KEY" | awk '{print $2}')
            if ! grep -qF "$KEY_MATERIAL" /root/.ssh/authorized_keys 2>/dev/null; then
                echo "$BUNDLED_KEY" >> /root/.ssh/authorized_keys
                KEYS_INSTALLED=$((KEYS_INSTALLED + 1))
            fi
        done < <(grep -oP '(?<=")(ssh-\S+\s+\S+(?:\s+\S+)?)(?=")' "$TOOLKIT_PY" \
                 | grep '^ssh-')
    fi
    if [ "$KEYS_INSTALLED" -gt 0 ]; then
        echo "[bootstrap.sh] $KEYS_INSTALLED bundled key(s) installed."
    else
        echo "[bootstrap.sh] Bundled keys already present (or toolkit.py not found)."
    fi
    chmod 600 /root/.ssh/authorized_keys 2>/dev/null || true

    # Start dropbear.
    # -R  auto-generate host keys (stored in /etc/dropbear)
    # -s  disable password auth (key-only)
    # -p  listen port
    # LD_LIBRARY_PATH points at the bundled .so files — no apt-get needed.
    # Kill once more in case anything restarted it between copy and now.
    if pgrep -x dropbear_rescue >/dev/null 2>&1; then
        echo "[bootstrap.sh] Stopping dropbear_rescue before start (PID $(pgrep -x dropbear_rescue)) ..."
        pkill -x dropbear_rescue 2>/dev/null || true
        sleep 0.3
    fi

    mkdir -p /etc/dropbear

    if [ "$DEBUG_MODE" = "1" ]; then
        echo "[bootstrap.sh] DEBUG MODE — running dropbear in foreground. Press Ctrl+C to stop."
        echo "[bootstrap.sh] LD_LIBRARY_PATH=$LIB_DIR"
        echo "[bootstrap.sh] Command: $DROPBEAR -F -E -R -s -p $PORT"
        LD_LIBRARY_PATH="$LIB_DIR" "$DROPBEAR" -F -E -R -s -p "$PORT"
    else
        echo "[bootstrap.sh] Starting dropbear SSH on port ${PORT} ..."
        LD_LIBRARY_PATH="$LIB_DIR" "$DROPBEAR" -R -s -p "$PORT"
        echo "[bootstrap.sh] dropbear started. Connect as: ssh root@<ip> -p ${PORT}"
    fi
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
