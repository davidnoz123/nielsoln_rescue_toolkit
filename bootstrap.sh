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
    # Parse --port from args
    for arg in "$@"; do
        case "$arg" in
            --port=*) PORT="${arg#--port=}" ;;
        esac
    done

    # Locate sshd — Ubuntu puts it in /usr/sbin which may not be in PATH
    SSHD=""
    for candidate in \
            "$(command -v sshd 2>/dev/null)" \
            /usr/sbin/sshd \
            /sbin/sshd; do
        if [ -x "$candidate" ]; then
            SSHD="$candidate"
            break
        fi
    done

    # Install if missing
    if [ -z "$SSHD" ]; then
        echo "[bootstrap.sh] sshd not found — installing openssh-server ..."
        apt-get install -y openssh-server
        # Re-probe after install
        for candidate in \
                "$(command -v sshd 2>/dev/null)" \
                /usr/sbin/sshd \
                /sbin/sshd; do
            if [ -x "$candidate" ]; then
                SSHD="$candidate"
                break
            fi
        done
    fi

    if [ -z "$SSHD" ]; then
        echo "ERROR: openssh-server install failed or sshd still not found."
        exit 1
    fi

    # Ensure PermitRootLogin is set
    SSHD_CONF=/etc/ssh/sshd_config
    if [ -f "$SSHD_CONF" ]; then
        if ! grep -q "PermitRootLogin" "$SSHD_CONF"; then
            echo "PermitRootLogin yes" >> "$SSHD_CONF"
        fi
    else
        mkdir -p /etc/ssh
        cat > "$SSHD_CONF" <<EOF
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile /root/.ssh/authorized_keys
PasswordAuthentication yes
Port ${PORT}
EOF
    fi

    # Generate host keys if absent
    if command -v ssh-keygen >/dev/null 2>&1; then
        ssh-keygen -A >/dev/null 2>&1 || true
    fi

    # Ensure /run/sshd exists (required by openssh)
    mkdir -p /run/sshd

    # Install bundled developer key from toolkit.py into authorized_keys.
    # This runs in pure bash so key auth works even if Python never starts.
    # The key is on a single line: _SSH_BUNDLED_PUBKEY = "ssh-ed25519 ..."
    TOOLKIT_PY="$ROOT/toolkit.py"
    BUNDLED_KEY=""
    if [ -f "$TOOLKIT_PY" ]; then
        BUNDLED_KEY=$(
            grep '_SSH_BUNDLED_PUBKEY = ' "$TOOLKIT_PY" \
            | sed 's/.*"\(ssh-[^"]*\)".*/\1/'
        )
    fi

    if [ -n "$BUNDLED_KEY" ]; then
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        AUTHKEYS=/root/.ssh/authorized_keys
        # Add only if not already present (match on key material, not comment).
        KEY_MATERIAL=$(echo "$BUNDLED_KEY" | awk '{print $2}')
        if ! grep -qF "$KEY_MATERIAL" "$AUTHKEYS" 2>/dev/null; then
            echo "$BUNDLED_KEY" >> "$AUTHKEYS"
            echo "[bootstrap.sh] Bundled developer key installed."
        else
            echo "[bootstrap.sh] Bundled developer key already present."
        fi
        chmod 600 "$AUTHKEYS"
    else
        echo "[bootstrap.sh] WARNING: could not extract bundled key from toolkit.py"
    fi

    # Start sshd
    echo "[bootstrap.sh] Starting sshd on port ${PORT} ..."
    "$SSHD" -p "$PORT"
    echo "[bootstrap.sh] sshd started."
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
