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

if [ "$OS" = "Darwin" ] && [ "$ARCH" = "x86_64" ]; then
    PY="$ROOT/runtimes/macos-x86_64/python/bin/python3"
    if [ -x "$PY" ]; then
        exec "$PY" "$ROOT/toolkit/bootstrap.py" "$@"
    fi
fi

if [ "$OS" = "Darwin" ] && [ "$ARCH" = "arm64" ]; then
    PY="$ROOT/runtimes/macos-arm64/python/bin/python3"
    if [ -x "$PY" ]; then
        exec "$PY" "$ROOT/toolkit/bootstrap.py" "$@"
    fi
fi

echo "No compatible Python found. Install python3 or add a bundled runtime to runtimes/."
exit 1
