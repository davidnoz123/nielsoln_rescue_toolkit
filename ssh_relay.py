"""ssh_relay.py — Persistent SSH relay daemon for Nielsoln dev tools.

Prompts for the key passphrase ONCE at startup, then routes all SSH/SCP
commands from devtools.py without further prompting.

Run once in a separate terminal (keep it open):
    import runpy; temp = runpy._run_module_as_main("ssh_relay")

Protocol: one TCP connection per command (127.0.0.1:19022).
  Request:  single JSON line
  Response: one or more JSON lines, terminated by a line with "done" key.

Non-streaming ops
-----------------
  {"op": "ping"}
      -> {"done": true, "ok": true}

  {"op": "scp_put", "local": "modules/m25.py", "remote": "/usb/modules/m25.py"}
  {"op": "scp_get", "remote": "/usb/logs/x.json", "local": "x.json"}
      -> {"done": true, "ok": true/false, "rc": 0, "out": "...", "err": "..."}

  {"op": "shutdown"}
      -> {"done": true, "ok": true}

Streaming op (for long-running SSH commands)
--------------------------------------------
  {"op": "ssh", "cmd": "...", "stdin_b64": null_or_base64_string}
      -> zero or more: {"type": "out", "data": "..."}
                       {"type": "err", "data": "..."}
         final:        {"done": true, "rc": 0}

devtools.py detects the relay automatically and uses it when available.
Falls back to direct subprocess (with passphrase prompt) if relay is down.
"""

import base64
import collections
import datetime
import getpass
import json
import logging
import logging.handlers
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

# ---------------------------------------------------------------------------
# Configuration (must match devtools.py)
# ---------------------------------------------------------------------------

HOST        = "192.168.1.67"
PORT        = 22
KEY         = r"C:\Users\david\.ssh\id_ed25519"
RELAY_PORT  = 19022
RELAY_ADDR  = "127.0.0.1"

# Path to the Python interpreter (used in the SSH_ASKPASS helper script)
_PY = r"C:\analytics\projects\git\lexi\demos\venv\Scripts\python.exe"

# Set when the relay starts up
_askpass_bat: str = ""
_shutdown_event = threading.Event()
_start_time: float = 0.0

# ---------------------------------------------------------------------------
# Logging — rotating file + in-memory ring buffer (last 200 entries)
# ---------------------------------------------------------------------------

LOG_PATH = pathlib.Path(tempfile.gettempdir()) / "ssh_relay.log"
_ring: collections.deque = collections.deque(maxlen=200)
_ring_lock = threading.Lock()

_logger = logging.getLogger("ssh_relay")


def _setup_logging() -> None:
    _logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s",
                            datefmt="%H:%M:%S")
    # Rotating file: 256 KB, keep 3 backups
    fh = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=256 * 1024, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    _logger.addHandler(fh)
    # Console (the terminal running the relay)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    _logger.addHandler(ch)


class _RingHandler(logging.Handler):
    """Appends formatted log records to the in-memory ring buffer."""
    def emit(self, record):
        msg = self.format(record)
        with _ring_lock:
            _ring.append(msg)


def _add_ring_handler() -> None:
    h = _RingHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(message)s",
                                     datefmt="%H:%M:%S"))
    _logger.addHandler(h)


# ---------------------------------------------------------------------------
# SSH_ASKPASS helper — write a .bat that echoes the passphrase via Python
# ---------------------------------------------------------------------------

def _write_askpass_bat(passphrase: str) -> str:
    """Write a temp .bat that prints the passphrase to stdout and return its path.

    Encoding the passphrase as base64 and decoding it in Python avoids any
    batch-file escaping issues with special characters.
    """
    encoded = base64.b64encode(passphrase.encode("utf-8")).decode("ascii")
    py_snippet = (
        f"import base64,sys;"
        f"sys.stdout.write(base64.b64decode(b'{encoded}').decode())"
    )
    bat = f'@echo off\n"{_PY}" -c "{py_snippet}"\n'
    tmp = pathlib.Path(tempfile.gettempdir()) / "ssh_relay_askpass.bat"
    tmp.write_text(bat, encoding="ascii")
    return str(tmp)


def _askpass_env() -> dict:
    """Return a copy of os.environ with SSH_ASKPASS injected."""
    env = os.environ.copy()
    env["SSH_ASKPASS"]         = _askpass_bat
    env["SSH_ASKPASS_REQUIRE"] = "force"
    # Older OpenSSH builds require DISPLAY to be non-empty before honouring
    # SSH_ASKPASS, even on Windows.  Any non-empty value works.
    env.setdefault("DISPLAY", "localhost:0")
    return env


# ---------------------------------------------------------------------------
# SSH / SCP subprocess wrappers
# ---------------------------------------------------------------------------

def _ssh_base_args(cmd: str) -> list:
    return [
        "ssh", "-p", str(PORT), "-i", KEY,
        "-o", "StrictHostKeyChecking=no",
        f"root@{HOST}", cmd,
    ]


def _scp_base_args(src: str, dst: str) -> list:
    return [
        "scp", "-O", "-P", str(PORT), "-i", KEY,
        "-o", "StrictHostKeyChecking=no",
        src, dst,
    ]


_SSH_RETRY_ATTEMPTS = 3   # total attempts (1 original + 2 retries)
_SSH_RETRY_DELAY    = 2   # seconds between attempts


def _run_buffered(args: list, stdin_bytes: bytes = None) -> dict:
    """Run a subprocess, capture all output, return result dict.

    Retries up to _SSH_RETRY_ATTEMPTS times on SSH connection failure (rc=255).
    """
    t0 = time.monotonic()
    for attempt in range(1, _SSH_RETRY_ATTEMPTS + 1):
        result = subprocess.run(
            args,
            env=_askpass_env(),
            input=stdin_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 255 or attempt == _SSH_RETRY_ATTEMPTS:
            break
        _logger.warning(
            "ssh rc=255 (connection dropped) — retry %d/%d in %ds",
            attempt, _SSH_RETRY_ATTEMPTS, _SSH_RETRY_DELAY,
        )
        time.sleep(_SSH_RETRY_DELAY)
    elapsed = time.monotonic() - t0
    return {
        "done":    True,
        "ok":      result.returncode == 0,
        "rc":      result.returncode,
        "elapsed": round(elapsed, 2),
        "out":     result.stdout.decode("utf-8", errors="replace"),
        "err":     result.stderr.decode("utf-8", errors="replace"),
    }


def _run_streaming(args: list, stdin_bytes: bytes, send_line):
    """Run a subprocess, streaming stdout/stderr back via *send_line* callback.

    Retries up to _SSH_RETRY_ATTEMPTS times on SSH connection failure (rc=255).
    Note: on retry, previously-streamed output is NOT re-streamed; only the
    retry's output is forwarded.  This is acceptable because a dropped
    connection typically produces no useful output before failing.
    """
    lock = threading.Lock()
    t0 = time.monotonic()

    def _emit(obj):
        with lock:
            send_line(obj)

    for attempt in range(1, _SSH_RETRY_ATTEMPTS + 1):
        proc = subprocess.Popen(
            args,
            env=_askpass_env(),
            stdin=subprocess.PIPE  if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if stdin_bytes is not None:
            proc.stdin.write(stdin_bytes)
            proc.stdin.close()

        # Collect output into lists so we can decide whether to emit or retry
        out_chunks: list[str] = []
        err_chunks: list[str] = []

        def _collect(pipe, store):
            for chunk in iter(lambda: pipe.read(256), b""):
                store.append(chunk.decode("utf-8", errors="replace"))
            pipe.close()

        t1 = threading.Thread(target=_collect, args=(proc.stdout, out_chunks), daemon=True)
        t2 = threading.Thread(target=_collect, args=(proc.stderr, err_chunks), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        rc = proc.wait()

        if rc != 255 or attempt == _SSH_RETRY_ATTEMPTS:
            # Emit all collected output, then final done packet
            for chunk in out_chunks:
                _emit({"type": "out", "data": chunk})
            for chunk in err_chunks:
                _emit({"type": "err", "data": chunk})
            elapsed = time.monotonic() - t0
            _emit({"done": True, "rc": rc, "elapsed": round(elapsed, 2)})
            return

        _logger.warning(
            "ssh rc=255 (connection dropped) — retry %d/%d in %ds",
            attempt, _SSH_RETRY_ATTEMPTS, _SSH_RETRY_DELAY,
        )
        _emit({"type": "err",
               "data": f"[relay] connection dropped (rc=255) — retry {attempt}/{_SSH_RETRY_ATTEMPTS}...\n"})
        time.sleep(_SSH_RETRY_DELAY)



# ---------------------------------------------------------------------------
# Request dispatcher
# ---------------------------------------------------------------------------

def _dispatch(req: dict, send_line) -> None:
    """Handle one request dict, calling *send_line* for each response line."""
    op  = req.get("op", "")
    t0  = time.monotonic()

    def _logged_send(obj):
        send_line(obj)

    if op == "ping":
        _logger.debug("ping")
        send_line({"done": True, "ok": True})

    elif op == "status":
        uptime = round(time.monotonic() - _start_time)
        with _ring_lock:
            recent = list(_ring)
        send_line({
            "done":     True,
            "ok":       True,
            "uptime_s": uptime,
            "log_path": str(LOG_PATH),
            "recent":   recent,
        })

    elif op == "shutdown":
        _logger.info("shutdown requested")
        send_line({"done": True, "ok": True})
        _shutdown_event.set()

    elif op == "ssh":
        cmd         = req["cmd"]
        stdin_b64   = req.get("stdin_b64")
        stdin_bytes = base64.b64decode(stdin_b64) if stdin_b64 else None
        stream      = req.get("stream", True)
        args        = _ssh_base_args(cmd)
        short_cmd   = cmd[:80] + ("..." if len(cmd) > 80 else "")
        _logger.info("ssh  %s", short_cmd)
        if stream:
            _run_streaming(args, stdin_bytes, send_line)
        else:
            resp = _run_buffered(args, stdin_bytes)
            elapsed = resp.get("elapsed", 0)
            _logger.info("ssh  done rc=%s  %.1fs", resp["rc"], elapsed)
            send_line(resp)

    elif op == "scp_put":
        src = req["local"]; dst = req["remote"]
        _logger.info("scp_put  %s -> %s", src, dst)
        args = _scp_base_args(src, f"root@{HOST}:{dst}")
        resp = _run_buffered(args)
        _logger.info("scp_put  done rc=%s  %.1fs", resp["rc"], resp.get("elapsed", 0))
        send_line(resp)

    elif op == "scp_get":
        src = req["remote"]; dst = req["local"]
        _logger.info("scp_get  %s -> %s", src, dst)
        args = _scp_base_args(f"root@{HOST}:{src}", dst)
        resp = _run_buffered(args)
        _logger.info("scp_get  done rc=%s  %.1fs", resp["rc"], resp.get("elapsed", 0))
        send_line(resp)

    else:
        _logger.warning("unknown op: %r", op)
        send_line({"done": True, "ok": False, "err": f"Unknown op: {op!r}"})


# ---------------------------------------------------------------------------
# TCP server — one connection per command
# ---------------------------------------------------------------------------

class _Handler(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr

    def run(self):
        try:
            with self.conn.makefile("rb") as rfile, \
                 self.conn.makefile("wb") as wfile:

                line = rfile.readline()
                if not line:
                    return
                req = json.loads(line)
                op  = req.get("op", "?")

                def _send(obj):
                    wfile.write((json.dumps(obj) + "\n").encode("utf-8"))
                    wfile.flush()

                _dispatch(req, _send)
        except Exception as exc:
            _logger.exception("handler error for op=%r: %s", req.get("op", "?") if 'req' in dir() else "?", exc)
            try:
                self.conn.sendall((json.dumps(
                    {"done": True, "ok": False, "err": str(exc)}) + "\n").encode())
            except OSError:
                pass
        finally:
            try:
                self.conn.close()
            except OSError:
                pass


def _serve():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((RELAY_ADDR, RELAY_PORT))
    srv.listen(8)
    srv.settimeout(1.0)   # so we can check _shutdown_event
    _logger.info("Listening on %s:%s  (Ctrl-C to stop)", RELAY_ADDR, RELAY_PORT)
    while not _shutdown_event.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        _Handler(conn, addr).start()
    srv.close()
    _logger.info("Shutdown.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    global _askpass_bat, _start_time

    _setup_logging()
    _add_ring_handler()

    _logger.info("SSH Relay starting — host=root@%s:%s  key=%s", HOST, PORT, KEY)
    _logger.info("Log file: %s", LOG_PATH)

    # --- singleton check ---
    try:
        with socket.create_connection((RELAY_ADDR, RELAY_PORT), timeout=1) as s:
            s.sendall(b'{"op":"ping"}\n')
        _logger.warning("Relay is already running on %s:%s — exiting.", RELAY_ADDR, RELAY_PORT)
        print(f"Relay already running on {RELAY_ADDR}:{RELAY_PORT}. Nothing to do.")
        return
    except OSError:
        pass  # port free, proceed

    passphrase = getpass.getpass("Key passphrase: ")
    _askpass_bat = _write_askpass_bat(passphrase)

    # Verify connectivity immediately
    _logger.info("Testing SSH connection ...")
    result = subprocess.run(
        _ssh_base_args("echo relay-ok"),
        env=_askpass_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0 or b"relay-ok" not in result.stdout:
        _logger.error("SSH test FAILED (rc=%s): %s",
                      result.returncode, result.stderr.decode(errors="replace"))
        sys.exit(1)
    _logger.info("SSH connection OK")

    _start_time = time.monotonic()

    try:
        _serve()
    except KeyboardInterrupt:
        _logger.info("Interrupted by user.")
    finally:
        # Clean up the temp askpass file
        try:
            pathlib.Path(_askpass_bat).unlink(missing_ok=True)
        except OSError:
            pass
        _logger.info("Relay stopped.")


if __name__ == "__main__":
    main()
else:
    main()
