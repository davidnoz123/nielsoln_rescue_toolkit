"""session_secrets.py — Session-scoped encrypted secret storage.

Secrets are encrypted with a key derived from two inputs:

  SESSION_MASTER_SECRET   (env var)  — the real secret; never stored on disk
  EXECUTION_SESSION_ID    (env var)  — non-secret namespace / PBKDF2 salt

Key derivation  : PBKDF2HMAC-SHA256, 480 000 iterations
Encryption      : Fernet  (AES-128-CBC + HMAC-SHA256, authenticated)
Storage         : ~/.nielsoln_rescue/sessions/{session_id}/{name}.enc

Environment variables
---------------------
SESSION_MASTER_SECRET   Required for all encrypt / decrypt operations.
EXECUTION_SESSION_ID    Required; create one with create_session_id() if absent.

Public API
----------
    create_session_id()                     → str
    encrypt_session_secret(name, plaintext) → None
    decrypt_session_secret(name)            → str
    delete_session_secret(name)             → None
    list_session_secrets()                  → list[str]

Rules
-----
- Plaintext secrets are NEVER written to disk, logged, or printed.
- Encrypted blobs use Fernet (authenticated); tampering raises InvalidToken.
- Secrets are namespaced by EXECUTION_SESSION_ID, so a secret from one
  session cannot be decrypted with a different session's derived key even if
  SESSION_MASTER_SECRET is identical (the salt differs).
- Deleting all secrets for a session does not delete the session directory
  itself; use delete_session() for that.

Interactive run
---------------
    import runpy ; temp = runpy._run_module_as_main("session_secrets")
"""

import base64
import os
import pathlib
import secrets
import uuid

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_STORE_ROOT = pathlib.Path.home() / ".nielsoln_rescue" / "sessions"
_KDF_ITERATIONS = 480_000
_ENV_MASTER = "SESSION_MASTER_SECRET"
_ENV_SESSION = "EXECUTION_SESSION_ID"


def _session_dir(session_id: str) -> pathlib.Path:
    """Return (and create) the storage directory for this session."""
    d = _STORE_ROOT / session_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _derive_fernet_key(master_secret: str, session_id: str) -> Fernet:
    """Derive a Fernet key from SESSION_MASTER_SECRET + EXECUTION_SESSION_ID."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id.encode("utf-8"),
        iterations=_KDF_ITERATIONS,
    )
    raw_key = kdf.derive(master_secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(raw_key))


def _get_env(name: str) -> str:
    """Read a required environment variable, raising clearly if absent."""
    val = os.environ.get(name, "")
    if not val:
        raise RuntimeError(
            f"Environment variable {name!r} is not set. "
            f"Set it before calling session_secrets functions."
        )
    return val


def _secret_path(session_id: str, name: str) -> pathlib.Path:
    """Return the .enc file path for a named secret."""
    # Sanitise name so it can only be a plain filename component
    safe = "".join(c for c in name if c.isalnum() or c in "-_.")
    if not safe:
        raise ValueError(f"Invalid secret name: {name!r}")
    return _session_dir(session_id) / f"{safe}.enc"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_session_id() -> str:
    """Generate a fresh EXECUTION_SESSION_ID, store it in the env, and return it.

    The caller should also propagate it to sub-processes as needed, e.g.::

        os.environ["EXECUTION_SESSION_ID"] = create_session_id()
    """
    sid = str(uuid.uuid4())
    os.environ[_ENV_SESSION] = sid
    _session_dir(sid)           # create storage dir immediately
    print(f"[session_secrets] Created session: {sid}")
    return sid


def encrypt_session_secret(name: str, plaintext: str) -> None:
    """Encrypt *plaintext* and store it as secret *name* for the current session.

    Requires SESSION_MASTER_SECRET and EXECUTION_SESSION_ID to be set.
    The plaintext is never written to disk; only the Fernet ciphertext is.
    """
    master   = _get_env(_ENV_MASTER)
    sid      = _get_env(_ENV_SESSION)
    fernet   = _derive_fernet_key(master, sid)
    token    = fernet.encrypt(plaintext.encode("utf-8"))
    path     = _secret_path(sid, name)
    path.write_bytes(token)
    # Restrict permissions so only the owner can read the file
    try:
        path.chmod(0o600)
    except OSError:
        pass  # Windows — best-effort
    print(f"[session_secrets] Stored encrypted secret: {name!r} → {path}")


def decrypt_session_secret(name: str) -> str:
    """Decrypt and return the plaintext for secret *name* in the current session.

    Returns the decrypted string.  Never prints or logs the value.
    Raises FileNotFoundError if the secret does not exist.
    Raises cryptography.fernet.InvalidToken if decryption fails (wrong key
    or tampered ciphertext).
    """
    master   = _get_env(_ENV_MASTER)
    sid      = _get_env(_ENV_SESSION)
    path     = _secret_path(sid, name)
    if not path.exists():
        raise FileNotFoundError(f"Secret {name!r} not found for session {sid!r}")
    fernet   = _derive_fernet_key(master, sid)
    token    = path.read_bytes()
    try:
        plain = fernet.decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise InvalidToken(
            f"Failed to decrypt secret {name!r}: wrong SESSION_MASTER_SECRET "
            f"or EXECUTION_SESSION_ID, or ciphertext was tampered with."
        ) from exc
    # plain is returned to the caller; never printed here
    return plain


def delete_session_secret(name: str) -> None:
    """Delete a single named secret for the current session."""
    sid  = _get_env(_ENV_SESSION)
    path = _secret_path(sid, name)
    if path.exists():
        path.unlink()
        print(f"[session_secrets] Deleted secret: {name!r}")
    else:
        print(f"[session_secrets] Secret {name!r} not found — nothing to delete.")


def delete_session(session_id: str | None = None) -> None:
    """Delete ALL secrets (and the storage dir) for a session.

    Defaults to the current EXECUTION_SESSION_ID if *session_id* is None.
    """
    import shutil
    sid = session_id or _get_env(_ENV_SESSION)
    d   = _STORE_ROOT / sid
    if d.exists():
        shutil.rmtree(d)
        print(f"[session_secrets] Deleted session directory: {d}")
    else:
        print(f"[session_secrets] Session directory not found: {d}")


def list_session_secrets() -> list:
    """Return a list of secret names stored for the current session.

    The names are the bare filenames without the .enc extension.
    """
    sid = _get_env(_ENV_SESSION)
    d   = _session_dir(sid)
    names = [p.stem for p in sorted(d.glob("*.enc"))]
    return names


# ---------------------------------------------------------------------------
# Interactive self-test  (main)
# ---------------------------------------------------------------------------

def main() -> None:
    """Interactive smoke-test.  Run via:

        import runpy ; temp = runpy._run_module_as_main("session_secrets")
    """
    import getpass

    print("=== session_secrets smoke-test ===")

    # Use existing session or create a fresh one
    sid = os.environ.get(_ENV_SESSION) or create_session_id()
    print(f"Session ID : {sid}")

    # Use existing master or prompt
    if not os.environ.get(_ENV_MASTER):
        master = getpass.getpass("SESSION_MASTER_SECRET: ")
        os.environ[_ENV_MASTER] = master
    else:
        print("SESSION_MASTER_SECRET already set in environment.")

    # Round-trip test with a dummy secret (never the real passphrase)
    test_name = "_smoke_test"
    test_val  = secrets.token_hex(8)
    encrypt_session_secret(test_name, test_val)
    recovered = decrypt_session_secret(test_name)
    assert recovered == test_val, "Round-trip mismatch!"
    print(f"[session_secrets] Round-trip OK (value not shown).")
    delete_session_secret(test_name)

    print(f"Secrets in session : {list_session_secrets()}")
    print("=== done ===")


if __name__ == "__main__":
    main()
