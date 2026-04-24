"""
LockJaw — TOTP Manager
Provisions and verifies time-based one-time passwords (RFC 6238).
"""

import base64
import os
import shelve
from pathlib import Path

import pyotp


DATA_DIR = Path(os.getenv("LOCKJAW_DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
SECRETS_DB = str(DATA_DIR / "totp_secrets")


class TOTPManager:
    """Manages TOTP secrets per node identity."""

    def provision(self, node_id: str) -> tuple[str, str]:
        """
        Generate (or retrieve existing) TOTP secret for a node.
        Returns (base32_secret, otpauth_uri).
        """
        with shelve.open(SECRETS_DB) as db:
            if node_id in db:
                secret = db[node_id]
            else:
                secret = pyotp.random_base32()
                db[node_id] = secret

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=node_id,
            issuer_name="LockJaw",
        )
        return secret, uri

    def verify(self, node_id: str, code: str, window: int = 1) -> bool:
        """
        Verify a TOTP code.
        window=1 allows ±30s drift for clock skew.
        """
        with shelve.open(SECRETS_DB) as db:
            secret = db.get(node_id)

        if not secret:
            return False

        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=window)

    def get_current(self, node_id: str) -> str | None:
        """Return the current valid TOTP code for a node (for testing)."""
        with shelve.open(SECRETS_DB) as db:
            secret = db.get(node_id)
        if not secret:
            return None
        return pyotp.TOTP(secret).now()

    def revoke(self, node_id: str) -> bool:
        """Remove a node's TOTP secret (forces re-registration)."""
        with shelve.open(SECRETS_DB) as db:
            if node_id in db:
                del db[node_id]
                return True
        return False
