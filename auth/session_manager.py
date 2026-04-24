"""
LockJaw — Session Manager
Issues and validates short-lived session tokens post-2FA.
"""

import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field
from typing import Optional


SECRET_KEY = os.getenv("LOCKJAW_SECRET_KEY", os.urandom(32).hex())
SESSION_TTL = int(os.getenv("LOCKJAW_SESSION_TTL", "3600"))  # 1 hour


@dataclass
class Session:
    node_id: str
    machine_id: str
    beale_phrase_hash: str
    created_at: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > SESSION_TTL


class SessionManager:
    def __init__(self):
        self._sessions: dict[str, Session] = {}

    def create_session(self, node_id: str, machine_id: str, beale_phrase: str) -> str:
        phrase_hash = hashlib.sha256(beale_phrase.encode()).hexdigest()
        token = self._generate_token(node_id, machine_id)
        self._sessions[token] = Session(
            node_id=node_id,
            machine_id=machine_id,
            beale_phrase_hash=phrase_hash,
        )
        return token

    def validate_token(self, token: str) -> Optional[Session]:
        session = self._sessions.get(token)
        if not session:
            return None
        if session.is_expired():
            del self._sessions[token]
            return None
        return session

    def revoke(self, token: str):
        self._sessions.pop(token, None)

    def clear_all(self):
        self._sessions.clear()

    @staticmethod
    def _generate_token(node_id: str, machine_id: str) -> str:
        payload = f"{node_id}:{machine_id}:{time.time()}:{os.urandom(16).hex()}"
        sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return f"{hashlib.sha256(payload.encode()).hexdigest()[:32]}{sig[:32]}"
