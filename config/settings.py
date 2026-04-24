"""
LockJaw — Configuration Settings
Environment-driven via .env or environment variables.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")


class Settings:
    HOST: str = os.getenv("LOCKJAW_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("LOCKJAW_PORT", "8765"))
    DEBUG: bool = os.getenv("LOCKJAW_DEBUG", "false").lower() == "true"

    ALLOWED_ORIGINS: list[str] = os.getenv(
        "LOCKJAW_ORIGINS", "http://localhost:3000,http://localhost:5173"
    ).split(",")

    SECRET_KEY: str = os.getenv("LOCKJAW_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
    SESSION_TTL: int = int(os.getenv("LOCKJAW_SESSION_TTL", "3600"))

    DATA_DIR: Path = Path(os.getenv("LOCKJAW_DATA_DIR", "./data"))

    LOG_LEVEL: str = os.getenv("LOCKJAW_LOG_LEVEL", "INFO")

    # Zero-trust: server NEVER stores beale phrases or plaintext
    STORE_PLAINTEXT: bool = False
    STORE_BEALE_PHRASE: bool = False
