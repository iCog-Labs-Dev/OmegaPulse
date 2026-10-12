from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

_CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ConfigurationError(ValueError):
    """Raised when the monitor cannot start safely."""


def container_name(value: str) -> str:
    if not _CONTAINER_NAME.fullmatch(value):
        raise ConfigurationError("OMA_MONITOR_CONTAINER is not a valid Docker container name")
    return value


@dataclass(frozen=True)
class MonitorConfig:
    auth_db: Path = Path('monitor/.local/auth/users.sqlite3')
    container_name: str = 'omega'
    host: str = '127.0.0.1'
    port: int = 8765
    reconnect_seconds: float = 2.0
    browser_log_limit: int = 1000
    security_events_file: Path | None = None
    cookie_secure: bool = True
    session_idle_seconds: int = 900
    session_lifetime_seconds: int = 28800

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None):
        values = os.environ if environ is None else environ
        host = values.get('OMA_MONITOR_HOST', '127.0.0.1').strip()
        if not host:
            raise ConfigurationError('OMA_MONITOR_HOST cannot be empty')
        try:
            port = int(values.get('OMA_MONITOR_PORT', '8765'))
        except ValueError as exc:
            raise ConfigurationError('OMA_MONITOR_PORT must be an integer') from exc
        if not 1 <= port <= 65535:
            raise ConfigurationError('OMA_MONITOR_PORT must be between 1 and 65535')
        secure = values.get('OMA_MONITOR_COOKIE_SECURE', 'true').lower()
        if secure not in {'true', 'false'}:
            raise ConfigurationError('OMA_MONITOR_COOKIE_SECURE must be true or false')
        if secure == 'false' and host not in {'127.0.0.1', '::1', 'localhost'}:
            raise ConfigurationError('Insecure cookies are allowed only on loopback')
        db = values.get('OMA_MONITOR_AUTH_DB', 'monitor/.local/auth/users.sqlite3').strip()
        if not db:
            raise ConfigurationError('OMA_MONITOR_AUTH_DB cannot be empty')
        return cls(auth_db=Path(db).expanduser(),
                   container_name=container_name(values.get('OMA_MONITOR_CONTAINER', 'omega').strip()),
                   host=host, port=port, cookie_secure=secure == 'true',
                   security_events_file=Path(values['OMA_MONITOR_SECURITY_EVENTS_FILE']).expanduser()
                   if values.get('OMA_MONITOR_SECURITY_EVENTS_FILE', '').strip() else None)
