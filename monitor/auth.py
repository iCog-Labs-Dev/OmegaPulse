"""Local accounts and revocable server-side sessions; no browser-cached credentials."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from pathlib import Path

import pyotp
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeSerializer, BadSignature

USERNAME = re.compile(r"^[\w.@+-]{1,64}$", re.UNICODE)
ROLES = {"viewer", "operator"}
COOKIE = "oma_session"
DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32))


class LoginLimited(Exception):
    pass


class AuthStore:
    def __init__(self, path: Path, clock=time.time, idle_seconds=900, lifetime_seconds=28800):
        self.path = Path(path)
        self.clock = clock
        self.idle_seconds = idle_seconds
        self.lifetime_seconds = lifetime_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Exclusive, restrictive creation; never truncate an existing database.
        import os
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077:
            raise ValueError("Auth database must be private (chmod 600)")
        with self.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                    totp_secret TEXT, last_totp INTEGER NOT NULL DEFAULT -1);
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, username TEXT,
                    csrf TEXT NOT NULL, created REAL NOT NULL, touched REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts (
                    ip TEXT NOT NULL, username TEXT NOT NULL,
                    time REAL NOT NULL, failed INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS attempts_time ON attempts(time);
                CREATE INDEX IF NOT EXISTS attempts_user ON attempts(username, failed, time);
                CREATE INDEX IF NOT EXISTS attempts_ip ON attempts(ip, time);
            ''')

        with self.connection() as db:
            # Retire pre-login database rows from the previous implementation.
            db.execute("DELETE FROM sessions WHERE username IS NULL")
            db.execute("INSERT OR IGNORE INTO metadata VALUES('csrf_key', ?)", (secrets.token_hex(32),))
            key = db.execute("SELECT value FROM metadata WHERE name='csrf_key'").fetchone()[0]
        self.prelogin_signer = URLSafeSerializer(key, salt='oma-prelogin-v1')

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def add_user(self, username, password, role):
        if not USERNAME.fullmatch(username) or role not in ROLES:
            raise ValueError("Use a valid username and viewer/operator role")
        self.validate_password(password)
        with self.connection() as db:
            db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                       (username, generate_password_hash(password), role))

    @staticmethod
    def validate_password(password):
        if not 12 <= len(password) <= 1024:
            raise ValueError("Password must have between 12 and 1024 characters")

    def update_user(self, username, **changes):
        allowed = {"password_hash", "role", "enabled", "totp_secret", "last_totp"}
        if not changes or not changes.keys() <= allowed:
            raise ValueError("Unsupported account change")
        if "role" in changes and changes["role"] not in ROLES:
            raise ValueError("Role must be viewer or operator")
        with self.connection() as db:
            if not db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise ValueError("Unknown account")
            db.execute("UPDATE users SET " + ",".join(f"{key}=?" for key in changes) + " WHERE username=?",
                       (*changes.values(), username))
            db.execute("DELETE FROM sessions WHERE username=?", (username,))

    def users(self):
        with self.connection() as db:
            return [dict(row) for row in db.execute(
                "SELECT username,role,enabled,totp_secret IS NOT NULL AS mfa FROM users ORDER BY username")]

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def _cleanup(self, db, now):
        db.execute("DELETE FROM attempts WHERE time < ?", (now - 900,))
        db.execute("DELETE FROM sessions WHERE created < ? OR touched < ?",
                   (now - self.lifetime_seconds, now - self.idle_seconds))

    def _new_session(self, db, username, now):
        self._cleanup(db, now)
        if db.execute("SELECT count(*) FROM sessions").fetchone()[0] >= 10000:
            raise LoginLimited()
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        db.execute("INSERT INTO sessions VALUES(?,?,?,?,?)",
                   (self.digest(token), username, csrf, now, now))
        return token, csrf

    def anonymous_session(self):
        # Anonymous CSRF cookies are signed and short-lived, never database rows.
        csrf = secrets.token_urlsafe(32)
        token = 'prelogin.' + self.prelogin_signer.dumps({'csrf': csrf, 'created': self.clock()})
        return token, csrf

    def session(self, token, touch=False):
        if not token or len(token) > 256:
            return None
        now = self.clock()
        if token.startswith('prelogin.'):
            try:
                data = self.prelogin_signer.loads(token[9:])
                if 0 <= now - data['created'] < 300:
                    return {'username': None, 'csrf': data['csrf']}
            except (BadSignature, KeyError, TypeError):
                pass
            return None
        with self.connection() as db:
            row = db.execute('''SELECT s.*, u.role, u.enabled FROM sessions s
                LEFT JOIN users u ON s.username=u.username WHERE token_hash=?''',
                (self.digest(token),)).fetchone()
            if row is None:
                return None
            if (now - row["created"] >= self.lifetime_seconds or
                now - row["touched"] >= self.idle_seconds or
                (row["username"] is not None and not row["enabled"])):
                db.execute("DELETE FROM sessions WHERE token_hash=?", (self.digest(token),))
                return None
            if touch:
                db.execute("UPDATE sessions SET touched=? WHERE token_hash=?", (now, self.digest(token)))
            return dict(row)

    def revoke(self, token):
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (self.digest(token),))

    def login(self, username, password, otp, ip, previous_token):
        now = self.clock()
        username = username[:64]
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._cleanup(db, now)
            ip_count = db.execute("SELECT count(*) FROM attempts WHERE ip=?", (ip,)).fetchone()[0]
            failures = db.execute("SELECT count(*) FROM attempts WHERE username=? AND ip=? AND failed=1", (username, ip)).fetchone()[0]
            if ip_count >= 20 or failures >= 5:
                raise LoginLimited()
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            valid = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
            valid = bool(valid and user and user["enabled"])
            counter = None
            if valid and user["totp_secret"]:
                totp = pyotp.TOTP(user["totp_secret"])
                for step in (int(now // 30) - 1, int(now // 30), int(now // 30) + 1):
                    if step > user["last_totp"] and hmac.compare_digest(totp.at(step * 30).encode(), otp.encode()):
                        counter = step
                        break
                valid = counter is not None
            db.execute("INSERT INTO attempts VALUES(?,?,?,?)", (ip, username, now, int(not valid)))
            if not valid:
                return None
            if counter is not None:
                db.execute("UPDATE users SET last_totp=? WHERE username=?", (counter, username))
            db.execute("DELETE FROM attempts WHERE username=? AND ip=? AND failed=1", (username, ip))
            db.execute("DELETE FROM sessions WHERE token_hash=?", (self.digest(previous_token),))
            token, csrf = self._new_session(db, username, now)
            return token, csrf
