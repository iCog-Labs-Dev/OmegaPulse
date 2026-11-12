"""Private local accounts, mandatory two-step MFA, and revocable sessions."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

from itsdangerous import BadSignature, URLSafeSerializer
import pyotp
from werkzeug.security import check_password_hash, generate_password_hash

USERNAME = re.compile(r"^[\w.@+-]{1,64}$", re.UNICODE)
ROLES = {"viewer", "operator"}
COOKIE = "oma_session"
CHALLENGE_SECONDS = 300
DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32))


class LoginLimited(Exception):
    pass


class SessionExpired(Exception):
    pass


class AuthStore:
    def __init__(self, path: Path, clock=time.time, idle_seconds=3600, lifetime_seconds=28800):
        self.path, self.clock = Path(path), clock
        self.idle_seconds, self.lifetime_seconds = idle_seconds, lifetime_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
                    token_hash TEXT PRIMARY KEY, username TEXT, csrf TEXT NOT NULL,
                    created REAL NOT NULL, touched REAL NOT NULL,
                    phase TEXT NOT NULL, pending_secret TEXT, pending_until REAL, pending_user TEXT, failures INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS attempts (
                    ip TEXT NOT NULL, username TEXT NOT NULL, time REAL NOT NULL, failed INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS attempts_time ON attempts(time);
                CREATE INDEX IF NOT EXISTS attempts_user ON attempts(username, failed, time);
                CREATE INDEX IF NOT EXISTS attempts_ip ON attempts(ip, time);
            ''')
            db.execute('BEGIN IMMEDIATE')
            columns = {row['name'] for row in db.execute('PRAGMA table_info(sessions)')}
            for name, declaration in [('phase', "TEXT NOT NULL DEFAULT 'legacy'"),
                                      ('pending_secret', 'TEXT'), ('pending_until', 'REAL'), ('pending_user', 'TEXT'),
                                      ('failures','INTEGER NOT NULL DEFAULT 0')]:
                if name not in columns:
                    db.execute(f'ALTER TABLE sessions ADD COLUMN {name} {declaration}')
            # Invalidate password-only AND legacy MFA sessions once on upgrade.
            if not db.execute("SELECT 1 FROM metadata WHERE name='mandatory_mfa_v1'").fetchone():
                db.execute('DELETE FROM sessions')
                db.execute("INSERT INTO metadata VALUES('mandatory_mfa_v1','1')")
            db.execute("DELETE FROM sessions WHERE phase='legacy' OR (username IS NULL AND pending_user IS NULL)")
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
            raise ValueError('Use a valid username and viewer/operator role')
        self.validate_password(password)
        with self.connection() as db:
            db.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',
                       (username, generate_password_hash(password), role))

    @staticmethod
    def validate_password(password):
        if not 12 <= len(password) <= 1024:
            raise ValueError('Password must have between 12 and 1024 characters')

    def update_user(self, username, **changes):
        allowed = {'password_hash', 'role', 'enabled', 'totp_secret', 'last_totp'}
        if not changes or not changes.keys() <= allowed:
            raise ValueError('Unsupported account change')
        if 'role' in changes and changes['role'] not in ROLES:
            raise ValueError('Role must be viewer or operator')
        with self.connection() as db:
            if not db.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
                raise ValueError('Unknown account')
            db.execute('UPDATE users SET '+','.join(f'{key}=?' for key in changes)+' WHERE username=?',
                       (*changes.values(), username))
            db.execute('DELETE FROM sessions WHERE username=? OR pending_user=?', (username,username))

    def users(self):
        with self.connection() as db:
            return [dict(row) for row in db.execute(
                'SELECT username,role,enabled,totp_secret IS NOT NULL AS mfa FROM users ORDER BY username')]

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def _cleanup(self, db, now):
        db.execute('DELETE FROM attempts WHERE time < ?', (now-900,))
        db.execute('DELETE FROM sessions WHERE created < ? OR touched < ? OR (phase != ? AND created <= ?)',
                   (now-self.lifetime_seconds, now-self.idle_seconds, 'full', now-CHALLENGE_SECONDS))
        db.execute('UPDATE sessions SET pending_secret=NULL,pending_until=NULL WHERE pending_until <= ?', (now,))

    def _new_session(self, db, username, now, phase):
        self._cleanup(db, now)
        if db.execute('SELECT count(*) FROM sessions').fetchone()[0] >= 10000:
            raise LoginLimited()
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        secret = pyotp.random_base32() if phase == 'enroll' else None
        # Pending identities live separately so older code also fails closed: it
        # only recognizes a non-null sessions.username as authenticated.
        db.execute('''INSERT INTO sessions(token_hash,username,csrf,created,touched,phase,
                       pending_secret,pending_until,pending_user) VALUES(?,?,?,?,?,?,?,?,?)''',
                   (self.digest(token), username if phase=='full' else None, csrf, now, now, phase, secret,
                    now+CHALLENGE_SECONDS if secret else None, username if phase!='full' else None))
        return token, csrf

    def anonymous_session(self):
        csrf = secrets.token_urlsafe(32)
        return 'prelogin.'+self.prelogin_signer.dumps({'csrf':csrf, 'created':self.clock()}), csrf

    def _lookup(self, db, token, now, phases):
        row = db.execute('''SELECT s.*,u.username AS account_username,u.role,u.enabled,u.totp_secret IS NOT NULL AS mfa
                            FROM sessions s JOIN users u ON COALESCE(s.username,s.pending_user)=u.username
                            WHERE token_hash=?''', (self.digest(token),)).fetchone()
        if not row or not row['enabled']:
            return None
        if (now-row['created'] >= self.lifetime_seconds or now-row['touched'] >= self.idle_seconds or
            (row['phase'] != 'full' and now-row['created'] >= CHALLENGE_SECONDS)):
            return None
        if row['phase'] == 'full' and not row['mfa']:
            return None
        if row['phase'] not in phases:
            return None
        return {**dict(row), 'username':row['account_username']}

    def session(self, token, touch=False, phases=('full',)):
        """Authorize completed MFA by default; challenge routes explicitly opt in."""
        if not token or len(token) > 256:
            return None
        now = self.clock()
        if token.startswith('prelogin.'):
            try:
                data = self.prelogin_signer.loads(token[9:])
                if 0 <= now-data['created'] < CHALLENGE_SECONDS:
                    return {'username':None, 'phase':'anonymous', 'csrf':data['csrf']}
            except (BadSignature, KeyError, TypeError):
                pass
            return None
        with self.connection() as db:
            row = self._lookup(db, token, now, phases)
            if row and touch and row['phase'] == 'full':
                db.execute('UPDATE sessions SET touched=? WHERE token_hash=?', (now, self.digest(token)))
            return row

    def revoke(self, token):
        with self.connection() as db:
            db.execute('DELETE FROM sessions WHERE token_hash=?', (self.digest(token),))

    def _limit(self, db, username, ip, now):
        self._cleanup(db, now)
        ip_count = db.execute('SELECT count(*) FROM attempts WHERE ip=?', (ip,)).fetchone()[0]
        failures = db.execute('SELECT count(*) FROM attempts WHERE username=? AND ip=? AND failed=1',
                              (username, ip)).fetchone()[0]
        if ip_count >= 20 or failures >= 5:
            raise LoginLimited()

    @staticmethod
    def _record(db, username, ip, now, valid):
        db.execute('INSERT INTO attempts VALUES(?,?,?,?)', (ip,username,now,int(not valid)))

    @staticmethod
    def _clear_failures(db, username, ip):
        db.execute('DELETE FROM attempts WHERE username=? AND ip=? AND failed=1', (username,ip))

    @staticmethod
    def _otp_counter(secret, code, now, last=-1):
        if not secret or not re.fullmatch(r'[0-9]{6}', code):
            return None
        totp = pyotp.TOTP(secret)
        for step in (int(now//30)-1, int(now//30), int(now//30)+1):
            if step > last and hmac.compare_digest(totp.at(step*30), code):
                return step
        return None

    def begin_login(self, username, password, ip, previous_token):
        now = self.clock()
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._limit(db, username, ip, now)
            user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            valid = check_password_hash(user['password_hash'] if user else DUMMY_HASH, password)
            valid = bool(valid and user and user['enabled'])
            self._record(db,username,ip,now,valid)
            if not valid:
                return None
            # Keep a bounded number of pending challenges per account.
            db.execute('''DELETE FROM sessions WHERE token_hash IN
                          (SELECT token_hash FROM sessions WHERE pending_user=? AND phase != 'full'
                           ORDER BY created DESC LIMIT -1 OFFSET 4)''', (username,))
            db.execute('DELETE FROM sessions WHERE token_hash=?', (self.digest(previous_token),))
            return self._new_session(db,username,now,'verify' if user['totp_secret'] else 'enroll')

    def complete_login(self, token, code, ip):
        now = self.clock()
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = self._lookup(db,token,now,('verify','enroll'))
            if not current:
                raise SessionExpired()
            name = current['username']
            self._limit(db,name,ip,now)
            user = db.execute('SELECT * FROM users WHERE username=?', (name,)).fetchone()
            enrolling = current['phase'] == 'enroll' and not user['totp_secret']
            secret = current['pending_secret'] if enrolling else user['totp_secret']
            counter = self._otp_counter(secret,code,now,-1 if enrolling else user['last_totp'])
            self._record(db,name,ip,now,counter is not None)
            if counter is None:
                # Bound guesses per challenge even when the source address changes.
                if current['failures'] >= 4:
                    db.execute('DELETE FROM sessions WHERE token_hash=?',(self.digest(token),))
                else:
                    db.execute('UPDATE sessions SET failures=failures+1 WHERE token_hash=?',(self.digest(token),))
                return None
            if enrolling:
                db.execute('UPDATE users SET totp_secret=?,last_totp=? WHERE username=?', (secret,counter,name))
                db.execute('DELETE FROM sessions WHERE username=? OR pending_user=?', (name,name))
            else:
                db.execute('UPDATE users SET last_totp=? WHERE username=?', (counter,name))
                db.execute('DELETE FROM sessions WHERE token_hash=?', (self.digest(token),))
            self._clear_failures(db,name,ip)
            return self._new_session(db,name,now,'full')

    def enrollment(self, token):
        current = self.session(token,phases=('enroll','full'))
        if not current or not current.get('pending_secret') or current['pending_until'] <= self.clock():
            return None
        secret = current['pending_secret']
        return {'secret':secret, 'uri':pyotp.TOTP(secret).provisioning_uri(current['username'],issuer_name='Omega-Pulse')}

    def _reauthenticate(self, db, token, password, code, ip, now):
        current = self._lookup(db,token,now,('full',))
        if not current:
            raise SessionExpired()
        name = current['username']
        self._limit(db,name,ip,now)
        user = db.execute('SELECT * FROM users WHERE username=?', (name,)).fetchone()
        password_ok = check_password_hash(user['password_hash'],password)
        counter = self._otp_counter(user['totp_secret'],code,now,user['last_totp']) if password_ok else None
        self._record(db,name,ip,now,counter is not None)
        if counter is None:
            return None
        db.execute('UPDATE users SET last_totp=? WHERE username=?',(counter,name))
        self._clear_failures(db,name,ip)
        return name

    def change_password(self, token, password, code, new_password, ip):
        self.validate_password(new_password)
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            name = self._reauthenticate(db,token,password,code,ip,self.clock())
            if name is None:
                return False
            db.execute('UPDATE users SET password_hash=? WHERE username=?',(generate_password_hash(new_password),name))
            db.execute('DELETE FROM sessions WHERE username=? OR pending_user=?',(name,name))
            return True

    def begin_replacement(self, token, password, code, ip):
        now = self.clock()
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if self._reauthenticate(db,token,password,code,ip,now) is None:
                return False
            replacement_token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            db.execute('''UPDATE sessions SET token_hash=?,csrf=?,pending_secret=?,pending_until=?,touched=?
                          WHERE token_hash=?''',
                       (self.digest(replacement_token),csrf,pyotp.random_base32(),now+CHALLENGE_SECONDS,now,self.digest(token)))
            return replacement_token, csrf

    def complete_replacement(self, token, code, ip):
        now = self.clock()
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            current = self._lookup(db,token,now,('full',))
            if not current:
                raise SessionExpired()
            name = current['username']
            self._limit(db,name,ip,now)
            secret = current['pending_secret'] if (current['pending_until'] or 0) > now else None
            counter = self._otp_counter(secret,code,now)
            self._record(db,name,ip,now,counter is not None)
            if counter is None:
                return False
            db.execute('UPDATE users SET totp_secret=?,last_totp=? WHERE username=?',(secret,counter,name))
            db.execute('DELETE FROM sessions WHERE username=? OR pending_user=?',(name,name))
            self._clear_failures(db,name,ip)
            return True

    def cancel_replacement(self, token):
        with self.connection() as db:
            db.execute('UPDATE sessions SET pending_secret=NULL,pending_until=NULL WHERE token_hash=?',
                       (self.digest(token),))
