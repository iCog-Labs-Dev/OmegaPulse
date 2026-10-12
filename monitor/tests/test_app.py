from pathlib import Path
import re
import time

import pyotp
import pytest

from monitor.app import create_app
from monitor.auth import AuthStore, COOKIE
from monitor.config import MonitorConfig


class FakeBackend:
    def __init__(self):
        self.status_calls = 0
        self.actions = []

    def status(self):
        self.status_calls += 1
        return {'state': 'running', 'container': 'omega', 'agent_healthy': None}

    def log_events(self, stop_event=None):
        yield {'type': 'log', 'text': '<img src=x onerror=alert(1)>'}

    def perform_action(self, action):
        self.actions.append(action)
        return {**self.status(), 'action': action}


@pytest.fixture
def setup(tmp_path):
    now = [1700000000.0]
    store = AuthStore(tmp_path / 'auth.sqlite3', clock=lambda: now[0])
    store.add_user('alice', 'a-long-test-password', 'operator')
    store.add_user('bob', 'another-long-password', 'viewer')
    backend = FakeBackend()
    app = create_app(MonitorConfig(auth_db=store.path, cookie_secure=False), backend, auth_store=store)
    app.testing = True
    return app, app.test_client(), backend, store, now


def login(client, username='alice', password='a-long-test-password', otp='', headers=None):
    page = client.get('/login').get_data(as_text=True)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    return client.post('/login', json={'username': username, 'password': password, 'otp': otp, 'csrf_token': csrf}, headers=headers)


def token(client):
    page = client.get('/').get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)


def test_routes_require_session_and_basic_auth_is_no_longer_accepted(setup):
    _, client, backend, _, _ = setup
    for path in ('/api/status', '/api/logs', '/api/security/status', '/api/security/events'):
        response = client.get(path, headers={'Authorization': 'Basic YWxpY2U6YS1sb25nLXRlc3QtcGFzc3dvcmQ='})
        assert response.status_code == 401
        assert 'WWW-Authenticate' not in response.headers
        assert response.headers['Cache-Control'] == 'no-store'
    assert client.get('/').status_code == 303
    assert client.post('/api/actions/stop', json={}).status_code == 401
    assert backend.actions == []


def test_login_requires_csrf_and_rejects_invalid_credentials(setup):
    _, client, _, _, _ = setup
    assert client.post('/login', json={'username': 'alice', 'password': 'a-long-test-password'}).status_code == 403
    assert login(client, password='wrong-🔑').status_code == 401
    assert client.get('/api/status').status_code == 401


def test_sessions_rotate_after_login_and_have_cookie_security(setup):
    _, client, _, store, _ = setup
    client.get('/login')
    old = client.get_cookie(COOKIE).value
    response = login(client)
    assert response.status_code == 200
    assert client.get_cookie(COOKIE).value != old
    assert store.session(old)['username'] is None  # Pre-login tokens cannot authorize APIs.
    cookie = response.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
    assert 'a-long-test-password' not in store.path.read_bytes().decode(errors='ignore')
    assert client.get('/api/status').json['container'] == 'omega'


def test_secure_cookie_default(tmp_path):
    store = AuthStore(tmp_path / 'auth.db')
    store.add_user('alice', 'a-long-test-password', 'viewer')
    app = create_app(MonitorConfig(auth_db=store.path), FakeBackend(), auth_store=store)
    assert 'Secure' in app.test_client().get('/login').headers['Set-Cookie']


def test_viewer_cannot_control_container_even_with_valid_csrf(setup):
    _, client, backend, _, _ = setup
    assert login(client, 'bob', 'another-long-password').status_code == 200
    csrf = token(client)
    for action in ('start', 'stop', 'restart'):
        assert client.post('/api/actions/'+action, json={}, headers={'X-CSRF-Token': csrf}).status_code == 403
    assert backend.actions == []
    assert 'id="stop-container"' not in client.get('/').get_data(as_text=True)
    assert client.get('/api/security/status').status_code == 200


def test_operator_action_requires_csrf_json_and_fixed_target(setup):
    _, client, backend, _, _ = setup
    login(client)
    assert client.post('/api/actions/stop').status_code == 415
    assert client.post('/api/actions/stop', json={}).status_code == 403
    assert client.post('/api/actions/stop', json={}, headers={'X-CSRF-Token': 'é'}).status_code == 403
    headers = {'X-CSRF-Token': token(client)}
    assert client.post('/api/actions/restart', json={}, headers=headers).status_code == 200
    assert backend.actions == ['restart']
    assert client.post('/api/actions/start?container=other', json={}, headers=headers).status_code == 400
    assert client.get('/api/status?container=other').status_code == 400
    assert client.get('/api/logs?container=other').status_code == 400
    assert client.post('/api/actions/stop', json={}, headers={**headers,'Sec-Fetch-Site':'cross-site'}).status_code == 403
    assert backend.actions == ['restart']


def test_logout_revokes_server_session_and_requires_csrf(setup):
    app, client, _, _, _ = setup
    login(client)
    cookie = client.get_cookie(COOKIE).value
    assert client.post('/logout').status_code == 403
    assert client.post('/logout', headers={'X-CSRF-Token':token(client)}).status_code == 200
    attacker = app.test_client()
    attacker.set_cookie(COOKIE, cookie)
    assert attacker.get('/api/status').status_code == 401


@pytest.mark.parametrize('change',[{'enabled':0},{'role':'viewer'},{'password_hash':'unused'}])
def test_account_changes_revoke_sessions(setup, change):
    _, client, _, store, _ = setup
    login(client)
    store.update_user('alice', **change)
    assert client.get('/api/status').status_code == 401


@pytest.mark.parametrize('seconds',[901,28801])
def test_session_expiration(setup, seconds):
    _, client, _, _, now = setup
    login(client)
    now[0] += seconds
    assert client.get('/api/status').status_code == 401


def test_background_status_poll_does_not_extend_idle_session(setup):
    _, client, _, _, now = setup
    login(client)
    now[0] += 800
    assert client.get('/api/status').status_code == 200
    now[0] += 101
    assert client.get('/api/status').status_code == 401


def test_source_account_lockout_persists_and_does_not_lock_other_addresses(setup):
    app, client, _, _, now = setup
    for _ in range(5):
        assert login(client, password='wrong').status_code == 401
    restarted_store = AuthStore(setup[3].path, clock=lambda:now[0])
    restarted = create_app(MonitorConfig(auth_db=restarted_store.path,cookie_secure=False),
                           FakeBackend(),auth_store=restarted_store)
    other = restarted.test_client()
    assert login(other).status_code == 429
    other.environ_base['REMOTE_ADDR'] = '192.0.2.2'
    assert login(other).status_code == 200
    other.environ_base['REMOTE_ADDR'] = '127.0.0.1'
    now[0] += 901
    assert login(other).status_code == 200


def test_ip_limit_applies_across_usernames_and_ignores_forwarded_header(setup):
    _, client, _, _, _ = setup
    for number in range(20):
        assert login(client, username=f'unknown{number}', headers={'X-Forwarded-For':f'10.0.0.{number}'}).status_code == 401
    assert login(client).status_code == 429


def test_optional_mfa_requires_code_and_rejects_replay(setup):
    app, client, _, store, now = setup
    secret = pyotp.random_base32()
    store.update_user('alice', totp_secret=secret)
    assert login(client).status_code == 401
    assert login(client, otp='🔑').status_code == 401
    code = pyotp.TOTP(secret).at(now[0])
    assert login(client, otp=code).status_code == 200
    other = app.test_client()
    assert login(other, otp=code).status_code == 401
    now[0] += 30
    assert login(other, otp=pyotp.TOTP(secret).at(now[0])).status_code == 200


def test_session_csrf_is_not_shared_between_users(setup):
    app, client, _, _, _ = setup
    login(client)
    other = app.test_client()
    login(other, 'bob', 'another-long-password')
    assert token(client) != token(other)


def test_unicode_password_authenticates(setup):
    _, client, _, store, _ = setup
    store.add_user('opérateur', 'a-long-password-🔑', 'viewer')
    assert login(client, 'opérateur', 'a-long-password-🔑').status_code == 200


def test_log_stream_and_rendering_treat_text_as_data(setup):
    _, client, _, _, _ = setup
    login(client)
    response = client.get('/api/logs')
    assert response.content_type == 'text/event-stream; charset=utf-8'
    assert '"text": "<img src=x onerror=alert(1)>"' in response.get_data(as_text=True)
    script = (Path(__file__).parents[1] / 'static/monitor.js').read_text()
    assert 'logView.textContent' in script and 'innerHTML' not in script


def test_open_stream_stops_delivering_after_session_revocation(setup):
    _, client, _, store, _ = setup
    login(client)
    response = client.get('/api/logs', buffered=False)
    assert next(response.response) == b'retry: 3000\n\n'
    store.revoke(client.get_cookie(COOKIE).value)
    assert b'auth-expired' in next(response.response)
    with pytest.raises(StopIteration):
        next(response.response)
    response.close()


def test_startup_without_accounts_fails_closed(tmp_path):
    with pytest.raises(ValueError, match='No accounts'):
        create_app(MonitorConfig(auth_db=tmp_path/'empty.db'), FakeBackend())


def test_quiet_stream_closes_after_logout(setup):
    app, client, backend, store, _ = setup
    def quiet(stop_event=None):
        stop_event.wait(5)
        if False:
            yield None
    backend.log_events = quiet
    login(client)
    response = client.get('/api/logs', buffered=False)
    next(response.response)
    # Start collection and verify heartbeat while no Docker records exist.
    assert b'keepalive' in next(response.response)
    store.revoke(client.get_cookie(COOKIE).value)
    assert b'auth-expired' in next(response.response)
    response.close()


def test_prelogin_flood_does_not_fill_session_table(setup):
    app, client, _, store, now = setup
    # The reported 10,000-cookie-free-request attack creates no persistent rows.
    for _ in range(10001):
        anonymous, _ = store.anonymous_session()
        assert store.session(anonymous)['username'] is None
    with store.connection() as db:
        assert db.execute('SELECT count(*) FROM sessions').fetchone()[0] == 0
    assert login(client).status_code == 200
    now[0] += 301
    assert store.session(anonymous) is None


def test_tampered_prelogin_cookie_cannot_log_in(setup):
    _, client, _, _, _ = setup
    client.get('/login')
    client.set_cookie(COOKIE, client.get_cookie(COOKIE).value + 'tampered')
    assert client.post('/login', json={'csrf_token': 'anything'}).status_code == 403


def test_audit_success_is_visible_and_contains_no_credentials(setup, capfd):
    _, client, _, _, _ = setup
    # Handler may have been installed before capture; verify through a fresh handler.
    import io, logging
    from monitor.app import logger
    capture = io.StringIO()
    handler = logging.StreamHandler(capture)
    logger.addHandler(handler)
    try:
        login(client)
        client.post('/api/actions/start', json={}, headers={'X-CSRF-Token': token(client)})
    finally:
        logger.removeHandler(handler)
    output = capture.getvalue()
    assert 'login user=alice result=accepted' in output
    assert 'operator_action user=alice action=start' in output
    assert 'a-long-test-password' not in output


def test_stream_limit_leaves_controls_available_and_releases_slots(setup):
    app, client, backend, store, _ = setup
    login(client)
    responses = [client.get('/api/logs', buffered=False) for _ in range(4)]
    try:
        assert all(response.status_code == 200 for response in responses)
        assert client.get('/api/logs').status_code == 429
        assert client.get('/api/status').status_code == 200
        assert client.post('/api/actions/stop', json={}, headers={'X-CSRF-Token': token(client)}).status_code == 200
    finally:
        for response in responses:
            response.close()
    response = client.get('/api/logs', buffered=False)
    assert response.status_code == 200
    response.close()


def test_upgrade_retires_legacy_anonymous_rows_and_preserves_signed_cookies(setup):
    _, client, _, store, now = setup
    prelogin, _ = store.anonymous_session()
    assert login(client).status_code == 200
    authenticated = client.get_cookie(COOKIE).value
    with store.connection() as db:
        db.execute('INSERT INTO sessions VALUES(?,NULL,?,?,?)',
                   ('legacy-anonymous', 'old-csrf', now[0], now[0]))
    upgraded = AuthStore(store.path, clock=lambda: now[0])
    assert upgraded.session(prelogin)['username'] is None
    assert upgraded.session(authenticated)['username'] == 'alice'
    with upgraded.connection() as db:
        assert db.execute('SELECT count(*) FROM sessions WHERE username IS NULL').fetchone()[0] == 0
