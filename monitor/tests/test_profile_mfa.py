"""Security boundaries for mandatory MFA, upgrades and profile changes."""
from concurrent.futures import ThreadPoolExecutor
import re
import sqlite3

import pyotp
import pytest
from werkzeug.security import generate_password_hash

from monitor.auth import AuthStore, COOKIE, SessionExpired
from test_app import setup, login, password_step, token

SECRET='JBSWY3DPEHPK3PXP'


def csrf_page(client, path):
    page=client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"',page).group(1)


def confirm(client, otp):
    return client.post('/login/mfa',json={'otp':otp,'csrf_token':csrf_page(client,'/login/mfa')})


def profile_post(client, action, **fields):
    return client.post('/profile/'+action,json={'csrf_token':csrf_page(client,'/profile'),**fields})


def code(now, secret=SECRET):
    return pyotp.TOTP(secret).at(now[0])


def test_new_account_must_enroll_before_any_dashboard_access(setup):
    app,client,backend,store,now=setup
    store.add_user('new-user','new-user-long-password','viewer')
    assert password_step(client,'new-user','new-user-long-password').json['next']=='/login/mfa'
    pending=client.get_cookie(COOKIE).value
    assert store.session(pending) is None
    for path in ('/api/status','/api/logs','/api/security/status','/api/security/events'):
        assert client.get(path).status_code==401
    assert client.get('/').status_code==303
    assert client.get('/profile').status_code==303
    assert client.post('/api/actions/stop',json={}).status_code==401
    assert backend.actions==[]
    page=client.get('/login/mfa')
    secret=store.enrollment(pending)['secret']
    assert '<svg' in page.get_data(as_text=True)
    assert secret in page.get_data(as_text=True)
    assert page.headers['Cache-Control']=='no-store'
    assert store.enrollment(pending)['secret']==secret  # Refresh does not change enrollment.
    assert confirm(client,'abcdef').status_code==401
    assert not next(u for u in store.users() if u['username']=='new-user')['mfa']
    assert confirm(client,code(now,secret)).status_code==200
    full=client.get_cookie(COOKIE).value
    assert full!=pending
    assert store.session(full)['phase']=='full'
    assert store.session(pending,phases=('enroll','verify')) is None
    assert client.get('/api/status').status_code==200
    assert secret not in client.get('/profile').get_data(as_text=True)


def test_password_request_cannot_skip_second_step_even_with_valid_otp(setup):
    _,client,_,store,now=setup
    csrf=csrf_page(client,'/login')
    response=client.post('/login',json={'username':'alice','password':'a-long-test-password',
                                      'otp':code(now),'csrf_token':csrf})
    assert response.status_code==200
    assert client.get('/api/status').status_code==401
    assert client.post('/profile/password',json={}).status_code==401
    assert 'Set up your authenticator' not in client.get('/login/mfa').get_data(as_text=True)
    assert confirm(client,code(now)).status_code==200


def test_pending_cookie_expires_without_extension_and_cannot_be_replayed(setup):
    app,client,_,store,now=setup
    password_step(client)
    pending=client.get_cookie(COOKIE).value
    for _ in range(3):
        now[0]+=90
        assert client.get('/login/mfa').status_code==200
    now[0]+=31
    assert client.get('/login/mfa').status_code==303
    assert store.session(pending,phases=('verify',)) is None
    assert client.get('/api/status').status_code==401


def test_enrollment_winner_revokes_other_pending_enrollments(setup):
    app,client,_,store,now=setup
    store.add_user('new','new-long-password','viewer')
    other=app.test_client()
    password_step(client,'new','new-long-password')
    first=client.get_cookie(COOKIE).value
    password_step(other,'new','new-long-password')
    second=other.get_cookie(COOKIE).value
    first_secret=store.enrollment(first)['secret']
    second_secret=store.enrollment(second)['secret']
    assert first_secret!=second_secret
    assert confirm(client,code(now,first_secret)).status_code==200
    assert store.enrollment(second) is None
    assert other.post('/login/mfa',json={'otp':code(now,second_secret),'csrf_token':'old'}).status_code==401


def test_mfa_confirmation_is_atomic_under_concurrent_replay(setup):
    _,client,_,store,now=setup
    password_step(client)
    pending=client.get_cookie(COOKIE).value
    def finish(_):
        try:
            return bool(store.complete_login(pending,code(now),'192.0.2.10'))
        except SessionExpired:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(finish,range(2)))==[False,True]


def test_mfa_failures_cannot_be_cleared_by_restarting_password_step(setup):
    app,client,_,_,now=setup
    password_step(client)
    for _ in range(5):
        assert confirm(client,'abcdef').status_code==401
    assert password_step(client).status_code==429
    other=app.test_client()
    other.environ_base['REMOTE_ADDR']='192.0.2.22'
    assert login(other).status_code==200
    now[0]+=901
    assert login(client).status_code==200


@pytest.mark.parametrize('username,password',[('alice','a-long-test-password'),('bob','another-long-password')])
def test_both_roles_can_change_own_password_and_all_sessions_are_revoked(setup,username,password):
    app,client,_,store,now=setup
    assert login(client,username,password).status_code==200
    other=app.test_client()
    now[0]+=30
    assert login(other,username,password).status_code==200
    now[0]+=30
    assert profile_post(client,'password',current_password=password,otp=code(now),
                        new_password='new-long-profile-password',confirm_password='new-long-profile-password').status_code==200
    assert client.get('/api/status').status_code==401
    assert other.get('/api/status').status_code==401
    assert password_step(client,username,password).status_code==401
    now[0]+=30
    assert login(client,username,'new-long-profile-password').status_code==200
    assert next(u for u in store.users() if u['username']==username)['role']==('viewer' if username=='bob' else 'operator')


@pytest.mark.parametrize('changes,status',[
    ({'current_password':'wrong'},401),({'otp':'abcdef'},401),
    ({'confirm_password':'different'},400),({'new_password':'short','confirm_password':'short'},400),
])
def test_password_change_rejects_bad_credentials_and_validation_without_revocation(setup,changes,status):
    _,client,_,_,now=setup
    login(client); now[0]+=30
    fields={'current_password':'a-long-test-password','otp':code(now),
            'new_password':'new-long-test-password','confirm_password':'new-long-test-password'}
    fields.update(changes)
    assert profile_post(client,'password',**fields).status_code==status
    assert client.get('/api/status').status_code==200


def test_profile_changes_require_csrf_and_same_origin(setup):
    _,client,_,_,_=setup
    login(client)
    assert client.post('/profile/password',json={}).status_code==403
    csrf=csrf_page(client,'/profile')
    assert client.post('/profile/mfa-start',json={'csrf_token':csrf},headers={'Sec-Fetch-Site':'cross-site'}).status_code==403
    assert client.post('/profile/mfa-cancel',json={'csrf_token':'🔑'}).status_code==403


def test_mfa_replacement_keeps_old_factor_until_confirmed_and_revokes_sessions(setup):
    app,client,_,store,now=setup
    login(client)
    other=app.test_client(); now[0]+=30; login(other)
    now[0]+=30
    assert profile_post(client,'mfa-start',current_password='a-long-test-password',otp=code(now)).status_code==200
    replacement=store.enrollment(client.get_cookie(COOKIE).value)['secret']
    with store.connection() as db:
        assert db.execute("SELECT totp_secret FROM users WHERE username='alice'").fetchone()[0]==SECRET
    assert profile_post(client,'mfa-confirm',otp='abcdef').status_code==401
    assert client.get('/api/status').status_code==200
    assert profile_post(client,'mfa-confirm',otp=code(now,replacement)).status_code==200
    assert other.get('/api/status').status_code==401
    assert client.get('/api/status').status_code==401
    now[0]+=30
    assert login(client,otp=code(now,SECRET)).status_code==401
    assert login(client,otp=code(now,replacement)).status_code==200


def test_replacement_requires_old_factor_and_cancellation_preserves_it(setup):
    _,client,_,store,now=setup
    login(client); now[0]+=30
    assert profile_post(client,'mfa-start',current_password='a-long-test-password',otp='abcdef').status_code==401
    assert store.enrollment(client.get_cookie(COOKIE).value) is None
    assert profile_post(client,'mfa-start',current_password='a-long-test-password',otp=code(now)).status_code==200
    assert profile_post(client,'mfa-cancel').status_code==200
    assert store.enrollment(client.get_cookie(COOKIE).value) is None
    now[0]+=30
    assert login(client).status_code==200


def test_replacement_expires_without_changing_active_factor(setup):
    _,client,_,store,now=setup
    login(client); now[0]+=30
    profile_post(client,'mfa-start',current_password='a-long-test-password',otp=code(now))
    secret=store.enrollment(client.get_cookie(COOKIE).value)['secret']
    now[0]+=301
    assert store.enrollment(client.get_cookie(COOKIE).value) is None
    assert profile_post(client,'mfa-confirm',otp=code(now,secret)).status_code==401
    assert login(client).status_code==200


def test_admin_reset_revokes_access_and_forces_enrollment_again(setup):
    _,client,_,store,_=setup
    login(client)
    store.update_user('alice',totp_secret=None,last_totp=-1)
    assert client.get('/api/status').status_code==401
    assert password_step(client).status_code==200
    assert client.get('/api/status').status_code==401
    assert store.enrollment(client.get_cookie(COOKIE).value)


def test_pending_sign_in_can_be_cancelled_with_csrf(setup):
    _,client,_,store,_=setup
    password_step(client)
    pending=client.get_cookie(COOKIE).value
    csrf=csrf_page(client,'/login/mfa')
    assert client.post('/logout',data={'csrf_token':csrf}).status_code==303
    assert store.session(pending,phases=('verify','enroll')) is None


def test_legacy_sessions_invalidated_once_and_accounts_factors_preserved(tmp_path):
    path=tmp_path/'legacy.sqlite3'
    with sqlite3.connect(path) as db:
        db.executescript('''CREATE TABLE users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,
            role TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,totp_secret TEXT,last_totp INTEGER NOT NULL DEFAULT -1);
            CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,username TEXT,csrf TEXT NOT NULL,created REAL NOT NULL,touched REAL NOT NULL);''')
        password_hash=generate_password_hash('existing-long-password')
        db.execute('INSERT INTO users VALUES(?,?,?,?,?,?)',('existing',password_hash,'operator',1,SECRET,-1))
        db.execute('INSERT INTO sessions VALUES(?,?,?,?,?)',(AuthStore.digest('old-cookie'),'existing','old-csrf',1700000000,1700000000))
    path.chmod(0o600)
    now=[1700000000.0]
    store=AuthStore(path,clock=lambda:now[0])
    assert store.session('old-cookie') is None
    pending,_=store.begin_login('existing','existing-long-password','127.0.0.1','old')
    assert store.session(pending) is None
    full,_=store.complete_login(pending,code(now),'127.0.0.1')
    restarted=AuthStore(path,clock=lambda:now[0])
    assert restarted.session(full)['username']=='existing'
    with restarted.connection() as db:
        row=db.execute('SELECT * FROM users').fetchone()
        assert row['password_hash']==password_hash and row['totp_secret']==SECRET


def test_pending_session_is_also_unauthorized_to_legacy_session_lookup(setup):
    _,client,_,store,_=setup
    password_step(client)
    pending=client.get_cookie(COOKIE).value
    # Old monitors authorize only a non-null sessions.username. Keep pending
    # identities separate even if an old process briefly overlaps an upgrade.
    with store.connection() as db:
        row=db.execute('SELECT username,pending_user FROM sessions WHERE token_hash=?',
                       (store.digest(pending),)).fetchone()
        assert row['username'] is None
        assert row['pending_user']=='alice'
    assert store.session(pending) is None


def test_completed_login_does_not_log_out_when_revisiting_second_step(setup):
    _,client,_,_,_=setup
    login(client)
    assert client.get('/login/mfa').status_code==303
    assert client.get('/api/status').status_code==200


def test_security_change_cannot_target_another_account_or_reuse_login_code(setup):
    _,client,_,store,now=setup
    login(client)
    assert profile_post(client,'mfa-start',current_password='a-long-test-password',otp=code(now)).status_code==401
    now[0]+=30
    assert profile_post(client,'password',username='bob',role='operator',current_password='a-long-test-password',
                        otp=code(now),new_password='changed-alice-password',confirm_password='changed-alice-password').status_code==200
    now[0]+=30
    assert login(client,'bob','another-long-password').status_code==200
    assert next(u for u in store.users() if u['username']=='bob')['role']=='viewer'


def test_factor_reauthentication_rotates_cookie_before_exposing_new_secret(setup):
    app,client,_,store,now=setup
    login(client)
    old_cookie=client.get_cookie(COOKIE).value
    old_csrf=csrf_page(client,'/profile')
    now[0]+=30
    assert profile_post(client,'mfa-start',current_password='a-long-test-password',otp=code(now)).status_code==200
    new_cookie=client.get_cookie(COOKIE).value
    assert new_cookie!=old_cookie
    assert csrf_page(client,'/profile')!=old_csrf
    attacker=app.test_client(); attacker.set_cookie(COOKIE,old_cookie)
    assert attacker.get('/profile').status_code==303
    assert store.enrollment(old_cookie) is None
    assert store.enrollment(new_cookie)


def test_password_form_supports_documented_unicode_length_limit(setup):
    _,client,_,_,now=setup
    login(client); now[0]+=30
    password='🔑'*1024
    assert profile_post(client,'password',current_password='a-long-test-password',otp=code(now),
                        new_password=password,confirm_password=password).status_code==200
    now[0]+=30
    assert login(client,password=password).status_code==200


def test_oversized_authentication_request_remains_bounded(setup):
    _,client,_,_,_=setup
    assert client.post('/login',data=b'x'*65537,content_type='application/json').status_code==413


def test_mfa_challenge_guess_limit_applies_across_source_addresses(setup):
    _,client,_,store,_=setup
    password_step(client)
    pending=client.get_cookie(COOKIE).value
    for number in range(5):
        client.environ_base['REMOTE_ADDR']=f'192.0.2.{number+1}'
        assert confirm(client,'abcdef').status_code==401
    assert store.session(pending,phases=('verify','enroll')) is None
    assert client.get('/login/mfa').status_code==303
    assert client.get('/api/status').status_code==401


@pytest.mark.parametrize('field',['csrf_token','username','password'])
def test_malformed_unicode_auth_fields_fail_closed_instead_of_server_error(setup,field):
    _,client,_,_,_=setup
    csrf=csrf_page(client,'/login')
    values={'username':'alice','password':'a-long-test-password','csrf_token':csrf}
    values[field]='\ud800'
    assert client.post('/login',json=values).status_code==403
    assert client.get('/api/status').status_code==401
