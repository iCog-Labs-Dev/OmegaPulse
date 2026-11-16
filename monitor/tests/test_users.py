import sys
import pyotp
import pytest
from monitor.auth import AuthStore
from monitor import users


def test_cli_creates_individual_role_and_hides_password(tmp_path, monkeypatch, capsys):
    path=tmp_path/'users.sqlite3'
    monkeypatch.setenv('OMA_MONITOR_AUTH_DB',str(path))
    monkeypatch.setattr(sys,'argv',['users','add','alice','--role','operator'])
    monkeypatch.setattr(users.getpass,'getpass',lambda _prompt:'a-long-cli-password')
    users.main()
    store=AuthStore(path)
    assert store.users()==[{'username':'alice','role':'operator','enabled':1,'mfa':0}]
    token,_=store.anonymous_session()
    pending,_=store.begin_login('alice','a-long-cli-password','127.0.0.1',token)
    assert store.session(pending) is None
    assert store.enrollment(pending)
    assert 'a-long-cli-password' not in capsys.readouterr().out


def test_cli_role_change_revokes_existing_session(tmp_path, monkeypatch):
    path=tmp_path/'users.sqlite3'
    monkeypatch.setenv('OMA_MONITOR_AUTH_DB',str(path))
    store=AuthStore(path)
    store.add_user('alice','a-long-cli-password','operator')
    anonymous,_=store.anonymous_session()
    pending,_=store.begin_login('alice','a-long-cli-password','127.0.0.1',anonymous)
    secret=store.enrollment(pending)['secret']
    token,_=store.complete_login(pending,pyotp.TOTP(secret).at(store.clock()),'127.0.0.1')
    monkeypatch.setattr(sys,'argv',['users','role','alice','--role','viewer'])
    users.main()
    assert store.session(token) is None
    assert store.users()[0]['role']=='viewer'


def test_cli_mfa_reset_revokes_full_and_pending_sessions_and_forces_enrollment(tmp_path,monkeypatch):
    path=tmp_path/'users.sqlite3'
    monkeypatch.setenv('OMA_MONITOR_AUTH_DB',str(path))
    store=AuthStore(path)
    store.add_user('alice','a-long-cli-password','operator')
    anonymous,_=store.anonymous_session()
    pending,_=store.begin_login('alice','a-long-cli-password','127.0.0.1',anonymous)
    secret=store.enrollment(pending)['secret']
    full,_=store.complete_login(pending,pyotp.TOTP(secret).at(store.clock()),'127.0.0.1')
    waiting,_=store.begin_login('alice','a-long-cli-password','127.0.0.1','another-browser')
    monkeypatch.setattr(sys,'argv',['users','disable-mfa','alice'])
    users.main()
    assert store.session(full) is None
    assert store.session(waiting,phases=('verify','enroll')) is None
    new_pending,_=store.begin_login('alice','a-long-cli-password','127.0.0.1','new-browser')
    assert store.session(new_pending) is None
    assert store.enrollment(new_pending)
