import sys
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
    assert store.login('alice','a-long-cli-password','', '127.0.0.1',token)
    assert 'a-long-cli-password' not in capsys.readouterr().out


def test_cli_role_change_revokes_existing_session(tmp_path, monkeypatch):
    path=tmp_path/'users.sqlite3'
    monkeypatch.setenv('OMA_MONITOR_AUTH_DB',str(path))
    store=AuthStore(path)
    store.add_user('alice','a-long-cli-password','operator')
    anonymous,_=store.anonymous_session()
    token,_=store.login('alice','a-long-cli-password','', '127.0.0.1',anonymous)
    monkeypatch.setattr(sys,'argv',['users','role','alice','--role','viewer'])
    users.main()
    assert store.session(token) is None
    assert store.users()[0]['role']=='viewer'
