import pytest
from monitor.config import ConfigurationError, MonitorConfig


def test_default_target_and_secure_cookie():
    config = MonitorConfig.from_env({})
    assert config.container_name == 'omega'
    assert config.host == '127.0.0.1'
    assert config.cookie_secure


@pytest.mark.parametrize('name',['','other/container','--privileged','has space','injection" or true'])
def test_invalid_container_name(name):
    with pytest.raises(ConfigurationError, match='container name'):
        MonitorConfig.from_env({'OMA_MONITOR_CONTAINER':name})


def test_insecure_cookie_allowed_only_on_loopback():
    assert not MonitorConfig.from_env({'OMA_MONITOR_COOKIE_SECURE':'false'}).cookie_secure
    with pytest.raises(ConfigurationError, match='loopback'):
        MonitorConfig.from_env({'OMA_MONITOR_HOST':'0.0.0.0','OMA_MONITOR_COOKIE_SECURE':'false'})


@pytest.mark.parametrize('values',[{'OMA_MONITOR_PORT':'foo'},{'OMA_MONITOR_PORT':'0'},
                                  {'OMA_MONITOR_COOKIE_SECURE':'maybe'},{'OMA_MONITOR_AUTH_DB':''}])
def test_bad_configuration(values):
    with pytest.raises(ConfigurationError):
        MonitorConfig.from_env(values)
