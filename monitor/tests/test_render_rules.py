from pathlib import Path
import pytest
from monitor.config import ConfigurationError
from monitor.render_rules import render


def test_target_rendered_from_same_validated_configuration():
    template=(Path(__file__).parents[1]/'falco/oma_rules.yaml').read_text()
    rules=render(template,'my-oma.2')
    assert 'condition: container.name = "my-oma.2"' in rules
    assert '__OMA_MONITOR_CONTAINER__' not in rules
    assert 'condition: container.name = omega' not in rules


@pytest.mark.parametrize('name',['evil" or true','', '--privileged','a b'])
def test_target_injection_rejected(name):
    with pytest.raises(ConfigurationError):render('__OMA_MONITOR_CONTAINER__',name)
