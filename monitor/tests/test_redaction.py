import pytest

from monitor.redaction import redact


@pytest.mark.parametrize(
    ("source", "secret"),
    [
        ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
        ('request={"api_key":"sk-example123"}', "sk-example123"),
        ("password=hunter2 next=value", "hunter2"),
        ("bot 123456789:AAExampleTelegramToken_123456789", "AAExampleTelegramToken"),
        ("https://alice:supersecret@example.test/path", "supersecret"),
    ],
)
def test_recognizable_credentials_are_redacted(source, secret):
    result = redact(source)
    assert secret not in result
    assert "[REDACTED]" in result


def test_non_secret_log_content_is_preserved():
    assert redact("2026-01-01 job completed") == "2026-01-01 job completed"



@pytest.mark.parametrize('source', [
    'ANTHROPIC_API_KEY=secret-value', 'OPENAI_API_KEY=secret-value',
    'GITHUB_TOKEN=secret-value', 'DB_PASSWORD=secret-value',
    'Authorization: token secret-value',
    '{"Authorization": "Bearer secret-value"}',
    "{'proxy-authorization': 'Basic secret-value'}",
    'https://149.154.166.110:443/bot123456789:AAExampleTelegramToken_123456789/getUpdates',
    'bare sk-ant-abcdefghijklmnopqrstuvwxyz', 'bare sk-proj-abcdefghijklmnopqrstuvwxyz',
    'bare ghp_abcdefghijklmnopqrstuvwxyz', 'bare github_pat_abcdefghijklmnopqrstuvwxyz',
])
def test_reported_secret_formats_are_redacted(source):
    result = redact(source)
    assert '[REDACTED]' in result
    assert 'secret-value' not in result
    assert 'AAExampleTelegramToken' not in result
    assert 'abcdefghijklmnopqrstuvwxyz' not in result
