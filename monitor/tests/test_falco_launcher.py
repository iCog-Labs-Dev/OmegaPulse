import os
from pathlib import Path
import subprocess
import pytest


SCRIPT = Path(__file__).resolve().parents[1]/'scripts/falco.sh'


def test_zero_writer_identity_fails_before_docker_launch(tmp_path):
    result = subprocess.run(['bash', str(SCRIPT)], env={**os.environ,
                            'OMA_MONITOR_WRITER_UID': '0', 'OMA_MONITOR_WRITER_GID': '0'},
                            text=True, capture_output=True)
    assert result.returncode == 1
    assert 'non-root monitor account IDs' in result.stderr


@pytest.mark.parametrize('owner', ['1000:1000', '2000:2000'])
def test_explicit_writer_ids_are_forwarded_and_directory_ownership_checked(tmp_path, owner):
    commands = tmp_path/'commands'
    fake_bin = tmp_path/'bin'
    fake_bin.mkdir()
    for name, body in {
        'id': 'echo 0',
        'stat': f'echo {owner}',
        'docker': f'''echo "$*" >> '{commands}'
if [ "$1" = container ]; then exit 1; fi
exit 0''',
    }.items():
        path = fake_bin/name
        path.write_text('#!/bin/sh\n'+body+'\n')
        path.chmod(0o700)
    result = subprocess.run(['bash', str(SCRIPT)], env={**os.environ,
                            'PATH': str(fake_bin)+':'+os.environ['PATH'],
                            'OMA_MONITOR_WRITER_UID': '1000', 'OMA_MONITOR_WRITER_GID': '1000',
                            'OMA_MONITOR_EVENTS_DIR': str(tmp_path/'events')},
                            text=True, capture_output=True)
    if owner != '1000:1000':
        assert result.returncode == 1
        assert 'Events directory must be owned' in result.stderr
        assert 'run ' not in commands.read_text()
        return
    assert result.returncode == 0, result.stderr
    assert 'OMA_MONITOR_WRITER_UID=1000' in commands.read_text()
    assert 'OMA_MONITOR_WRITER_GID=1000' in commands.read_text()
