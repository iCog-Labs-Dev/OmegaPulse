"""Opt-in native syscall check using an approved sensor and a disposable target.

Run from the repository root. This never controls the existing Oma container.
The sensor needs privileged kernel access; the target has no host mounts/socket.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import time


def docker(*args):
    result = subprocess.run(['docker', *map(str, args)], check=True, text=True,
                            capture_output=True, timeout=90)
    return (result.stdout + (result.stderr if args[0] == 'logs' else '')).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-privileged-sensor', action='store_true')
    parser.add_argument('--image', default='oma-falco:review-hardening')
    parser.add_argument('--target-image', default='oma-monitor:review-hardening')
    args = parser.parse_args()
    if not args.allow_privileged_sensor:
        parser.error('Explicitly approve the privileged sensor with --allow-privileged-sensor')
    if os.getuid() == 0 or os.getgid() == 0:
        parser.error('Run this check as the non-root monitor account')
    root = Path(__file__).resolve().parents[2]
    marker = f'oma-review-check-{time.time_ns()}'
    target, sensor = marker+'-target', marker+'-sensor'
    directory = root/'monitor/.local'/marker
    directory.mkdir(mode=0o700, parents=True)
    rules = (root/'monitor/falco/oma_rules.yaml').read_text().replace(
        '__OMA_MONITOR_CONTAINER__', json.dumps(target))
    (directory/'rules.yaml').write_text(rules)
    created = []
    try:
        docker('run', '--rm', '-d', '--name', target, '--network', 'none',
               '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '--tmpfs', '/run:rw,mode=1777', '--entrypoint', 'python',
               args.target_image, '-c', 'import time; time.sleep(180)')
        created.append(target)
        target_id = docker('inspect', '--format', '{{.Id}}', target)
        docker('run', '--rm', '-d', '--name', sensor, '--privileged',
               '-e', f'OMA_MONITOR_WRITER_UID={os.getuid()}',
               '-e', f'OMA_MONITOR_WRITER_GID={os.getgid()}',
               '-e', 'OMA_MONITOR_LOG_MAX_BYTES=20480',
               '--mount', 'type=bind,src=/sys/kernel/tracing,dst=/sys/kernel/tracing,readonly',
               '--mount', 'type=bind,src=/var/run/docker.sock,dst=/host/var/run/docker.sock',
               '--mount', 'type=bind,src=/proc,dst=/host/proc,readonly',
               '--mount', 'type=bind,src=/etc,dst=/host/etc,readonly',
               '--mount', f'type=bind,src={directory},dst=/events',
               args.image, 'falco', '-U', '-r', '/events/rules.yaml',
               '-o', 'engine.kind=modern_ebpf', '-o', 'json_output=true',
               '-o', 'buffered_outputs=false', '-o', 'stdout_output.enabled=false',
               '-o', 'file_output.enabled=false', '-o', 'program_output.enabled=true',
               '-o', 'program_output.keep_alive=true',
               '-o', 'program_output.program=python3 -u /writer/event_writer.py')
        created.append(sensor)
        for _ in range(60):
            if 'Starting health webserver' in docker('logs', sensor) or (directory/'oma-events.jsonl').exists():
                break
            time.sleep(0.5)
        # Allow container metadata resolution before emitting the test syscalls.
        time.sleep(2)
        code = '''import ctypes, socket, os
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'check',('127.0.0.1',9))
s.sendmsg([b'check'],[],0,('127.0.0.1',9))
c=socket.socket()
try: c.connect(('127.0.0.1',9))
except OSError: pass
u=socket.socket(socket.AF_UNIX); u.bind('/run/docker.sock'); u.listen(1)
v=socket.socket(socket.AF_UNIX); v.connect('/run/docker.sock'); u.accept()[0].close()
try: open('/run/docker.sock')
except OSError: pass
os.mkdir('/run/alternate')
a=socket.socket(socket.AF_UNIX); a.bind('/run/alternate/docker.sock'); a.listen(1)
b=socket.socket(socket.AF_UNIX); b.connect('/run/alternate/docker.sock'); a.accept()[0].close()
try: open('/proc/1/environ','rb').read(1)
except OSError: pass
libc=ctypes.CDLL(None,use_errno=True)
libc.ptrace(16,-1,0,0)
libc.unshare(0x00020000)
'''
        docker('exec', target, 'python', '-c', code, marker)
        docker('exec', target, 'sh', '-c', 'true', marker)
        expected = {'Oma outbound connection attempt', 'Oma namespace or mount manipulation',
                    'Unexpected shell or network utility in Oma', 'Oma attempts Docker socket access',
                    'Oma process tracing attempt', 'Oma process environment access'}
        matched = []
        for _ in range(40):
            matched = []
            for path in sorted(directory.glob('oma-events*.jsonl')):
                for line in path.read_text().splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    fields = event.get('output_fields', {})
                    event_id = str(fields.get('container.id', ''))
                    if len(event_id) >= 12 and target_id.startswith(event_id) and fields.get('container.name') == target and marker in event.get('output', ''):
                        matched.append(event)
            if expected <= {event['rule'] for event in matched}:
                break
            time.sleep(0.5)
        counts = Counter(event['rule'] for event in matched)
        outbound_syscalls = {event['output_fields'].get('syscall.type') for event in matched
                             if event['rule'] == 'Oma outbound connection attempt'}
        socket_syscalls = {event['output_fields'].get('syscall.type') for event in matched
                           if event['rule'] == 'Oma attempts Docker socket access'}
        coverage = {'connect', 'sendto', 'sendmsg'} <= outbound_syscalls and 'connect' in socket_syscalls
        alternate_path = any('/run/alternate/docker.sock' in event['output_fields'].get('fd.name', '')
                             for event in matched if event['rule'] == 'Oma attempts Docker socket access')
        report = {'result': 'passed' if expected <= counts.keys() and coverage and alternate_path else 'failed',
                  'outbound_syscalls': sorted(outbound_syscalls), 'socket_syscalls': sorted(socket_syscalls),
                  'alternate_socket_path_detected': alternate_path,
                  'rules': dict(counts), 'missing': sorted(expected-counts.keys()),
                  'target_id': target_id, 'events_directory': str(directory),
                  'socket_alerts': [{'time': event['time'], 'rule': event['rule'],
                                     'priority': event['priority'], 'source': event['source'],
                                     'output_fields': {key: event['output_fields'].get(key)
                                                       for key in ('container.name', 'container.id', 'syscall.type', 'fd.name')}}
                                    for event in matched if event['rule'] == 'Oma attempts Docker socket access']}
        (directory/'result.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
        if report['result'] != 'passed':
            print(docker('logs', sensor)[-4000:])
            raise SystemExit(1)
    finally:
        for container in reversed(created):
            subprocess.run(['docker', 'stop', '--time', '2', container],
                           capture_output=True, timeout=20, check=False)


if __name__ == '__main__':
    main()
