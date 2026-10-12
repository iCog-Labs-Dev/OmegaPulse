"""Single-writer, record-boundary rotation for Falco program_output JSON lines."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time


class EventWriter:
    def __init__(self, path: Path, max_bytes=20480, interval_seconds=3600, keep=100, clock=time.time):
        if min(max_bytes, interval_seconds, keep) <= 0:
            raise ValueError('Rotation size, interval, and retention must be positive')
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_bytes, self.interval, self.keep, self.clock = max_bytes, interval_seconds, keep, clock
        self.opened = self.path.stat().st_mtime if self.path.exists() else clock()
        self.sequence = 0
        self.file = self.path.open('ab', buffering=0)
        os.chmod(self.path, 0o600)

    def write(self, record: bytes):
        # Bound input and preserve a complete, valid JSON record per line.
        record = record.rstrip(b'\r\n') + b'\n'
        if len(record) > 1048576:
            raise ValueError('Falco record exceeds 1 MiB')
        json.loads(record)
        size = self.file.tell()
        now = self.clock()
        if size and (size + len(record) > self.max_bytes or now - self.opened >= self.interval):
            self.rotate(now)
        self.file.write(record)

    def rotate(self, now):
        self.file.close()
        stamp = datetime.fromtimestamp(now, timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
        self.sequence += 1
        archive = self.path.with_name(f'{self.path.stem}.{stamp}.{time.time_ns()}.{self.sequence}.jsonl')
        self.path.rename(archive)
        self.file = self.path.open('xb', buffering=0)
        os.chmod(self.path, 0o600)
        self.opened = now
        for old in sorted(self.path.parent.glob(f'{self.path.stem}.*.jsonl'))[:-self.keep]:
            old.unlink()

    def close(self):
        self.file.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', type=Path, default=Path(os.environ.get('OMA_MONITOR_WRITER_FILE', '/events/oma-events.jsonl')))
    parser.add_argument('--max-bytes', type=int, default=int(os.environ.get('OMA_MONITOR_LOG_MAX_BYTES', '20480')))
    parser.add_argument('--interval-seconds', type=int, default=int(os.environ.get('OMA_MONITOR_LOG_INTERVAL_SECONDS', '3600')))
    parser.add_argument('--keep', type=int, default=int(os.environ.get('OMA_MONITOR_LOG_KEEP', '100')))
    args = parser.parse_args()
    # The sensor is privileged, but the file writer uses the operator's UID/GID.
    uid, gid = os.environ.get('OMA_MONITOR_WRITER_UID'), os.environ.get('OMA_MONITOR_WRITER_GID')
    if uid is not None or gid is not None:
        if uid is None or gid is None or int(uid) <= 0 or int(gid) <= 0:
            parser.error('Writer UID/GID must both be positive non-root IDs')
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(int(gid))
            os.setuid(int(uid))
        elif os.geteuid() != int(uid) or os.getegid() != int(gid):
            parser.error('Writer identity does not match requested UID/GID')
    writer = EventWriter(args.path, args.max_bytes, args.interval_seconds, args.keep)
    try:
        while record := sys.stdin.buffer.readline(1048577):
            writer.write(record)
    finally:
        writer.close()


if __name__ == '__main__':
    main()
