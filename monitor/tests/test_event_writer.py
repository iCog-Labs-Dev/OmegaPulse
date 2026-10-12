import json
import pytest
from monitor.event_writer import EventWriter
from monitor.security_backend import SecurityEventReader


def record(number):
    return json.dumps({'output_fields':{'container.name':'omega'},'output':str(number)}).encode()+b'\n'


def test_size_rotation_preserves_lines_and_timestamped_archives(tmp_path):
    path=tmp_path/'oma-events.jsonl'
    records=[record(i) for i in range(5)]
    writer=EventWriter(path,max_bytes=len(records[0])*2,keep=10)
    for r in records: writer.write(r)
    writer.close()
    archives=sorted(tmp_path.glob('oma-events.*.jsonl'))
    assert len(archives)==2
    assert all('T' in p.name and 'Z' in p.name for p in archives)
    assert b''.join(p.read_bytes() for p in archives+[path])==b''.join(records)
    assert all(p.stat().st_size<=len(records[0])*2 for p in archives+[path])
    assert path.stat().st_mode & 0o077 == 0


def test_interval_rotation_and_retention(tmp_path):
    now=[1700000000.0]
    path=tmp_path/'oma-events.jsonl'
    writer=EventWriter(path,max_bytes=99999,interval_seconds=60,keep=2,clock=lambda:now[0])
    for i in range(5):
        writer.write(record(i)); now[0]+=61
    writer.close()
    assert len(list(tmp_path.glob('oma-events.*.jsonl')))==2
    assert path.read_bytes()==record(4)


def test_oversized_complete_record_is_kept_intact_and_bad_json_rejected(tmp_path):
    path=tmp_path/'oma-events.jsonl'
    writer=EventWriter(path,max_bytes=20)
    writer.write(record(1))
    writer.write(record(2))
    with pytest.raises(ValueError):writer.write(b'not json\n')
    writer.close()
    assert path.read_bytes()==record(2)
    assert len(list(tmp_path.glob('oma-events.*.jsonl')))==1


def test_reader_follows_rotated_writer(tmp_path):
    path=tmp_path/'oma-events.jsonl'
    writer=EventWriter(path,max_bytes=len(record(1)))
    writer.write(record(1))
    def rotate(_seconds):writer.write(record(2))
    events=SecurityEventReader(path,'omega',sleeper=rotate).events()
    assert next(events)['text']=='1'
    assert 'rotated' in next(events)['text']
    assert next(events)['text']=='2'
    events.close(); writer.close()


def test_reader_drains_unread_archives_when_multiple_rotations_happen_between_polls(tmp_path):
    path=tmp_path/'oma-events.jsonl'
    writer=EventWriter(path,max_bytes=len(record(1))*2)
    writer.write(record(0))
    def rotate(_seconds):
        for i in range(1,7):writer.write(record(i))
    events=SecurityEventReader(path,'omega',sleeper=rotate).events()
    assert next(events)['text']=='0'
    assert 'rotated' in next(events)['text']
    assert [next(events)['text'] for _ in range(6)]==[str(i) for i in range(1,7)]
    events.close(); writer.close()


def test_new_reader_replays_recent_history_across_archives(tmp_path):
    path = tmp_path/'oma-events.jsonl'
    writer = EventWriter(path, max_bytes=len(record(0))*2)
    for number in range(8):
        writer.write(record(number))
    writer.close()
    events = SecurityEventReader(path, 'omega').events()
    assert [next(events)['text'] for _ in range(8)] == [str(i) for i in range(8)]
    events.close()
