import json

from monitor.security_backend import SecurityEventReader


def falco_event(container="omega", output="Outbound connection token=secret"):
    return json.dumps(
        {
            "time": "2026-10-04T12:00:00Z",
            "priority": "Warning",
            "rule": "Oma outbound connection attempt",
            "output": output,
            "output_fields": {"container.name": container},
        }
    ).encode()


def test_security_status_is_explicit_when_not_configured():
    assert SecurityEventReader(None, "omega").status() == {
        "state": "not-configured",
        "configured": False,
    }


def test_security_event_is_filtered_and_redacted(tmp_path):
    events_file = tmp_path / "events.jsonl"
    events_file.write_bytes(
        falco_event(container="other") + b"\n" + falco_event() + b"\n"
    )
    reader = SecurityEventReader(events_file, "omega", sleeper=lambda _seconds: None)
    event = next(reader.events())
    assert event["type"] == "security"
    assert event["priority"] == "Warning"
    assert event["rule"] == "Oma outbound connection attempt"
    assert event["text"] == "Outbound connection token=[REDACTED]"


def test_security_reader_ignores_malformed_input(tmp_path):
    events_file = tmp_path / "events.jsonl"
    events_file.write_bytes(b"not-json\n" + falco_event() + b"\n")
    reader = SecurityEventReader(events_file, "omega", sleeper=lambda _seconds: None)
    assert next(reader.events())["type"] == "security"


def test_security_tail_is_bounded_to_latest_100_records(tmp_path):
    events_file = tmp_path / "events.jsonl"
    events_file.write_bytes(b"\n".join(falco_event(output=f"event {i}") for i in range(105)) + b"\n")
    reader = SecurityEventReader(events_file, "omega", sleeper=lambda _seconds: None)
    events = reader.events()
    assert next(events)["text"] == "event 5"


def test_partial_appends_are_delivered_once_when_complete(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_bytes(falco_event(output="first") + b"\n")
    second = falco_event(output="second token=private") + b"\n"
    writes = iter((second[:40], second[40:]))

    def append(_seconds):
        with path.open("ab") as stream:
            stream.write(next(writes))

    events = SecurityEventReader(path, "omega", sleeper=append).events()
    assert next(events)["text"] == "first"
    assert next(events)["text"] == "second token=[REDACTED]"


def test_initial_partial_record_is_completed_on_next_poll(tmp_path):
    path = tmp_path / "events.jsonl"
    record = falco_event(output="completed") + b"\n"
    path.write_bytes(record[:30])

    def complete(_seconds):
        with path.open("ab") as stream:
            stream.write(record[30:])

    events = SecurityEventReader(path, "omega", sleeper=complete).events()
    assert next(events)["text"] == "completed"


def test_read_failure_reports_unreadable_without_ending_stream(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    path.write_bytes(falco_event() + b"\n")
    original_open = type(path).open

    def deny(*_args, **_kwargs):
        raise PermissionError("not permitted")

    monkeypatch.setattr(type(path), "open", deny)
    reader = SecurityEventReader(path, "omega", sleeper=lambda _seconds: monkeypatch.setattr(type(path), "open", original_open))
    assert reader.status()["state"] == "events-file-unreadable"
    events = reader.events()
    assert next(events)["type"] == "system"
    assert next(events)["type"] == "security"


def test_file_replacement_follows_new_records(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_bytes(falco_event(output="old") + b"\n")

    def replace(_seconds):
        replacement = tmp_path / "replacement.jsonl"
        replacement.write_bytes(falco_event(output="new") + b"\n")
        replacement.replace(path)

    events = SecurityEventReader(path, "omega", sleeper=replace).events()
    assert next(events)["text"] == "old"
    assert "rotated" in next(events)["text"]
    assert next(events)["text"] == "new"
