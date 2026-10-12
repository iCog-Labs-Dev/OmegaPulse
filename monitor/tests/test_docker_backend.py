from docker.errors import DockerException, NotFound

from monitor.docker_backend import DockerBackend, _bounded_lines


class FakeContainer:
    def __init__(self, status="running", state=None, container_id="abcdef1234567890"):
        self.status = status
        self.id = container_id
        self.attrs = {"State": state or {"Status": status}}
        self.actions = []

    def reload(self):
        return None

    def start(self):
        self.actions.append(("start", None))

    def stop(self, timeout):
        self.actions.append(("stop", timeout))

    def restart(self, timeout):
        self.actions.append(("restart", timeout))


class FakeLogContainer(FakeContainer):
    def __init__(self, records, container_id):
        super().__init__(container_id=container_id)
        self.records = records
        self.log_calls = []

    def logs(self, **kwargs):
        self.log_calls.append(kwargs)
        return iter(self.records)


class FakeContainers:
    def __init__(self, result):
        self.result = result
        self.requested = []

    def get(self, name):
        self.requested.append(name)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FakeClient:
    def __init__(self, result, ping_error=None):
        self.containers = FakeContainers(result)
        self.ping_error = ping_error
        self.closed = False

    def ping(self):
        if self.ping_error:
            raise self.ping_error
        return True

    def close(self):
        self.closed = True


def test_running_status_does_not_claim_agent_health():
    client = FakeClient(FakeContainer())
    backend = DockerBackend("omega", client_factory=lambda: client)
    result = backend.status()
    assert result["state"] == "running"
    assert result["agent_healthy"] is None
    assert client.containers.requested == ["omega"]
    assert client.closed


def test_restarting_state_is_distinct():
    container = FakeContainer(status="running", state={"Status": "running", "Restarting": True})
    result = DockerBackend("omega", client_factory=lambda: FakeClient(container)).status()
    assert result["state"] == "restarting"


def test_exited_container_is_stopped():
    result = DockerBackend(
        "omega", client_factory=lambda: FakeClient(FakeContainer(status="exited"))
    ).status()
    assert result["state"] == "stopped"


def test_missing_container_is_reported():
    missing = NotFound("not found")
    result = DockerBackend("omega", client_factory=lambda: FakeClient(missing)).status()
    assert result["state"] == "missing"


def test_docker_failure_is_reported_without_details():
    unavailable = DockerException("socket path and internal detail")
    result = DockerBackend(
        "omega", client_factory=lambda: FakeClient(None, ping_error=unavailable)
    ).status()
    assert result["state"] == "docker-unavailable"
    assert "detail" not in result


def test_lifecycle_actions_use_only_configured_container():
    container = FakeContainer(status="running")
    clients = []

    def factory():
        client = FakeClient(container)
        clients.append(client)
        return client

    backend = DockerBackend("omega", client_factory=factory)
    for action in ("start", "stop", "restart"):
        result = backend.perform_action(action)
        assert result["action"] == action
    assert container.actions == [("start", None), ("stop", 10), ("restart", 10)]
    assert all(client.containers.requested == ["omega"] for client in clients)


def test_unknown_lifecycle_action_is_rejected_before_docker_access():
    called = False

    def factory():
        nonlocal called
        called = True
        return FakeClient(None)

    backend = DockerBackend("omega", client_factory=factory)
    from monitor.docker_backend import DockerActionError

    try:
        backend.perform_action("remove")
        raise AssertionError("expected DockerActionError")
    except DockerActionError as exc:
        assert exc.code == "unsupported-action"
    assert called is False



def test_partial_log_lines_are_bounded():
    lines = list(_bounded_lines([b"a" * 12 + b"\nnext\n"], limit=5))
    assert lines == [
        "aaaaa [line truncated]",
        "aaaaa [line truncated]",
        "aa",
        "next",
    ]


def test_log_stream_reconnects_to_recreated_container_with_fresh_tail():
    first = FakeLogContainer([b"first\n"], "container-one")
    second = FakeLogContainer([b"second\n"], "container-two")
    clients = iter([FakeClient(first), FakeClient(second)])
    backend = DockerBackend(
        "omega", client_factory=lambda: next(clients), sleeper=lambda _seconds: None
    )
    events = backend.log_events()

    assert next(events) == {"type": "log", "text": "first"}
    assert "reconnecting" in next(events)["text"]
    assert "recreation detected" in next(events)["text"]
    assert next(events) == {"type": "log", "text": "second"}
    assert first.log_calls[0]["tail"] == 200
    assert second.log_calls[0]["tail"] == 200
    assert first.log_calls[0]["timestamps"] is True
    assert first.log_calls[0]["follow"] is True


def test_log_stream_recovers_after_docker_failure():
    failure = FakeClient(None, ping_error=DockerException("engine down"))
    recovered_container = FakeLogContainer([b"token=secret-value\n"], "container-one")
    clients = iter([failure, FakeClient(recovered_container)])
    backend = DockerBackend(
        "omega", client_factory=lambda: next(clients), sleeper=lambda _seconds: None
    )
    events = backend.log_events()

    assert "Docker is unavailable" in next(events)["text"]
    recovered = next(events)
    assert recovered["type"] == "log"
    assert recovered["text"] == "token=[REDACTED]"


def test_stopped_container_delivers_history_then_one_waiting_notice():
    container = FakeLogContainer([b"last line\n"], "container-one")
    container.status = "exited"
    container.attrs = {"State": {"Status": "exited"}}
    sleep_calls = 0

    def stop_after_first_poll(_seconds):
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            raise RuntimeError("test complete")

    backend = DockerBackend(
        "omega",
        client_factory=lambda: FakeClient(container),
        sleeper=stop_after_first_poll,
    )
    events = backend.log_events()
    assert next(events) == {"type": "log", "text": "last line"}
    assert "stopped" in next(events)["text"]
    try:
        next(events)
        raise AssertionError("expected test sentinel")
    except RuntimeError as exc:
        assert str(exc) == "test complete"
    assert container.log_calls[0]["follow"] is False
    assert container.log_calls[0]["tail"] == 200


def test_restart_same_container_resumes_timestamped_logs_without_duplicates():
    first_line = b'2026-10-09T12:00:00.123456789Z first\n'
    startup = b'2026-10-09T12:00:01.123456789Z startup\n'
    first = FakeLogContainer([first_line], 'same-id')
    second = FakeLogContainer([first_line, startup], 'same-id')
    clients = iter([FakeClient(first), FakeClient(second)])
    events = DockerBackend('omega', client_factory=lambda: next(clients), sleeper=lambda _: None).log_events()
    assert next(events)['text'].endswith('first')
    assert 'reconnecting' in next(events)['text']
    assert next(events)['text'].endswith('startup')
    assert second.log_calls[0]['tail'] == 'all'
    assert second.log_calls[0]['since'].isoformat() == '2026-10-09T12:00:00+00:00'
    events.close()
