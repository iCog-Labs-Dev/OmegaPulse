"""Opt-in combined acceptance test using an existing disposable container.

This exercises the real Docker backend and the authenticated Flask surface. It
uses controlled Falco-format JSON because real syscall capture requires native
Linux. The test never creates or removes the target container and restores its
initial running/stopped state.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from monitor.app import create_app
from monitor.auth import AuthStore
from monitor.config import MonitorConfig
from monitor.docker_backend import DockerBackend
from monitor.security_backend import SecurityEventReader


TARGET = os.environ.get("OMA_MONITOR_ACCEPTANCE_CONTAINER")

pytestmark = [pytest.mark.integration, pytest.mark.skipif(
    not TARGET,
    reason="set OMA_MONITOR_ACCEPTANCE_CONTAINER to an existing disposable container",
)]


def _falco_record(container: str, output: str) -> str:
    return json.dumps(
        {
            "time": "2026-10-06T12:00:00Z",
            "priority": "Warning",
            "rule": "Oma outbound connection attempt",
            "output": output,
            "output_fields": {"container.name": container},
        }
    )


def _next_matching(response, marker: bytes, limit: int = 20) -> bytes:
    chunks: list[bytes] = []
    for _ in range(limit):
        chunk = next(response.response)
        chunks.append(chunk)
        if marker in chunk:
            return b"".join(chunks)
    raise AssertionError(f"stream did not produce {marker!r}")


def test_combined_monitor_acceptance(tmp_path: Path) -> None:
    assert TARGET is not None
    username = "acceptance-operator"
    password = "acceptance-password-only"
    events_file = tmp_path / "falco-events.jsonl"
    events_file.write_text(
        "\n".join(
            (
                _falco_record("other-container", "must be filtered"),
                _falco_record(TARGET, "Outbound test token=super-secret"),
            )
        )
        + "\n",
        encoding="utf-8",
    )

    backend = DockerBackend(TARGET, reconnect_seconds=0.01)
    initial = backend.status()
    assert initial["state"] in {"running", "stopped"}
    initially_running = initial["state"] == "running"
    if not initially_running:
        assert backend.perform_action("start")["state"] == "running"

    config = MonitorConfig(
        auth_db=tmp_path / "users.sqlite3",
        cookie_secure=False,
        container_name=TARGET,
        reconnect_seconds=0.01,
        security_events_file=events_file,
    )
    store = AuthStore(config.auth_db)
    store.add_user(username, password, "operator")
    app = create_app(config, backend, SecurityEventReader(events_file, TARGET), store)
    app.testing = True
    client = app.test_client()
    auth = {}

    try:
        assert client.get("/api/status").status_code == 401
        login_page = client.get("/login").get_data(as_text=True)
        login_csrf = re.search(r'name="csrf_token" value="([^\"]+)"', login_page).group(1)
        assert client.post("/login", json={"username":username, "password":"wrong-password", "csrf_token":login_csrf}).status_code == 401
        assert client.post("/login", json={"username":username, "password":password, "csrf_token":login_csrf}).status_code == 200

        page_response = client.get("/", headers=auth)
        assert page_response.status_code == 200
        page = page_response.get_data(as_text=True)
        csrf = re.search(r'name="csrf-token" content="([^"]+)"', page)
        assert csrf is not None

        status_response = client.get("/api/status", headers=auth)
        assert status_response.status_code == 200
        assert status_response.json["container"] == TARGET
        assert status_response.json["state"] == "running"
        assert status_response.json["agent_healthy"] is None
        assert client.get("/api/status?container=other", headers=auth).status_code == 400

        log_response = client.get("/api/logs", headers=auth, buffered=False)
        try:
            log_body = _next_matching(log_response, b"event: log")
            assert b"data:" in log_body
        finally:
            log_response.close()

        security_status = client.get("/api/security/status", headers=auth)
        assert security_status.json == {"configured": True, "state": "available"}
        security_response = client.get(
            "/api/security/events", headers=auth, buffered=False
        )
        try:
            security_body = _next_matching(security_response, b"event: security")
            assert b"Oma outbound connection attempt" in security_body
            assert b"token=[REDACTED]" in security_body
            assert b"super-secret" not in security_body
            assert b"must be filtered" not in security_body
        finally:
            security_response.close()

        action_headers = {
            **auth,
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf.group(1),
        }
        stopped = client.post("/api/actions/stop", headers=action_headers, json={})
        assert stopped.status_code == 200
        assert stopped.json["state"] == "stopped"

        started = client.post("/api/actions/start", headers=action_headers, json={})
        assert started.status_code == 200
        assert started.json["state"] == "running"

        restarted = client.post("/api/actions/restart", headers=action_headers, json={})
        assert restarted.status_code == 200
        assert restarted.json["state"] == "running"
    finally:
        current = backend.status()["state"]
        if initially_running and current != "running":
            backend.perform_action("start")
        elif not initially_running and current != "stopped":
            backend.perform_action("stop")
