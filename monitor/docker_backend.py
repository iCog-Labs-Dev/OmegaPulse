from __future__ import annotations

import time
import threading
from collections.abc import Callable, Generator, Iterable
from datetime import datetime, timezone
from typing import Any

import docker
from docker.errors import DockerException, NotFound

from .redaction import redact


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_lines(chunks: Iterable[bytes], limit: int = 16_384) -> Generator[str, None, None]:
    """Turn Docker chunks into lines without retaining an unbounded partial line."""
    pending = ""
    for chunk in chunks:
        pending += chunk.decode("utf-8", errors="replace")
        while "\n" in pending:
            line, pending = pending.split("\n", 1)
            if line.endswith("\r"):
                line = line[:-1]
            while len(line) > limit:
                yield line[:limit] + " [line truncated]"
                line = line[limit:]
            yield line
        while len(pending) > limit:
            yield pending[:limit] + " [line truncated]"
            pending = pending[limit:]
    if pending:
        yield pending


class DockerBackend:
    """The only component allowed to communicate with the Docker API."""

    def __init__(
        self,
        container_name: str,
        reconnect_seconds: float = 2.0,
        client_factory: Callable[[], Any] = docker.from_env,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.container_name = container_name
        self.reconnect_seconds = reconnect_seconds
        self._client_factory = client_factory
        self._sleep = sleeper
        self._action_lock = threading.Lock()

    def status(self) -> dict[str, str | bool | None]:
        client = None
        try:
            client = self._client_factory()
            client.ping()
            container = client.containers.get(self.container_name)
            container.reload()
            state = container.attrs.get("State", {})
            docker_status = str(state.get("Status") or container.status or "").lower()
            if docker_status == "restarting" or state.get("Restarting") is True:
                display_state = "restarting"
            elif docker_status == "running":
                display_state = "running"
            else:
                display_state = "stopped"
            return {
                "state": display_state,
                "container": self.container_name,
                "container_id": container.id[:12],
                "docker_status": docker_status or None,
                "agent_healthy": None,
                "checked_at": _utc_now(),
            }
        except NotFound:
            return self._failure_status("missing")
        except DockerException:
            return self._failure_status("docker-unavailable")
        finally:
            self._close_client(client)

    def _failure_status(self, state: str) -> dict[str, str | bool | None]:
        return {
            "state": state,
            "container": self.container_name,
            "container_id": None,
            "docker_status": None,
            "agent_healthy": None,
            "checked_at": _utc_now(),
        }

    def perform_action(self, action: str, timeout: int = 10) -> dict[str, str | bool | None]:
        """Run one explicitly allowed lifecycle action on the configured target."""
        if action not in {"start", "stop", "restart"}:
            raise DockerActionError("unsupported-action", 400)
        if not self._action_lock.acquire(blocking=False):
            raise DockerActionError("action-in-progress", 409)

        client = None
        try:
            client = self._client_factory()
            client.ping()
            container = client.containers.get(self.container_name)
            if action == "start":
                container.start()
            elif action == "stop":
                container.stop(timeout=timeout)
            else:
                container.restart(timeout=timeout)
        except NotFound as exc:
            raise DockerActionError("missing", 404) from exc
        except DockerException as exc:
            raise DockerActionError("docker-unavailable", 503) from exc
        finally:
            try:
                self._close_client(client)
            finally:
                self._action_lock.release()

        result = self.status()
        result["action"] = action
        return result

    def log_events(self, stop_event=None) -> Generator[dict[str, str], None, None]:
        """Follow logs forever, reconnecting after failures or container replacement."""
        last_container_id: str | None = None
        last_notice: str | None = None
        cursor = None
        boundary_counts = {}

        def unseen(line, replay_counts):
            nonlocal cursor, boundary_counts
            stamp, separator, _ = line.partition(' ')
            if not separator or not stamp.endswith('Z'):
                return True
            try:
                second = datetime.fromisoformat(stamp.replace('Z', '+00:00')).replace(microsecond=0)
            except ValueError:
                return True
            # Docker's since is inclusive; preserve counts of identical lines.
            if replay_counts.get(line, 0):
                replay_counts[line] -= 1
                return False
            if cursor is None or second > cursor:
                cursor, boundary_counts = second, {}
            if second == cursor:
                boundary_counts[line] = boundary_counts.get(line, 0) + 1
                if len(boundary_counts) > 2000:
                    boundary_counts.pop(next(iter(boundary_counts)))
            return True

        while stop_event is None or not stop_event.is_set():
            client = None
            try:
                client = self._client_factory()
                client.ping()
                container = client.containers.get(self.container_name)
                container_id = container.id
                is_new_container = container_id != last_container_id
                if is_new_container:
                    cursor = None
                    boundary_counts = {}
                tail = 200 if cursor is None else 'all'
                resume = {'since': cursor} if cursor else {}
                if last_container_id is not None and is_new_container:
                    yield self._system_event("Container recreation detected; attached to the replacement.")
                last_container_id = container_id
                container.reload()
                docker_status = str(
                    container.attrs.get("State", {}).get("Status")
                    or container.status
                    or ""
                ).lower()
                if docker_status not in {"running", "restarting"}:
                    if is_new_container:
                        historical_chunks = container.logs(
                            stdout=True,
                            stderr=True,
                            stream=True,
                            follow=False,
                            timestamps=True,
                            tail=tail,
                        )
                        for line in _bounded_lines(historical_chunks):
                            unseen(line, {})
                            last_notice = None
                            yield {"type": "log", "text": redact(line)}
                    notice = "Target container is stopped; waiting for it to start."
                    if notice != last_notice:
                        yield self._system_event(notice)
                        last_notice = notice
                    self._sleep(self.reconnect_seconds) if stop_event is None else stop_event.wait(self.reconnect_seconds)
                    continue
                chunks = container.logs(
                    stdout=True,
                    stderr=True,
                    stream=True,
                    follow=True,
                    timestamps=True,
                    tail=tail,
                    **resume,
                )
                replay_counts = dict(boundary_counts)
                finished = threading.Event()
                if stop_event is not None:
                    def cancel_when_stopped(watched=chunks, done=finished):
                        while not done.wait(0.2):
                            if stop_event.is_set():
                                if hasattr(watched, "close"):
                                    watched.close()
                                return
                    threading.Thread(target=cancel_when_stopped, daemon=True).start()
                try:
                    for line in _bounded_lines(chunks):
                        if stop_event is not None and stop_event.is_set():
                            return
                        if not unseen(line, replay_counts):
                            continue
                        last_notice = None
                        yield {"type": "log", "text": redact(line)}
                finally:
                    finished.set()
                    if hasattr(chunks, "close"):
                        chunks.close()
                notice = "Log stream ended unexpectedly; reconnecting."
                if notice != last_notice:
                    yield self._system_event(notice)
                    last_notice = notice
            except NotFound:
                notice = "Target container is missing; waiting for it to appear."
                if notice != last_notice:
                    yield self._system_event(notice)
                    last_notice = notice
                last_container_id = None
            except DockerException:
                notice = "Docker is unavailable; retrying the backend connection."
                if notice != last_notice:
                    yield self._system_event(notice)
                    last_notice = notice
            finally:
                self._close_client(client)
            self._sleep(self.reconnect_seconds) if stop_event is None else stop_event.wait(self.reconnect_seconds)

    @staticmethod
    def _system_event(message: str) -> dict[str, str]:
        return {"type": "system", "text": message, "timestamp": _utc_now()}

    @staticmethod
    def _close_client(client: Any | None) -> None:
        if client is None:
            return
        try:
            client.close()
        except DockerException:
            pass


class DockerActionError(RuntimeError):
    def __init__(self, code: str, http_status: int) -> None:
        super().__init__(code)
        self.code = code
        self.http_status = http_status
