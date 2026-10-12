from __future__ import annotations

import hmac
import json
import logging
import queue
import threading
from functools import wraps
from typing import Any, Callable

from flask import Flask, Response, g, jsonify, redirect, render_template, request

from .auth import AuthStore, COOKIE, LoginLimited
from .config import MonitorConfig
from .docker_backend import DockerActionError, DockerBackend
from .security_backend import SecurityEventReader


SERVER_THREADS = 16
MAX_STREAMS = 8
MAX_USER_STREAMS = 4
logger = logging.getLogger("oma_monitor.audit")


def configure_audit_logging():
    # Configure only our audit logger, keeping host applications' logging intact.
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s'))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def create_app(
    config: MonitorConfig | None = None,
    backend: DockerBackend | None = None,
    security_backend: SecurityEventReader | None = None,
    auth_store: AuthStore | None = None,
) -> Flask:
    configure_audit_logging()
    settings = config or MonitorConfig.from_env()
    docker_backend = backend or DockerBackend(
        settings.container_name, settings.reconnect_seconds
    )
    accounts = auth_store or AuthStore(settings.auth_db, idle_seconds=settings.session_idle_seconds,
                                       lifetime_seconds=settings.session_lifetime_seconds)
    if not accounts.users():
        raise ValueError("No accounts configured; run python -m monitor.users add USER --role operator")
    event_reader = security_backend or SecurityEventReader(
        settings.security_events_file, settings.container_name
    )
    app = Flask(__name__)
    app.config.update(
        AUTH_STORE=accounts,
        MAX_CONTENT_LENGTH=16_384,
        MONITOR_CONFIG=settings,
        DOCKER_BACKEND=docker_backend,
        SECURITY_BACKEND=event_reader,
        SEND_FILE_MAX_AGE_DEFAULT=0,
    )

    def authenticated(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            current = accounts.session(request.cookies.get(COOKIE, ""))
            if not current or not current["username"]:
                if request.path == "/":
                    return redirect("/login", 303)
                return jsonify({"error": "authentication-required"}), 401
            g.identity = current
            return function(*args, **kwargs)

        return wrapped

    stream_lock = threading.Lock()
    streams = {}

    def stream_response(iterator):
        username = g.identity['username']
        with stream_lock:
            if sum(streams.values()) >= MAX_STREAMS or streams.get(username, 0) >= MAX_USER_STREAMS:
                response = jsonify({'error': 'stream-limit', 'message': 'Close another dashboard and retry.'})
                response.status_code = 429
                response.headers['Retry-After'] = '5'
                return response
            streams[username] = streams.get(username, 0) + 1
        released = False

        def release():
            nonlocal released
            with stream_lock:
                if not released:
                    streams[username] -= 1
                    if not streams[username]:
                        del streams[username]
                    released = True

        def admitted():
            try:
                yield from iterator
            finally:
                iterator.close()
                release()

        response = Response(admitted(), content_type='text/event-stream; charset=utf-8',
                            headers={'X-Accel-Buffering': 'no'})
        response.call_on_close(release)
        return response

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        return response

    def set_cookie(response, token):
        response.set_cookie(COOKIE, token, secure=settings.cookie_secure,
                            httponly=True, samesite="Strict", path="/")
        return response

    def valid_csrf(current, candidate):
        return bool(current and candidate and hmac.compare_digest(
            candidate.encode(), current["csrf"].encode()))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        token = request.cookies.get(COOKIE, "")
        current = accounts.session(token)
        if request.method == "GET":
            if current and current["username"]:
                return redirect("/", 303)
            if current is None:
                try:
                    token, _ = accounts.anonymous_session()
                except LoginLimited:
                    return jsonify({"error": "login-limited"}), 429
                current = accounts.session(token)
            return set_cookie(app.make_response(render_template("login.html", csrf_token=current["csrf"])), token)
        fields = request.get_json(silent=True) if request.is_json else request.form
        fields = fields if isinstance(fields, dict) or hasattr(fields, "get") else {}
        if request.headers.get("Sec-Fetch-Site") == "cross-site" or not valid_csrf(
            current, str(fields.get("csrf_token", ""))):
            return jsonify({"error": "invalid-csrf-token"}), 403
        username, password, otp = (str(fields.get(key, "")) for key in ("username", "password", "otp"))
        if len(username) > 64 or len(password) > 1024 or len(otp) > 6:
            return jsonify({"error": "invalid-credentials"}), 401
        try:
            result = accounts.login(username, password, otp, request.remote_addr or "unknown", token)
        except LoginLimited:
            response = jsonify({"error": "login-limited", "message": "Try again in 15 minutes."})
            response.status_code = 429
            response.headers["Retry-After"] = "900"
            return response
        if result is None:
            logger.warning("login result=denied")
            if request.is_json:
                return jsonify({"error": "invalid-credentials"}), 401
            return render_template("login.html", csrf_token=current["csrf"],
                                   error="Invalid credentials or authenticator code."), 401
        logger.info("login user=%s result=accepted", username)
        response = jsonify({"ok": True}) if request.is_json else redirect("/", 303)
        return set_cookie(response, result[0])

    @app.post("/logout")
    @authenticated
    def logout():
        if not valid_csrf(g.identity, request.headers.get("X-CSRF-Token", "")):
            return jsonify({"error": "invalid-csrf-token"}), 403
        accounts.revoke(request.cookies.get(COOKIE, ""))
        response = jsonify({"ok": True})
        response.delete_cookie(COOKIE, secure=settings.cookie_secure, httponly=True, samesite="Strict")
        return response

    def authorized_events(factory, token):
        # Poll revocation even while Docker or the security file is quiet.
        stopped = threading.Event()
        pending = queue.Queue(maxsize=32)
        finished = object()

        def collect():
            events = factory(stopped)
            try:
                for event in events:
                    while not stopped.is_set():
                        try:
                            pending.put(event, timeout=0.2)
                            break
                        except queue.Full:
                            continue
                    if stopped.is_set():
                        return
            finally:
                events.close()
                while not stopped.is_set():
                    try:
                        pending.put(finished, timeout=0.2)
                        break
                    except queue.Full:
                        continue

        worker = threading.Thread(target=collect, daemon=True)
        worker.start()
        try:
            while True:
                if not accounts.session(token):
                    yield {"type": "auth-expired", "text": "Session expired. Please sign in again."}
                    return
                try:
                    event = pending.get(timeout=1)
                except queue.Empty:
                    yield {"type": "heartbeat"}
                    continue
                if event is finished:
                    return
                if not accounts.session(token):
                    yield {"type": "auth-expired", "text": "Session expired. Please sign in again."}
                    return
                yield event
        finally:
            stopped.set()
            worker.join(timeout=1)

    @app.get("/")
    @authenticated
    def index() -> str:
        accounts.session(request.cookies.get(COOKIE, ""), touch=True)
        return render_template(
            "index.html",
            container_name=settings.container_name,
            browser_log_limit=settings.browser_log_limit,
            csrf_token=g.identity["csrf"],
            username=g.identity["username"],
            can_control=g.identity["role"] == "operator",
        )

    @app.get("/api/status")
    @authenticated
    def status() -> Response:
        if request.args:
            return jsonify({"error": "query parameters are not accepted"}), 400
        return jsonify(docker_backend.status())

    @app.get("/api/logs")
    @authenticated
    def logs() -> Response:
        if request.args:
            return jsonify({"error": "query parameters are not accepted"}), 400

        token = request.cookies.get(COOKIE, "")

        def stream() -> Any:
            yield "retry: 3000\n\n"
            for event in authorized_events(lambda stop: docker_backend.log_events(stop_event=stop), token):
                if event.get("type") == "heartbeat":
                    yield ": keepalive\n\n"
                    continue
                event_type = event.get("type") if event.get("type") in {"log", "auth-expired"} else "system"
                yield f"event: {event_type}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"

        return stream_response(stream())

    @app.post("/api/actions/<action>")
    @authenticated
    def action(action: str) -> Response:
        if g.identity["role"] != "operator":
            return jsonify({"error": "forbidden"}), 403
        if request.args or action not in {"start", "stop", "restart"}:
            return jsonify({"error": "unsupported-action"}), 400
        if not request.is_json:
            return jsonify({"error": "application/json is required"}), 415
        candidate = request.headers.get("X-CSRF-Token", "")
        if not valid_csrf(g.identity, candidate):
            return jsonify({"error": "invalid-csrf-token"}), 403
        if request.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
            return jsonify({"error": "cross-site-request-denied"}), 403

        accounts.session(request.cookies.get(COOKIE, ""), touch=True)
        try:
            result = docker_backend.perform_action(action)
        except DockerActionError as exc:
            logger.warning(
                "operator_action user=%s action=%s target=%s result=%s",
                g.identity["username"],
                action,
                settings.container_name,
                exc.code,
            )
            return jsonify({"error": exc.code}), exc.http_status

        logger.info(
            "operator_action user=%s action=%s target=%s result=accepted",
            g.identity["username"],
            action,
            settings.container_name,
        )
        return jsonify(result)

    @app.get("/api/security/status")
    @authenticated
    def security_status() -> Response:
        if request.args:
            return jsonify({"error": "query parameters are not accepted"}), 400
        return jsonify(event_reader.status())

    @app.get("/api/security/events")
    @authenticated
    def security_events() -> Response:
        if request.args:
            return jsonify({"error": "query parameters are not accepted"}), 400

        token = request.cookies.get(COOKIE, "")

        def stream() -> Any:
            yield "retry: 3000\n\n"
            for event in authorized_events(lambda stop: event_reader.events(stop_event=stop), token):
                if event.get("type") == "heartbeat":
                    yield ": keepalive\n\n"
                    continue
                event_type = event.get("type") if event.get("type") in {"security", "auth-expired"} else "system"
                yield f"event: {event_type}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"

        return stream_response(stream())

    return app


def main() -> None:
    from waitress import serve

    settings = MonitorConfig.from_env()
    app = create_app(settings)
    serve(app, host=settings.host, port=settings.port, threads=SERVER_THREADS)


if __name__ == "__main__":
    main()
