"""Exercise the actual threaded HTTP server, not only Flask's test client."""
import re
import threading
import time

import requests
from waitress import create_server

from monitor.app import create_app, SERVER_THREADS
from monitor.auth import AuthStore
from monitor.config import MonitorConfig


class QuietBackend:
    def status(self):
        return {'state': 'running'}

    def perform_action(self, action):
        return {'action': action}

    def log_events(self, stop_event):
        while not stop_event.wait(0.1):
            if False:
                yield None


def test_saturated_streams_do_not_block_status_login_or_stop(tmp_path):
    store = AuthStore(tmp_path/'users.db')
    for name in ('alice', 'bob', 'operator'):
        store.add_user(name, 'long-server-password', 'operator')
    app = create_app(MonitorConfig(auth_db=store.path, cookie_secure=False),
                     QuietBackend(), auth_store=store)
    server = create_server(app, host='127.0.0.1', port=0, threads=SERVER_THREADS)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.effective_port}'
    streams, clients = [], []

    def login(name):
        client = requests.Session()
        clients.append(client)
        page = client.get(base+'/login', timeout=2).text
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        response = client.post(base+'/login', json={'username': name,
                               'password': 'long-server-password', 'csrf_token': csrf}, timeout=2)
        assert response.status_code == 200
        return client

    try:
        alice, bob = login('alice'), login('bob')
        for client in (alice, bob):
            for _ in range(4):
                response = client.get(base+'/api/logs', stream=True, timeout=2)
                assert response.status_code == 200
                streams.append(response)
        # Eight admitted streams used to occupy every worker. Further attempts
        # now fail immediately, leaving capacity for login and emergency Stop.
        for _ in range(8):
            assert alice.get(base+'/api/logs', timeout=2).status_code == 429
        started = time.monotonic()
        assert alice.get(base+'/api/status', timeout=2).status_code == 200
        operator = login('operator')
        page = operator.get(base+'/', timeout=2).text
        csrf = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
        assert operator.post(base+'/api/actions/stop', json={},
                             headers={'X-CSRF-Token': csrf}, timeout=2).status_code == 200
        assert time.monotonic() - started < 3
    finally:
        for name in ('alice', 'bob', 'operator'):
            store.update_user(name, enabled=0)
        for response in streams:
            response.close()
        for client in clients:
            client.close()
        server.task_dispatcher.shutdown(timeout=3)
        server.close()
        thread.join(timeout=3)
