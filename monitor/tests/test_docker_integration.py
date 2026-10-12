"""Opt-in integration test; never creates or removes the target container."""

import os
import unittest
import pytest

pytestmark = pytest.mark.integration

from monitor.docker_backend import DockerBackend


TARGET = os.environ.get("OMA_MONITOR_INTEGRATION_CONTAINER")


@unittest.skipUnless(
    TARGET, "set OMA_MONITOR_INTEGRATION_CONTAINER to a disposable container name"
)
class DockerLifecycleIntegrationTest(unittest.TestCase):
    def test_real_docker_status_and_logs(self):
        backend = DockerBackend(TARGET)
        status = backend.status()
        self.assertEqual(status["container"], TARGET)
        self.assertEqual(status["state"], "running")
        self.assertIsNone(status["agent_healthy"])

        events = backend.log_events()
        try:
            log_event = next(event for event in events if event["type"] == "log")
            self.assertTrue(log_event["text"])
        finally:
            events.close()

    def test_real_docker_lifecycle_for_disposable_container(self):
        backend = DockerBackend(TARGET)
        initial = backend.status()
        self.assertIn(initial["state"], {"running", "stopped"})

        stopped = backend.perform_action("stop")
        self.assertEqual(stopped["state"], "stopped")

        started = backend.perform_action("start")
        self.assertEqual(started["state"], "running")

        restarted = backend.perform_action("restart")
        self.assertEqual(restarted["state"], "running")
