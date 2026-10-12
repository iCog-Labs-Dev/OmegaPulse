"""Run Omega's deterministic mock LLM and communication servers for manual tests."""

from __future__ import annotations

import signal
import sys
import threading
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOCK_ROOT = REPO_ROOT / "Autotests" / "mock"
sys.path.insert(0, str(MOCK_ROOT))

from comm import COMM_MOCK_PORT, CommMockServer  # noqa: E402
from llm import LLM_MOCK_PORT, LlmMockController  # noqa: E402


def main() -> None:
    stopped = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    llm = LlmMockController(("0.0.0.0", LLM_MOCK_PORT))
    channel = CommMockServer(("0.0.0.0", COMM_MOCK_PORT))
    print(
        f"Omega mock services ready: LLM={LLM_MOCK_PORT} channel={COMM_MOCK_PORT}",
        flush=True,
    )
    try:
        stopped.wait()
    finally:
        channel.stop(5)
        llm.stop(5)


if __name__ == "__main__":
    main()

