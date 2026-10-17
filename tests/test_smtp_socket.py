"""SMTP notification delivery against a real SMTP conversation on a loopback socket.

The sink below speaks enough RFC 5321 for ``smtplib`` (EHLO/HELO, MAIL, RCPT, DATA, RSET,
NOOP, QUIT). It proves the adapter and the outbox work over a real connection; it does not
prove delivery to a person's inbox, which needs the company mail relay.
"""

from __future__ import annotations

import socket
import socketserver
import threading

import pytest

from app.enums import DeliveryStatus, NotificationKind, OperatorRole
from tests.conftest import Env
from tests.test_reminders import _notes, _task


class _SmtpSink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *, drop_during_data: bool = False):
        self.messages: list[str] = []
        self.drop_during_data = drop_during_data
        super().__init__(("127.0.0.1", 0), _SmtpHandler)


class _SmtpHandler(socketserver.StreamRequestHandler):
    def _send(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())

    def handle(self) -> None:
        server: _SmtpSink = self.server  # type: ignore[assignment]
        self._send("220 sink.test ESMTP")
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            command = raw.decode(errors="replace").strip().upper()
            if command.startswith("EHLO"):
                self._send("250-sink.test")
                self._send("250 8BITMIME")
            elif command.startswith(("HELO", "MAIL", "RCPT", "RSET", "NOOP")):
                self._send("250 OK")
            elif command == "DATA":
                self._send("354 end with <CRLF>.<CRLF>")
                lines = []
                while (line := self.rfile.readline()) not in (b".\r\n", b""):
                    lines.append(line.decode(errors="replace"))
                if server.drop_during_data:
                    self.connection.shutdown(socket.SHUT_RDWR)  # accepted the bytes, never answered
                    return
                server.messages.append("".join(lines))
                self._send("250 queued")
            elif command == "QUIT":
                self._send("221 bye")
                return
            else:
                self._send("502 not implemented")


@pytest.fixture
def sink():
    server = _SmtpSink()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def _smtp_env(tmp_path, port: int) -> Env:
    return Env(
        tmp_path, notification_backend="smtp", smtp_host="127.0.0.1", smtp_port=port, smtp_from="ops@testco.example",
        smtp_starttls=False, smtp_timeout_seconds=5,
    )


def test_assignment_is_delivered_over_a_real_smtp_connection(tmp_path, sink):
    env = _smtp_env(tmp_path, sink.server_address[1])
    owner = env.person("Sam Rivera")
    task_id = _task(env, owner)
    summary = env.container.notifications.dispatch_pending(env.container.session_factory)
    assert summary.sent == 1 and len(sink.messages) == 1
    message = sink.messages[0]
    assert "Subject: [Ops task] Reminder test task" in message and "sam.rivera@testco.example" in message
    assert "Never reply with passwords" in message
    assert _notes(env, task_id, NotificationKind.ASSIGNMENT)[0].delivery_status == DeliveryStatus.SENT
    assert env.client().get("/api/v1/integrations", headers=env.headers(owner, OperatorRole.VIEWER)).json()["notifications"]["configured"]
    env.container.engine.dispose()


def test_connection_dropped_after_data_is_uncertain_and_never_resent(tmp_path):
    server = _SmtpSink(drop_during_data=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        env = _smtp_env(tmp_path, server.server_address[1])
        owner = env.person("Sam Rivera")
        task_id = _task(env, owner)
        first = env.container.notifications.dispatch_pending(env.container.session_factory)
        assert first.uncertain == 1 and first.sent == 0
        again = env.container.notifications.dispatch_pending(env.container.session_factory)
        assert again.sent == 0 and again.uncertain == 0  # an uncertain send waits for a human requeue
        assert _notes(env, task_id, NotificationKind.ASSIGNMENT)[0].delivery_status == DeliveryStatus.UNCERTAIN
        env.container.engine.dispose()
    finally:
        server.shutdown()
        server.server_close()
