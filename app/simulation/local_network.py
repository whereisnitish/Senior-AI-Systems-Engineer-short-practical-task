"""Local stand-ins for a neutral test endpoint and approved forward proxies.

Used by ``scripts/proxy_demo.py`` and the integration tests when no company
proxies are available. Results obtained with these are SIMULATED and labelled so.

* ``NeutralEndpoint`` - a tiny HTTP service on 127.0.0.1 whose behaviour can be
  switched between ok / error (503) / challenge (403 + challenge header) /
  ratelimit (429) / slow.
* ``LocalForwardProxy`` - an HTTP forward proxy on 127.0.0.1 that requires Basic
  proxy authentication and refuses to forward anywhere except localhost, so it
  can never act as an open proxy.
"""

from __future__ import annotations

import base64
import http.client
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

_LOCAL_HOSTS = {"127.0.0.1", "localhost"}


class _QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        return

    def _send(self, code: int, body: dict, headers: dict[str, str] | None = None) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


class _Server:
    def __init__(self, handler: type[BaseHTTPRequestHandler], host: str, port: int):
        self._host, self._port, self._handler = host, port, handler
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = port

    def start(self) -> None:
        self._server = ThreadingHTTPServer((self._host, self.port), self._handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def running(self) -> bool:
        return self._server is not None


class NeutralEndpoint(_Server):
    def __init__(self, host: str = "127.0.0.1", port: int = 0, slow_seconds: float = 3.0):
        self.mode = "ok"
        self.slow_seconds = slow_seconds
        self.hits = 0
        outer = self

        class Handler(_QuietHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib naming
                outer.hits += 1
                mode = outer.mode
                if mode == "slow":
                    time.sleep(outer.slow_seconds)
                if mode == "error":
                    self._send(503, {"status": "unavailable"})
                elif mode == "challenge":
                    self._send(403, {"error": "challenge_required"}, {"X-Security-Challenge": "required"})
                elif mode == "ratelimit":
                    self._send(429, {"error": "rate_limited"}, {"Retry-After": "60"})
                else:
                    self._send(200, {"status": "ok", "service": "neutral-test-endpoint (local simulation)"})

        super().__init__(Handler, host, port)

    @property
    def health_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/health"


class LocalForwardProxy(_Server):
    def __init__(self, name: str, username: str, password: str, host: str = "127.0.0.1", port: int = 0):
        self.name = name
        self.mode = "ok"  # ok | slow | reject_auth
        self.slow_seconds = 3.0
        self.requests = 0
        expected = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        outer = self

        class Handler(_QuietHandler):
            def do_GET(self) -> None:  # noqa: N802
                outer.requests += 1
                if outer.mode == "slow":
                    time.sleep(outer.slow_seconds)
                if outer.mode == "reject_auth" or self.headers.get("Proxy-Authorization") != expected:
                    self._send(407, {"error": "proxy authentication required"}, {"Proxy-Authenticate": 'Basic realm="local-sim"'})
                    return
                target = urlsplit(self.path)
                if target.scheme != "http" or target.hostname not in _LOCAL_HOSTS:
                    self._send(403, {"error": "local simulation proxy only forwards to localhost"})
                    return
                try:
                    conn = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=10)
                    path = target.path + (f"?{target.query}" if target.query else "")
                    conn.request("GET", path or "/", headers={"User-Agent": self.headers.get("User-Agent", "")})
                    upstream = conn.getresponse()
                    body = upstream.read()
                    headers = {k: v for k, v in upstream.getheaders() if k.lower() in ("content-type", "x-security-challenge", "retry-after")}
                    conn.close()
                except OSError:
                    self._send(502, {"error": "upstream unreachable"})
                    return
                self.send_response(upstream.status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Via", f"1.1 local-sim-proxy-{outer.name}")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        super().__init__(Handler, host, port)
