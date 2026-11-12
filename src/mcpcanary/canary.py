"""A localhost-only HTTP listener used by the SSRF-via-tool probe.

The listener binds 127.0.0.1 on an ephemeral port and records every
request that reaches it. When a tool under test is handed a canary URL
pointing at this listener and the server fetches it, the hit is the
evidence: the running server made an outbound request to an
operator-controlled address, on a tool argument an attacker could
influence.

It never binds a non-loopback interface and it is only ever started by
the probe, for the duration of the probe.
"""

from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class CanaryListener:
    def __init__(self):
        self.token = secrets.token_hex(6)
        self.hits = []
        self._server = None
        self._thread = None

    def __enter__(self):
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def _record(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                listener.hits.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "address": self.client_address[0],
                        "user_agent": self.headers.get("User-Agent", ""),
                        "body": body.decode("utf-8", "replace")[:500],
                    }
                )
                payload = b"mcpcanary listener ok: " + listener.token.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _record
            do_POST = _record
            do_HEAD = _record
            do_PUT = _record

            def log_message(self, *args):  # keep test output clean
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        return self

    @property
    def port(self):
        return self._server.server_address[1]

    def url_for(self, label):
        return "http://127.0.0.1:%d/canary/%s/%s" % (
            self.port,
            self.token,
            label,
        )

    def hits_for(self, label):
        marker = "/canary/%s/%s" % (self.token, label)
        return [h for h in self.hits if h["path"].startswith(marker)]

    def __exit__(self, *exc):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        return False
