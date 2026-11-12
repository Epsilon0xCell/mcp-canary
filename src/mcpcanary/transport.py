"""Transports for talking JSON-RPC to a running MCP server.

Two transports are supported, matching the MCP specification:

- stdio: the server is a local subprocess, messages are newline-delimited
  JSON on its stdin/stdout.
- Streamable HTTP: JSON-RPC POSTs to a single HTTP endpoint; responses are
  either plain JSON or an SSE (text/event-stream) body. The session id
  issued at initialize time is echoed back on later requests.

Standard library only.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import urllib.request
import urllib.error


class MCPError(Exception):
    """A JSON-RPC error response, or a transport-level failure."""

    def __init__(self, message, code=None, data=None):
        super().__init__(message)
        self.code = code
        self.data = data


class StdioTransport:
    """MCP over a subprocess's stdin/stdout (newline-delimited JSON)."""

    def __init__(self, command, timeout=20.0, env=None):
        self.command = command
        self.timeout = timeout
        self.env = env
        self._proc = None
        self._next_id = 0
        self._pending = {}
        self._lock = threading.Lock()

    def start(self):
        if self._proc is not None:
            return
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=self.env,
        )
        reader = threading.Thread(target=self._read_loop, daemon=True)
        reader.start()

    def _read_loop(self):
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg_id = msg.get("id")
            with self._lock:
                q = self._pending.pop(msg_id, None)
            if q is not None:
                q.put(msg)

    def request(self, method, params=None):
        self.start()
        with self._lock:
            self._next_id += 1
            req_id = self._next_id
            q = queue.Queue(maxsize=1)
            self._pending[req_id] = q
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)
        try:
            msg = q.get(timeout=self.timeout)
        except queue.Empty:
            raise MCPError(
                "timeout after %.0fs waiting for %s" % (self.timeout, method)
            )
        if "error" in msg:
            err = msg["error"] or {}
            raise MCPError(
                err.get("message", "JSON-RPC error"),
                code=err.get("code"),
                data=err.get("data"),
            )
        return msg.get("result", {})

    def notify(self, method, params=None):
        self.start()
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)

    def _send(self, payload):
        if self._proc is None or self._proc.stdin is None:
            raise MCPError("stdio transport is not running")
        self._proc.stdin.write(json.dumps(payload) + "\n")
        self._proc.stdin.flush()

    def close(self):
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None


class HTTPTransport:
    """MCP over Streamable HTTP (single endpoint, POST per message)."""

    def __init__(self, url, timeout=20.0, headers=None):
        self.url = url
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.session_id = None
        self.protocol_version = None
        self._next_id = 0

    def request(self, method, params=None):
        self._next_id += 1
        req_id = self._next_id
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        msg = self._post(payload, expect_response=True)
        if msg is None:
            raise MCPError("empty response to %s" % method)
        if "error" in msg:
            err = msg["error"] or {}
            raise MCPError(
                err.get("message", "JSON-RPC error"),
                code=err.get("code"),
                data=err.get("data"),
            )
        return msg.get("result", {})

    def notify(self, method, params=None):
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._post(payload, expect_response=False)

    def _post(self, payload, expect_response):
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        headers.update(self.headers)
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        req = urllib.request.Request(
            self.url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                session = resp.headers.get("Mcp-Session-Id")
                if session:
                    self.session_id = session
                raw = resp.read().decode("utf-8", "replace")
                ctype = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            raise MCPError("HTTP %s from MCP endpoint: %s" % (exc.code, detail))
        except urllib.error.URLError as exc:
            raise MCPError("cannot reach MCP endpoint: %s" % exc.reason)
        if not expect_response:
            return None
        if "text/event-stream" in ctype:
            return self._parse_sse(raw, payload.get("id"))
        if not raw.strip():
            return None
        return json.loads(raw)

    @staticmethod
    def _parse_sse(raw, want_id):
        found = None
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            try:
                msg = json.loads(line[len("data:"):].strip())
            except json.JSONDecodeError:
                continue
            if msg.get("id") == want_id:
                found = msg
        return found

    def close(self):
        pass
