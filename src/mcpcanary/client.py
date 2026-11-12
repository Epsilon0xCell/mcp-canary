"""A minimal synchronous MCP client built on the transports.

Implements the parts of the protocol a security tester needs: the
initialize handshake, tools/list, resources/list, prompts/list and
tools/call, with pagination and graceful handling of servers that do not
implement the optional list methods.
"""

from __future__ import annotations

from . import __version__
from .transport import MCPError

PROTOCOL_CANDIDATES = ["2025-06-18", "2025-03-26", "2024-11-05"]
METHOD_NOT_FOUND = -32601


class MCPClient:
    def __init__(self, transport):
        self.transport = transport
        self.server_info = {}
        self.capabilities = {}
        self.protocol_version = None
        self.instructions = None

    def connect(self):
        last_error = None
        for version in PROTOCOL_CANDIDATES:
            try:
                result = self.transport.request(
                    "initialize",
                    {
                        "protocolVersion": version,
                        "capabilities": {},
                        "clientInfo": {
                            "name": "mcpcanary",
                            "version": __version__,
                        },
                    },
                )
            except MCPError as exc:
                last_error = exc
                continue
            self.protocol_version = result.get("protocolVersion", version)
            self.server_info = result.get("serverInfo", {}) or {}
            self.capabilities = result.get("capabilities", {}) or {}
            self.instructions = result.get("instructions")
            if hasattr(self.transport, "protocol_version"):
                self.transport.protocol_version = self.protocol_version
            self.transport.notify("notifications/initialized")
            return self
        raise MCPError("initialize handshake failed: %s" % last_error)

    def _list(self, method, key):
        items = []
        cursor = None
        while True:
            params = {}
            if cursor:
                params["cursor"] = cursor
            result = self.transport.request(method, params)
            items.extend(result.get(key, []) or [])
            cursor = result.get("nextCursor")
            if not cursor:
                return items

    def list_tools(self):
        return self._list("tools/list", "tools")

    def list_resources(self):
        """Returns (items, note). note is set when the server lacks the method."""
        try:
            return self._list("resources/list", "resources"), None
        except MCPError as exc:
            if exc.code == METHOD_NOT_FOUND:
                return [], "server does not implement resources/list"
            raise

    def list_prompts(self):
        try:
            return self._list("prompts/list", "prompts"), None
        except MCPError as exc:
            if exc.code == METHOD_NOT_FOUND:
                return [], "server does not implement prompts/list"
            raise

    def call_tool(self, name, arguments):
        return self.transport.request(
            "tools/call", {"name": name, "arguments": arguments}
        )

    def close(self):
        self.transport.close()


def result_text(result):
    """Flatten a tools/call result into plain text for scanning."""
    parts = []
    for item in result.get("content", []) or []:
        if isinstance(item, dict):
            if item.get("type") == "text":
                parts.append(item.get("text", ""))
            else:
                parts.append(str(item))
        else:
            parts.append(str(item))
    structured = result.get("structuredContent")
    if structured is not None:
        import json

        parts.append(json.dumps(structured))
    return "\n".join(parts)
