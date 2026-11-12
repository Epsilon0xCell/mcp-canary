#!/usr/bin/env python3
"""A minimal, benign MCP server used as the clean fixture in tests.

One tool, an honest description, no fetching, no instructions aimed at
the model. It deliberately does not implement resources/list or
prompts/list, so the client's handling of optional methods is exercised
too. Run over stdio.
"""

import json
import sys


def handle(msg):
    method = msg.get("method")
    msg_id = msg.get("id")
    if method == "initialize":
        requested = (msg.get("params") or {}).get("protocolVersion")
        version = requested if requested in (
            "2025-06-18", "2025-03-26", "2024-11-05"
        ) else "2025-03-26"
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "benign-calc", "version": "1.0.0"},
            },
        }
    if msg_id is None:
        return None
    if method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "add",
                    "description": "Adds two integers and returns their sum.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "integer",
                                  "description": "First addend."},
                            "b": {"type": "integer",
                                  "description": "Second addend."},
                        },
                        "required": ["a", "b"],
                    },
                }
            ]
        }
    elif method == "tools/call":
        params = msg.get("params") or {}
        if params.get("name") != "add":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": "unknown tool"},
            }
        args = params.get("arguments") or {}
        total = int(args.get("a", 0)) + int(args.get("b", 0))
        result = {
            "content": [{"type": "text", "text": str(total)}],
            "isError": False,
        }
    elif method == "ping":
        result = {}
    else:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": "method not found"},
        }
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
