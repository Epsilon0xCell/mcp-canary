#!/bin/sh
# One-command demo: run the mcpcanary battery against the bundled
# poisoned MCP server and print the scoreboard.
# Works from a fresh checkout; no installation step and no dependencies
# beyond Python 3.10+.
set -e
cd "$(dirname "$0")/.."
PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m mcpcanary demo
