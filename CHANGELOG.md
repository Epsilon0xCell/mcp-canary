# Changelog

## 0.1.0 - 2026-11-12

Initial release.

- MCP client for stdio and streamable HTTP transports, standard library
  only, with the initialize handshake, tools/resources/prompts
  enumeration and tools/call.
- Session baselines: snapshot a server's identity, capabilities and tool
  definitions to JSON, with a content hash per tool.
- Runtime battery, each check mapped to the OWASP MCP Top 10 (v0.1,
  2025):
  - Tool poisoning surface scan of descriptions and parameter
    descriptions (MCP03), including hidden-Unicode detection.
  - Rug-pull detection by diffing a live session against a saved
    baseline (MCP03).
  - Output exfiltration probes using canary-marked arguments (MCP10).
  - SSRF-via-tool probes using a loopback-only canary listener (MCP05).
  - Cross-session consistency between back-to-back connections (MCP09).
- Markdown scoreboard and machine-readable JSON reports; scan exit code
  is 1 when any check fails, so it can gate CI.
- Bundled demo: a deliberately poisoned MCP server plus a one-command
  demo that catches all five planted attacks, and a benign fixture
  server proving the battery stays green on a clean server.
