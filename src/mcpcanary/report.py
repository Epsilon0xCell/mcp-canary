"""Report writers: a Markdown scoreboard and a JSON report."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__


def build_report(results, snapshot, transport_desc):
    server = (snapshot or {}).get("server", {})
    return {
        "tool": "mcpcanary",
        "tool_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "transport": transport_desc,
        "server": server,
        "summary": {
            "pass": sum(1 for r in results if r.status == "PASS"),
            "fail": sum(1 for r in results if r.status == "FAIL"),
            "skipped": sum(1 for r in results if r.status == "SKIPPED"),
        },
        "results": [r.to_dict() for r in results],
    }


def _cell(text, limit=180):
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[:limit] + "..."


def render_markdown(report):
    server = report.get("server", {})
    lines = [
        "# mcp-canary runtime report",
        "",
        "Server: **%s %s** over %s"
        % (server.get("name", "?"), server.get("version", "?"),
           report.get("transport", "?")),
        "",
        "Generated: %s" % report.get("generated_at", ""),
        "",
        "| Test | OWASP MCP Top 10 | Result | Evidence |",
        "|---|---|---|---|",
    ]
    for entry in report["results"]:
        evidence = entry["evidence"][0] if entry["evidence"] else entry["summary"]
        lines.append(
            "| %s | %s | %s | %s |"
            % (
                entry["name"],
                entry["owasp"],
                entry["status"],
                _cell(evidence),
            )
        )
    summary = report["summary"]
    lines += [
        "",
        "Totals: %d pass, %d fail, %d skipped."
        % (summary["pass"], summary["fail"], summary["skipped"]),
        "",
        "## Details",
        "",
    ]
    for entry in report["results"]:
        lines.append("### %s: %s" % (entry["name"], entry["status"]))
        lines.append("")
        lines.append(entry["summary"])
        for item in entry["evidence"]:
            lines.append("- %s" % item)
        lines.append("")
    return "\n".join(lines)


def render_json(report):
    return json.dumps(report, indent=2)
