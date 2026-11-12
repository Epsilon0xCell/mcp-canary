"""Command line interface.

Usage:
  mcpcanary scan --stdio "python3 server.py" [--invoke] [--baseline base.json]
  mcpcanary scan --http http://127.0.0.1:8000/mcp [--invoke]
  mcpcanary snapshot --stdio "python3 server.py" --out base.json
  mcpcanary demo

Exit status for scan: 0 when no check fails, 1 when at least one does,
2 on usage or connection errors. Tool-invoking probes (exfiltration and
SSRF) run only with --invoke: they call the server's tools, which is a
step an operator should take deliberately, against a server they own or
are engaged to test.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shlex
import sys
from pathlib import Path

from . import checks
from .client import MCPClient
from .report import build_report, render_json, render_markdown
from .snapshot import build_snapshot, load_snapshot, save_snapshot
from .transport import HTTPTransport, MCPError, StdioTransport

CANARY_TOKEN = "mcpcanary-probe-7f3a9c"


def _connector(stdio=None, http=None, timeout=20.0, env_extra=None):
    """Return (connect_fn, transport_description)."""
    if stdio:
        command = shlex.split(stdio)
        desc = "stdio: %s" % stdio

        def connect():
            env = None
            if env_extra is not None:
                env = dict(os.environ)
                env.update(env_extra)
            transport = StdioTransport(command, timeout=timeout, env=env)
            return MCPClient(transport).connect()

        return connect, desc
    if http:
        desc = "http: %s" % http

        def connect():
            transport = HTTPTransport(http, timeout=timeout)
            return MCPClient(transport).connect()

        return connect, desc
    raise SystemExit("one of --stdio or --http is required")


def run_battery(connect, invoke=False, baseline=None):
    """Run the full battery against fresh connections from connect()."""
    results = []
    client = connect()
    try:
        snap_a = build_snapshot(client, getattr(client, "_desc", ""))
        results.append(checks.check_poisoning_surface(snap_a))
        if baseline is not None:
            results.append(checks.check_rug_pull(baseline, snap_a))
        else:
            results.append(
                checks.skipped(
                    "rug-pull",
                    "Rug-pull detection (baseline diff)",
                    checks.OWASP["MCP03"],
                    "No baseline supplied. Take one with "
                    "'mcpcanary snapshot' and pass it with --baseline to "
                    "detect tools that changed after approval.",
                )
            )
        if invoke:
            results.append(
                checks.check_exfil_probes(client, snap_a, CANARY_TOKEN)
            )
            results.append(checks.check_ssrf_probes(client, snap_a))
        else:
            results.append(
                checks.skipped(
                    "exfil-probes",
                    "Output exfiltration probes",
                    checks.OWASP["MCP10"],
                    "Tool invocation is off. Pass --invoke to call tools "
                    "with canary-marked arguments and scan what they "
                    "return.",
                )
            )
            results.append(
                checks.skipped(
                    "ssrf-probes",
                    "SSRF-via-tool probes",
                    checks.OWASP["MCP05"],
                    "Tool invocation is off. Pass --invoke to probe "
                    "URL-accepting tools with a loopback canary URL.",
                )
            )
    finally:
        client.close()

    client_b = connect()
    try:
        snap_b = build_snapshot(client_b, getattr(client_b, "_desc", ""))
    finally:
        client_b.close()
    results.append(checks.check_cross_session(snap_a, snap_b))
    return results, snap_a


def _add_connection_args(parser):
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--stdio", metavar="CMD",
                     help="command that starts the MCP server (stdio)")
    grp.add_argument("--http", metavar="URL",
                     help="streamable HTTP endpoint of the MCP server")
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="per-request timeout in seconds (default 20)")


def cmd_scan(args):
    connect, desc = _connector(args.stdio, args.http, args.timeout)
    orig_connect = connect

    def connect_with_desc():
        client = orig_connect()
        client._desc = desc
        return client

    baseline = load_snapshot(args.baseline) if args.baseline else None
    try:
        results, snap = run_battery(
            connect_with_desc, invoke=args.invoke, baseline=baseline
        )
    except MCPError as exc:
        print("mcpcanary: %s" % exc, file=sys.stderr)
        return 2
    if args.save_baseline:
        save_snapshot(snap, args.save_baseline)
        print("baseline saved to %s" % args.save_baseline, file=sys.stderr)
    report = build_report(results, snap, desc)
    markdown = render_markdown(report)
    if args.out:
        Path(args.out).write_text(markdown, encoding="utf-8")
        print(
            "report written to %s (%d pass, %d fail, %d skipped)"
            % (args.out, report["summary"]["pass"],
               report["summary"]["fail"], report["summary"]["skipped"])
        )
    else:
        print(markdown)
    if args.json:
        Path(args.json).write_text(render_json(report), encoding="utf-8")
        print("json report written to %s" % args.json, file=sys.stderr)
    return 1 if report["summary"]["fail"] else 0


def cmd_snapshot(args):
    connect, desc = _connector(args.stdio, args.http, args.timeout)
    try:
        client = connect()
        try:
            snap = build_snapshot(client, desc)
        finally:
            client.close()
    except MCPError as exc:
        print("mcpcanary: %s" % exc, file=sys.stderr)
        return 2
    save_snapshot(snap, args.out)
    server = snap["server"]
    print(
        "baseline saved to %s: %s %s, %d tool(s)"
        % (args.out, server.get("name"), server.get("version"),
           len(snap["tools"]))
    )
    return 0


def cmd_demo(args):
    server_py = (
        Path(__file__).resolve().parents[2] / "demo" / "poisoned_server.py"
    )
    if not server_py.exists():
        print(
            "mcpcanary: the demo ships with the source repository; run "
            "'mcpcanary demo' from a checkout.",
            file=sys.stderr,
        )
        return 2
    command = "%s %s" % (shlex.quote(sys.executable), shlex.quote(str(server_py)))

    base_connect, _ = _connector(command, None, 20.0, env_extra={})
    try:
        client = base_connect()
        try:
            baseline = build_snapshot(client, "stdio: demo server (baseline)")
        finally:
            client.close()
    except MCPError as exc:
        print("mcpcanary: demo baseline failed: %s" % exc, file=sys.stderr)
        return 2

    mut_connect, desc = _connector(
        command,
        None,
        20.0,
        env_extra={
            "DEMO_MUTATE": "1",
            "DEMO_STATE_KEY": secrets.token_hex(4),
        },
    )

    def connect_with_desc():
        client = mut_connect()
        client._desc = "stdio: demo server (mutated)"
        return client

    try:
        results, snap = run_battery(
            connect_with_desc, invoke=True, baseline=baseline
        )
    except MCPError as exc:
        print("mcpcanary: demo run failed: %s" % exc, file=sys.stderr)
        return 2
    report = build_report(results, snap, desc)
    print(render_markdown(report))
    caught = [r for r in results if r.status == checks.FAIL]
    print(
        "demo: %d of %d planted attacks caught"
        % (len(caught), len(results))
    )
    return 0 if len(caught) == len(results) else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mcpcanary",
        description="Runtime security tester for MCP servers.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="run the battery against a server")
    _add_connection_args(p_scan)
    p_scan.add_argument("--invoke", action="store_true",
                        help="call the server's tools (exfiltration and "
                             "SSRF probes); off by default")
    p_scan.add_argument("--baseline", metavar="FILE",
                        help="saved snapshot to diff against (rug-pull)")
    p_scan.add_argument("--save-baseline", metavar="FILE",
                        help="save this session as a baseline snapshot")
    p_scan.add_argument("--out", metavar="FILE",
                        help="write the Markdown report here "
                             "(default: stdout)")
    p_scan.add_argument("--json", metavar="FILE",
                        help="also write a machine-readable JSON report")
    p_scan.set_defaults(func=cmd_scan)

    p_snap = sub.add_parser("snapshot", help="record a baseline snapshot")
    _add_connection_args(p_snap)
    p_snap.add_argument("--out", metavar="FILE", required=True,
                        help="where to write the snapshot JSON")
    p_snap.set_defaults(func=cmd_snapshot)

    p_demo = sub.add_parser(
        "demo", help="run the battery against the bundled poisoned demo "
                     "server and print the scoreboard"
    )
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
