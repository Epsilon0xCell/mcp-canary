"""The runtime test battery.

Each check returns a Result with a status (PASS, FAIL or SKIPPED), a
plain-language summary and quoted evidence. Every check names the OWASP
MCP Top 10 category it covers (list version v0.1, identifiers MCP01:2025
to MCP10:2025; the list is in beta and IDs may move).

Checks never attack anything except the server the operator pointed the
tool at, and the invocation-based checks (exfiltration and SSRF probes)
only run when the operator explicitly enables tool invocation.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from .canary import CanaryListener
from .client import result_text
from .patterns import URL_RE, scan_exfil_surface, scan_instruction_surface
from .snapshot import diff_snapshots
from .transport import MCPError

OWASP = {
    "MCP03": "MCP03:2025 Tool Poisoning",
    "MCP05": "MCP05:2025 Unauthorized Command Execution",
    "MCP09": "MCP09:2025 Shadow MCP Servers",
    "MCP10": "MCP10:2025 Context Injection and Over-Sharing",
}

PASS = "PASS"
FAIL = "FAIL"
SKIPPED = "SKIPPED"


@dataclass
class Result:
    check_id: str
    name: str
    owasp: str
    status: str
    summary: str
    evidence: list = field(default_factory=list)

    def to_dict(self):
        return {
            "check": self.check_id,
            "name": self.name,
            "owasp": self.owasp,
            "status": self.status,
            "summary": self.summary,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------- helpers

_URL_HINTS = ("url", "uri", "link", "href", "endpoint", "fetch", "host", "address")


def is_url_param(name, schema):
    lname = name.lower()
    if any(hint in lname for hint in _URL_HINTS):
        return True
    if schema.get("format") in ("uri", "uri-template", "url"):
        return True
    desc = (schema.get("description") or "").lower()
    return "http://" in desc or "https://" in desc


def safe_args(schema, canary_value, url_value=None):
    """Build harmless arguments for a tool call from its input schema.

    Strings get a recognisable canary token (or the canary URL for
    URL-shaped parameters when a url_value is supplied); numbers and
    booleans get neutral values; everything else gets an empty shape.
    """
    args = {}
    props = (schema or {}).get("properties", {}) or {}
    for name, prop in props.items():
        if not isinstance(prop, dict):
            args[name] = canary_value
            continue
        if url_value is not None and is_url_param(name, prop):
            args[name] = url_value
            continue
        enum = prop.get("enum")
        if enum:
            args[name] = enum[0]
            continue
        ptype = prop.get("type")
        if isinstance(ptype, list):
            ptype = ptype[0] if ptype else "string"
        if ptype == "integer":
            args[name] = 1
        elif ptype == "number":
            args[name] = 1.0
        elif ptype == "boolean":
            args[name] = True
        elif ptype == "array":
            args[name] = []
        elif ptype == "object":
            args[name] = {}
        else:
            args[name] = canary_value
    return args


def _schema_descriptions(schema, prefix=""):
    """Yield (path, description) for every description inside a schema."""
    found = []
    if isinstance(schema, dict):
        desc = schema.get("description")
        if desc:
            found.append((prefix or "$", desc))
        for key, sub in (schema.get("properties") or {}).items():
            found.extend(_schema_descriptions(sub, "%s.%s" % (prefix, key)))
        items = schema.get("items")
        if isinstance(items, dict):
            found.extend(_schema_descriptions(items, prefix + "[]"))
    return found


def _excerpt(text, limit=220):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "..."


# ------------------------------------------------------------------ checks

def check_poisoning_surface(snapshot):
    """MCP03: instruction-like content in tool/parameter descriptions."""
    evidence = []
    for tool in snapshot.get("tools", []):
        surfaces = [("description", tool.get("description", ""))]
        surfaces.extend(
            ("parameter %s" % path, desc)
            for path, desc in _schema_descriptions(tool.get("inputSchema", {}))
        )
        for where, text in surfaces:
            if not text:
                continue
            for label, excerpt in scan_instruction_surface(text):
                evidence.append(
                    'tool "%s" %s [%s]: "%s"'
                    % (tool["name"], where, label, _excerpt(excerpt, 160))
                )
            if len(text) > 900:
                evidence.append(
                    'tool "%s" %s [oversized-description]: %d characters '
                    "(long enough to hide instructions in plain sight)"
                    % (tool["name"], where, len(text))
                )
    if evidence:
        return Result(
            "poisoning-surface",
            "Tool poisoning surface",
            OWASP["MCP03"],
            FAIL,
            "%d instruction-shaped fragment(s) found in tool descriptions "
            "or parameter descriptions." % len(evidence),
            evidence,
        )
    return Result(
        "poisoning-surface",
        "Tool poisoning surface",
        OWASP["MCP03"],
        PASS,
        "No instruction-shaped content found in any tool or parameter "
        "description.",
        [],
    )


def check_rug_pull(baseline, current):
    """MCP03: the live surface differs from the approved baseline."""
    changes = diff_snapshots(baseline, current)
    if changes:
        return Result(
            "rug-pull",
            "Rug-pull detection (baseline diff)",
            OWASP["MCP03"],
            FAIL,
            "The server's current surface differs from the saved baseline "
            "in %d place(s). Anything approved against the baseline was "
            "approved against a different tool than the one now served."
            % len(changes),
            changes,
        )
    return Result(
        "rug-pull",
        "Rug-pull detection (baseline diff)",
        OWASP["MCP03"],
        PASS,
        "Tool definitions, server identity and capabilities match the "
        "saved baseline exactly.",
        [],
    )


def check_cross_session(first, second):
    """MCP09: two fresh connections should describe the same server."""
    changes = diff_snapshots(first, second)
    if changes:
        return Result(
            "cross-session",
            "Cross-session consistency",
            OWASP["MCP09"],
            FAIL,
            "Two back-to-back connections were served different server "
            "identities or tool definitions. A client cannot tell which "
            "server it approved, which is the shadow-server failure mode.",
            changes,
        )
    return Result(
        "cross-session",
        "Cross-session consistency",
        OWASP["MCP09"],
        PASS,
        "Back-to-back connections report identical server info, "
        "capabilities and tool definitions.",
        [],
    )


def check_exfil_probes(client, snapshot, canary_token):
    """MCP10: tool results that order the agent to exfiltrate data."""
    evidence = []
    notes = []
    for tool in snapshot.get("tools", []):
        args = safe_args(tool.get("inputSchema", {}), canary_token)
        try:
            result = client.call_tool(tool["name"], args)
        except MCPError as exc:
            notes.append('tool "%s": call failed (%s)' % (tool["name"], exc))
            continue
        if result.get("isError"):
            notes.append('tool "%s": returned an error result' % tool["name"])
            continue
        text = result_text(result)
        for label, excerpt in scan_exfil_surface(text):
            evidence.append(
                'tool "%s" result [%s]: "%s"'
                % (tool["name"], label, _excerpt(excerpt, 200))
            )
        urls = URL_RE.findall(text)
        if urls and canary_token in text:
            evidence.append(
                'tool "%s" result pairs the probe\'s canary input with an '
                "outbound URL (%s): data handed to this tool is one "
                "instruction away from leaving." % (tool["name"], urls[0])
            )
    if evidence:
        return Result(
            "exfil-probes",
            "Output exfiltration probes",
            OWASP["MCP10"],
            FAIL,
            "%d exfiltration-shaped fragment(s) in tool results. A client "
            "that follows result text as instructions would leak data."
            % len(evidence),
            evidence + notes,
        )
    return Result(
        "exfil-probes",
        "Output exfiltration probes",
        OWASP["MCP10"],
        PASS,
        "Every tool was invoked once with canary-marked arguments; no "
        "result contained directives to send, fetch or include data.",
        notes,
    )


def check_ssrf_probes(client, snapshot):
    """MCP05: URL-accepting tools fetching an operator canary address."""
    candidates = []
    for tool in snapshot.get("tools", []):
        props = (tool.get("inputSchema", {}) or {}).get("properties", {}) or {}
        url_params = [
            name for name, prop in props.items()
            if isinstance(prop, dict) and is_url_param(name, prop)
        ]
        if url_params:
            candidates.append((tool, url_params))
    if not candidates:
        return Result(
            "ssrf-probes",
            "SSRF-via-tool probes",
            OWASP["MCP05"],
            SKIPPED,
            "No tool accepts a URL-shaped argument, so there is no "
            "server-side fetch surface to probe.",
            [],
        )

    evidence = []
    notes = []
    with CanaryListener() as listener:
        for tool, _params in candidates:
            label = re.sub(r"[^a-z0-9]+", "-", tool["name"].lower()).strip("-")
            canary_url = listener.url_for(label)
            args = safe_args(
                tool.get("inputSchema", {}),
                "mcpcanary-ssrf-probe",
                url_value=canary_url,
            )
            try:
                client.call_tool(tool["name"], args)
            except MCPError as exc:
                notes.append(
                    'tool "%s": call failed (%s)' % (tool["name"], exc)
                )
            deadline = time.time() + 2.5
            hits = []
            while time.time() < deadline:
                hits = listener.hits_for(label)
                if hits:
                    break
                time.sleep(0.1)
            for hit in hits:
                evidence.append(
                    'tool "%s" fetched the canary URL %s (%s from %s, '
                    "user agent %r). Whoever controls this argument "
                    "controls a server-side request."
                    % (
                        tool["name"],
                        canary_url,
                        hit["method"],
                        hit["address"],
                        hit["user_agent"],
                    )
                )
    if evidence:
        return Result(
            "ssrf-probes",
            "SSRF-via-tool probes",
            OWASP["MCP05"],
            FAIL,
            "%d canary fetch(es) observed: the server fetched an "
            "operator-supplied loopback URL from inside its own network "
            "position." % len(evidence),
            evidence + notes,
        )
    return Result(
        "ssrf-probes",
        "SSRF-via-tool probes",
        OWASP["MCP05"],
        PASS,
        "%d URL-accepting tool(s) probed with a loopback canary URL; no "
        "fetch reached the listener." % len(candidates),
        notes,
    )


def skipped(check_id, name, owasp, reason):
    return Result(check_id, name, owasp, SKIPPED, reason, [])
