"""Session baselines: what a server claimed to be, frozen as JSON.

A snapshot records server info, negotiated protocol version, capabilities
and the full tool/resource/prompt surface, with a content hash per tool
definition. Diffing a live session against a saved baseline is what turns
a rug pull (a tool silently changing after approval) into evidence.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def definition_hash(tool):
    payload = {
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema", {}),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_snapshot(client, transport_desc):
    tools = []
    for tool in client.list_tools():
        entry = {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "inputSchema": tool.get("inputSchema", {}),
        }
        entry["definition_hash"] = definition_hash(entry)
        tools.append(entry)
    tools.sort(key=lambda t: t["name"])

    resources, resources_note = client.list_resources()
    prompts, prompts_note = client.list_prompts()

    return {
        "snapshot_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "transport": transport_desc,
        "server": {
            "name": client.server_info.get("name", ""),
            "version": client.server_info.get("version", ""),
            "protocolVersion": client.protocol_version,
            "capabilities": client.capabilities,
        },
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
        "notes": [n for n in (resources_note, prompts_note) if n],
    }


def save_snapshot(snapshot, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2, sort_keys=True)


def load_snapshot(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _first_difference(a, b):
    """Short excerpt around the first position where two strings differ."""
    limit = min(len(a), len(b))
    idx = next((i for i in range(limit) if a[i] != b[i]), limit)
    start = max(0, idx - 30)
    old = a[start:idx + 50].replace("\n", " ")
    new = b[start:idx + 50].replace("\n", " ")
    return "baseline: ...%s... | current: ...%s..." % (old, new)


def diff_snapshots(old, new):
    """Human-readable list of changes between two snapshots."""
    changes = []
    old_server = old.get("server", {})
    new_server = new.get("server", {})
    for field in ("name", "version", "protocolVersion"):
        if old_server.get(field) != new_server.get(field):
            changes.append(
                "server %s changed: %r -> %r"
                % (field, old_server.get(field), new_server.get(field))
            )
    if old_server.get("capabilities") != new_server.get("capabilities"):
        changes.append(
            "server capabilities changed: %s -> %s"
            % (
                json.dumps(old_server.get("capabilities"), sort_keys=True),
                json.dumps(new_server.get("capabilities"), sort_keys=True),
            )
        )

    old_tools = {t["name"]: t for t in old.get("tools", [])}
    new_tools = {t["name"]: t for t in new.get("tools", [])}
    for name in sorted(set(new_tools) - set(old_tools)):
        changes.append("tool added: %s" % name)
    for name in sorted(set(old_tools) - set(new_tools)):
        changes.append("tool removed: %s" % name)
    for name in sorted(set(old_tools) & set(new_tools)):
        o, n = old_tools[name], new_tools[name]
        if o.get("definition_hash") == n.get("definition_hash"):
            continue
        if o.get("description", "") != n.get("description", ""):
            changes.append(
                "tool %s: description changed (%s)"
                % (name, _first_difference(o.get("description", ""),
                                           n.get("description", "")))
            )
        if o.get("inputSchema", {}) != n.get("inputSchema", {}):
            changes.append(
                "tool %s: input schema changed (%s -> %s)"
                % (
                    name,
                    json.dumps(o.get("inputSchema", {}), sort_keys=True),
                    json.dumps(n.get("inputSchema", {}), sort_keys=True),
                )
            )

    old_res = {r.get("uri") for r in old.get("resources", [])}
    new_res = {r.get("uri") for r in new.get("resources", [])}
    if old_res != new_res:
        changes.append(
            "resources changed: %s -> %s" % (sorted(old_res), sorted(new_res))
        )
    old_pr = {p.get("name") for p in old.get("prompts", [])}
    new_pr = {p.get("name") for p in new.get("prompts", [])}
    if old_pr != new_pr:
        changes.append(
            "prompts changed: %s -> %s" % (sorted(old_pr), sorted(new_pr))
        )
    return changes
