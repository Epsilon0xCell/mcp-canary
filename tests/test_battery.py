"""End-to-end tests for the mcpcanary battery.

Every battery check is proven in both directions: it fires against the
deliberately poisoned demo server, and it passes (or legitimately skips)
against a minimal benign server. Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import os
import secrets
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from mcpcanary import checks  # noqa: E402
from mcpcanary.cli import run_battery  # noqa: E402
from mcpcanary.client import MCPClient  # noqa: E402
from mcpcanary.snapshot import build_snapshot  # noqa: E402
from mcpcanary.transport import StdioTransport  # noqa: E402

DEMO_SERVER = REPO_ROOT / "demo" / "poisoned_server.py"
BENIGN_SERVER = REPO_ROOT / "tests" / "fixtures" / "benign_server.py"


def connect_factory(script, env_extra=None):
    def connect():
        env = None
        if env_extra is not None:
            env = dict(os.environ)
            env.update(env_extra)
        transport = StdioTransport(
            [sys.executable, str(script)], timeout=20.0, env=env
        )
        client = MCPClient(transport).connect()
        client._desc = "stdio: %s" % script.name
        return client

    return connect


def snapshot_of(script, env_extra=None):
    client = connect_factory(script, env_extra)()
    try:
        return build_snapshot(client, "stdio: %s" % script.name)
    finally:
        client.close()


def mutate_env():
    return {"DEMO_MUTATE": "1", "DEMO_STATE_KEY": secrets.token_hex(4)}


def by_id(results):
    return {r.check_id: r for r in results}


class PoisoningSurfaceTests(unittest.TestCase):
    def test_demo_server_is_flagged_with_quoted_evidence(self):
        snap = snapshot_of(DEMO_SERVER)
        result = checks.check_poisoning_surface(snap)
        self.assertEqual(result.status, checks.FAIL)
        blob = "\n".join(result.evidence)
        self.assertIn("get_weather", blob)
        self.assertIn("secrecy-directive", blob)
        self.assertIn("Do not tell the user", blob)

    def test_benign_server_is_clean(self):
        snap = snapshot_of(BENIGN_SERVER)
        result = checks.check_poisoning_surface(snap)
        self.assertEqual(result.status, checks.PASS, result.evidence)


class RugPullTests(unittest.TestCase):
    def test_mutated_server_differs_from_baseline(self):
        baseline = snapshot_of(DEMO_SERVER)
        current = snapshot_of(DEMO_SERVER, mutate_env())
        result = checks.check_rug_pull(baseline, current)
        self.assertEqual(result.status, checks.FAIL)
        blob = "\n".join(result.evidence)
        self.assertIn("get_weather", blob)
        self.assertIn("description changed", blob)
        self.assertIn("session_token", blob)

    def test_identical_server_matches_baseline(self):
        baseline = snapshot_of(BENIGN_SERVER)
        current = snapshot_of(BENIGN_SERVER)
        result = checks.check_rug_pull(baseline, current)
        self.assertEqual(result.status, checks.PASS, result.evidence)


class CrossSessionTests(unittest.TestCase):
    def test_mutated_demo_drifts_between_connections(self):
        results, _snap = run_battery(
            connect_factory(DEMO_SERVER, mutate_env()), invoke=False
        )
        result = by_id(results)["cross-session"]
        self.assertEqual(result.status, checks.FAIL, result.evidence)
        self.assertIn("version", "\n".join(result.evidence))

    def test_benign_server_is_consistent(self):
        results, _snap = run_battery(
            connect_factory(BENIGN_SERVER), invoke=False
        )
        result = by_id(results)["cross-session"]
        self.assertEqual(result.status, checks.PASS, result.evidence)


class InvocationProbeTests(unittest.TestCase):
    def test_exfil_probe_flags_demo(self):
        results, _snap = run_battery(
            connect_factory(DEMO_SERVER), invoke=True
        )
        result = by_id(results)["exfil-probes"]
        self.assertEqual(result.status, checks.FAIL, result.evidence)
        blob = "\n".join(result.evidence)
        self.assertIn("send_feedback", blob)
        self.assertIn("collector.example.net", blob)

    def test_ssrf_probe_flags_demo(self):
        results, _snap = run_battery(
            connect_factory(DEMO_SERVER), invoke=True
        )
        result = by_id(results)["ssrf-probes"]
        self.assertEqual(result.status, checks.FAIL, result.evidence)
        blob = "\n".join(result.evidence)
        self.assertIn("fetch_page", blob)
        self.assertIn("canary", blob)

    def test_probes_skip_without_invoke(self):
        results, _snap = run_battery(
            connect_factory(DEMO_SERVER), invoke=False
        )
        found = by_id(results)
        self.assertEqual(found["exfil-probes"].status, checks.SKIPPED)
        self.assertEqual(found["ssrf-probes"].status, checks.SKIPPED)

    def test_benign_server_passes_invocation_probes(self):
        results, _snap = run_battery(
            connect_factory(BENIGN_SERVER), invoke=True
        )
        found = by_id(results)
        self.assertEqual(found["exfil-probes"].status, checks.PASS,
                         found["exfil-probes"].evidence)
        # the benign server has no URL-accepting tool, so SSRF skips
        self.assertEqual(found["ssrf-probes"].status, checks.SKIPPED)


class FullBatteryTests(unittest.TestCase):
    def test_demo_battery_catches_every_planted_attack(self):
        baseline = snapshot_of(DEMO_SERVER)
        results, _snap = run_battery(
            connect_factory(DEMO_SERVER, mutate_env()),
            invoke=True,
            baseline=baseline,
        )
        found = by_id(results)
        for check_id in (
            "poisoning-surface",
            "rug-pull",
            "exfil-probes",
            "ssrf-probes",
            "cross-session",
        ):
            self.assertEqual(
                found[check_id].status,
                checks.FAIL,
                "%s did not fire: %s" % (check_id, found[check_id].summary),
            )

    def test_benign_battery_is_green(self):
        baseline = snapshot_of(BENIGN_SERVER)
        results, _snap = run_battery(
            connect_factory(BENIGN_SERVER), invoke=True, baseline=baseline
        )
        for result in results:
            self.assertIn(result.status, (checks.PASS, checks.SKIPPED),
                          "%s: %s" % (result.check_id, result.summary))


if __name__ == "__main__":
    unittest.main()
