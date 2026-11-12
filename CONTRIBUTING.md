# Contributing

Thanks for looking. This project has one rule that shapes everything
else: **claims are proven against live servers, in both directions.**
Every check must fire on a server that exhibits the problem and pass on
a server that does not.

## Development setup

No dependencies beyond Python 3.10+ and the standard library.

```sh
git clone https://github.com/Epsilon0xCell/mcp-canary
cd mcp-canary
PYTHONPATH=src python3 -m mcpcanary demo     # the demo scoreboard
python3 -m unittest discover -s tests -v     # the test suite
```

## Adding a check

1. Add the check to `src/mcpcanary/checks.py`, returning a `Result` with
   a name, the OWASP MCP Top 10 category it covers, a plain-language
   summary and quoted evidence. A check that cannot quote evidence is a
   guess; make it quote.
2. Plant the attack in `demo/poisoned_server.py` (labelled in the
   source, harmless outside the demo) so the demo catches it.
3. Prove both directions in `tests/test_battery.py`: the check fires on
   the demo server and passes on `tests/fixtures/benign_server.py`.
4. Wire it into `run_battery` in `src/mcpcanary/cli.py` and update the
   README scoreboard table by re-running the demo.

## Ground rules

- Standard library first. A new dependency needs a justification in the
  pull request; the bar is high because the install story ("one command,
  nothing to audit") is part of the product.
- Probes only ever touch the server the operator pointed the tool at.
  The SSRF listener binds loopback only and must stay that way.
- Invocation-based probes stay behind `--invoke`. Calling a server's
  tools is an operator decision, never a default.
- Keep report language plain and specific: what was observed, where,
  and the exact text or request that proves it.
