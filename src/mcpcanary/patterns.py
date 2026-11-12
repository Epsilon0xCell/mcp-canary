"""Detection patterns for instruction-shaped content.

Two surfaces are scanned:

- Tool descriptions and parameter descriptions. A description is supposed
  to tell the model what a tool does. Instruction-like text there
  (imperatives aimed at the model, secrecy directives, cross-tool
  instructions, hidden Unicode) is the tool-poisoning surface.
- Tool results. A result is supposed to be data. Directives in a result
  telling the agent to send, fetch, or include conversation data are
  exfiltration-shaped output.

Patterns are deliberately explainable: every hit reports the exact matched
text so a human can judge it.
"""

from __future__ import annotations

import re

INSTRUCTION_PATTERNS = [
    ("urgency-marker", re.compile(r"(?i)\b(important|critical|mandatory|urgent)\s*[:!]")),
    ("imperative-to-model", re.compile(r"(?i)\byou (must|should|need to|have to|are required to)\b")),
    ("secrecy-directive", re.compile(r"(?i)\bdo not (tell|inform|mention|reveal|disclose|alert)\b")),
    ("override-directive", re.compile(r"(?i)\bignore (all )?(previous|prior|above|earlier) (instructions|directions|prompts)\b")),
    ("pre-action-directive", re.compile(r"(?i)\bbefore (using|calling|proceeding|continuing|running)\b[^.]{0,100}\b(read|open|fetch|send|include|call|load)\b")),
    ("cross-tool-directive", re.compile(r"(?i)\bwhen(ever)? (using|calling|invoking) this tool\b[^.]{0,140}\b(also|first|then|immediately)\b")),
    ("always-directive", re.compile(r"(?i)\balways (include|send|append|fetch|call|attach|add)\b")),
    ("fake-system-tag", re.compile(r"(?i)<\s*/?\s*(system|sys|instructions?)\s*>")),
    ("addressed-to-model", re.compile(r"(?i)\b(note|instruction|message|reminder) (to|for) (the )?(assistant|model|ai|llm)\b")),
    ("context-access-request", re.compile(r"(?i)\b(conversation history|chat history|previous messages|user'?s files|home directory|system prompt)\b")),
    ("encoded-blob", re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")),
]

EXFIL_PATTERNS = [
    ("history-exfil-request", re.compile(r"(?i)\b(include|attach|send|append|provide|forward|share)\b[^.\n]{0,80}\b(conversation|chat history|previous messages|full context|system prompt|chat transcript)\b")),
    ("agent-directive", re.compile(r"(?i)\b(the )?(assistant|model|ai) (must|should|needs? to|is required to)\b")),
    ("markdown-image-exfil", re.compile(r"!\[[^\]]*\]\(https?://[^)\s]+\)")),
    ("fetch-directive", re.compile(r"(?i)\b(fetch|retrieve|load|open|visit)\b[^.\n]{0,50}https?://")),
    ("send-to-url", re.compile(r"(?i)\b(send|post|upload|transmit|forward|report)\b[^.\n]{0,80}https?://")),
    ("tool-call-directive", re.compile(r"(?i)\b(call|invoke|use) the [a-z0-9_ -]{1,40} tool\b")),
]

URL_RE = re.compile(r"https?://[^\s\"'\)\]]+")

HIDDEN_CODEPOINT_RANGES = [
    (0x200B, 0x200F),   # zero-width spaces/joiners, bidi marks
    (0x202A, 0x202E),   # bidi embedding/override controls
    (0x2060, 0x2064),   # word joiner, invisible operators
    (0xE0000, 0xE007F),  # Unicode tag characters (classic smuggling range)
]
HIDDEN_SINGLE = {0x00AD, 0xFEFF, 0x180E}


def hidden_unicode_findings(text):
    """Return a list of 'U+XXXX (count)' strings for hidden characters."""
    counts = {}
    for ch in text:
        cp = ord(ch)
        if cp in HIDDEN_SINGLE or any(lo <= cp <= hi for lo, hi in HIDDEN_CODEPOINT_RANGES):
            counts[cp] = counts.get(cp, 0) + 1
    return ["U+%04X x%d" % (cp, n) for cp, n in sorted(counts.items())]


def scan_instruction_surface(text):
    """Scan one description; returns [(label, matched_text), ...]."""
    hits = []
    for label, pattern in INSTRUCTION_PATTERNS:
        for match in pattern.finditer(text):
            start = max(0, match.start() - 20)
            end = min(len(text), match.end() + 40)
            excerpt = text[start:end].replace("\n", " ").strip()
            hits.append((label, excerpt))
    for finding in hidden_unicode_findings(text):
        hits.append(("hidden-unicode", "invisible characters present: %s" % finding))
    return hits


def scan_exfil_surface(text):
    """Scan one tool result; returns [(label, matched_text), ...]."""
    hits = []
    for label, pattern in EXFIL_PATTERNS:
        for match in pattern.finditer(text):
            start = max(0, match.start() - 20)
            end = min(len(text), match.end() + 40)
            excerpt = text[start:end].replace("\n", " ").strip()
            hits.append((label, excerpt))
    return hits
