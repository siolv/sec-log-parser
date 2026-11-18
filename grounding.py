"""Narrative grounding check.

The model writes prose; the rules produce data. A model can invent an IP, a
username, or a timestamp that was never in the logs. Nothing parses the
narrative back into findings, so the data stays clean — but a human reading
report.md could still be misled.

This module scans the narrative for indicators of compromise that do not
appear in the evidence, and reports them so the report can label them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# IPv4, excluding obvious non-IOCs.
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Addresses that legitimately appear in prose but are not evidence.
ALLOWED_IPS = {
    "0.0.0.0",
    "127.0.0.1",
}

# Documentation / private ranges are safe to mention as examples.
BENIGN_PREFIXES = (
    "127.",
    "10.",
    "192.168.",
)


@dataclass
class GroundingResult:
    """Outcome of comparing the narrative against the structured evidence."""

    checked_ips: list[str] = field(default_factory=list)
    ungrounded_ips: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def clean(self) -> bool:
        return not self.ungrounded_ips


def _valid_ip(candidate: str) -> bool:
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def check_narrative(narrative: str, findings) -> GroundingResult:
    """Flag IPs in `narrative` that no finding actually reported."""
    if not narrative:
        return GroundingResult(detail="no narrative to check")

    known: set[str] = set()
    for finding in findings:
        known.update(finding.ips or [])

    mentioned = {ip for ip in IP_RE.findall(narrative) if _valid_ip(ip)}
    checked: list[str] = []
    ungrounded: list[str] = []

    for ip in sorted(mentioned):
        if ip in ALLOWED_IPS or ip.startswith(BENIGN_PREFIXES):
            continue
        checked.append(ip)
        if ip not in known:
            ungrounded.append(ip)

    if ungrounded:
        detail = (
            "Narrative mentions address(es) not present in the findings: "
            + ", ".join(ungrounded)
            + ". Treat these as model-generated text, not evidence."
        )
    elif checked:
        detail = "All addresses in the narrative match the findings."
    else:
        detail = "Narrative mentions no addresses."

    return GroundingResult(
        checked_ips=checked,
        ungrounded_ips=ungrounded,
        detail=detail,
    )


def render_warning(result: GroundingResult) -> list[str]:
    """Markdown lines to place above the AI narrative when it is ungrounded."""
    if result.clean:
        return []
    return [
        "> [!warning] Narrative grounding check",
        f"> {result.detail}",
        "> The structured findings below and in `findings.json` are authoritative.",
        "",
    ]
