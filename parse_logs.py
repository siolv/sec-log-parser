#!/usr/bin/env python3
"""AI-Assisted Security Log Analyzer.

Parses OpenSSH/sudo syslog and nginx/Apache combined access logs, runs a small
rule engine for brute force, password spraying, recon and post-compromise
activity, then asks a LOCAL Ollama model for a Markdown triage narrative.

Standard library only. No third-party packages. No cloud calls. $0 token cost.

Examples
--------
    python parse_logs.py sample_auth.log sample_access.log
    python parse_logs.py *.log --no-ai --out report.md --json findings.json
    python parse_logs.py sample_auth.log --model qwen3.5:9b --window 5 --threshold 5

Exit codes: 0 report written, 1 bad input or no events parsed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "qwen3.5:9b"
DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"

# Accounts that should not authenticate outside business hours.
PRIVILEGED_USERS = {"root", "admin", "deploy", "svc-backup"}

# HTTP statuses that mean "authentication rejected" on a login endpoint.
WEB_LOGIN_FAIL_STATUSES = {401, 403, 429}

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# ---------------------------------------------------------------------------
# Log format patterns (compiled once, reused for every line)
# ---------------------------------------------------------------------------

# Classic syslog: "Nov 17 22:14:08 web01 sshd[3901]: Failed password ..."
AUTH_LINE_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
ACCEPTED_RE = re.compile(
    r"^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\w.:]+)"
)
FAILED_RE = re.compile(
    r"^Failed (?:password|publickey) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\w.:]+)"
)
SUDO_USER_RE = re.compile(r"\buser=(?P<user>\S+)")
RHOST_RE = re.compile(r"\brhost=(?P<rhost>\S*)")

# nginx/Apache combined format:
# 203.0.113.42 - - [17/Nov/2026:22:05:10 +0800] "POST /login HTTP/1.1" 401 41 "-" "curl/8.4.0"
WEB_LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<stamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)
WEB_STAMP_RE = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+(?P<off>[+-]\d{4})$"
)
REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)")

# Paths that are authentication endpoints.
LOGIN_PATH_RE = re.compile(
    r"(?i)/(?:login|signin|sign-in|auth|session|wp-login\.php)(?:$|[/?])"
)
# Paths and payload signatures used by scanners and exploit probes.
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:/\.env|/\.git|wp-login\.php|wp-admin|phpmyadmin|/admin|"
    r"/manager/html|/actuator|/server-status|/etc/passwd|xmlrpc\.php|"
    r"/cgi-bin/|\.\./|union(?:\s|\+|%20)+select|or(?:\s|\+|%20)+1=1|"
    r"information_schema)"
)

MAX_EVIDENCE_LINES = 5


@dataclass(frozen=True)
class Config:
    """Every threshold in one place, so the rules can be tuned without edits."""

    window_minutes: int = 5
    auth_failure_threshold: int = 5
    web_login_threshold: int = 5
    spray_min_ips: int = 3
    spray_window_minutes: int = 10
    success_after_failure_threshold: int = 3
    success_lookback_minutes: int = 15
    recon_404_threshold: int = 10
    off_hours_start: int = 0
    off_hours_end: int = 6


@dataclass
class Event:
    """One normalised security event, whatever log format it came from."""

    timestamp: datetime
    source: str                 # "auth" or "web"
    ip: str                     # client address, or "local" for tty-only sudo
    outcome: str                # "success" or "failure"
    user: str = "-"
    detail: str = ""            # syslog message or raw request line
    path: str = ""              # request target (path + query)
    status: int | None = None   # HTTP status
    user_agent: str = ""
    raw: str = ""               # original log line, kept for evidence


@dataclass
class Finding:
    """A rule hit. Holds its own evidence so the report and JSON stand alone."""

    rule: str
    title: str
    severity: str               # Critical / High / Medium / Low
    ips: list[str]
    description: str
    first_seen: datetime
    last_seen: datetime
    count: int
    users: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    events: list[Event] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "source_ips": self.ips,
            "users": self.users,
            "event_count": self.count,
            "first_seen": iso(self.first_seen),
            "last_seen": iso(self.last_seen),
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    ignored: int = 0            # valid syslog lines with no security meaning
    skipped: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def iso(stamp: datetime) -> str:
    """ISO 8601 with the original UTC offset, second precision."""
    return stamp.isoformat(timespec="seconds")


def parse_offset(text: str) -> timezone:
    """Turn "+08:00" into a timezone. Syslog lines carry no offset."""
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text.strip())
    if not match:
        raise ValueError(f"Invalid UTC offset {text!r}; expected +08:00")
    sign = 1 if match.group(1) == "+" else -1
    delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
    return timezone(sign * delta)


def group_by(items: list[Event], key) -> dict:
    """Group events by a key function; each group stays time-sorted."""
    grouped: dict = defaultdict(list)
    for item in items:
        grouped[key(item)].append(item)
    for bucket in grouped.values():
        bucket.sort(key=lambda event: event.timestamp)
    return grouped


def max_window(events: list[Event], minutes: int) -> tuple[list[Event], int]:
    """Return the densest <minutes>-wide window of events and its size.

    A sliding window: move the right edge forward one event at a time, then
    pull the left edge forward while the span is too wide. Every window that
    ends at events[right] is checked, so the maximum is exact, not sampled.
    """
    best: list[Event] = []
    left = 0
    for right, event in enumerate(events):
        while event.timestamp - events[left].timestamp > timedelta(minutes=minutes):
            left += 1
        if right - left + 1 > len(best):
            best = events[left : right + 1]
    return best, len(best)


def make_finding(
    rule: str,
    title: str,
    severity: str,
    ips: list[str],
    events: list[Event],
    description: str,
    evidence_events: list[Event] | None = None,
) -> Finding:
    stamps = [event.timestamp for event in events]
    users = sorted({e.user for e in events if e.user not in ("-", "")})
    evidence_source = evidence_events if evidence_events is not None else events
    return Finding(
        rule=rule,
        title=title,
        severity=severity,
        ips=sorted(set(ips)),
        description=description,
        first_seen=min(stamps),
        last_seen=max(stamps),
        count=len(events),
        users=users,
        evidence=[e.raw for e in evidence_source[:MAX_EVIDENCE_LINES]],
        events=list(events),
    )


# ---------------------------------------------------------------------------
# Parsing: one function per log format, both returning Event objects
# ---------------------------------------------------------------------------


def _parse_web_stamp(stamp: str) -> datetime:
    match = WEB_STAMP_RE.match(stamp)
    if not match:
        raise ValueError(f"Unrecognised web timestamp: {stamp!r}")
    offset = match["off"]
    sign = 1 if offset[0] == "+" else -1
    tz = timezone(
        sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))
    )
    return datetime(
        int(match["year"]), MONTHS[match["mon"]], int(match["day"]),
        int(match["hh"]), int(match["mm"]), int(match["ss"]), tzinfo=tz,
    )


def parse_auth_line(line: str, year: int, tz: timezone) -> Event | None:
    """Parse one syslog line. Returns None for lines with no auth outcome."""
    match = AUTH_LINE_RE.match(line)
    if not match:
        return None
    # Syslog omits the year, so the caller supplies it (--year). A production
    # parser must also handle the Dec -> Jan rollover.
    stamp = datetime(
        year, MONTHS[match["mon"]], int(match["day"]),
        *map(int, match["clock"].split(":")), tzinfo=tz,
    )
    msg = match["msg"]

    accepted = ACCEPTED_RE.match(msg)
    if accepted:
        return Event(
            timestamp=stamp, source="auth", ip=accepted["ip"],
            outcome="success", user=accepted["user"], detail=msg, raw=line,
        )

    failed = FAILED_RE.match(msg)
    if failed:
        return Event(
            timestamp=stamp, source="auth", ip=failed["ip"],
            outcome="failure", user=failed["user"], detail=msg, raw=line,
        )

    if "authentication failure" in msg:
        user = SUDO_USER_RE.search(msg)
        rhost = RHOST_RE.search(msg)
        return Event(
            timestamp=stamp, source="auth",
            ip=(rhost["rhost"] if rhost and rhost["rhost"] else "local"),
            outcome="failure", user=user["user"] if user else "-",
            detail=msg, raw=line,
        )

    return None


def parse_web_line(line: str) -> Event | None:
    """Parse one nginx/Apache combined log line."""
    match = WEB_LINE_RE.match(line)
    if not match:
        return None
    request = match["request"]
    parsed_request = REQUEST_RE.match(request)
    method = parsed_request["method"] if parsed_request else "-"
    target = parsed_request["target"] if parsed_request else request
    status = int(match["status"])
    return Event(
        timestamp=_parse_web_stamp(match["stamp"]),
        source="web",
        ip=match["ip"],
        outcome="success" if status < 400 else "failure",
        detail=f"{method} {target} -> {status}",
        path=target,
        status=status,
        user_agent=match["ua"] or "",
        raw=line,
    )


def parse_file(path: Path, year: int, tz: timezone) -> ParseResult:
    """Read a file and classify each line as web, auth, ignored, or skipped."""
    result = ParseResult()
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue
            event = parse_web_line(line)
            if event is None:
                event = parse_auth_line(line, year, tz)
            if event is not None:
                result.events.append(event)
            elif AUTH_LINE_RE.match(line):
                result.ignored += 1
            else:
                result.skipped.append(line)
    result.events.sort(key=lambda event: event.timestamp)
    return result


# ---------------------------------------------------------------------------
# Detection rules: each function is independent and returns Findings
# ---------------------------------------------------------------------------


def detect_auth_bruteforce(events: list[Event], cfg: Config) -> list[Finding]:
    """>= N failed SSH logins from one IP inside one window."""
    failures = [
        e for e in events if e.source == "auth" and e.outcome == "failure"
    ]
    findings = []
    for ip, bucket in group_by(failures, lambda e: e.ip).items():
        if ip in ("-", "local"):
            continue
        window, count = max_window(bucket, cfg.window_minutes)
        if count < cfg.auth_failure_threshold:
            continue
        severity = "Critical" if count >= cfg.auth_failure_threshold * 2 else "High"
        users = sorted({e.user for e in window})
        findings.append(
            make_finding(
                rule="auth_brute_force",
                title=f"SSH brute force: {count} failures in {cfg.window_minutes} min",
                severity=severity,
                ips=[ip],
                events=window,
                description=(
                    f"{count} failed SSH authentications from {ip} against "
                    f"{len(users)} username(s) ({', '.join(users)}) within "
                    f"{cfg.window_minutes} minutes."
                ),
            )
        )
    return findings


def detect_password_spray(events: list[Event], cfg: Config) -> list[Finding]:
    """One username tried from >= N distinct IPs inside the spray window."""
    failures = [
        e for e in events
        if e.source == "auth" and e.outcome == "failure"
        and e.ip not in ("-", "local")
    ]
    findings = []
    for user, bucket in group_by(failures, lambda e: e.user.lower()).items():
        if not user or user == "-":
            continue
        best_events: list[Event] = []
        best_ips: set[str] = set()
        for anchor in bucket:
            window = [
                e for e in bucket
                if timedelta(0) <= e.timestamp - anchor.timestamp
                <= timedelta(minutes=cfg.spray_window_minutes)
            ]
            ips = {e.ip for e in window}
            if len(ips) > len(best_ips):
                best_events, best_ips = window, ips
        if len(best_ips) < cfg.spray_min_ips:
            continue
        findings.append(
            make_finding(
                rule="password_spray",
                title=f"Password spray: user '{user}' from {len(best_ips)} IPs",
                severity="High",
                ips=sorted(best_ips),
                events=best_events,
                description=(
                    f"Account '{user}' was targeted from {len(best_ips)} distinct "
                    f"source IPs ({', '.join(sorted(best_ips))}) within "
                    f"{cfg.spray_window_minutes} minutes, a distributed spray "
                    "pattern rather than a single-source brute force."
                ),
            )
        )
    return findings


def detect_success_after_failure(events: list[Event], cfg: Config) -> list[Finding]:
    """A successful login from an IP that just failed repeatedly: possible crack."""
    findings = []
    auth_events = [
        e for e in events if e.source == "auth" and e.ip not in ("-", "local")
    ]
    for ip, bucket in group_by(auth_events, lambda e: e.ip).items():
        failures = [e for e in bucket if e.outcome == "failure"]
        for success in (e for e in bucket if e.outcome == "success"):
            recent = [
                f for f in failures
                if timedelta(0) <= success.timestamp - f.timestamp
                <= timedelta(minutes=cfg.success_lookback_minutes)
            ]
            if len(recent) < cfg.success_after_failure_threshold:
                continue
            findings.append(
                make_finding(
                    rule="compromise_success",
                    title=(
                        f"Possible compromise: {success.user} logged in from "
                        f"{ip} after {len(recent)} failures"
                    ),
                    severity="Critical",
                    ips=[ip],
                    events=recent + [success],
                    # Last failures plus the success make the cleanest evidence.
                    evidence_events=recent[-3:] + [success],
                    description=(
                        f"{ip} failed {len(recent)} times in the "
                        f"{cfg.success_lookback_minutes} minutes before a "
                        f"successful login as '{success.user}'. Either the "
                        "password was guessed or valid credentials were used "
                        "from an untrusted address."
                    ),
                )
            )
            break  # one finding per IP is enough
    return findings


def detect_off_hours(events: list[Event], cfg: Config) -> list[Finding]:
    """Successful auth for a privileged account between midnight and 06:00."""
    hits = [
        e for e in events
        if e.source == "auth" and e.outcome == "success"
        and e.user in PRIVILEGED_USERS and e.ip not in ("-", "local")
        and cfg.off_hours_start <= e.timestamp.hour < cfg.off_hours_end
    ]
    findings = []
    for (ip, user), bucket in group_by(hits, lambda e: (e.ip, e.user)).items():
        findings.append(
            make_finding(
                rule="off_hours_privileged_login",
                title=f"Off-hours login: {user} from {ip}",
                severity="Medium",
                ips=[ip],
                events=bucket,
                description=(
                    f"Privileged account '{user}' authenticated from {ip} at "
                    f"{iso(bucket[0].timestamp)} (local time), inside the "
                    f"{cfg.off_hours_start:02d}:00-{cfg.off_hours_end:02d}:00 "
                    "quiet window. Confirm whether change management approved it."
                ),
            )
        )
    return findings


def detect_web_login_bruteforce(events: list[Event], cfg: Config) -> list[Finding]:
    """>= N rejected POSTs to a login endpoint from one IP."""
    attempts = [
        e for e in events
        if e.source == "web" and e.status in WEB_LOGIN_FAIL_STATUSES
        and LOGIN_PATH_RE.search(e.path or "")
    ]
    findings = []
    for ip, bucket in group_by(attempts, lambda e: e.ip).items():
        window, count = max_window(bucket, cfg.window_minutes)
        if count < cfg.web_login_threshold:
            continue
        severity = "Critical" if count >= cfg.web_login_threshold * 2 else "High"
        agents = sorted({e.user_agent for e in window if e.user_agent})
        findings.append(
            make_finding(
                rule="web_login_bruteforce",
                title=f"Web login brute force: {count} rejected attempts",
                severity=severity,
                ips=[ip],
                events=window,
                description=(
                    f"{count} authentication requests from {ip} were rejected by "
                    "the web login endpoint in "
                    f"{cfg.window_minutes} minutes"
                    + (f", using user agent(s): {'; '.join(agents)}." if agents else ".")
                ),
            )
        )
    return findings


def detect_web_recon(events: list[Event], cfg: Config) -> list[Finding]:
    """Mass 404s and/or probes for sensitive paths from one IP."""
    web_events = [e for e in events if e.source == "web"]
    findings = []
    for ip, bucket in group_by(web_events, lambda e: e.ip).items():
        missing = [e for e in bucket if e.status == 404]
        missing_window, missing_count = max_window(missing, cfg.window_minutes)
        probes = [e for e in bucket if SENSITIVE_PATH_RE.search(e.path or "")]
        if missing_count < cfg.recon_404_threshold and len(probes) < 2:
            continue
        flagged = {id(e): e for e in missing_window + probes}
        flagged_events = sorted(flagged.values(), key=lambda e: e.timestamp)
        signals = []
        if missing_count >= cfg.recon_404_threshold:
            signals.append(
                f"{missing_count} HTTP 404s within {cfg.window_minutes} minutes"
            )
        if len(probes) >= 2:
            signals.append(f"{len(probes)} probes for sensitive paths")
        findings.append(
            make_finding(
                rule="web_recon",
                title=f"Web scanning: {' and '.join(signals)}",
                severity="High" if len(probes) >= 2 else "Medium",
                ips=[ip],
                events=flagged_events,
                description=(
                    f"Directory/exploit scanning from {ip}: "
                    f"{' and '.join(signals)}. Probes include "
                    f"{', '.join(sorted({e.path.split('?')[0] for e in probes})[:6]) or 'n/a'}."
                ),
            )
        )
    return findings


def run_detections(events: list[Event], cfg: Config) -> list[Finding]:
    """Run every rule, then return findings worst-first."""
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings = []
    findings += detect_auth_bruteforce(events, cfg)
    findings += detect_password_spray(events, cfg)
    findings += detect_success_after_failure(events, cfg)
    findings += detect_off_hours(events, cfg)
    findings += detect_web_login_bruteforce(events, cfg)
    findings += detect_web_recon(events, cfg)
    findings.sort(key=lambda f: (severity_rank.get(f.severity, 9), -f.count))
    return findings


# ---------------------------------------------------------------------------
# Risk scoring and statistics
# ---------------------------------------------------------------------------

RULE_WEIGHTS = {
    "auth_brute_force": 40,
    "password_spray": 35,
    "compromise_success": 50,
    "off_hours_privileged_login": 15,
    "web_login_bruteforce": 45,
    "web_recon": 45,
}

RULE_LABELS = {
    "auth_brute_force": "SSH brute force",
    "password_spray": "Password spray",
    "compromise_success": "Success after failures",
    "off_hours_privileged_login": "Off-hours admin login",
    "web_login_bruteforce": "Web login brute force",
    "web_recon": "Web scanning",
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def risk_label(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def build_ip_summary(findings: list[Finding]) -> list[dict]:
    """Sum rule weights per IP (capped at 100) to rank the sources."""
    rows: dict[str, dict] = {}
    for finding in findings:
        for ip in finding.ips:
            row = rows.setdefault(
                ip, {"ip": ip, "score": 0, "rules": [], "findings": 0}
            )
            row["score"] = min(100, row["score"] + RULE_WEIGHTS.get(finding.rule, 10))
            row["rules"].append(finding.rule)
            row["findings"] += 1
    for row in rows.values():
        row["rules"] = sorted(set(row["rules"]))
        row["risk"] = risk_label(row["score"])
    return sorted(rows.values(), key=lambda row: (-row["score"], row["ip"]))


def build_stats(
    events: list[Event], ignored: int, skipped: list[str], files: list[str]
) -> dict:
    auth = [e for e in events if e.source == "auth"]
    web = [e for e in events if e.source == "web"]
    auth_failures = [e for e in auth if e.outcome == "failure"]
    web_failures = [e for e in web if e.outcome == "failure"]
    talkers = Counter(e.ip for e in events)
    return {
        "inputs": files,
        "total_events": len(events),
        "auth_events": len(auth),
        "web_events": len(web),
        "auth_failures": len(auth_failures),
        "web_failures": len(web_failures),
        "web_404s": sum(1 for e in web if e.status == 404),
        "unique_source_ips": len({e.ip for e in events}),
        "first_event": iso(min(e.timestamp for e in events)),
        "last_event": iso(max(e.timestamp for e in events)),
        "ignored_lines": ignored,
        "unparsed_lines": len(skipped),
        "top_talkers": [
            {"ip": ip, "events": count} for ip, count in talkers.most_common(5)
        ],
    }


def build_timeline(findings: list[Finding], limit: int = 30) -> list[dict]:
    """Merge flagged events into one chronological timeline."""
    seen = set()
    rows = []
    for finding in findings:
        for event in finding.events:
            key = (event.timestamp, event.ip, event.outcome)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "time": iso(event.timestamp),
                    "ip": event.ip,
                    "source": event.source,
                    "outcome": event.outcome,
                    "rule": finding.rule,
                    "detail": event.detail,
                }
            )
    rows.sort(key=lambda row: row["time"])
    return rows[:limit]


# ---------------------------------------------------------------------------
# Local LLM: prompt assembly and Ollama call
# ---------------------------------------------------------------------------

PROMPT_HEADER = """You are a Tier-1 SOC analyst writing the narrative section of an incident triage report.

CONTEXT
- The dataset is a synthetic lab sample for a portfolio project; no production data.
- All timestamps are local time (+08:00).
- Detection is already done by explicit rules. Analyse and explain the evidence; do not invent new events.

STRICT RULES
1. Use only the evidence below. Never invent IPs, usernames, hostnames, CVEs, or timestamps.
2. Quote IPs and timestamps exactly as written.
3. If the logs cannot establish something, write "not established from the available logs".
4. Output Markdown only. No code fences around the answer. No top-level (#) title.
5. 300-420 words.
6. Treat "compromise_success" as a probable compromise, not a proven one.
7. Every "compromise_success" and "off_hours_privileged_login" finding is a real successful authentication. Account for all of them; never claim only one login succeeded when several findings exist.
8. Use the exact success timestamp from the evidence, not the last failure timestamp.

REQUIRED SECTIONS
### Executive Summary
2-3 sentences: what happened, overall severity, highest-risk source IP, and whether any login succeeded.
### Attack Chain
Chronological story: attempts, escalation, success, follow-on activity. Merge findings that share a source IP.
### MITRE ATT&CK Mapping
A table with columns: Technique | ID | Evidence. Only techniques the evidence supports (for example T1110 Brute Force, T1078 Valid Accounts, T1595 Active Scanning, T1190 Exploit Public-Facing Application). Omit any row you cannot support; do not force five rows.
### Containment & Remediation
4-6 prioritised, concrete actions for the flagged IPs, accounts, and services.
### Detection Gaps & Next Steps
3-4 sentences on what this rule set would miss or over-alert on, and which log sources or rules to add next.

EVIDENCE (JSON)
"""


def build_prompt(findings: list[Finding], stats: dict, meta: dict) -> str:
    """Feed the model compact, structured evidence - never raw whole logs."""
    evidence = {
        "generated_at": meta["generated_at"],
        "inputs": meta["files"],
        "statistics": stats,
        "findings": [
            {
                "rule": f.rule,
                "severity": f.severity,
                "title": f.title,
                "source_ips": f.ips,
                "users": f.users,
                "events": f.count,
                "first_seen": iso(f.first_seen),
                "last_seen": iso(f.last_seen),
                "description": f.description,
                "sample_log_lines": [line[:220] for line in f.evidence[-2:]],
            }
            for f in findings
        ],
    }
    return PROMPT_HEADER + json.dumps(
        evidence, separators=(",", ":"), ensure_ascii=True
    )


def clean_narrative(text: str) -> str:
    """Strip code fences and any thinking block some models emit."""
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\s*\n", "", text)
    text = re.sub(r"\n```$", "", text)
    # Some reasoning models wrap hidden chain-of-thought in a think block.
    text = re.sub(r"<think.*?think>", "", text, flags=re.S)
    return text.strip()


def ask_ollama(
    prompt: str, model: str, url: str, timeout: int
) -> str:
    """Single blocking call to Ollama's generate endpoint. No streaming."""
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {"temperature": 0.2, "num_ctx": 4096, "num_predict": 1100},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"Ollama HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"cannot reach Ollama at {url} ({exc.reason}); is 'ollama serve' running?"
        ) from exc
    except (TimeoutError, OSError) as exc:
        raise RuntimeError(f"Ollama call failed after {timeout}s: {exc}") from exc
    if body.get("done_reason") == "length":
        print(
            "[!] warning: model hit the output token cap; narrative may be truncated.",
            file=sys.stderr,
        )
    text = clean_narrative(body.get("response", ""))
    if not text:
        raise RuntimeError("Ollama returned an empty response")
    return text


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _cell(value) -> str:
    """Keep table cells from breaking the Markdown table."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def md_table(headers: list[str], rows: list[list]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        lines.append("| " + " | ".join(_cell(value) for value in row) + " |")
    return lines


def render_report(
    findings: list[Finding],
    ip_rows: list[dict],
    stats: dict,
    timeline: list[dict],
    narrative: str | None,
    ai_error: str | None,
    meta: dict,
    cfg: Config,
) -> str:
    lines: list[str] = []
    model_line = (
        f"`{meta['model']}` via Ollama - local inference, $0 cloud cost"
        if narrative
        else "not used for this run (rule-based output only)"
    )
    lines += [
        "# Security Log Triage Report",
        "",
        f"**Generated:** {meta['generated_at']}  ",
        f"**Analyzer:** `parse_logs.py` rule engine + local LLM  ",
        f"**Model:** {model_line}  ",
        f"**Inputs:** {', '.join(f'`{name}`' for name in meta['files'])}  ",
        "",
        "## 1. Detection Summary",
        "",
    ]
    counts = Counter(f.severity for f in findings)
    lines += md_table(
        ["Metric", "Value"],
        [
            ["Events parsed", stats["total_events"]],
            ["Auth / web events", f"{stats['auth_events']} / {stats['web_events']}"],
            ["Failed auth events", stats["auth_failures"]],
            ["Findings", len(findings)],
            [
                "Severity mix",
                ", ".join(
                    f"{severity}: {counts.get(severity, 0)}"
                    for severity in SEVERITY_ORDER
                ),
            ],
            ["Flagged source IPs", len(ip_rows)],
            ["Observation window", f"{stats['first_event']} -> {stats['last_event']}"],
        ],
    )

    lines += ["", "## 2. Findings at a Glance", ""]
    if findings:
        lines += md_table(
            ["#", "Severity", "Rule", "Finding", "Source IP(s)", "Events", "Window"],
            [
                [
                    index,
                    finding.severity.upper(),
                    f"`{finding.rule}`",
                    finding.title,
                    ", ".join(finding.ips),
                    finding.count,
                    f"{iso(finding.first_seen)} -> {iso(finding.last_seen)}",
                ]
                for index, finding in enumerate(findings, 1)
            ],
        )
    else:
        lines.append(
            "No rule thresholds were triggered. The log window looks clean at "
            "the configured sensitivity."
        )

    lines += ["", "## 3. Suspicious IP Ranking", ""]
    if ip_rows:
        lines += md_table(
            ["Risk", "Score", "Source IP", "Findings", "Rules triggered"],
            [
                [
                    row["risk"],
                    f"{row['score']}/100",
                    f"`{row['ip']}`",
                    row["findings"],
                    ", ".join(RULE_LABELS.get(rule, rule) for rule in row["rules"]),
                ]
                for row in ip_rows
            ],
        )
        lines += [
            "",
            "Scores are the sum of per-rule weights, capped at 100. They rank "
            "attention, not certainty.",
        ]
    else:
        lines.append("No source IP crossed a detection threshold.")

    lines += ["", "## 4. Triage Narrative", ""]
    if narrative:
        lines.append(narrative)
    else:
        lines += [
            f"> **Local model narrative unavailable.** {ai_error}",
            ">",
            "> The rule-based findings in this report are complete and unaffected. "
            "Start Ollama (`ollama serve`) and rerun without `--no-ai` to add the "
            "narrative.",
        ]

    lines += ["", "## 5. Detection Detail", ""]
    if findings:
        for index, finding in enumerate(findings, 1):
            lines += [
                f"### 5.{index} [{finding.severity.upper()}] {finding.title}",
                "",
                f"- **Rule:** `{finding.rule}`",
                f"- **Source IP(s):** {', '.join(f'`{ip}`' for ip in finding.ips)}",
                f"- **Users involved:** {', '.join(finding.users) if finding.users else 'n/a'}",
                f"- **Events:** {finding.count}",
                f"- **First seen:** {iso(finding.first_seen)}",
                f"- **Last seen:** {iso(finding.last_seen)}",
                "",
                finding.description,
                "",
                "```text",
                *finding.evidence,
                "```",
                "",
            ]
    else:
        lines += ["Nothing to detail.", ""]

    lines += ["## 6. Flagged Event Timeline", ""]
    if timeline:
        lines += md_table(
            ["Time", "Source", "IP", "Outcome", "Rule", "Detail"],
            [
                [
                    row["time"],
                    row["source"],
                    row["ip"],
                    row["outcome"],
                    f"`{row['rule']}`",
                    row["detail"],
                ]
                for row in timeline
            ],
        )
    else:
        lines.append("No flagged events.")

    lines += ["", "## 7. Appendix - Parsed Statistics", ""]
    lines += md_table(
        ["Statistic", "Value"],
        [
            ["Input files", ", ".join(stats["inputs"])],
            ["Total events", stats["total_events"]],
            ["Auth events", stats["auth_events"]],
            ["Web events", stats["web_events"]],
            ["Auth failures", stats["auth_failures"]],
            ["Web failures (4xx/5xx)", stats["web_failures"]],
            ["HTTP 404 responses", stats["web_404s"]],
            ["Unique source IPs", stats["unique_source_ips"]],
            ["Valid but non-security lines ignored", stats["ignored_lines"]],
            ["Unrecognised lines skipped", stats["unparsed_lines"]],
            [
                "Busiest source IPs",
                ", ".join(
                    f"{row['ip']} ({row['events']})"
                    for row in stats["top_talkers"]
                ),
            ],
        ],
    )

    lines += ["", "## 8. Appendix - Detection Configuration", ""]
    lines += md_table(
        ["Parameter", "Value"],
        [
            ["Burst window", f"{cfg.window_minutes} min"],
            ["SSH failure threshold", f">= {cfg.auth_failure_threshold} / window"],
            ["Web login threshold", f">= {cfg.web_login_threshold} / window"],
            ["Spray: distinct IPs", f">= {cfg.spray_min_ips} / {cfg.spray_window_minutes} min"],
            [
                "Success after failures",
                f">= {cfg.success_after_failure_threshold} failures in {cfg.success_lookback_minutes} min",
            ],
            ["Web recon 404 threshold", f">= {cfg.recon_404_threshold} / window"],
            ["Quiet hours", f"{cfg.off_hours_start:02d}:00-{cfg.off_hours_end:02d}:00 local"],
        ],
    )
    lines += ["", "### Rule weights", ""]
    lines += md_table(
        ["Rule", "Weight"],
        [[f"`{rule}`", weight] for rule, weight in RULE_WEIGHTS.items()],
    )

    lines += [
        "",
        "---",
        "",
        "*Synthetic lab data. Detection and narrative were produced on local "
        "hardware: Python rules plus `qwen3.5:9b` through Ollama. No log content "
        "left this machine.*",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Rule-based log triage with a local Ollama narrative."
    )
    parser.add_argument("logs", nargs="+", help="auth syslog and/or access logs")
    parser.add_argument("--out", default="report.md", help="Markdown report path")
    parser.add_argument("--json", default="findings.json", help="JSON findings path")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model tag")
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument(
        "--no-ai", action="store_true", help="skip Ollama, deterministic report only"
    )
    parser.add_argument(
        "--year", type=int, default=None, help="year for syslog lines (default: now)"
    )
    parser.add_argument(
        "--tz", default="+08:00", help="UTC offset for syslog lines (default: +08:00)"
    )
    parser.add_argument(
        "--window", type=int, default=5, help="burst window in minutes (default: 5)"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="failures per window before alerting (default: 5)",
    )
    parser.add_argument(
        "--timeout", type=int, default=600, help="Ollama timeout in seconds"
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        tz = parse_offset(args.tz)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    year = args.year or datetime.now(tz).year

    events: list[Event] = []
    ignored = 0
    skipped: list[str] = []
    for name in args.logs:
        path = Path(name)
        if not path.is_file():
            print(f"[!] missing log file: {path}", file=sys.stderr)
            return 1
        result = parse_file(path, year, tz)
        events.extend(result.events)
        ignored += result.ignored
        skipped.extend(result.skipped)
    events.sort(key=lambda event: event.timestamp)
    if not events:
        print("[!] no events parsed - check the format or --year", file=sys.stderr)
        return 1

    cfg = replace(
        Config(),
        window_minutes=args.window,
        auth_failure_threshold=args.threshold,
        web_login_threshold=args.threshold,
    )
    findings = run_detections(events, cfg)
    meta = {
        "generated_at": datetime.now(tz).isoformat(timespec="seconds"),
        "files": [Path(name).name for name in args.logs],
        "model": args.model,
    }
    stats = build_stats(events, ignored, skipped, [Path(n).name for n in args.logs])
    ip_rows = build_ip_summary(findings)
    timeline = build_timeline(findings)

    print(
        f"[*] Parsed {stats['total_events']} events "
        f"(auth {stats['auth_events']} / web {stats['web_events']}), "
        f"{ignored} ignored, {len(skipped)} unparsed"
    )
    print(f"[*] {len(findings)} findings across {len(ip_rows)} flagged IP(s)")

    narrative: str | None = None
    ai_error: str | None = None
    if args.no_ai:
        ai_error = "Skipped by `--no-ai`."
    elif not findings:
        ai_error = "No findings above threshold, so no narrative was requested."
    else:
        print(f"[*] Asking {args.model} for the triage narrative (local)...")
        try:
            narrative = ask_ollama(
                build_prompt(findings, stats, meta),
                args.model,
                args.ollama_url,
                args.timeout,
            )
        except RuntimeError as exc:
            ai_error = str(exc)
            print(f"[!] {exc}", file=sys.stderr)
            print("[*] Continuing with the deterministic report only.")

    report_path = Path(args.out)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        render_report(findings, ip_rows, stats, timeline, narrative, ai_error, meta, cfg),
        encoding="utf-8",
        newline="\n",
    )

    payload = {
        "generated_at": meta["generated_at"],
        "inputs": meta["files"],
        "model": None if args.no_ai else args.model,
        "config": vars(cfg).copy(),
        "statistics": stats,
        "ip_summary": ip_rows,
        "findings": [finding.to_dict() for finding in findings],
        "ai": {"used": narrative is not None, "error": ai_error},
    }
    json_path = Path(args.json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"[+] Wrote {report_path} and {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
