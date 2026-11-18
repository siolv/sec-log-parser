"""Test suite for the AI-Assisted Security Log Analyzer.

Standard library only — runs with `python -m unittest discover -s tests`.

Each test pins one behaviour the README promises. If a rule's threshold,
window, or grouping ever drifts, one of these fails.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import parse_logs as pl  # noqa: E402

TZ = timezone(timedelta(hours=8))
AUTH = ROOT / "sample_auth.log"
ACCESS = ROOT / "sample_access.log"


def load_events() -> list[pl.Event]:
    events: list[pl.Event] = []
    for path in (AUTH, ACCESS):
        events.extend(pl.parse_file(path, 2026, TZ).events)
    return events


def run(events=None, **cfg_overrides) -> list[pl.Finding]:
    events = events if events is not None else load_events()
    return pl.run_detections(events, pl.Config(**cfg_overrides))


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


class ParserTests(unittest.TestCase):
    """Both log formats must collapse into the same Event shape."""

    def test_auth_log_parses_to_events(self):
        result = pl.parse_file(AUTH, 2026, TZ)
        self.assertGreater(len(result.events), 0, "auth log produced no events")
        for event in result.events:
            self.assertEqual(event.source, "auth")
            self.assertIn(event.outcome, ("success", "failure"))

    def test_web_log_parses_to_events(self):
        result = pl.parse_file(ACCESS, 2026, TZ)
        self.assertGreater(len(result.events), 0, "web log produced no events")
        for event in result.events:
            self.assertEqual(event.source, "web")

    def test_web_event_carries_path_and_status(self):
        events = [e for e in pl.parse_file(ACCESS, 2026, TZ).events
                  if e.path == "/login" and e.status is not None]
        self.assertTrue(events, "no /login request parsed")
        self.assertIn(events[0].status, (200, 401, 403, 429))

    def test_unparseable_lines_are_ignored_not_fatal(self):
        result = pl.parse_file(ROOT / "sample_auth.log", 2026, TZ)
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, "ignored"))

    def test_timestamps_are_timezone_aware(self):
        for event in load_events():
            self.assertIsNotNone(event.timestamp.tzinfo,
                                 f"naive timestamp on: {event.raw[:60]}")


class RuleTests(unittest.TestCase):
    """Each of the six detectors must fire on its planted scenario."""

    def test_auth_bruteforce_flagged(self):
        hits = by_rule(run(), "auth_brute_force")
        self.assertTrue(hits, "SSH brute force not detected")
        self.assertIn("203.0.113.42", hits[0].ips)

    def test_password_spray_groups_by_user_across_ips(self):
        hits = by_rule(run(), "password_spray")
        self.assertTrue(hits, "spray not detected")
        self.assertGreaterEqual(len(hits[0].ips), 3,
                                "spray should name at least 3 source IPs")
        self.assertTrue(hits[0].users, "spray should name the targeted account")

    def test_success_after_failure_flagged(self):
        hits = by_rule(run(), "compromise_success")
        self.assertTrue(hits, "compromise_success not detected")
        self.assertIn("203.0.113.42", hits[0].ips)

    def test_off_hours_privileged_login_flagged(self):
        hits = by_rule(run(), "off_hours_privileged_login")
        self.assertTrue(hits, "off-hours login not detected")
        hour = hits[0].first_seen.astimezone(TZ).hour
        self.assertTrue(hour < 6, f"expected an hour before 06:00, got {hour}")

    def test_web_login_bruteforce_flagged(self):
        hits = by_rule(run(), "web_login_bruteforce")
        self.assertTrue(hits, "web login brute force not detected")
        self.assertIn("198.51.100.66", hits[0].ips)

    def test_web_recon_flagged(self):
        hits = by_rule(run(), "web_recon")
        self.assertTrue(hits, "web recon not detected")
        self.assertIn("192.0.2.77", hits[0].ips)


class NoiseTests(unittest.TestCase):
    """The sample is full of normal traffic. The rules must stay quiet on it."""

    def test_noise_ips_are_not_flagged(self):
        flagged = set()
        for finding in run():
            flagged.update(finding.ips)
        for benign in ("192.0.2.45", "198.51.100.23"):
            self.assertNotIn(benign, flagged,
                             f"{benign} is normal traffic but was flagged")

    def test_raising_thresholds_silences_the_bruteforce(self):
        hits = by_rule(run(auth_failure_threshold=500), "auth_brute_force")
        self.assertFalse(hits, "threshold override did not take effect")


class ScoringTests(unittest.TestCase):
    """Scores rank attention and are capped, so the scale stays readable."""

    def test_critical_ip_scores_100(self):
        summary = {row["ip"]: row for row in pl.build_ip_summary(run())}
        self.assertIn("203.0.113.42", summary)
        self.assertEqual(summary["203.0.113.42"]["score"], 100,
                         "score should cap at 100, not accumulate past it")

    def test_weights_are_documented_and_stable(self):
        self.assertEqual(pl.RULE_WEIGHTS["compromise_success"], 50)
        self.assertEqual(pl.RULE_WEIGHTS["auth_brute_force"], 40)
        self.assertEqual(pl.RULE_WEIGHTS["off_hours_privileged_login"], 15)

    def test_every_finding_has_evidence(self):
        for finding in run():
            self.assertTrue(finding.evidence,
                            f"{finding.rule} produced a finding with no evidence")

    def test_all_rule_names_have_a_weight(self):
        for finding in run():
            self.assertIn(finding.rule, pl.RULE_WEIGHTS,
                          f"{finding.rule} has no weight defined")


class PromptTests(unittest.TestCase):
    """The model receives findings only — never raw log lines wholesale."""

    def test_prompt_contains_findings_not_raw_logs(self):
        findings = run()
        prompt = pl.build_prompt(findings, {"events": 82}, {"generated_at": "now", "files": ["x"]})
        self.assertIn("auth_brute_force", prompt)
        self.assertIn("203.0.113.42", prompt)
        self.assertLess(len(prompt), 20000,
                        "prompt is suspiciously large — raw logs may be leaking in")

    def test_prompt_forbids_invention(self):
        findings = run()
        prompt = pl.build_prompt(findings, {}, {"generated_at": "now", "files": ["x"]})
        self.assertIn("not established from the available logs", prompt)
        self.assertIn("do not invent", prompt.lower())

    def test_prompt_evidence_lines_are_truncated(self):
        findings = run()
        prompt = pl.build_prompt(findings, {}, {"generated_at": "now", "files": ["x"]})
        for finding in findings:
            for line in finding.evidence:
                self.assertLessEqual(len(line), 220,
                                     "evidence lines must be truncated to 220 chars")


class NarrativeSafetyTests(unittest.TestCase):
    """A hallucinated IP must be detectable and must never reach the JSON."""

    def test_clean_narrative_strips_code_fences(self):
        raw = "```markdown\n### Executive Summary\nText here.\n```"
        self.assertEqual(pl.clean_narrative(raw), "### Executive Summary\nText here.")

    def test_clean_narrative_strips_think_blocks(self):
        raw = "<think>secret reasoning</think>\n### Summary\nReal content."
        self.assertNotIn("secret reasoning", pl.clean_narrative(raw))

    def test_findings_json_contains_only_parsed_ips(self):
        """The JSON is built from Finding objects, never from model output."""
        parsed_ips = {e.ip for e in load_events()}
        for finding in run():
            for ip in finding.ips:
                self.assertIn(ip, parsed_ips,
                              f"{ip} was never seen in the logs")

    def test_hallucinated_ip_is_not_in_findings_payload(self):
        findings = run()
        payload = json.dumps([f.to_dict() for f in findings])
        self.assertNotIn("45.33.12.9", payload,
                         "a never-seen IP leaked into the findings payload")


class GroundingTests(unittest.TestCase):
    """The grounding check must catch invented addresses in the narrative."""

    def test_grounded_narrative_passes(self):
        from grounding import check_narrative
        findings = run()
        text = "Traffic from 203.0.113.42 was blocked after brute force."
        result = check_narrative(text, findings)
        self.assertTrue(result.clean, result.detail)

    def test_hallucinated_ip_is_flagged(self):
        from grounding import check_narrative
        findings = run()
        text = "The attacker at 45.33.12.9 moved laterally at 02:14."
        result = check_narrative(text, findings)
        self.assertFalse(result.clean)
        self.assertIn("45.33.12.9", result.ungrounded_ips)

    def test_private_and_loopback_addresses_are_ignored(self):
        from grounding import check_narrative
        findings = run()
        text = "Local host 127.0.0.1 and internal 10.0.0.5 relayed traffic."
        self.assertTrue(check_narrative(text, findings).clean)

    def test_warning_block_is_rendered_only_on_failure(self):
        from grounding import check_narrative, render_warning
        findings = run()
        ok = check_narrative("203.0.113.42 attacked.", findings)
        bad = check_narrative("45.33.12.9 attacked.", findings)
        self.assertEqual(render_warning(ok), [])
        self.assertTrue(render_warning(bad))
        self.assertIn("45.33.12.9", " ".join(render_warning(bad)))

    def test_invalid_ip_shapes_are_not_flagged(self):
        from grounding import check_narrative
        findings = run()
        text = "Build 999.999.999.999 shipped in version 1.2.3 next to 10.1.2."
        result = check_narrative(text, findings)
        self.assertNotIn("999.999.999.999", result.ungrounded_ips,
                         "invalid octets should not be flagged as an IP")
        self.assertNotIn("1.2.3", result.ungrounded_ips,
                         "a three-part version string is not an address")


class CliTests(unittest.TestCase):
    """The end-to-end path writes both outputs and exits cleanly."""

    def test_no_ai_run_writes_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.md"
            js = Path(tmp) / "f.json"
            code = pl.main([
                str(AUTH), str(ACCESS),
                "--no-ai", "--out", str(out), "--json", str(js),
            ])
            self.assertEqual(code, 0, "CLI did not exit 0")
            self.assertTrue(out.is_file(), "report.md not written")
            self.assertTrue(js.is_file(), "findings.json not written")

            data = json.loads(js.read_text(encoding="utf-8"))
            self.assertIn("findings", data)
            self.assertTrue(data["findings"], "no findings in JSON output")
            self.assertFalse(data.get("ai", {}).get("enabled", False),
                             "--no-ai should record the model as disabled")

    def test_report_renders_without_ai(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.md"
            pl.main([str(AUTH), str(ACCESS), "--no-ai", "--out", str(out),
                     "--json", str(Path(tmp) / "f.json")])
            text = out.read_text(encoding="utf-8")
            self.assertIn("203.0.113.42", text)
            self.assertIn("CRITICAL", text.upper())

    def test_missing_log_file_exits_nonzero(self):
        code = pl.main(["does_not_exist.log", "--no-ai"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
