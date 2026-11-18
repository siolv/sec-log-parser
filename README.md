# AI-Assisted Security Log Analyzer

Rule-based log triage in Python, with the incident narrative written by a **local** LLM.
No cloud APIs, no API keys, no per-token bill. Runs on one machine and the logs never leave it.

```
sample_auth.log   ─┐
sample_access.log ─┴─> parse -> detect -> score -> local LLM -> report.md
                                                            └─> findings.json
```

## What it does

1. Parses SSH/sudo syslog and nginx/Apache combined access logs into one normalised `Event` stream.
2. Runs six independent detection rules: SSH brute force, distributed password spray, success after failures, off-hours privileged login, web login brute force, web reconnaissance.
3. Scores and ranks every source IP.
4. Feeds **only the structured findings** to `qwen3.5:9b` through Ollama and writes a Markdown incident triage report.
5. Always writes the deterministic findings, even if the model is offline. The AI is enrichment, not the detector.

## Quickstart

Requirements: Python 3.10+, [Ollama](https://ollama.com) with the model pulled.

```bash
ollama pull qwen3.5:9b

cd sec-log-parser
python parse_logs.py sample_auth.log sample_access.log
```

That produces:

| File | Contents |
| --- | --- |
| `report.md` | Full triage report: summary, IP ranking, AI narrative, evidence, timeline, config |
| `findings.json` | Machine-readable findings for a SIEM, dashboard, or next pipeline stage |

No `pip install` is needed. The analyzer is standard library only.

Fast, offline, deterministic run (no model call):

```bash
python parse_logs.py sample_auth.log sample_access.log --no-ai
```

## Example output

From `report.md` on the bundled sample:

| Risk | Score | Source IP | Rules triggered |
| --- | --- | --- | --- |
| CRITICAL | 100/100 | `203.0.113.42` | SSH brute force, success after failures, off-hours login, web login brute force |
| HIGH | 45/100 | `198.51.100.66` | Web login brute force |
| HIGH | 45/100 | `192.0.2.77` | Web scanning |
| MEDIUM | 35/100 | `192.0.2.201` | Password spray |
| MEDIUM | 35/100 | `192.0.2.202` | Password spray |
| MEDIUM | 35/100 | `192.0.2.203` | Password spray |

The model's narrative turns those rows into an attack chain, a MITRE ATT&CK table, containment steps and detection gaps. It is told to use only supplied evidence and to say "not established from the available logs" when the data cannot support a claim.

## Tests

Standard library only, no install needed:

```bash
python -m unittest discover -s tests -v
```

32 tests pin the behaviour the README promises:

| Group | What it locks down |
| --- | --- |
| `ParserTests` | both formats produce `Event`s, timestamps stay timezone-aware, junk lines don't crash |
| `RuleTests` | each of the six detectors fires on its planted scenario |
| `NoiseTests` | normal traffic is *not* flagged, and threshold overrides take effect |
| `ScoringTests` | weights are stable, scores cap at 100, every finding carries evidence |
| `PromptTests` | only findings reach the model, and the anti-invention rules are present |
| `NarrativeSafetyTests` | model text never becomes data in `findings.json` |
| `GroundingTests` | invented addresses in the narrative are caught |
| `CliTests` | end-to-end run writes both files and exits 0 |

CI runs the suite on Python 3.10, 3.11 and 3.12 plus a real CLI invocation on every push.

## Narrative grounding check

The model can write prose; it cannot create a finding. That separation keeps the data clean, but a human reading `report.md` could still be misled by an invented IP.

`grounding.py` closes that gap. After the model responds, every address in the narrative is compared against the addresses in the findings. Anything that appears in prose but not in evidence triggers a warning block above the narrative:

> [!warning] Narrative grounding check
> Narrative mentions address(es) not present in the findings: `45.33.12.9`. Treat these as model-generated text, not evidence.

Loopback and private ranges are ignored so ordinary prose doesn't trip it. The JSON is never affected — it is built from `Finding` objects and never parses model output.

## Detection rules

| Rule | Signal | Default trigger | Weight |
| --- | --- | --- | --- |
| `auth_brute_force` | Many SSH failures, one IP | >= 5 failures in 5 min | 40 |
| `password_spray` | One username, many IPs | >= 3 IPs in 10 min | 35 |
| `compromise_success` | Success right after failures | >= 3 failures in the prior 15 min | 50 |
| `off_hours_privileged_login` | Root/admin/deploy/svc-* login at night | 00:00-05:59 local | 15 |
| `web_login_bruteforce` | Rejected POSTs to a login path | >= 5 in 5 min (401/403/429) | 45 |
| `web_recon` | 404 bursts and sensitive-path probes | >= 10 404s in 5 min or >= 2 probes | 45 |

IP score = sum of triggered rule weights, capped at 100. Scores rank attention, not certainty.
Thresholds and windows live in one `Config` dataclass and can be overridden from the CLI.

## What is planted in the sample logs

The sample is synthetic. Every address is from an RFC 5737 documentation range.

| Scenario | Source | What to look for |
| --- | --- | --- |
| SSH brute force -> success | `203.0.113.42` | 9 failures from 22:14, `svc-backup` accepted at 22:21 |
| Follow-on privileged login | `203.0.113.42` | `deploy` accepted at 02:14 the next morning |
| Credential stuffing | `198.51.100.66` | 8 rejected `POST /login`, then HTTP 429 at 09:42 |
| Recon / exploit probes | `192.0.2.77` | `/.env`, `/.git/config`, `/phpmyadmin/`, SQLi payload, Nmap/sqlmap UAs |
| Distributed spray | `192.0.2.201-203` | `admin` tried from three IPs in under two minutes |
| Normal noise | multiple | health checks, a typo 404, a failed `sudo`, routine deploy logins |

The normal noise matters: the report would be useless if every 404 or one mistyped password raised an incident.

## CLI

```text
python parse_logs.py LOG [LOG ...] [options]

--out PATH            Markdown report path              (default: report.md)
--json PATH           JSON findings path               (default: findings.json)
--model TAG           Ollama model tag                 (default: qwen3.5:9b)
--ollama-url URL      Ollama generate endpoint         (default: http://localhost:11434/api/generate)
--no-ai               Skip the model, write the rule-based report only
--year YYYY           Year for syslog lines            (default: current year)
--tz +HH:MM           UTC offset for syslog lines      (default: +08:00)
--window MINUTES      Burst window                     (default: 5)
--threshold N         Failures per window              (default: 5)
--timeout SECONDS     Ollama request timeout           (default: 600)
```

## How the AI layer is wired

- Findings are serialised to compact JSON: rule, severity, IPs, users, timestamps, counts, descriptions, two sample lines each. Raw logs are not shipped to the model.
- The prompt forbids invented IPs, users, CVEs and timestamps, and requires an explicit "not established" when evidence is thin.
- Temperature 0.2, `think: false`, 4k context, 900 output-token cap. Qwen 9B on CPU is slow (roughly 4 tokens/s here); the default timeout is 600 seconds. Use `--no-ai` while iterating on rules.
- If Ollama is down, the report still renders and says why the narrative is missing.

## Project layout

```
sec-log-parser/
├── parse_logs.py         # parser + detectors + prompt + Ollama client + report renderer
├── sample_auth.log       # synthetic SSH/sudo syslog
├── sample_access.log     # synthetic nginx combined access log
├── report.md             # generated sample report
├── findings.json         # generated JSON findings
├── WALKTHROUGH.md        # line-by-line explanation of the detection logic
└── README.md
```

## Design choices

- **One event model for two formats.** Rules never care whether a failure came from SSH or HTTP, only about the fields they need.
- **Exact sliding windows.** `max_window()` finds the densest burst per IP, so a slow trickle over an hour does not alert while a real burst does.
- **Evidence attached to every finding.** Report, JSON, and prompt all read from the same object; nothing is re-derived later.
- **Deterministic core, probabilistic narrative.** A hallucinating model cannot create or remove a finding. It only explains what the rules already proved.

## Limitations

- Single-file, batch mode. No tailing, no persistence, no state between runs.
- Grounding check compares narrative IPs only; invented usernames or timestamps in prose are not yet cross-checked.
- Regex parsers target classic syslog and nginx/Apache combined format. JSON logs, Windows Event Log and cloud trails need adapters.
- No geolocation, threat-intel enrichment, or baseline learning. A successful login is flagged only when it follows failures or happens off-hours for a privileged account.
- `svc-backup` is treated as privileged by name, not by directory lookup. Real deployments should resolve privilege from IAM.
- Success is not proof of compromise. The report language says "possible" on purpose.

## Roadmap

- JSON and Windows Event Log adapters behind the same `Event` model.
- YAML rule config and per-rule severity overrides.
- `--follow` mode with in-memory state and webhook alerts.
- Optional STIX/CSV export and ATT&CK coverage summary.
- Dockerfile and packaging as a single binary.

## Safety

The sample data is fabricated and uses RFC 5737 documentation ranges. No credentials, tokens, or real infrastructure details are stored in this repository. The analyzer sends findings to `localhost` only and has no telemetry.
