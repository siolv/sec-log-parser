# Walkthrough - How the Detection Logic Works

This is the study companion to `parse_logs.py`. It follows one line of data from raw log
text to a ranked finding and then into the model prompt. Read it with the code open; every
rule is small enough to verify by hand.

## 0. The shape of the program

Three stages, deliberately separated:

```
parse_file()          -> list[Event]      one normalised object per security-relevant line
run_detections()      -> list[Finding]    independent rules, each returns evidence
render_report()       -> report.md        deterministic report + optional AI narrative
```

The model is called **after** detection. It cannot add, remove, or reweight a finding.

## 1. The event model

Two log formats become one dataclass:

```python
@dataclass
class Event:
    timestamp: datetime
    source: str        # "auth" | "web"
    ip: str            # "local" for sudo failures with no remote host
    outcome: str       # "success" | "failure"
    user: str = "-"
    detail: str = ""
    path: str = ""
    status: int | None = None
    user_agent: str = ""
    raw: str = ""      # original line, reused as evidence
```

Why normalise first? A rule such as "5 failures from one IP in 5 minutes" should not care
whether the failure was an SSH password or an HTTP 401. The detectors only read
`source`, `outcome`, `ip`, `user`, `status` and `path`.

`raw` is kept so the report can quote the exact log line without re-reading the file.

## 2. Parsing, format by format

### SSH / sudo syslog

Real line:

```text
Nov 17 22:14:08 web01 sshd[3901]: Failed password for root from 203.0.113.42 port 44210 ssh2
```

Pattern (`AUTH_LINE_RE`), using named groups so the code never indexes magic positions:

```python
r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
r"(?P<proc>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
```

- `proc` is `[^\s\[]+` rather than a hardcoded list, so `sshd`, `sudo` and
  `pam_unix(sudo:auth)` all parse.
- Syslog has **no year**. `parse_auth_line()` receives `year` (`--year`, default current
  year) and a timezone (`--tz`, default `+08:00`), then builds an aware `datetime`. A
  production parser also needs a Dec 31 -> Jan 1 rollover check; the sample stays inside
  one year.
- The message decides the outcome:
  - `Accepted password|publickey for <user> from <ip>` -> success
  - `Failed password|publickey for [invalid user] <user> from <ip>` -> failure
  - `authentication failure ... user=<user>` (sudo) -> failure, with `rhost` or `local`
- Anything else that is still valid syslog (for example `Server listening`) returns
  `None` and is counted as **ignored**, not an error. A line that matches no format at
  all goes into **skipped**. On the sample: 6 ignored, 0 skipped.

Subtlety worth knowing: `SUDO_USER_RE = r"\buser=(?P<user>\S+)"`. The word boundary stops
the regex from also matching the `user=` inside `ruser=deploy`. Without it you would pull
the wrong field from the sudo line.

### nginx / Apache combined

Real line:

```text
203.0.113.42 - - [17/Nov/2026:22:05:10 +0800] "POST /login HTTP/1.1" 401 41 "-" "curl/8.4.0"
```

`WEB_LINE_RE` captures client IP, bracketed timestamp, quoted request, status, size and
optional user agent. `WEB_STAMP_RE` parses the timestamp manually instead of using
`strptime("%b")`, because month-name parsing depends on the OS locale. `MONTHS` is a plain
dict, so the result is identical everywhere.

A request like `"GET /products?page=2 HTTP/1.1"` is split into method and target. The
target, query string included, is kept in `path`: that is how the SQLi probe
`/api/v1/users?id=1%27+OR+1=1--` still matches the sensitive-path rule.

Web outcome is simply `status < 400` -> success, otherwise failure. Individual rules then
use the status code itself (`401/403/429` for auth, `404` for recon).

## 3. Grouping and the sliding window

Two helpers carry most of the logic.

`group_by()` buckets events by any key (IP, username, `(ip, user)`) and keeps each bucket
time-sorted.

`max_window(events, minutes)` answers: *what is the densest burst of events inside any
window of N minutes?*

```python
left = 0
for right, event in enumerate(events):
    while event.timestamp - events[left].timestamp > timedelta(minutes=minutes):
        left += 1
    if right - left + 1 > len(best):
        best = events[left : right + 1]
```

It is a two-pointer scan:

1. Move `right` one event forward.
2. While the span `events[right] - events[left]` is wider than the window, move `left`.
3. The remaining slice is a valid window; keep it if it is the largest seen.

Every event gets its turn as the right edge, so the maximum is exact and the cost is
linear, not `O(n^2)`.

Worked example from the sample. The nine SSH failures from `203.0.113.42` run from
22:14:08 to 22:19:31:

| Window start | Window end (+5 min) | Failures inside |
| --- | --- | --- |
| 22:14:08 | 22:19:08 | 8 (the 22:19:31 attempt falls outside) |
| 22:14:52 | 22:19:52 | 8 (the 22:14:08 attempt falls outside) |

No 5-minute window can hold all nine: the first and last are 5m23s apart. The densest
window is therefore 8, and the rule reports 8. A burst threshold is a **rate**, not a
total. The `compromise_success` rule still sees all nine because it looks back 15
minutes from the successful login at 22:21:44.

## 4. The six rules

Each detector is a plain function `(events, cfg) -> list[Finding]`. Adding a rule means
adding a function and one line in `run_detections()`.

`make_finding()` captures the common fields: first/last timestamp, event count, involved
users, up to five raw evidence lines (or a chosen evidence subset), and the events
themselves for the timeline.

### 4.1 `auth_brute_force`

Filter auth failures, drop `local`, group by IP, take the densest 5-minute window.

```python
window, count = max_window(bucket, cfg.window_minutes)
if count < cfg.auth_failure_threshold:   # default 5
    continue
severity = "Critical" if count >= cfg.auth_failure_threshold * 2 else "High"
```

Sample: 8 failures in the densest window -> High. Ten or more in one window would be
Critical.

Why per-IP? A single noisy attacker is the common case, and per-IP grouping keeps normal
users from pooling their occasional typos into one alert.

### 4.2 `password_spray`

The inverse shape: one username, many sources.

```python
for anchor in bucket:
    window = [e for e in bucket if 0 <= e.timestamp - anchor.timestamp <= 10 min]
    ips = {e.ip for e in window}
    if len(ips) > len(best_ips): ...
if len(best_ips) < 3: continue
```

Sample: `admin` attempted from `192.0.2.201`, `.202`, `.203` between 15:47:23 and
15:49:07. Each IP has only two failures, so the per-IP brute-force rule correctly stays
quiet; the spray rule is what catches the coordinated pattern.

### 4.3 `compromise_success`

For each IP, look at every successful auth and count failures in the preceding 15
minutes. Three or more upgrades the event to a Critical finding.

```python
recent = [f for f in failures
          if 0 <= success.timestamp - f.timestamp <= 15 min]
if len(recent) >= 3:
    events=recent + [success]
    evidence_events=recent[-3:] + [success]
```

Sample: 9 failures, then `Accepted password for svc-backup` at 22:21:44. The finding
counts 10 events but shows the last three failures plus the success as evidence, which is
the shortest readable proof.

Important wording: this is **possible** compromise. A user who fat-fingers a password
three times and then gets it right produces the same shape. The report says "possible" and
the remediation asks for verification, not automatic account destruction.

### 4.4 `off_hours_privileged_login`

Successes for `{root, admin, deploy, svc-backup}` where `0 <= hour < 6`. Grouped by
`(ip, user)`.

Sample: `deploy` from `203.0.113.42` at 02:14:37. The IP is already flagged, so this adds
context and 15 points rather than driving the score alone.

Real deployments should resolve "privileged" from IAM or sudoers, not a hardcoded set.
That is called out in the README limitations.

### 4.5 `web_login_bruteforce`

Filter web events where:

- `status in {401, 403, 429}` (rejected or rate-limited), and
- `LOGIN_PATH_RE` matches the target (`/login`, `/signin`, `/auth`, `/session`, `/wp-login.php`).

Then the same densest-window check, default 5 in 5 minutes.

Sample: 9 attempts from `198.51.100.66` between 09:41:02 and 09:42:34, user agent
`python-requests/2.31.0`, ending in HTTP 429. Eight 401s plus the rate-limit response all
count as failed authentication attempts.

### 4.6 `web_recon`

Two independent signals, one finding:

1. At least 10 HTTP 404s in a 5-minute window, and/or
2. At least 2 requests whose path matches `SENSITIVE_PATH_RE`
   (`/.env`, `/.git`, `wp-login`, `phpmyadmin`, `/admin`, `/actuator`, SQLi fragments,
   path traversal, and similar).

```python
if missing_count < 10 and len(probes) < 2:
    continue
severity = "High" if len(probes) >= 2 else "Medium"
```

Sample: 10 404s in 4m35s plus 12 sensitive probes from `192.0.2.77`, including a SQLi
payload answered with HTTP 500. One signal alone is weaker evidence; together they are a
scanner.

## 5. Scoring

```python
RULE_WEIGHTS = {
    "compromise_success": 50,
    "web_login_bruteforce": 45,
    "web_recon": 45,
    "auth_brute_force": 40,
    "password_spray": 35,
    "off_hours_privileged_login": 15,
}
```

For every IP appearing in a finding, sum the weights of the rules it triggered and cap at
100. Bands: >= 70 CRITICAL, >= 45 HIGH, >= 20 MEDIUM, otherwise LOW.

`203.0.113.42` triggers 40 + 50 + 15 + 45 = 150 -> capped 100 -> CRITICAL.
`198.51.100.66` gets 45 -> HIGH. The three spray IPs get 35 each -> MEDIUM.

This is why the same attack can have a High finding but a Medium IP: severity describes
the event, score describes the source. `192.0.2.77` is High as a scanning event and
45/100 as a source.

## 6. From findings to the model

`build_prompt()` serialises a compact evidence object: run metadata, statistics, and one
entry per finding with rule, severity, IPs, users, timestamps, count, description, and two
truncated sample lines. The full logs are never sent.

The header imposes constraints because a 9B model will happily invent details otherwise:

- use only the supplied evidence;
- never invent IPs, users, hosts, CVEs, or timestamps;
- say "not established from the available logs" when evidence is missing;
- treat `compromise_success` as probable, not proven;
- account for every successful login in the findings, not just the first;
- a fixed section list and a 300-420 word budget.

`ask_ollama()` posts to `http://localhost:11434/api/generate` with `stream: false`,
`think: false`, temperature 0.2, 4k context and a 900-token output cap. `"think": false`
matters: Qwen can spend the whole budget on hidden reasoning and return an empty
`response`. The function also strips code fences and any thinking block before the text
reaches the report.

Failure is not fatal. Any connection error, HTTP error, timeout, or empty response becomes
an `ai_error` string, and `render_report()` writes a notice instead of a narrative. The
findings and evidence are unaffected.

## 7. Report assembly

`render_report()` is pure string assembly, no new analysis:

1. Metadata: time, model, inputs.
2. Detection summary and severity mix.
3. Findings table.
4. IP ranking with weights.
5. AI narrative (or the fallback notice).
6. Per-finding detail with rule fields and a fenced evidence block.
7. Merged timeline of flagged events, deduplicated by `(timestamp, ip, outcome)`.
8. Appendices: parsed statistics and detection configuration, including weights.

`findings.json` carries the same data in machine-readable form plus the config and the
AI status.

## 8. Tuning exercises

These are safe ways to see the logic move:

```bash
# Everything becomes a "burst"
python parse_logs.py sample_auth.log sample_access.log --no-ai --threshold 2

# No SSH burst can fire; the compromise and off-hours rules still should
python parse_logs.py sample_auth.log --no-ai --threshold 20

# Make the window so wide that the slow spray also looks like a burst
python parse_logs.py sample_auth.log --no-ai --window 60 --threshold 5

# Check the report without a model
python parse_logs.py sample_auth.log sample_access.log --no-ai --out /tmp/rule-only.md
```

Good next rule to add for practice: **distributed spray on web logins** (one user, many
IPs) using the same shape as `detect_password_spray`, or **repeat offender tracking**
across runs using `findings.json`.

## 9. Check yourself

<details>
<summary>1. Why does the brute-force rule return 8 events when there are 9 failures?</summary>

The rule reports the densest 5-minute window, not the whole cluster. The 9th failure at
22:19:31 sits outside the window that first reached the maximum count. The compromise
rule, with a 15-minute lookback, sees all nine.
</details>

<details>
<summary>2. Why can one IP have a High finding and a Medium risk score?</summary>

Finding severity is set by the rule and its count. Risk score is the sum of rule weights
for that IP, capped at 100. `web_recon` is a High event but weighs 45, which lands at the
bottom of the HIGH band; a single 35-point spray IP lands at MEDIUM.
</details>

<details>
<summary>3. What is the difference between "ignored" and "skipped" lines?</summary>

Ignored means the line matched the syslog format but had no security outcome (for example
`Server listening`). Skipped means no parser recognised it. A high skip count signals a
format the tool does not support yet.
</details>

<details>
<summary>4. Why send findings instead of raw logs to the model?</summary>

Smaller prompt, lower CPU cost, no accidental exposure of unrelated log content, and the
model cannot "detect" something the rules did not. The deterministic report remains the
source of truth.
</details>

<details>
<summary>5. Where would this rule set fail on a real network?</summary>

Slow password spraying below the window threshold, successful logins using valid
credentials with no preceding failures, encrypted or JSON-only log sources, and any
post-login lateral movement (the logs show authentication, not process or file activity).
The report's "Detection Gaps" section is supposed to name these honestly.
</details>

## 10. Portfolio talking points

- **Deterministic core, AI at the edge.** Detection is testable Python; the model only
  summarises. That is the safe pattern for LLM-assisted security tooling.
- **Privacy and cost.** Local inference means logs and findings never leave the host, and
  the marginal cost per report is zero.
- **Evidence-first.** Every finding carries its own timestamps and raw lines, so the
  report is auditable without rerunning the parser.
- **Graceful degradation.** Missing model, wrong model tag, or a timeout still produces a
  complete rule-based report.
- **Honest limitations.** Synthetic data, batch mode, regex formats, no threat intel. A
  reviewer trusts a project more when it names what it does not do.
