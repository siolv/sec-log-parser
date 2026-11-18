# Security Log Triage Report

**Generated:** 2026-11-18T17:12:14+08:00  
**Analyzer:** `parse_logs.py` rule engine + local LLM  
**Model:** `qwen3.5:9b` via Ollama - local inference, $0 cloud cost  
**Inputs:** `sample_auth.log`, `sample_access.log`  

## 1. Detection Summary

| Metric | Value |
|---|---|
| Events parsed | 82 |
| Auth / web events | 29 / 53 |
| Failed auth events | 19 |
| Findings | 7 |
| Severity mix | Critical: 1, High: 5, Medium: 1, Low: 0 |
| Flagged source IPs | 6 |
| Observation window | 2026-11-17T08:02:14+08:00 -> 2026-11-18T02:16:05+08:00 |

## 2. Findings at a Glance

| # | Severity | Rule | Finding | Source IP(s) | Events | Window |
|---|---|---|---|---|---|---|
| 1 | CRITICAL | `compromise_success` | Possible compromise: svc-backup logged in from 203.0.113.42 after 9 failures | 203.0.113.42 | 10 | 2026-11-17T22:14:08+08:00 -> 2026-11-17T22:21:44+08:00 |
| 2 | HIGH | `web_recon` | Web scanning: 10 HTTP 404s within 5 minutes and 12 probes for sensitive paths | 192.0.2.77 | 12 | 2026-11-17T11:20:04+08:00 -> 2026-11-17T11:24:39+08:00 |
| 3 | HIGH | `web_login_bruteforce` | Web login brute force: 9 rejected attempts | 198.51.100.66 | 9 | 2026-11-17T09:41:02+08:00 -> 2026-11-17T09:42:34+08:00 |
| 4 | HIGH | `auth_brute_force` | SSH brute force: 8 failures in 5 min | 203.0.113.42 | 8 | 2026-11-17T22:14:08+08:00 -> 2026-11-17T22:18:47+08:00 |
| 5 | HIGH | `password_spray` | Password spray: user 'admin' from 3 IPs | 192.0.2.201, 192.0.2.202, 192.0.2.203 | 6 | 2026-11-17T15:47:23+08:00 -> 2026-11-17T15:49:07+08:00 |
| 6 | HIGH | `web_login_bruteforce` | Web login brute force: 6 rejected attempts | 203.0.113.42 | 6 | 2026-11-17T22:05:10+08:00 -> 2026-11-17T22:08:44+08:00 |
| 7 | MEDIUM | `off_hours_privileged_login` | Off-hours login: deploy from 203.0.113.42 | 203.0.113.42 | 1 | 2026-11-18T02:14:37+08:00 -> 2026-11-18T02:14:37+08:00 |

## 3. Suspicious IP Ranking

| Risk | Score | Source IP | Findings | Rules triggered |
|---|---|---|---|---|
| CRITICAL | 100/100 | `203.0.113.42` | 4 | SSH brute force, Success after failures, Off-hours admin login, Web login brute force |
| HIGH | 45/100 | `192.0.2.77` | 1 | Web scanning |
| HIGH | 45/100 | `198.51.100.66` | 1 | Web login brute force |
| MEDIUM | 35/100 | `192.0.2.201` | 1 | Password spray |
| MEDIUM | 35/100 | `192.0.2.202` | 1 | Password spray |
| MEDIUM | 35/100 | `192.0.2.203` | 1 | Password spray |

Scores are the sum of per-rule weights, capped at 100. They rank attention, not certainty.

## 4. Triage Narrative

### Executive Summary
A coordinated attack originating primarily from IP 203.0.113.42 resulted in a probable compromise of the 'svc-backup' account following a brute force campaign, alongside suspicious off-hours access by the 'deploy' user. The incident severity is Critical due to confirmed successful authentications for privileged and service accounts after multiple failed attempts. While other IPs like 198.51.100.66 attempted web login attacks and 192.0.2.77 performed reconnaissance, only the activity from 203.0.113.42 led to successful logins that require immediate containment.

### Attack Chain
The attack timeline began on November 17 with reconnaissance and initial probing. IP 192.0.2.77 conducted web scanning, generating HTTP 404 errors for sensitive paths like /.env and /phpmyadmin between 11:20 and 11:24. Simultaneously, a distributed password spray targeted the 'admin' account from three distinct IPs in the 192.0.2.x range. The primary escalation occurred later that evening when IP 203.0.113.42 launched an SSH brute force attack against multiple users including root, oracle, and postgres. This host also attempted web login attacks using curl. Crucially, after nine failed SSH attempts between 22:14 and 22:18, the attacker successfully authenticated as 'svc-backup' at 22:21:44. The campaign continued into the next day with an off-hours privileged login for the 'deploy' account from the same source IP at 02:14:37 on November 18, indicating persistent access or a second actor using compromised credentials.

### MITRE ATT&CK Mapping
| Technique | ID | Evidence |
| :--- | :--- | :--- |
| Brute Force | T1110 | SSH brute force from 203.0.113.42 with 8 failures followed by success as 'svc-backup'. |
| Valid Accounts | T1078 | Successful authentication for 'svc-backup' and off-hours login for 'deploy' from untrusted IPs. |
| Active Scanning | T1595 | Web scanning from 192.0.2.77 probing sensitive paths like /admin and /.git/config. |
| Exploit Public-Facing Application | T1190 | Multiple web login brute force attempts against the portal endpoint from 198.51.100.66 and 203.0.113.42. |

### Containment & Remediation
1. Immediately disable or rotate credentials for 'svc-backup' and 'deploy', as both accounts were successfully accessed from external IPs.
2. Block IP 203.0.113.42 at the perimeter firewall to prevent further lateral movement or access to internal systems.
3. Investigate the off-hours login for 'deploy' to verify if it was authorized change management or a credential theft incident.
4. Implement rate limiting on SSH and web login endpoints to mitigate future brute force attempts from IPs like 198.51.100.66.
5. Review access logs for the 'admin' account to determine if the distributed spray attempt compromised any associated sessions.

### Detection Gaps & Next Steps
This rule set effectively detects brute force and successful logins but may miss lateral movement if the attacker switches identities after initial compromise. We should add rules to detect privilege escalation patterns, such as a service account accessing sensitive directories immediately after login. Additionally, integrating threat intelligence feeds would help identify known malicious IPs like 203.0.113.42 earlier in the kill chain. Finally, enhancing web application firewall logs could provide better visibility into exploit attempts beyond simple 404 responses.

## 5. Detection Detail

### 5.1 [CRITICAL] Possible compromise: svc-backup logged in from 203.0.113.42 after 9 failures

- **Rule:** `compromise_success`
- **Source IP(s):** `203.0.113.42`
- **Users involved:** admin, deploy, oracle, postgres, root, svc-backup, test, ubuntu
- **Events:** 10
- **First seen:** 2026-11-17T22:14:08+08:00
- **Last seen:** 2026-11-17T22:21:44+08:00

203.0.113.42 failed 9 times in the 15 minutes before a successful login as 'svc-backup'. Either the password was guessed or valid credentials were used from an untrusted address.

```text
Nov 17 22:18:02 web01 sshd[3930]: Failed password for ubuntu from 203.0.113.42 port 44280 ssh2
Nov 17 22:18:47 web01 sshd[3930]: Failed password for deploy from 203.0.113.42 port 44292 ssh2
Nov 17 22:19:31 web01 sshd[3941]: Failed password for root from 203.0.113.42 port 44304 ssh2
Nov 17 22:21:44 web01 sshd[3960]: Accepted password for svc-backup from 203.0.113.42 port 44322 ssh2
```

### 5.2 [HIGH] Web scanning: 10 HTTP 404s within 5 minutes and 12 probes for sensitive paths

- **Rule:** `web_recon`
- **Source IP(s):** `192.0.2.77`
- **Users involved:** n/a
- **Events:** 12
- **First seen:** 2026-11-17T11:20:04+08:00
- **Last seen:** 2026-11-17T11:24:39+08:00

Directory/exploit scanning from 192.0.2.77: 10 HTTP 404s within 5 minutes and 12 probes for sensitive paths. Probes include /.env, /.git/config, /actuator/env, /admin, /api/v1/users, /cgi-bin/luci.

```text
192.0.2.77 - - [17/Nov/2026:11:20:04 +0800] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.0.2.77 - - [17/Nov/2026:11:20:31 +0800] "GET /.git/config HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.0.2.77 - - [17/Nov/2026:11:21:02 +0800] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.0.2.77 - - [17/Nov/2026:11:21:18 +0800] "GET /wp-admin/ HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
192.0.2.77 - - [17/Nov/2026:11:21:44 +0800] "GET /phpmyadmin/ HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
```

### 5.3 [HIGH] Web login brute force: 9 rejected attempts

- **Rule:** `web_login_bruteforce`
- **Source IP(s):** `198.51.100.66`
- **Users involved:** n/a
- **Events:** 9
- **First seen:** 2026-11-17T09:41:02+08:00
- **Last seen:** 2026-11-17T09:42:34+08:00

9 authentication requests from 198.51.100.66 were rejected by the web login endpoint in 5 minutes, using user agent(s): python-requests/2.31.0.

```text
198.51.100.66 - - [17/Nov/2026:09:41:02 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "python-requests/2.31.0"
198.51.100.66 - - [17/Nov/2026:09:41:11 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "python-requests/2.31.0"
198.51.100.66 - - [17/Nov/2026:09:41:19 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "python-requests/2.31.0"
198.51.100.66 - - [17/Nov/2026:09:41:30 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "python-requests/2.31.0"
198.51.100.66 - - [17/Nov/2026:09:41:44 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "python-requests/2.31.0"
```

### 5.4 [HIGH] SSH brute force: 8 failures in 5 min

- **Rule:** `auth_brute_force`
- **Source IP(s):** `203.0.113.42`
- **Users involved:** admin, deploy, oracle, postgres, root, test, ubuntu
- **Events:** 8
- **First seen:** 2026-11-17T22:14:08+08:00
- **Last seen:** 2026-11-17T22:18:47+08:00

8 failed SSH authentications from 203.0.113.42 against 7 username(s) (admin, deploy, oracle, postgres, root, test, ubuntu) within 5 minutes.

```text
Nov 17 22:14:08 web01 sshd[3901]: Failed password for root from 203.0.113.42 port 44210 ssh2
Nov 17 22:14:52 web01 sshd[3901]: Failed password for root from 203.0.113.42 port 44216 ssh2
Nov 17 22:15:33 web01 sshd[3915]: Failed password for admin from 203.0.113.42 port 44230 ssh2
Nov 17 22:16:10 web01 sshd[3915]: Failed password for invalid user oracle from 203.0.113.42 port 44244 ssh2
Nov 17 22:16:44 web01 sshd[3922]: Failed password for postgres from 203.0.113.42 port 44256 ssh2
```

### 5.5 [HIGH] Password spray: user 'admin' from 3 IPs

- **Rule:** `password_spray`
- **Source IP(s):** `192.0.2.201`, `192.0.2.202`, `192.0.2.203`
- **Users involved:** admin
- **Events:** 6
- **First seen:** 2026-11-17T15:47:23+08:00
- **Last seen:** 2026-11-17T15:49:07+08:00

Account 'admin' was targeted from 3 distinct source IPs (192.0.2.201, 192.0.2.202, 192.0.2.203) within 10 minutes, a distributed spray pattern rather than a single-source brute force.

```text
Nov 17 15:47:23 web01 sshd[2902]: Failed password for admin from 192.0.2.201 port 44112 ssh2
Nov 17 15:47:41 web01 sshd[2902]: Failed password for admin from 192.0.2.201 port 44118 ssh2
Nov 17 15:48:02 web01 sshd[2915]: Failed password for admin from 192.0.2.202 port 58120 ssh2
Nov 17 15:48:18 web01 sshd[2915]: Failed password for admin from 192.0.2.202 port 58126 ssh2
Nov 17 15:48:51 web01 sshd[2929]: Failed password for invalid user admin from 192.0.2.203 port 40222 ssh2
```

### 5.6 [HIGH] Web login brute force: 6 rejected attempts

- **Rule:** `web_login_bruteforce`
- **Source IP(s):** `203.0.113.42`
- **Users involved:** n/a
- **Events:** 6
- **First seen:** 2026-11-17T22:05:10+08:00
- **Last seen:** 2026-11-17T22:08:44+08:00

6 authentication requests from 203.0.113.42 were rejected by the web login endpoint in 5 minutes, using user agent(s): curl/8.4.0.

```text
203.0.113.42 - - [17/Nov/2026:22:05:10 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "curl/8.4.0"
203.0.113.42 - - [17/Nov/2026:22:05:52 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "curl/8.4.0"
203.0.113.42 - - [17/Nov/2026:22:06:31 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "curl/8.4.0"
203.0.113.42 - - [17/Nov/2026:22:07:09 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "curl/8.4.0"
203.0.113.42 - - [17/Nov/2026:22:07:58 +0800] "POST /login HTTP/1.1" 401 41 "https://portal.example.com/login" "curl/8.4.0"
```

### 5.7 [MEDIUM] Off-hours login: deploy from 203.0.113.42

- **Rule:** `off_hours_privileged_login`
- **Source IP(s):** `203.0.113.42`
- **Users involved:** deploy
- **Events:** 1
- **First seen:** 2026-11-18T02:14:37+08:00
- **Last seen:** 2026-11-18T02:14:37+08:00

Privileged account 'deploy' authenticated from 203.0.113.42 at 2026-11-18T02:14:37+08:00 (local time), inside the 00:00-06:00 quiet window. Confirm whether change management approved it.

```text
Nov 18 02:14:37 web01 sshd[4402]: Accepted password for deploy from 203.0.113.42 port 45102 ssh2
```

## 6. Flagged Event Timeline

| Time | Source | IP | Outcome | Rule | Detail |
|---|---|---|---|---|---|
| 2026-11-17T09:41:02+08:00 | web | 198.51.100.66 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T09:41:11+08:00 | web | 198.51.100.66 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T09:41:19+08:00 | web | 198.51.100.66 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T09:41:30+08:00 | web | 198.51.100.66 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T09:41:44+08:00 | web | 198.51.100.66 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T09:41:58+08:00 | web | 198.51.100.66 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T09:42:07+08:00 | web | 198.51.100.66 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T09:42:20+08:00 | web | 198.51.100.66 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T09:42:34+08:00 | web | 198.51.100.66 | failure | `web_login_bruteforce` | POST /login -> 429 |
| 2026-11-17T11:20:04+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /.env -> 404 |
| 2026-11-17T11:20:31+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /.git/config -> 404 |
| 2026-11-17T11:21:02+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /wp-login.php -> 404 |
| 2026-11-17T11:21:18+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /wp-admin/ -> 404 |
| 2026-11-17T11:21:44+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /phpmyadmin/ -> 404 |
| 2026-11-17T11:22:05+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /admin -> 404 |
| 2026-11-17T11:22:33+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /api/v1/users?id=1%27+OR+1=1-- -> 500 |
| 2026-11-17T11:22:58+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /etc/passwd -> 404 |
| 2026-11-17T11:23:15+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /server-status -> 403 |
| 2026-11-17T11:23:41+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /actuator/env -> 404 |
| 2026-11-17T11:24:02+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /cgi-bin/luci -> 404 |
| 2026-11-17T11:24:39+08:00 | web | 192.0.2.77 | failure | `web_recon` | GET /xmlrpc.php -> 404 |
| 2026-11-17T15:47:23+08:00 | auth | 192.0.2.201 | failure | `password_spray` | Failed password for admin from 192.0.2.201 port 44112 ssh2 |
| 2026-11-17T15:47:41+08:00 | auth | 192.0.2.201 | failure | `password_spray` | Failed password for admin from 192.0.2.201 port 44118 ssh2 |
| 2026-11-17T15:48:02+08:00 | auth | 192.0.2.202 | failure | `password_spray` | Failed password for admin from 192.0.2.202 port 58120 ssh2 |
| 2026-11-17T15:48:18+08:00 | auth | 192.0.2.202 | failure | `password_spray` | Failed password for admin from 192.0.2.202 port 58126 ssh2 |
| 2026-11-17T15:48:51+08:00 | auth | 192.0.2.203 | failure | `password_spray` | Failed password for invalid user admin from 192.0.2.203 port 40222 ssh2 |
| 2026-11-17T15:49:07+08:00 | auth | 192.0.2.203 | failure | `password_spray` | Failed password for admin from 192.0.2.203 port 40230 ssh2 |
| 2026-11-17T22:05:10+08:00 | web | 203.0.113.42 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T22:05:52+08:00 | web | 203.0.113.42 | failure | `web_login_bruteforce` | POST /login -> 401 |
| 2026-11-17T22:06:31+08:00 | web | 203.0.113.42 | failure | `web_login_bruteforce` | POST /login -> 401 |

## 7. Appendix - Parsed Statistics

| Statistic | Value |
|---|---|
| Input files | sample_auth.log, sample_access.log |
| Total events | 82 |
| Auth events | 29 |
| Web events | 53 |
| Auth failures | 19 |
| Web failures (4xx/5xx) | 32 |
| HTTP 404 responses | 14 |
| Unique source IPs | 12 |
| Valid but non-security lines ignored | 6 |
| Unrecognised lines skipped | 0 |
| Busiest source IPs | 203.0.113.42 (18), 192.0.2.77 (12), 198.51.100.88 (9), 198.51.100.66 (9), 198.51.100.23 (9) |

## 8. Appendix - Detection Configuration

| Parameter | Value |
|---|---|
| Burst window | 5 min |
| SSH failure threshold | >= 5 / window |
| Web login threshold | >= 5 / window |
| Spray: distinct IPs | >= 3 / 10 min |
| Success after failures | >= 3 failures in 15 min |
| Web recon 404 threshold | >= 10 / window |
| Quiet hours | 00:00-06:00 local |

### Rule weights

| Rule | Weight |
|---|---|
| `auth_brute_force` | 40 |
| `password_spray` | 35 |
| `compromise_success` | 50 |
| `off_hours_privileged_login` | 15 |
| `web_login_bruteforce` | 45 |
| `web_recon` | 45 |

---

*Synthetic lab data. Detection and narrative were produced on local hardware: Python rules plus `qwen3.5:9b` through Ollama. No log content left this machine.*
