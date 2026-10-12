# Troubleshooting and Detection Lessons

Problems found while testing the lab that affected **what the SIEM could see**.
Each one is a detection gap or an investigation trap that also exists in real
environments.

| # | Problem | How I found it | Fix | Lesson |
|---|---|---|---|---|
| 1 | The audit GPO silently turned **off** Logoff and Special Logon (4672) auditing | Compared `auditpol` output before and after applying the GPO | Added those subcategories to the GPO | Advanced Audit Policy replaces the whole local policy – anything not configured is disabled. A classic visibility gap |
| 2 | Wazuh dashboard returned HTTP 500 and the first brute force run never reached the SIEM | Kernel `rcu_preempt ... stall` messages on WAZUH01 | Host CPU/RAM was exhausted by three VMs; ran only the VMs each step needed and re-ran the scenario | A stalled SIEM is a blind SIEM – monitor the health of the monitoring stack |
| 3 | A second brute force run produced failures but **no lockout** (no 4740) | No 4740 on DC01 despite repeated failures | DC01 had just booted; the client validated the password against cached credentials. Verified the domain channel with `Test-ComputerSecureChannel` before the final run | "No alert" can mean the activity never reached the system that logs it |
| 4 | Unplanned "SSH password guessing" alerts appeared | `agent.name` was `wazuh01`, and the times matched my own SSH logins | Classified as a **False Positive** | Check the source of an alert before trusting the dashboard chart |
| 5 | DC01 showed the lockout at 4:02 AM, not 14:02 | Compared DC01 Event Viewer with Wazuh times | DC01 was in Pacific Time (en-US default); set all Windows VMs to Israel time | Timelines across hosts need consistent time zones. Wazuh itself stores UTC |
| 6 | A search for Event 4720 returned no results | A "Level 12 or above" filter was still active | Removed the filter | Severity filters hide lower-level context events that complete the story |
| 7 | The Python parser crashed with `JSONDecodeError` | Traceback pointed at `json.loads(line)` | Skipped empty or broken lines with `try/except` and counted them | Real logs are messy; a parser must not stop on one bad line |
| 8 | Today's alert file contained none of yesterday's attacks | Only 15 alerts in `alerts.json` | Wazuh rotates the file daily (UTC midnight = 03:00 Israel time); the script reads the archived `.json.gz` as well | An attack crossing the rotation is split across two files – each half can fall below the detection threshold. The final script accepts several files |
