# Incident Report 001 – Password Guessing Against a Domain Account

| Field | Value |
|---|---|
| **Report ID** | IR-001 |
| **Date** | 2026-10-11 |
| **Analyst** | Dvir (Tier 1, Home SOC Lab) |
| **Environment** | Isolated lab – domain `soclab.local`, Wazuh 4.14.8 SIEM |
| **Severity** | Medium |
| **Status** | Closed – attack blocked by account lockout policy |
| **Verdict** | True Positive (controlled simulation) |

> **Note:** This activity was generated deliberately inside an isolated lab network
> (VMware host-only, no internet access) to test detection. It is written up as a
> Tier 1 analyst would document a real alert.

---

## 1. Summary

Six failed logon attempts against the domain account `SOCLAB\dana.levi` were made
from workstation `CLIENT01` within about 3 seconds. The Domain Controller (`DC01`)
locked the account after the threshold was reached. No successful logon by the
account was found after the attempts, so the attack did not succeed.

## 2. Timeline (Israel time, UTC+3)

| Time | Source | Event ID | Wazuh rule (level) | Description |
|---|---|---|---|---|
| 15:27:02.721 | CLIENT01 | 4625 | 60122 (5) | Logon failure – bad password for `dana.levi` |
| 15:27:02.723 | CLIENT01 | 4625 | 60122 (5) | Logon failure |
| 15:27:04.381 | CLIENT01 | 4625 | 60122 (5) | Logon failure |
| 15:27:04.383 | CLIENT01 | 4625 | 60122 (5) | Logon failure |
| 15:27:05.861 | DC01 | 4740 | 60115 (9) | **User account locked out** (multiple login errors) |
| 15:27:05.863 | CLIENT01 | 4625 | 60122 (5) | Logon failure (after lockout) |
| 15:27:05.866 | CLIENT01 | 4625 | 60122 (5) | Logon failure (after lockout) |

The lockout was also confirmed directly in the DC01 Security log
(Event 4740 at 15:27:04).

## 3. Key Facts

| Item | Finding |
|---|---|
| Targeted account | `SOCLAB\dana.levi` (standard user, OU `TLV\Users`) |
| Source host | `CLIENT01` (192.168.50.30, OU `TLV\Workstations`) |
| Failure reason (subStatus) | `0xc000006a` – wrong password (verified on the 14:31 attempts) |
| Attempts / time window | 6 failures in ~3 seconds |
| Account lockout | Yes – Event 4740 on DC01 |
| Successful logon afterwards (4624) | **None found** for `dana.levi` |

**How "no successful logon" was verified:**
1. Confirmed that Wazuh does collect Event 4624 (other users' successful logons appear).
2. Searched `data.win.system.eventID:4624 and data.win.eventdata.targetUserName:dana.levi`
   for the day – no results after the attack.

## 4. Analysis

- **Speed:** ~6 attempts in 3 seconds is far faster than a user retyping a forgotten
  password. This pattern matches automated or deliberate password guessing.
- **Escalation in severity:** each single failure is low severity (level 5), but the
  resulting lockout raised a level 9 alert. The pattern, not any single event, is
  what makes this suspicious.
- **Attempts continued after lockout:** two failures were logged after the 4740
  lockout event, showing the actor kept trying after the account was locked.
- **Paired events:** failures appear in pairs a few milliseconds apart. This may be
  Windows logging two events per attempt; it should not be read as 12 separate
  attempts without checking the event details.
- **Outcome:** the lockout policy (5 attempts / 15 minutes) stopped the attack, and
  no successful logon was found.

## 5. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Credential Access (TA0006) | **T1110.001 – Brute Force: Password Guessing** |

Wazuh mapped the related alerts to "Password Guessing" automatically.

## 6. Verdict

**True Positive.** Repeated failed logons at machine speed against a single
account, followed by a lockout. The attack was blocked; no account compromise
was found.

## 7. Recommended Actions

1. **Contact the user and her manager** to confirm whether she made these attempts
   and who had access to `CLIENT01` at 15:27.
2. **Reset the account password** after the user is verified, in case the password
   was partially known to the attacker.
3. **Monitor the account** for further failures or a successful logon from an
   unusual host over the next 24–48 hours.
4. **Check the logon type** of the failures (2 = local console, 3 = network,
   10 = RDP). If remote, investigate the source IP and check other accounts
   targeted from the same source.

## 8. Detection Notes / Lessons Learned

- Default Windows auditing was not enough; an **Advanced Audit Policy GPO** was
  required (Logon, Account Lockout, Credential Validation, Kerberos – Success and
  Failure).
- A first attempt at this scenario was **not recorded** in the SIEM because the
  Wazuh indexer stalled under host resource pressure. A second attempt did not lock
  the account because the workstation validated the password against **cached
  credentials** while the DC was unreachable. Both issues were found and fixed
  before the final run (verified with `Test-ComputerSecureChannel`).
- Earlier "SSH password guessing" alerts on `wazuh01` were traced to the analyst's
  own mistyped SSH passwords – a **False Positive**, closed after checking
  `agent.name` and the timeline.
- The same detection logic was reproduced in Python
  ([`scripts/failed_logins.py`](../scripts/failed_logins.py)), which flagged both
  brute force bursts and ignored the single Administrator typo
  ([screenshot](../screenshots/06-python-failed-logins-output.png)).

## Evidence

- [Failed logons and lockout in Wazuh](../screenshots/01-failed-logons-and-lockout-wazuh.png)
- [Lockout event 4740 on DC01](../screenshots/02-lockout-4740-dc01.png)
