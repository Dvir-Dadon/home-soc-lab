# Incident Report 002 – Domain Admin Rights Granted to a Newly Created Account

| Field | Value |
|---|---|
| **Report ID** | IR-002 |
| **Date** | 2026-10-11 |
| **Analyst** | Dvir (Tier 1, Home SOC Lab) |
| **Environment** | Isolated lab – domain `soclab.local`, Wazuh 4.14.8 SIEM |
| **Severity** | High |
| **Status** | Escalated – pending verification with IT |
| **Verdict** | Suspicious – requires verification (controlled simulation) |

> **Note:** This activity was generated deliberately inside an isolated lab network
> (VMware host-only, no internet access) to test detection. It is written up as a
> Tier 1 analyst would document a real alert.

---

## 1. Summary

A new domain account, `svc.update`, was created on the Domain Controller `DC01`
and added to the **Domain Admins** group 98 seconds later. Both actions were
performed by the account `SOCLAB\Administrator` from the **same logon session**.
No change request was found for this activity. The new account now has the
highest privileges in the domain, so the activity is treated as suspicious until
it is verified with the IT team.

## 2. Timeline (Israel time, UTC+3)

| Time | Host | Event ID | Wazuh rule (level) | Description |
|---|---|---|---|---|
| 18:08:14 | DC01 | 4720 | 60109 (8) | User account created: `svc.update` |
| 18:09:52 | DC01 | 4728 | 60159 (**12**) | `svc.update` added to **Domain Admins** |

## 3. Key Facts

| Item | Finding |
|---|---|
| Performed by (subject) | `SOCLAB\Administrator` – built-in domain admin (SID ends in **-500**) |
| Host | `DC01` (Domain Controller, 192.168.50.10) |
| Account created | `svc.update`, OU `TLV\Users`, no description |
| Group changed | `Domain Admins` (SID ends in **-512**) |
| Logon session of both events | **`0x134b73`** – identical |
| Time between events | 98 seconds |
| Change request / ticket | None found |

**Field note:** in Event 4728, `targetUserName` is the **group** (Domain Admins).
The account that was added appears in `memberName`
(`CN=svc.update,OU=Users,OU=TLV,DC=soclab,DC=local`).

## 4. Analysis

**Why this is suspicious:**
- **Create-then-elevate sequence:** a brand-new account received the most powerful
  role in the domain within 98 seconds. Legitimate onboarding rarely grants Domain
  Admin immediately after account creation.
- **Same logon session:** both events share Logon ID `0x134b73`, so they were
  performed in one continuous session by the same actor – not two unrelated
  changes.
- **Name looks like a service account:** `svc.update` imitates a legitimate
  service account, a common way to blend in. Service accounts should not be
  members of Domain Admins.
- **No documentation:** no change request, no description on the account, and the
  security team was not notified in advance.
- **Severity escalation:** account creation alone is routine (level 8), but adding
  an account to Domain Admins triggered a level 12 alert.

**What cannot be determined from the logs:**
The logs show **which account** performed the actions, not **which person**.
Possible explanations:
1. A legitimate administrator performing an undocumented change.
2. An attacker using **compromised Administrator credentials**.
3. An insider misusing the Administrator account.

The next investigation step is to find the Event 4624 (successful logon) with
Logon ID `0x134b73` to identify **where** the Administrator session came from
(local console on DC01 or a remote IP).

## 5. MITRE ATT&CK Mapping

| Event | Wazuh mapping | Analyst mapping | Tactic |
|---|---|---|---|
| 4720 – account created | – | **T1136.002** – Create Account: Domain Account | Persistence |
| 4728 – added to Domain Admins | T1484 – Domain Policy Modification | **T1098.007** – Account Manipulation: Additional Local or Domain Groups | Persistence, Privilege Escalation |

Wazuh mapped the group change to T1484. T1098.007 describes the activity more
precisely: adding an account under the actor's control to a privileged domain
group to keep persistent access.

## 6. Verdict

**Suspicious – requires verification.** The activity matches a known persistence
pattern, but the logs alone cannot show whether the Administrator account was used
by a legitimate admin or by an attacker. Because Domain Admin access is at stake,
the account is contained until the activity is confirmed.

## 7. Recommended Actions

**Immediate (containment):**
1. **Disable `svc.update`** and **remove it from Domain Admins**, according to the
   playbook or with Tier 2 approval.
2. **Escalate to Tier 2 / Incident Response** – unexplained Domain Admin access is
   high severity.

**Verification:**
3. **Ask the IT team** whether anyone created `svc.update` and granted it Domain
   Admin at 18:08–18:10, and check for a matching change request.
4. **Trace the Administrator session** – search for Event 4624 with Logon ID
   `0x134b73` to find the source host or IP of the session.

**If the activity is not confirmed as legitimate:**
5. **Reset the Administrator password** and review all other recent actions by the
   Administrator account (other accounts created, group changes, GPO changes).
6. **Delete `svc.update`** after evidence is preserved.

## 8. Detection Notes / Lessons Learned

- The alert was found by starting from **high-severity alerts (level 12+)**, not by
  reading all events – the way a Tier 1 analyst triages a queue.
- The related account-creation event (level 8) was hidden by the level 12 filter.
  Pivoting on the account name and time window showed the full sequence.
- Correlating **Logon IDs** across events links separate actions into one session
  and is a key technique when investigating Windows activity.

## Evidence

- [Timeline: 4720 and 4728 in Wazuh](../screenshots/03-timeline-4720-4728.png)
- [4728 details – subject, member, Logon ID](../screenshots/04-domain-admins-4728-details-part1.png)
- [4728 details – rule level 12, MITRE mapping](../screenshots/05-domain-admins-4728-details-part2.png)
