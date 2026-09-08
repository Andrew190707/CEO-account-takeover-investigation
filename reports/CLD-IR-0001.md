# Security Incident Report

**Cloudora Security Operations** | Template CLD-IR-TEMPLATE

| | |
|---|---|
| Report ID | CLD-IR-0001-AR (analyst rework) |
| Related ticket | CLD-0001 |
| Report title | CEO Account Takeover — Password Spray Leading to Compromise of daniel.reeve@cloudora.io and priya.nair@cloudora.io |
| Analyst | Moses Andrew Raymond |
| Date of report (UTC) | 2026-08-23 |
| Incident severity | **P1** — confirmed compromise of a C-level account plus attacker-established MFA persistence and a hidden mailbox rule. Business email compromise / invoice-fraud staging is a realistic next step if not contained. |
| Status | Contained (lab exercise — containment steps documented, not executed against live infra) |
| Classification | CONFIDENTIAL — Internal and client distribution only |

---

## 1. Executive summary

Between 8–10 August 2026, an attacker ran a password-spray attack against Cloudora from three Nigeria-based IP addresses, targeting 26 accounts with low-volume guesses to stay under lockout thresholds. On 10 August the spray succeeded against two accounts: CEO Daniel Reeve and Priya Nair. On Daniel's account the attacker registered their own MFA device and created a hidden inbox rule, meaning a password reset alone would not have removed their access. On Priya's account the attacker accessed SharePoint directly. Both compromises were confirmed by cross-referencing failed and successful sign-ins against each account's normal usage pattern, and by pivoting on the attacker's source IPs across the full sign-in log. Containment requires session revocation, password resets, removal of the rogue MFA device, and deletion of the malicious inbox rule on both accounts, plus blocking the three source IPs.

## 2. Incident timeline

*All times UTC.*

| Time (UTC) | Source | Event | Evidence / notes |
|---|---|---|---|
| Aug 08, 03:16–03:52 | CloudoraSignIn_CL | Spray begins — failed logins against multiple accounts from 102.89.44.17 / .23 | `ResultType 50126` across 20+ distinct accounts night one |
| Aug 09, 01:40–03:49 | CloudoraSignIn_CL | Spray continues, second night, same IP range | Failure volume steady, still low-per-account |
| Aug 10, 03:09–03:10 | CloudoraSignIn_CL | Failed attempts against daniel.reeve immediately precede his compromise | 102.89.44.17 |
| Aug 10, 03:12 | CloudoraSignIn_CL | **daniel.reeve@cloudora.io compromised** — successful sign-in, Microsoft 365 | 102.89.44.17, ResultType 0 |
| Aug 10, 03:14 | CloudoraSignIn_CL | Attacker accesses Outlook Web on Daniel's account | 102.89.44.17 |
| Aug 10, 03:18 | CloudoraAudit_CL | Attacker registers own Authenticator app ("Pixel 6") on Daniel's account | Persistence — survives password reset |
| Aug 10, 03:26 | CloudoraSignIn_CL | Attacker accesses Azure Portal on Daniel's account | 102.89.44.17 |
| Aug 10, 03:31 | CloudoraAudit_CL | Attacker creates hidden inbox rule "RSS Subscriptions" on Daniel's account | Hides mail from finance / containing "invoice" |
| Aug 10, 03:44–03:47 | CloudoraSignIn_CL | Failed then successful attempt against priya.nair | 102.89.45.101 |
| Aug 10, 03:47 | CloudoraSignIn_CL | **priya.nair@cloudora.io compromised** | 102.89.45.101, ResultType 0 |
| Aug 10, 03:52 | CloudoraSignIn_CL | Attacker accesses SharePoint Online on Priya's account | 35 minutes after Daniel's compromise — same attacker session window |
| Aug 10, 08:41 | CloudoraSignIn_CL | Daniel's genuine London sign-in — account owner unaware anything happened | 203.0.113.10, London |

## 3. Findings

**Finding 1 — This is a password spray, not a brute force.**
The three Lagos-region IPs each show failures spread across 20+ different accounts with only one to three attempts per account, rather than repeated attempts against one account. That's a spray built to stay under lockout thresholds (MITRE T1110.003), not someone guessing hard against a single target.

**Finding 2 — Daniel's sign-in pattern breaks every marker of normal use.**
Baselining his account shows eight days of consistent London activity. The Lagos sign-in appears once, at 03:12 local server time, on a device fingerprint never seen on the account before, with two failed attempts immediately in front of it. Compare that with omar.farah's Dubai sign-ins the same week — daytime hours, zero failures, his usual iOS device, repeated consistently over three days. One is travel, the other is a takeover, and the difference is entirely in the pattern, not the country.

**Finding 3 — The attacker didn't stop at access; they built persistence.**
Registering their own Authenticator device means a password reset on its own does nothing — they'd still pass MFA. The hidden inbox rule filtering anything from finance or containing "invoice" is a strong signal of intended follow-on business email compromise or invoice fraud, not just opportunistic access.

**Finding 4 — Priya Nair is a second confirmed victim, not a coincidence.**
Scoping the attacker's IPs across the full sign-in log (not just Daniel's account) surfaces a second successful login 35 minutes after Daniel's. The attacker worked both accounts in the same session. Priya's audit log shows no persistence actions from the attacker IP, but that's absence of evidence in this log source, not proof the account is clean — she gets the same full containment treatment as Daniel.

## 4. Indicators of compromise (IOCs)

| Type | Value | First seen (UTC) | Context |
|---|---|---|---|
| IP | 102.89.44.17 | Aug 08, 03:52 | Spray source, later used against daniel.reeve |
| IP | 102.89.44.23 | Aug 08, 03:16 | Spray source |
| IP | 102.89.45.101 | Aug 10, 03:44 | Spray source, used against priya.nair |
| Device | Windows 10 / Chrome 125 | Aug 10, 03:12 | Never seen on daniel.reeve's account before; attacker fingerprint |
| MFA method | Authenticator app "Pixel 6" | Aug 10, 03:18 | Attacker-registered, not the account owner's device |
| Mailbox rule | "RSS Subscriptions" | Aug 10, 03:31 | Attacker-created; filters mail from finance / containing "invoice" |

## 5. MITRE ATT&CK mapping

| Tactic | Technique ID | Technique name | Evidenced by |
|---|---|---|---|
| Credential Access | T1110.003 | Brute Force: Password Spraying | Finding 1 |
| Initial Access | T1078 | Valid Accounts | Finding 2 — successful login using sprayed credentials |
| Persistence | T1098.005 | Account Manipulation: Device Registration | Finding 3 — rogue MFA device |
| Collection / Defense Evasion | T1564.008 | Hide Artifacts: Email Hiding Rules | Finding 3 — inbox rule |

## 6. Scope

**Accounts confirmed compromised**
- daniel.reeve@cloudora.io — successful login + MFA persistence + inbox rule
- priya.nair@cloudora.io — successful login + direct SharePoint access

**Accounts targeted but not breached**
24 accounts received spray attempts from the same three IPs but show no successful login: alba.vega, amelia.frost, aria.reid, cole.burke, dina.said, emma.hayes, ethan.wells, freya.lynn, gwen.muir, isla.grant, joel.kerr, jude.ross, kian.patel, leah.stone, lena.voss, liam.doyle, mira.shah, nina.cole, omar.farah, rhys.owen, ruth.dean, ryan.boyd, seth.lane, sofia.marino (all @cloudora.io). These need precautionary password resets.

**Accounts investigated and cleared (false positives)**
- omar.farah@cloudora.io — new-country (Dubai) sign-ins initially looked suspicious alongside Daniel's, but every marker points to genuine travel: daytime hours, zero failures, consistent device fingerprint, repeated over three days rather than a single burst. Cleared. (Note: he is also on the targeted-but-not-breached list above from the spray itself — two separate facts about the same account.)

## 7. Actions taken

*This is a training-lab exercise; the actions below are the response I would take, documented as if performed, not executed against live infrastructure.*

| Time (UTC) | Action | Performed by | Verified how |
|---|---|---|---|
| T+0 | Revoke all active sessions and refresh tokens for daniel.reeve and priya.nair | Analyst | Re-run Step 5 scoping query, confirm no further attacker-IP activity |
| T+0 | Force password reset on both compromised accounts | Analyst | Confirm old credentials rejected |
| T+5m | Remove attacker-registered "Pixel 6" Authenticator device from daniel.reeve | Analyst | Re-check MFA methods list on account |
| T+5m | Delete "RSS Subscriptions" inbox rule from daniel.reeve | Analyst | Re-check inbox rules |
| T+10m | Force password reset on all 24 targeted-but-not-breached accounts | Analyst | Confirm resets delivered |
| T+15m | Block 102.89.44.17, 102.89.44.23, 102.89.45.101 at conditional access / firewall | Analyst | Re-run Step 5, confirm no logins from these IPs post-block |

## 8. Recommendations

1. **Quick win:** Enable sign-in risk policies / impossible-travel detection in Entra ID — this compromise had an 03:12 Lagos login next to an 08:41 London login on the same account the same day, which is a textbook impossible-travel signal that should alert on its own.
2. **Quick win:** Deploy the spray-detection rule in `queries/investigation.kql` (10+ distinct accounts failing from one IP in a 6h window) as a scheduled analytics rule — this would have fired on night one, two days before the breach.
3. **Strategic:** Require admin approval or alerting on any new MFA method registration for executive and finance accounts specifically.
4. **Strategic:** Alert on inbox rule creation that references finance-related keywords or moves mail to low-visibility folders — this is a well-known BEC staging pattern and shouldn't be silent.
5. **Strategic:** Lower the account-lockout threshold or add a spray-aware throttle, since this attack was specifically designed to stay under whatever the current threshold is.

## 9. Lessons learned

The account-level view alone doesn't scope an incident — I only found Priya because I explicitly pivoted on the attacker's IPs across the *whole* sign-in table rather than stopping once Daniel's compromise was confirmed. That's the habit I want to keep: never treat the first confirmed victim as the only victim. On the flip side, I initially wanted to flag Omar's Dubai activity as suspicious purely because it was a new country in the same week as a real incident — baselining it properly (time of day, failure pattern, device consistency) is what separated a genuine false positive from a second missed compromise, and that judgment call is worth practicing deliberately, not just running the query and reading the top row.

---

*Completed as a self-driven exercise against the official CLD-0001 project pack (MyFirstHack / myfirstcyberjob). Findings independently derived from the provided `cloudora_signin_logs.csv` and `cloudora_audit_logs.csv`, then checked against the task answer key.*
