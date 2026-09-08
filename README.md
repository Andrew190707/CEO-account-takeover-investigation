# CEO Account Takeover Investigation — Cloudora (KQL / Azure Data Explorer)

SOC investigation of a password-spray attack that led to the compromise of Cloudora's CEO account and a second employee account, including attacker persistence via a rogue MFA device and a hidden inbox rule.

Built against the official **CLD-0001** project pack (MyFirstHack / myfirstcyberjob community resource) — real synthetic sign-in and audit log data, worked through independently and checked against the provided answer key.

## Scenario
Ticket CLD-0001: suspicious sign-in activity flagged on `daniel.reeve@cloudora.io` (CEO). A three-night password spray from Nigeria-based IPs ends in two confirmed account compromises, one of which includes attacker-registered MFA and a mailbox rule built to hide finance-related mail — classic BEC staging.

## Repo structure
```
data/                          — real datasets (CloudoraSignIn_CL, CloudoraAudit_CL)
queries/investigation.kql      — every KQL query used, in investigation order
reports/CLD-IR-0001.md         — full incident report, filled per Cloudora's official template
```

## How to reproduce
1. Load `data/cloudora_signin_logs.csv` into Azure Data Explorer as table **`CloudoraSignIn_CL`**, and `data/cloudora_audit_logs.csv` as **`CloudoraAudit_CL`** (keep the `_CL` suffix — the queries expect it exactly).
2. At ingestion, set `TimeGenerated` to `datetime` and `ResultType` to `string` (ADX will otherwise infer `ResultType` as numeric and the quoted string comparisons in the queries return nothing).
3. Run `queries/investigation.kql` top to bottom — it's laid out in the same step order as the investigation itself (triage → baseline → attack detection → persistence → scope → second victim → task queries).

## Investigation summary
- **Attack:** Password spray (T1110.003) from three Nigeria-based IPs against 26 accounts over 3 nights, staying under lockout thresholds
- **Confirmed compromises:** `daniel.reeve@cloudora.io` (CEO) and `priya.nair@cloudora.io`
- **Persistence found:** Attacker-registered Authenticator device + hidden inbox rule filtering finance-related mail — on Daniel's account only
- **False positive cleared:** `omar.farah@cloudora.io` — a new-country (Dubai) sign-in the same week that baselines out as genuine travel once time-of-day, device consistency, and failure pattern are checked
- **Detection gap identified:** a spray-detection rule (10+ distinct accounts failing from one IP in a 6h window) would have fired two days before the actual breach

Full write-up, timeline, MITRE mapping, and containment plan: [reports/CLD-IR-0001.md](reports/CLD-IR-0001.md)

## Notes
Self-driven exercise built on the official CLD-0001 dataset and query pack. All company, employee, and IP data is synthetic training material.
