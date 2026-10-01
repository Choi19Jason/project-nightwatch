# Kerberoasting — RC4 Service Ticket Requested

| Field | Value |
|---|---|
| MITRE ATT&CK | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting (Credential Access) |
| Data source | Windows Security Event ID 4769 (Kerberos service ticket requested), DC01 via Splunk Universal Forwarder |
| Schedule | Every 15 minutes, searching the last 15 minutes |
| Trigger | Number of results greater than 0 |
| Severity | Medium |

## Why it matters

Kerberos service tickets are encrypted with the password hash of the account that runs the service. Tickets encrypted with RC4 (`0x17`) are much weaker than AES (`0x12`), and service accounts with human-chosen passwords are the accounts at risk. This lab is configured to use AES, so an RC4 service ticket for a user account is a signal worth reviewing.

## Search

```spl
index=* EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats count min(_time) as first_seen max(_time) as last_seen values(Service_Name) as services by Account_Name Client_Address
| convert ctime(first_seen) ctime(last_seen)
```

## Logic

- `Ticket_Encryption_Type=0x17` keeps only RC4-encrypted service tickets.
- `Service_Name!="*$"` excludes computer accounts and gMSAs, which use long, random, automatically rotated passwords.
- `Service_Name!="krbtgt"` removes a known system account.
- `stats` summarizes who requested which service, from where, and when.

## Validation

Tested on 2026-09-26 against lab telemetry. The search returned the RC4 ticket issued for the legacy service account `svc-sql` and correctly ignored the AES-256 ticket issued for `gmsa-web01$`. The saved alert then fired on its own schedule at 20:15 UTC after a fresh ticket request, confirming it works unattended.

## Known false positives

Older applications or service accounts that only support RC4 will trigger this alert.

## Tuning and response

- Allow-list known legacy accounts after review, with an owner and an expiry date.
- The long-term fix is to set service accounts to AES-only or migrate them to gMSAs, which removes the weak-ticket risk entirely.
- On an alert: confirm whether the requesting account and host normally use that service, and check for other service tickets requested by the same account in the same window.
