# Incident Write-Up — Kerberoasting: RC4 Service Ticket Requested

| | |
|---|---|
| **Ticket ID** | NW-2026-011 |
| **Date detected** | 2026-09-26 |
| **Analyst** | Joonwoo Choi |
| **Severity** | Medium |
| **Status** | Closed — simulated detection validation (home lab) |
| **MITRE ATT&CK** | [T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) (Credential Access) |

> **Context:** This is a controlled detection-validation exercise in an isolated lab, written in the format of a real SOC ticket. The "attacker" action is a benign Kerberos service-ticket request used only to generate the telemetry a detection must catch.

---

## 1. Summary

A Kerberos service ticket (Event ID 4769) was requested for the user account `svc-sql` using **RC4 encryption (`0x17`)**. In an environment standardized on AES, an RC4 service ticket for a user account is a known precondition for **Kerberoasting**, where an attacker requests a service ticket and cracks it offline to recover the service account's password. The activity was detected by a scheduled Splunk alert, triaged, and confirmed as expected validation activity.

## 2. Timeline (UTC)

| Time | Event |
|---|---|
| 20:11 | Baseline confirmed: Kerberos Service Ticket Operations auditing enabled on DC01 (Success). |
| ~20:11 | Service-ticket request issued for SPN `MSSQLSvc/sql01.nightwatch.local:1433` (account `svc-sql`). |
| 20:15 | Scheduled Splunk alert **"Kerberoasting - RC4 Service Ticket Requested"** fired (runs every 15 min). |
| 20:18 | Triage: event reviewed, source host and account identified. |
| 20:25 | Verdict reached; comparison against the gMSA control documented. |

## 3. Evidence

**Detection query (Splunk SPL):**
```spl
index=* EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats count min(_time) as first_seen max(_time) as last_seen values(Service_Name) as services by Account_Name Client_Address
| convert ctime(first_seen) ctime(last_seen)
```

**Key fields from Event ID 4769:**

| Field | Value |
|---|---|
| Account_Name | `Administrator@NIGHTWATCH.LOCAL` |
| Service_Name | `svc-sql` |
| Ticket_Encryption_Type | `0x17` (RC4-HMAC) |
| Client_Address | `::1` (request originated on DC01 — expected for this lab validation) |

**Control comparison:** in the same window, the gMSA `gmsa-web01$` received ticket type `0x12` (AES-256) and did **not** match the detection — confirming the rule distinguishes the weak account from the hardened one.

## 4. Analysis

- **Why it matters:** RC4 service tickets are derived from the account's password hash and can be brute-forced offline with no further interaction with the domain. `svc-sql` is a user account with an SPN and a human-set password — exactly the target class.
- **Why `svc-sql` and not the gMSA:** `svc-sql` was intentionally built as a legacy-style account (human-chosen password, RC4 not disabled). The gMSA uses a 240-byte auto-rotating password and AES-only encryption, so even a captured ticket is not practically crackable.
- **True vs. false positive:** in production, a legitimate legacy application that only supports RC4 could generate the same event. Triage must confirm whether the requesting account/host normally uses that service.

## 5. Verdict

**Confirmed detection of a Kerberoasting precondition (simulated).** The alert behaved correctly: it fired on the RC4 request for a user SPN and excluded computer/gMSA accounts and `krbtgt`.

## 6. Recommended next steps

1. **Remediate the weak account** — set `svc-sql` to AES-only (`msDS-SupportedEncryptionTypes`) or migrate it to a gMSA, then re-verify that 4769 shows `0x12`.
2. **Tune for false positives** — build an allow-list of reviewed legacy accounts, each with an owner and an expiry date.
3. **Add a behavioral companion rule** — alert when one account requests many distinct SPNs in a short window (catches an attacker who avoids RC4). Pending more service accounts in the lab.
4. **Monitor the control** — add a "host stopped reporting" alert so a silent forwarder outage can't hide this activity.

## 7. Artifacts
- Detection (Splunk): [`../detections/kerberoasting-rc4-service-ticket.md`](../detections/kerberoasting-rc4-service-ticket.md)
- Detection (Sigma): [`../detections/sigma/kerberoasting_rc4_service_ticket.yml`](../detections/sigma/kerberoasting_rc4_service_ticket.yml)
