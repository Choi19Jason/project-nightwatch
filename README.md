# Project Nightwatch — Enterprise AD & SOC Detection Lab

A segmented, 5-VM enterprise Active Directory environment built from scratch to practice the core work of a SOC analyst, systems administrator, and IAM analyst: building identity infrastructure, collecting security telemetry into a SIEM, hardening accounts, and writing detections that are validated against real lab data.

**Author:** Joonwoo Choi — B.S. Computer and Information Technology, Purdue University (Class of 2028)
**Status:** Active — 11 milestones completed (August–September 2026)

---

## Architecture

![Project Nightwatch topology](diagrams/topology.png)

| VM | Role | Segment | IP |
|---|---|---|---|
| PFSENSE01 | pfSense CE 2.9.0 — router / firewall | WAN, LAN, OPT1, OPT2 | .1 on each segment |
| DC01 | Windows Server 2025 Domain Controller (`nightwatch.local`) | LAN — Servers | 10.10.10.10 |
| WS01 | Windows 11 Enterprise, domain-joined | OPT1 — Workstations | 10.10.20.20 |
| WS02 | Windows 11 Enterprise, domain-joined | OPT1 — Workstations | 10.10.20.31 |
| SIEM01 | Ubuntu Server 22.04 + Splunk Enterprise 10.4.3 | OPT2 — Security | 10.10.30.10 |

The network is split into three trust zones by pfSense. Workstations can reach the domain controller only on the ports Active Directory requires, and log forwarding into the Security zone is allowed on a single host and port (TCP 9997).

## Tech Stack

- **Identity:** Active Directory Domain Services, DNS, Group Policy, Kerberos, Group Managed Service Accounts (gMSA)
- **Security monitoring:** Splunk Enterprise, Splunk Universal Forwarder, Sysmon (SwiftOnSecurity config)
- **Network:** pfSense CE, VirtualBox internal networks, firewall aliases
- **Automation:** PowerShell (Active Directory module)
- **Frameworks:** MITRE ATT&CK, NIST SP 800-53

## Highlights

### Least-privilege telemetry pipeline
![DC01 telemetry pipeline](diagrams/telemetry-pipeline.png)

The domain controller forwards Security, System, Application, and Sysmon logs to Splunk. The forwarder runs as a Windows virtual service account instead of LocalSystem. When Sysmon ingestion failed with an access-denied error, the fix was a single read-only permission on one event log channel for the forwarder, rather than giving it full system privileges.

### Group Managed Service Account vs. legacy service account
![gMSA vs legacy service account](diagrams/gmsa-ticket-encryption.png)

A gMSA was deployed with a 240-byte automatically rotated password, host-scoped retrieval rights, and AES-only Kerberos encryption. It was compared in Splunk (Event ID 4769) against a legacy service account: the legacy account received an RC4-encrypted service ticket (`0x17`), while the gMSA received AES-256 (`0x12`).

### Kerberoasting detection
A scheduled Splunk alert flags RC4-encrypted Kerberos service tickets issued for user accounts, mapped to MITRE ATT&CK T1558.003. See [`detections/`](detections/).

## Milestones

| # | Milestone | Focus |
|---|---|---|
| 1 | VirtualBox lab environment | Infrastructure |
| 2 | DC01 — Windows Server 2025 domain controller | Identity |
| 3 | OU design + PowerShell provisioning of 30 users | Identity / automation |
| 4 | Sysmon deployment on DC01 | Telemetry |
| 5 | WS01 domain-joined workstation (5 build blockers resolved) | Endpoint / troubleshooting |
| 6 | pfSense segmentation into 3 trust zones + WS02 | Network security |
| 7 | SIEM01 — Splunk Enterprise deployment | SIEM |
| 8 | Cross-segment DNS failure — root-caused by layer-by-layer elimination | Troubleshooting |
| 9 | Universal Forwarder + Sysmon ingestion from DC01 | Telemetry |
| 10 | gMSA + Kerberos ticket encryption telemetry | IAM |
| 11 | Kerberoasting detection alert (RC4 service tickets) | Detection engineering |

## Roadmap

- Joiner / Mover / Leaver lifecycle automation in PowerShell
- Role-based, least-privilege department file shares
- Access-review reporting script for group membership
- Extend the forwarder and Sysmon to WS01 and WS02
- Attack-chain simulation with SIEM detection validation
- AI agent + prompt-injection detection demo
- Entra ID / Okta developer tenant (Conditional Access, SSO)

## Repository Layout

```
diagrams/     Architecture and data-flow diagrams
detections/   Splunk detections with logic, tuning notes, and ATT&CK mapping
```

## Notes

This is an isolated home lab. No credentials, passwords, or secrets are stored in this repository.
