# Environment Context

Describes the target environment: domain, network segments, key assets, accounts, and crown jewels. Agents load this at hunt start via `get_topology()` / `get_env_context()`.

Edit this file to keep the environment picture current. Changes are reflected in the Knowledge Base → Environment tab on next page load.

---

## Domain

> name: CORP.LOCAL | netbios: CORP | forest: CORP.LOCAL | level: Windows Server 2019
> adfs: https://adfs.corp.local | ad-sync: Azure AD Connect · delta sync every 30 min

### Domain Controllers
- WIN-DC01.corp.local (10.0.1.10)
- WIN-DC02.corp.local (10.0.1.11)

### Sites
- HQ-Site (10.0.0.0/16)
- DR-Site (10.10.0.0/16)

### Trusts
- One-way outbound → PARTNER.LOCAL (selective auth)

---

## Stats

> label: Endpoints | value: 2,412 | note: Windows · macOS · Linux | color: blue
> label: Servers | value: 34 | note: On-prem · virtualised | color: indigo
> label: Segments | value: 8 | note: VLANs mapped | color: green
> label: User Accounts | value: 1,847 | note: 638 service accounts | color: yellow

---

## Anomalies

- crit | CORP\jsmith authenticated from 3 source IPs in 6h — off-hours logon anomaly (T1078.002)
- high | WIN-DC01: unexpected outbound SMB to 10.0.8.44 (Workstations VLAN) at 02:14 UTC
- high | svc-backup account interactive logon detected on WIN-WS041 — service accounts should never be interactive
- med | WIN-WS041: new service installed outside patch window — svchost.exe variant (T1543.003)

---

## Segment: Domain Controllers

> id: seg-dc | sensitivity: critical | cidr: 10.0.1.0/24 | vlan: 10 | gateway: 10.0.1.1 | hosts: 2 | icon: 🏛️

Tier-0 assets. No workstation traffic permitted. Firewalled from all non-admin VLANs.

### Tags
- Tier-0
- Jump-access only
- IDS monitored

### ACLs
- Allow: Admin VLAN (10.0.9.0/24)
- Allow: Splunk ES (10.0.5.20)
- Deny: all others

---

## Segment: Server Farm

> id: seg-srv | sensitivity: high | cidr: 10.0.2.0/24 | vlan: 20 | gateway: 10.0.2.1 | hosts: 28 | icon: 🖥️

Application and file servers. East-west traffic restricted via host-based firewall policy.

### Tags
- Production
- Change-controlled
- Sysmon deployed

### ACLs
- Allow: Corp Workstations
- Allow: Admin VLAN
- Deny: Guest/IoT

---

## Segment: Corp Workstations

> id: seg-ws | sensitivity: medium | cidr: 10.0.3.0/24 | vlan: 30 | gateway: 10.0.3.1 | hosts: 1840 | icon: 💻

Standard employee endpoints. Managed via Intune. No server-to-workstation initiation permitted.

### Tags
- Intune managed
- EDR deployed
- User VLAN

### ACLs
- Allow: Internet via proxy
- Allow: Server Farm (restricted ports)
- Deny: DC direct

---

## Segment: DMZ / Public-facing

> id: seg-dmz | sensitivity: high | cidr: 10.0.4.0/24 | vlan: 40 | gateway: 10.0.4.1 | hosts: 6 | icon: 🌐

Web servers, reverse proxies, email gateways. Strict egress filtering. No internal DNS.

### Tags
- Internet-facing
- WAF protected
- Isolated DNS

### ACLs
- Allow: inbound 443/80 from Internet
- Deny: lateral to internal subnets
- Allow: outbound SMTP 25

---

## Segment: Security / SOC

> id: seg-sec | sensitivity: high | cidr: 10.0.5.0/24 | vlan: 50 | gateway: 10.0.5.1 | hosts: 8 | icon: 🛡️

Splunk ES, EDR management console, SOAR. Read-only access to all other VLANs for log collection.

### Tags
- SOC tools
- Log collection
- Splunk ES

### ACLs
- Allow: syslog/UDP 514 from all
- Allow: Splunk forwarder 9997 from all
- Deny: outbound to Internet

---

## Segment: Admin / Privileged

> id: seg-admin | sensitivity: critical | cidr: 10.0.9.0/24 | vlan: 90 | gateway: 10.0.9.1 | hosts: 4 | icon: 🔑

Jump hosts, PAM solution, admin workstations. Requires MFA + privileged session recording.

### Tags
- Tier-0 access
- PAM enforced
- Session recorded

### ACLs
- Allow: DC VLAN
- Allow: Server Farm
- Allow: Splunk ES (read)
- Deny: Internet direct

---

## Segment: IoT / OT

> id: seg-iot | sensitivity: medium | cidr: 10.0.6.0/24 | vlan: 60 | gateway: 10.0.6.1 | hosts: 312 | icon: 📡

Building management, printers, physical security cameras. Isolated from corp network.

### Tags
- Isolated
- No domain join
- Unmanaged endpoints

### ACLs
- Allow: outbound NTP/DNS only
- Deny: all inbound
- Deny: corp subnets

---

## Segment: DR Site

> id: seg-dr | sensitivity: high | cidr: 10.10.0.0/16 | vlan: 100 | gateway: 10.10.0.1 | hosts: 220 | icon: 🔄

Disaster recovery site. Site-to-site VPN to HQ. Replication traffic only during off-hours.

### Tags
- DR site
- VPN tunnel
- Replication VLAN

### ACLs
- Allow: replication ports from HQ DCs
- Allow: backup traffic from svc-backup
- Deny: user traffic

---

## Asset: WIN-DC01

> ip: 10.0.1.10 | role: dc | os: Windows Server 2022 | segment: Domain Controllers | owner: IT Ops | status: online | last-seen: 2 min ago
> fqdn: WIN-DC01.corp.local | mac: 00:50:56:A1:01:10 | cpu: Intel Xeon E5 ×16 | ram: 32 GB | disk: SSD 500 GB
> uptime: 147 days | sysmon: v15.0 | edr: CrowdStrike 7.1 | patch: 2026-04-15 | criticality: Tier-0

Primary DC. FSMO roles: PDC, RID, Infrastructure. Kerberos KDC. Do not reboot without change ticket.

---

## Asset: WIN-DC02

> ip: 10.0.1.11 | role: dc | os: Windows Server 2022 | segment: Domain Controllers | owner: IT Ops | status: online | last-seen: 3 min ago
> fqdn: WIN-DC02.corp.local | mac: 00:50:56:A1:01:11 | cpu: Intel Xeon E5 ×16 | ram: 32 GB | disk: SSD 500 GB
> uptime: 147 days | sysmon: v15.0 | edr: CrowdStrike 7.1 | patch: 2026-04-15 | criticality: Tier-0

Secondary DC. DNS secondary. AD replication partner to WIN-DC01.

---

## Asset: WIN-FS01

> ip: 10.0.2.20 | role: srv | os: Windows Server 2019 | segment: Server Farm | owner: IT Ops | status: online | last-seen: 1 min ago
> fqdn: WIN-FS01.corp.local | mac: 00:50:56:A2:02:20 | cpu: Intel Xeon ×8 | ram: 64 GB | disk: NAS 20 TB
> uptime: 312 days | sysmon: v15.0 | edr: CrowdStrike 7.1 | patch: 2026-04-15 | criticality: High

Primary file server. DFS namespace root. Shares: \\corp\finance, \\corp\hr, \\corp\shared.

---

## Asset: WIN-APP01

> ip: 10.0.2.21 | role: srv | os: Windows Server 2019 | segment: Server Farm | owner: App Team | status: online | last-seen: 4 min ago
> fqdn: WIN-APP01.corp.local | mac: 00:50:56:A2:02:21 | cpu: Intel Xeon ×8 | ram: 32 GB | disk: SSD 200 GB
> uptime: 89 days | sysmon: v15.0 | edr: CrowdStrike 7.1 | patch: 2026-04-10 | criticality: High

Internal ERP application server (SAP). Service account: svc-erp. Connects to SQL-DB01.

---

## Asset: SQL-DB01

> ip: 10.0.2.30 | role: srv | os: Windows Server 2019 | segment: Server Farm | owner: DBA Team | status: online | last-seen: 2 min ago
> fqdn: SQL-DB01.corp.local | mac: 00:50:56:A2:02:30 | cpu: Intel Xeon ×16 | ram: 128 GB | disk: SSD RAID 2 TB
> uptime: 201 days | sysmon: v15.0 | edr: CrowdStrike 7.1 | patch: 2026-03-20 | criticality: Critical

SQL Server 2019. Hosts ERP and HR databases. SA account disabled. svc-sql service account. Named pipes disabled.

---

## Asset: SPLUNK-ES

> ip: 10.0.5.20 | role: sec | os: Linux (RHEL 8) | segment: Security / SOC | owner: SOC | status: online | last-seen: < 1 min
> fqdn: splunk-es.corp.local | mac: 00:50:56:A5:05:20 | cpu: AMD EPYC ×32 | ram: 256 GB | disk: SSD RAID 10 TB
> uptime: 61 days | sysmon: N/A | edr: CrowdStrike 7.1 | patch: 2026-04-20 | criticality: Critical

Splunk Enterprise Security 8.x. Ingest: ~80 GB/day. Indexes: main, security, windows, sysmon, network. REST API used by hunt agents.

---

## Asset: WIN-WS041

> ip: 10.0.3.41 | role: ws | os: Windows 11 Pro | segment: Corp Workstations | owner: jsmith | status: online | last-seen: 18 min ago
> fqdn: WIN-WS041.corp.local | mac: 00:50:56:A3:03:41 | cpu: Intel i7 ×8 | ram: 16 GB | disk: SSD 256 GB
> uptime: 12 days | sysmon: v15.0 | edr: CrowdStrike 7.1 | patch: 2026-04-08 | criticality: Medium

⚠ ALERT: Unusual LSASS access detected (EventCode 10, GrantedAccess 0x1fffff). Assigned to jsmith — currently under investigation (TH-2026-041).

---

## Asset: WIN-WS042

> ip: 10.0.3.42 | role: ws | os: Windows 11 Pro | segment: Corp Workstations | owner: mwebb | status: online | last-seen: 7 min ago
> fqdn: WIN-WS042.corp.local | mac: 00:50:56:A3:03:42 | cpu: Intel i7 ×8 | ram: 16 GB | disk: SSD 256 GB
> uptime: 5 days | sysmon: v15.0 | edr: CrowdStrike 7.1 | patch: 2026-04-15 | criticality: Low

Standard workstation assigned to Marcus Webb (SOC analyst).

---

## Asset: JUMP-01

> ip: 10.0.9.10 | role: net | os: Windows Server 2022 | segment: Admin / Privileged | owner: IT Ops | status: online | last-seen: 5 min ago
> fqdn: JUMP-01.corp.local | mac: 00:50:56:A9:09:10 | cpu: Intel Xeon ×4 | ram: 8 GB | disk: SSD 120 GB
> uptime: 88 days | sysmon: v15.0 | edr: CrowdStrike 7.1 | patch: 2026-04-15 | criticality: High

Privileged access workstation. CyberArk PSM installed. All admin sessions recorded. MFA enforced via Duo.

---

## Account: jsmith

> type: User | status: active | last-logon: 2026-04-27 02:41 UTC · WIN-DC01 | pwd-age: 47 days | mfa: Duo · enrolled
> groups: Domain Users, Finance-RW, VPN-Users

Normal: Business hours · Corp Workstations · WIN-WS041
Anomaly: ⚠ Off-hours logons from 3 source IPs in 6h — matches T1078.002 pattern (TH-2026-041)

---

## Account: mwebb

> type: User | status: active | last-logon: 2026-04-27 09:12 UTC · WIN-WS042 | pwd-age: 12 days | mfa: Duo · enrolled
> groups: Domain Users, SOC-Analysts, Splunk-Users

Normal: Business hours · Corp Workstations + JUMP-01

---

## Account: svc-backup

> type: Service | status: active | last-logon: 2026-04-27 02:18 UTC · WIN-WS041 | pwd-age: 180 days | mfa: N/A (service account)
> groups: Domain Users, Backup Operators

Normal: Non-interactive · scheduled tasks only · Server Farm + DC VLAN
Anomaly: ⚠ Interactive logon detected on WIN-WS041 at 02:18 UTC — service accounts must not log on interactively

---

## Account: svc-sql

> type: Service | status: active | last-logon: 2026-04-26 22:00 UTC · SQL-DB01 | pwd-age: 90 days | mfa: N/A (service account)
> groups: Domain Users, SQL-Service

Normal: Non-interactive · SQL-DB01 only

---

## Account: svc-splunk

> type: Service | status: active | last-logon: 2026-04-27 09:05 UTC · SPLUNK-ES | pwd-age: 60 days | mfa: N/A (service account)
> groups: Domain Users, Splunk-Service

Normal: Non-interactive · SPLUNK-ES only · read-only domain access

---

## Account: adm-itops

> type: Admin | status: active | last-logon: 2026-04-25 14:30 UTC · JUMP-01 | pwd-age: 30 days | mfa: Duo · hardware token
> groups: Domain Admins, Enterprise Admins, Schema Admins

Normal: Business hours · JUMP-01 only · PAM session required

---

## Account: krbtgt

> type: Service | status: active | last-logon: Never (system account) | pwd-age: 364 days | mfa: N/A
> groups: Domain Users

Normal: Never logged on interactively — Kerberos KDC account

---

## Topology

```
CORP.LOCAL — Network Topology
═══════════════════════════════════════════════════════════

  Internet
      │
  ┌───┴────────────────────────────────────────┐
  │  Perimeter Firewall (Palo Alto PA-5220)    │
  │  203.0.113.1 (external) · 10.0.4.1 (DMZ GW)      │
  └───┬────────────────────────────────────────┘
      │
  ┌───┴──────────────────────┐
  │  DMZ  10.0.4.0/24  VLAN 40  │  Web · Mail · Reverse Proxy
  └───┬──────────────────────┘
      │   (restricted — no lateral to internal)
  ┌───┴──────────────────────────────────────────────────┐
  │  Core Switch (Cisco Nexus 9000)                      │
  │  Inter-VLAN routing · ACL enforcement · span port ──→ SPLUNK-ES
  └──┬──────────┬──────────┬──────────┬──────────┬──────┘
     │          │          │          │          │
  ┌──┴──┐   ┌──┴──┐   ┌──┴──┐   ┌──┴──┐   ┌──┴──────┐
  │ DC  │   │ SRV │   │ WS  │   │SEC  │   │ ADMIN   │
  │VLAN │   │VLAN │   │VLAN │   │VLAN │   │VLAN 90  │
  │ 10  │   │ 20  │   │ 30  │   │ 50  │   │(PAM+MFA)│
  │/24  │   │/24  │   │/24  │   │/24  │   └──┬──────┘
  │Tier-0│  │Prod │   │Users│   │SOC  │      │
  └──┬──┘   └─────┘   └─────┘   └─────┘   jump hosts
     │
  ⚠ WIN-WS041 (10.0.3.41) → WIN-DC01 (10.0.1.10)
    Unexpected SMB (445) lateral movement detected
    TH-2026-041 · EventCode 5145 · jsmith / svc-backup

     │ Site-to-Site VPN (IPSec)
  ┌──┴──────────────────┐
  │  DR Site  10.10.0.0/16  │  Replication · Backup
  └─────────────────────┘

  IoT  VLAN 60  10.0.6.0/24  — isolated · no corp routing
```

---

## Infrastructure

- 🏛️ | WIN-DC01 / WIN-DC02 | Domain Controllers · FSMO roles · KDC | 10.0.1.10–11 | Tier-0
- 🛡️ | SPLUNK-ES | SIEM · Hunt agent MCP endpoint | 10.0.5.20 | Critical
- 🔑 | JUMP-01 | Privileged Access Workstation · PAM | 10.0.9.10 | High
- 🔥 | Palo Alto PA-5220 | Perimeter firewall · IPS · URL filtering | 203.0.113.1 | Critical
- 🔀 | Cisco Nexus 9000 | Core switch · Inter-VLAN routing · SPAN | 10.0.0.1 | Critical
- 🗄️ | SQL-DB01 | SQL Server 2019 · ERP + HR databases | 10.0.2.30 | Critical

---

## Crown Jewel: WIN-DC01

> tier: 0 | ip: 10.0.1.10 | segment: DC VLAN | exposure: high | ttp: T1078.002 · T1003.001 | icon: 🏛️

Role: Primary Domain Controller
Blast: Domain dominance · Golden Ticket · DCSync · extract all credential hashes from AD

---

## Crown Jewel: WIN-DC02

> tier: 0 | ip: 10.0.1.11 | segment: DC VLAN | exposure: medium | ttp: T1003.001 | icon: 🏛️

Role: Secondary Domain Controller
Blast: AD replication access · offline database copy · Tier-0 redundancy path

---

## Crown Jewel: PKI-01

> tier: 0 | ip: 10.0.2.5 | segment: Mgmt VLAN | exposure: low | icon: 🔐

Role: Root Certificate Authority
Blast: Certificate forgery · impersonate any identity · ESC1–8 ADCS attack surface · HTTPS interception

---

## Crown Jewel: BACKUP-01

> tier: 0 | ip: 10.0.3.15 | segment: Mgmt VLAN | exposure: medium | ttp: T1570 | icon: 💾

Role: Enterprise Backup Server
Blast: Full data corpus · stored credentials · offline AD database copy · ransomware primary target

---

## Crown Jewel: SCCM-01

> tier: 1 | ip: 10.0.5.20 | segment: Mgmt VLAN | exposure: low | icon: ⚙️

Role: SCCM / ConfigMgr Server
Blast: Code execution on ~2,400 endpoints · software push · local admin rights across all workstations

---

## Crown Jewel: SIEM-01

> tier: 1 | ip: 10.0.4.10 | segment: Security VLAN | exposure: low | icon: 🔍

Role: Splunk Enterprise Security
Blast: Security visibility manipulation · log tampering · detection blind spots · hunt data access

---

## Crown Jewel: SQL-PROD-01

> tier: 1 | ip: 10.0.6.5 | segment: Server VLAN | exposure: low | icon: 🗄️

Role: Production SQL Server
Blast: Financial records · customer PII · business-critical operational data · exfiltration target

---

## Crown Account: Administrator

> type: Built-in Domain Admin | group: Domain Admins | exposure: medium | ttp: T1078.002 | icon: 👑

Desc: Full domain control if compromised — primary adversary target for privilege escalation endpoint

---

## Crown Account: krbtgt

> type: Kerberos TGT Account | group: Domain Users | exposure: medium | ttp: T1003.006 | icon: 🔑

Desc: Golden Ticket via NTLM hash extraction — DCSync prerequisite · compromise = unrestricted domain access

---

## Crown Account: svc-backup

> type: Service Account | group: Backup Operators | exposure: low | ttp: T1558.003 | icon: 🛡️

Desc: Access to BACKUP-01 and the full backup data corpus · SPN registered · Kerberoasting target

---

## Crown Account: jsmith

> type: Domain User | group: Corp Workstations | exposure: high | ttp: T1078.002 · T1570 | icon: ⚠️

Desc: Current hunt subject · off-hours logon anomaly · touched 14 hosts · MFA enrolled · elevated exposure

---
