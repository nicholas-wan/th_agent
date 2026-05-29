# Environment Profile

**Last Updated:** 2026-01-13
**Review Cadence:** Quarterly
**Maintained By:** Security Operations Team

---

## Security & Monitoring Tools

### SIEM / Log Aggregation

- **Platform:** Splunk Enterprise Security 8.2
- **Version:** 8.2.4
- **Retention:** 90 days hot/warm storage, 1 year cold storage
- **Query Access:**
  - Web interface (https://splunk.corp.internal:8000)
  - REST API available at port 8089
  - Splunk SDK / CLI (splunk search) for automated hunts
- **Data Collections/Indexes:**
  - `security_events` - Primary security telemetry (12M+ events/day)
  - `windows_logs` - Windows Event Logs from all endpoints and servers
  - `endpoint_data` - Carbon Black EDR telemetry
  - `network_logs` - Palo Alto firewall and NetFlow data
  - `auth_logs` - Active Directory authentication events
  - `dns_logs` - Internal DNS query logs from Windows DNS servers
- **Common Fields:**
  - Windows: EventCode, ComputerName, User, LogonType, SourceNetworkAddress, TargetUserName
  - Network: src_ip, dest_ip, src_port, dest_port, protocol, action
  - Endpoint: process_name, parent_process, command_line, user, dest

### EDR / Endpoint Security

- **Product:** VMware Carbon Black EDR
- **Version:** 7.5.0
- **Deployment:** Sensor deployed on 98% of Windows endpoints and servers (~1,400 hosts)
- **Telemetry:** Process execution, network connections, file events, registry modifications, binary inventory

### Identity & Access

- **Identity Provider:** Active Directory (on-premises, corp.internal)
- **Domain Controllers:** 4 domain controllers — DC01, DC02 (HQ); DC03, DC04 (DR site)
- **MFA Solutions:** Duo Security — enforced for VPN, RDP, and all admin accounts
- **PAM Tools:** CyberArk PAS — manages all Tier-0 and Tier-1 privileged accounts
- **Key Event IDs:**
  - 4624 - Successful logon
  - 4625 - Failed logon
  - 4648 - Logon using explicit credentials
  - 4672 - Special privileges assigned to new logon
  - 4720 - User account created
  - 4732 - Member added to security-enabled local group
  - 4768 - Kerberos TGT requested
  - 4769 - Kerberos service ticket requested
  - 4771 - Kerberos pre-authentication failed
  - 4776 - NTLM authentication attempt

### Network Security

- **Firewalls:** Palo Alto PA-5220 (perimeter), PA-3220 (internal segmentation)
- **IDS/IPS:** Palo Alto Threat Prevention inline IPS on perimeter and DMZ segments
- **Flow Data:** NetFlow v9 ingested from core switches into Splunk (5-min aggregation)
- **Packet Capture:** Full PCAP on DMZ via ExtraHop Reveal(x) — 7-day rolling retention

### Cloud Security

- **Cloud Providers:** Microsoft Azure (primary), AWS (dev/test workloads)
- **Security Services:** Azure AD, Azure Sentinel (forwarding to Splunk), AWS CloudTrail, Azure Activity Logs

### Other Security Tools

- **Vulnerability Scanners:** Tenable Nessus — weekly authenticated scans, results ingested into Splunk
- **Asset Management:** ServiceNow CMDB — primary asset inventory (~1,450 managed endpoints)
- **Threat Intelligence:** Recorded Future (API integrated with Splunk ES for IOC correlation)
- **SOAR/Automation:** Splunk SOAR (Phantom) — automated triage for phishing and malware alerts

---

## Technology Stack

### Operating Systems

- **Servers:**
  - Windows Server 2019 (primary)
  - Windows Server 2022 (new deployments)
  - Windows Server 2016 (legacy, scheduled for decommission)

- **Workstations:**
  - Windows 11 Enterprise 23H2 (standard build)
  - Windows 10 Enterprise 22H2 (older hardware)

- **Mobile:**
  - iOS 17 (managed via Microsoft Intune MDM)

### Development Stack

- **Languages:** Python 3.11, PowerShell 7, C# (.NET 6)
- **Web Frameworks:** ASP.NET Core, React 18
- **API Frameworks:** FastAPI, .NET Web API

### Databases & Data Stores

- **Relational:** Microsoft SQL Server 2019 (primary), PostgreSQL 15 (dev)
- **NoSQL:** MongoDB 6.0 (application tier)
- **Caching:** Redis 7.0
- **Data Warehouses:** Azure Synapse Analytics

### Infrastructure & Platforms

- **Cloud Platforms:** Azure (East US 2 primary, West US 2 DR) — ~200 VMs, AKS clusters
- **Containers & Orchestration:** Docker, Kubernetes (AKS) — production workloads
- **CI/CD:** Azure DevOps Pipelines, GitHub Actions

### Networking

- **Network Architecture:** Hub-and-spoke; HQ + 2 remote sites + Azure connected via MPLS and ExpressRoute
- **Load Balancers:** F5 BIG-IP (external), Azure Application Gateway (cloud workloads)
- **DNS:** Windows DNS (on-prem, corp.internal); Azure DNS (cloud)
- **VPN/Remote Access:** Palo Alto GlobalProtect — split-tunnel, MFA-enforced
- **Jump Boxes:** PAW workstations in isolated VLAN (10.0.50.0/24) — required for Tier-0 admin access

### Applications & Services

- **Email:** Microsoft Exchange Online (M365 E3)
- **Collaboration:** Microsoft Teams, SharePoint Online
- **File Sharing:** SharePoint Online, OneDrive for Business; legacy CIFS share on FS01
- **Version Control:** GitHub Enterprise (self-hosted, github.corp.internal)
- **Project Management:** Jira Software (cloud)
- **Business Applications:** SAP S/4HANA (ERP), Salesforce (CRM)

---

## Crown Jewels

> Assets and accounts with the highest blast radius or direct hunt relevance. Update after any significant infrastructure change or privileged account review.

### Tier-0 Assets

- **Name:** WIN-DC01 | **Icon:** 🖥️ | **Role:** Primary Domain Controller (HQ) | **IP:** 10.0.1.10 | **Segment:** Corp-Core (10.0.1.0/24) | **Blast:** Full domain compromise — all user accounts, GPOs, trusts, and Kerberos infrastructure | **Exposure:** high | **TTP:** T1078.002
- **Name:** WIN-DC02 | **Icon:** 🖥️ | **Role:** Secondary Domain Controller (HQ) | **IP:** 10.0.1.11 | **Segment:** Corp-Core (10.0.1.0/24) | **Blast:** Full domain compromise — replication partner to DC01; failover DC | **Exposure:** medium

### Tier-1 Assets

- **Name:** WIN-SQL02 | **Icon:** 🗄️ | **Role:** SQL Server — ERP & Finance Backend | **IP:** 10.0.2.20 | **Segment:** App-Tier (10.0.2.0/24) | **Blast:** Finance and ERP data exfiltration; SAP S/4HANA backend | **Exposure:** high | **TTP:** T1505.001
- **Name:** WIN-FS01 | **Icon:** 📁 | **Role:** File Server — Legacy CIFS Share | **IP:** 10.0.2.30 | **Segment:** App-Tier (10.0.2.0/24) | **Blast:** Internal file share exfiltration; departmental and HR data | **Exposure:** medium
- **Name:** SIEM01 | **Icon:** 📊 | **Role:** Splunk Enterprise Security (primary indexer) | **IP:** 10.0.3.10 | **Segment:** Security-OOB (10.0.3.0/24) | **Blast:** Loss of all detection visibility across the environment | **Exposure:** low

### Critical Accounts

- **Name:** CORP\jsmith | **Icon:** 👤 | **Type:** Domain Admin | **Group:** Domain Admins | **Exposure:** high | **TTP:** T1078.002 | **Desc:** Primary domain admin — directly targeted in Volt Typhoon lateral movement chain; holds Tier-0 access to all DCs
- **Name:** svc-backup | **Icon:** ⚙️ | **Type:** Service Account | **Group:** Backup Operators | **Exposure:** medium | **Desc:** Backup service account with local admin on all servers; high-value target for privilege escalation via token impersonation
- **Name:** svc-splunk | **Icon:** ⚙️ | **Type:** Service Account | **Group:** Security Ops | **Exposure:** low | **Desc:** Splunk indexer service account; read access to all log data across every index
