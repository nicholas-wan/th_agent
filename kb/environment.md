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
