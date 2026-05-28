/* ── Environment fallback data ───────────────────────────────────────────
   Source of truth: kb/environment.md (fetched at runtime by initKbTab).
   This file is a local-dev fallback used when kb/environment.md cannot be
   fetched (e.g. file:// protocol). Do NOT edit here — edit environment.md.
   ──────────────────────────────────────────────────────────────────────── */
const envData = {
  meta: {
    lastUpdated:   '2026-01-13',
    reviewCadence: 'Quarterly',
    maintainedBy:  'Security Operations Team',
  },

  monitoring: {
    siem: {
      platform:  'Splunk Enterprise Security 8.2',
      version:   '8.2.4',
      retention: '90 days hot/warm storage, 1 year cold storage',
      queryAccess: [
        'Web interface (https://splunk.corp.internal:8000)',
        'REST API available at port 8089',
        'Splunk SDK / CLI (splunk search) for automated hunts',
      ],
      indexes: [
        { name: 'security_events', desc: 'Primary security telemetry (12M+ events/day)' },
        { name: 'windows_logs',    desc: 'Windows Event Logs from all endpoints and servers' },
        { name: 'endpoint_data',   desc: 'Carbon Black EDR telemetry' },
        { name: 'network_logs',    desc: 'Palo Alto firewall and NetFlow data' },
        { name: 'auth_logs',       desc: 'Active Directory authentication events' },
        { name: 'dns_logs',        desc: 'Internal DNS query logs from Windows DNS servers' },
      ],
      fields: {
        'Windows':  ['EventCode', 'ComputerName', 'User', 'LogonType', 'SourceNetworkAddress', 'TargetUserName'],
        'Network':  ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol', 'action'],
        'Endpoint': ['process_name', 'parent_process', 'command_line', 'user', 'dest'],
      },
    },
    edr: {
      product:    'VMware Carbon Black EDR',
      version:    '7.5.0',
      deployment: 'Sensor deployed on 98% of Windows endpoints and servers (~1,400 hosts)',
      telemetry:  'Process execution, network connections, file events, registry modifications, binary inventory',
    },
    network: {
      firewalls: 'Palo Alto PA-5220 (perimeter), PA-3220 (internal segmentation)',
      idsIps:    'Palo Alto Threat Prevention inline IPS on perimeter and DMZ segments',
      flowData:  'NetFlow v9 ingested from core switches into Splunk (5-min aggregation)',
      pcap:      'Full PCAP on DMZ via ExtraHop Reveal(x) — 7-day rolling retention',
    },
    cloud: {
      providers: 'Microsoft Azure (primary), AWS (dev/test workloads)',
      services:  'Azure AD, Azure Sentinel (forwarding to Splunk), AWS CloudTrail, Azure Activity Logs',
    },
    identity: {
      provider: 'Active Directory (on-premises, corp.internal)',
      dcs:      '4 domain controllers — DC01, DC02 (HQ); DC03, DC04 (DR site)',
      mfa:      'Duo Security — enforced for VPN, RDP, and all admin accounts',
      pam:      'CyberArk PAS — manages all Tier-0 and Tier-1 privileged accounts',
      eventIds: [
        { id: '4624', desc: 'Successful logon' },
        { id: '4625', desc: 'Failed logon' },
        { id: '4648', desc: 'Logon using explicit credentials' },
        { id: '4672', desc: 'Special privileges assigned to new logon' },
        { id: '4720', desc: 'User account created' },
        { id: '4732', desc: 'Member added to security-enabled local group' },
        { id: '4768', desc: 'Kerberos TGT requested' },
        { id: '4769', desc: 'Kerberos service ticket requested' },
        { id: '4771', desc: 'Kerberos pre-authentication failed' },
        { id: '4776', desc: 'NTLM authentication attempt' },
      ],
    },
    other: {
      vulnScanners: 'Tenable Nessus — weekly authenticated scans, results ingested into Splunk',
      assetMgmt:    'ServiceNow CMDB — primary asset inventory (~1,450 managed endpoints)',
      threatIntel:  'Recorded Future (API integrated with Splunk ES for IOC correlation)',
      soar:         'Splunk SOAR (Phantom) — automated triage for phishing and malware alerts',
    },
  },

  techStack: {
    os: {
      servers:      ['Windows Server 2019 (primary)', 'Windows Server 2022 (new deployments)', 'Windows Server 2016 (legacy, scheduled for decommission)'],
      workstations: ['Windows 11 Enterprise 23H2 (standard build)', 'Windows 10 Enterprise 22H2 (older hardware)'],
      mobile:       'iOS 17 (managed via Microsoft Intune MDM)',
    },
    dev: {
      languages:     'Python 3.11, PowerShell 7, C# (.NET 6)',
      webFrameworks: 'ASP.NET Core, React 18',
      apiFrameworks: 'FastAPI, .NET Web API',
    },
    databases: {
      relational: 'Microsoft SQL Server 2019 (primary), PostgreSQL 15 (dev)',
      nosql:      'MongoDB 6.0 (application tier)',
      caching:    'Redis 7.0',
      warehouse:  'Azure Synapse Analytics',
    },
    infrastructure: {
      cloud:      'Azure (East US 2 primary, West US 2 DR) — ~200 VMs, AKS clusters',
      containers: 'Docker, Kubernetes (AKS) — production workloads',
      cicd:       'Azure DevOps Pipelines, GitHub Actions',
    },
    networking: {
      architecture:  'Hub-and-spoke; HQ + 2 remote sites + Azure connected via MPLS and ExpressRoute',
      loadBalancers: 'F5 BIG-IP (external), Azure Application Gateway (cloud workloads)',
      dns:           'Windows DNS (on-prem, corp.internal); Azure DNS (cloud)',
      vpn:           'Palo Alto GlobalProtect — split-tunnel, MFA-enforced',
      jumpBoxes:     'PAW workstations in isolated VLAN (10.0.50.0/24) — required for Tier-0 admin access',
    },
    apps: {
      email:         'Microsoft Exchange Online (M365 E3)',
      collaboration: 'Microsoft Teams, SharePoint Online',
      fileSharing:   'SharePoint Online, OneDrive for Business; legacy CIFS share on FS01',
      versionControl:'GitHub Enterprise (self-hosted, github.corp.internal)',
      projectMgmt:   'Jira Software (cloud)',
      business:      'SAP S/4HANA (ERP), Salesforce (CRM)',
    },
  },
};

const crownJewels = { assets: [], accounts: [] };
