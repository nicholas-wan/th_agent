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
      platform:  'SIEM/Log Aggregation Platform (Splunk, Elasticsearch, Sentinel, etc.)',
      version:   '',
      retention: '90 days hot/warm storage, 1 year cold storage',
      queryAccess: [
        'Web interface for interactive querying',
        'REST API available for programmatic access',
        'CLI tools or SDK for automated hunts',
      ],
      indexes: [
        { name: 'security_events', desc: 'Primary security telemetry (12M+ events)' },
        { name: 'windows_logs',    desc: 'Windows Event Logs' },
        { name: 'endpoint_data',   desc: 'EDR/endpoint telemetry' },
        { name: 'network_logs',    desc: 'Network flow and firewall logs' },
        { name: 'auth_logs',       desc: 'Authentication events across all sources' },
      ],
      fields: {
        'Windows':  ['EventCode', 'ComputerName', 'User', 'LogonType', 'SourceNetworkAddress', 'TargetUserName'],
        'Network':  ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol', 'action'],
        'Endpoint': ['process_name', 'parent_process', 'command_line', 'user', 'dest'],
      },
    },
    edr: {
      product:    '',
      version:    '',
      deployment: '',
      telemetry:  'Process execution, network connections, file events, registry modifications',
    },
    network: {
      firewalls: '',
      idsIps:    '',
      flowData:  'NetFlow logs ingested into SIEM',
      pcap:      '',
    },
    cloud: {
      providers: '',
      services:  '',
    },
    identity: {
      provider: 'Active Directory (on-premises)',
      dcs:      'Multiple DCs logging authentication events to SIEM',
      mfa:      '',
      pam:      '',
      eventIds: [
        { id: '4624', desc: 'Successful logon' },
        { id: '4625', desc: 'Failed logon' },
        { id: '4648', desc: 'Logon using explicit credentials' },
        { id: '4768', desc: 'Kerberos TGT requested' },
        { id: '4769', desc: 'Kerberos service ticket requested' },
        { id: '4771', desc: 'Kerberos pre-authentication failed' },
      ],
    },
    other: {
      vulnScanners: '',
      assetMgmt:    '',
      threatIntel:  '',
      soar:         '',
    },
  },

  techStack: {
    os: {
      servers:      ['Windows Server 2016', 'Windows Server 2019', 'Windows Server 2022'],
      workstations: ['Windows 10', 'Windows 11'],
      mobile:       '',
    },
    dev: {
      languages:     '',
      webFrameworks: '',
      apiFrameworks: '',
    },
    databases: {
      relational: '',
      nosql:      '',
      caching:    '',
      warehouse:  '',
    },
    infrastructure: {
      cloud:      '',
      containers: '',
      cicd:       '',
    },
    networking: {
      architecture:  '',
      loadBalancers: '',
      dns:           '',
      vpn:           '',
      jumpBoxes:     '',
    },
    apps: {
      email:         '',
      collaboration: '',
      fileSharing:   '',
      versionControl:'',
      projectMgmt:   '',
      business:      '',
    },
  },

  gaps: [
    { label: 'Unmonitored Systems',  value: '' },
    { label: 'Data Source Gaps',     value: '' },
    { label: 'Tool Limitations',     value: '' },
    { label: 'Third-Party Services', value: '' },
    { label: 'RDP Visibility',       value: '' },
  ],

  priorityTtps: {
    tactics: [
      { id: 'TA0006', name: 'Credential Access',    desc: 'Password spraying, credential dumping' },
      { id: 'TA0008', name: 'Lateral Movement',      desc: 'RDP abuse, pass-the-hash, pass-the-ticket' },
      { id: 'TA0004', name: 'Privilege Escalation',  desc: 'Token manipulation, UAC bypass' },
      { id: 'TA0003', name: 'Persistence',           desc: 'Scheduled tasks, services, registry run keys' },
      { id: 'TA0010', name: 'Exfiltration',          desc: 'Data staging, exfil over C2 channel' },
    ],
    threatModel: [
      'Ransomware operators (initial access → lateral movement → encryption)',
      'Insider threats (data exfiltration, sabotage)',
      'External attackers (phishing → credential theft → lateral movement)',
    ],
  },

  maintenance: {
    checklist: [
      'Verify SIEM data collections and data sources are current',
      'Add new log sources integrated into SIEM',
      'Remove decommissioned systems',
      'Update tool coverage percentages',
      'Refresh internal documentation links',
      'Validate SIEM API access still works',
      'Update jump box allowlist for RDP hunts',
      'Review priority TTPs based on recent incidents',
    ],
    changeLog: [
      { date: '2026-01-13', note: 'Initial creation with SIEM configuration for RDP lateral movement hunting' },
    ],
  },
};

const crownJewels = { assets: [], accounts: [] };
