/* ── Environment fallback data ───────────────────────────────────────────
   Source of truth: kb/environment.md (fetched at runtime by initKbTab).
   This file is a local-dev fallback used when kb/environment.md cannot be
   fetched (e.g. file:// protocol). Do NOT edit here — edit environment.md.
   ──────────────────────────────────────────────────────────────────────── */
const envData = {
  domain: {
    name:'CORP.LOCAL', netbios:'CORP', forest:'CORP.LOCAL',
    functionalLevel:'Windows Server 2019',
    adfsUrl:'https://adfs.corp.local',
    adSync:'Azure AD Connect · delta sync every 30 min',
    dcs:['WIN-DC01.corp.local (10.0.1.10)','WIN-DC02.corp.local (10.0.1.11)'],
    sites:['HQ-Site (10.0.0.0/16)','DR-Site (10.10.0.0/16)'],
    trusts:['One-way outbound → PARTNER.LOCAL (selective auth)'],
  },
  stats:[
    { label:'Endpoints',    value:'2,412', note:'Windows · macOS · Linux',    color:'blue'   },
    { label:'Servers',      value:'34',    note:'On-prem · virtualised',       color:'indigo' },
    { label:'Segments',     value:'8',     note:'VLANs mapped',                color:'green'  },
    { label:'User Accounts',value:'1,847', note:'638 service accounts',        color:'yellow' },
  ],
  anomalies:[
    { sev:'crit', text:'CORP\\jsmith authenticated from 3 source IPs in 6h — off-hours logon anomaly (T1078.002)' },
    { sev:'high', text:'WIN-DC01: unexpected outbound SMB to 10.0.8.44 (Workstations VLAN) at 02:14 UTC' },
    { sev:'high', text:'svc-backup account interactive logon detected on WIN-WS041 — service accounts should never be interactive' },
    { sev:'med',  text:'WIN-WS041: new service installed outside patch window — svchost.exe variant (T1543.003)' },
  ],
  segments:[
    { id:'seg-dc',    name:'Domain Controllers', icon:'🏛️', sensitivity:'critical', cidr:'10.0.1.0/24',  vlan:10,  gateway:'10.0.1.1',  hosts:2,    desc:'Tier-0 assets. No workstation traffic permitted. Firewalled from all non-admin VLANs.', tags:['Tier-0','Jump-access only','IDS monitored'], acls:['Allow: Admin VLAN (10.0.9.0/24)','Allow: Splunk ES (10.0.5.20)','Deny: all others'] },
    { id:'seg-srv',   name:'Server Farm',         icon:'🖥️', sensitivity:'high',     cidr:'10.0.2.0/24',  vlan:20,  gateway:'10.0.2.1',  hosts:28,   desc:'Application and file servers. East-west traffic restricted via host-based firewall policy.', tags:['Production','Change-controlled','Sysmon deployed'], acls:['Allow: Corp Workstations','Allow: Admin VLAN','Deny: Guest/IoT'] },
    { id:'seg-ws',    name:'Corp Workstations',   icon:'💻', sensitivity:'medium',   cidr:'10.0.3.0/24',  vlan:30,  gateway:'10.0.3.1',  hosts:1840, desc:'Standard employee endpoints. Managed via Intune. No server-to-workstation initiation permitted.', tags:['Intune managed','EDR deployed','User VLAN'], acls:['Allow: Internet via proxy','Allow: Server Farm (restricted ports)','Deny: DC direct'] },
    { id:'seg-dmz',   name:'DMZ / Public-facing', icon:'🌐', sensitivity:'high',     cidr:'10.0.4.0/24',  vlan:40,  gateway:'10.0.4.1',  hosts:6,    desc:'Web servers, reverse proxies, email gateways. Strict egress filtering. No internal DNS.', tags:['Internet-facing','WAF protected','Isolated DNS'], acls:['Allow: inbound 443/80 from Internet','Deny: lateral to internal subnets','Allow: outbound SMTP 25'] },
    { id:'seg-sec',   name:'Security / SOC',      icon:'🛡️', sensitivity:'high',     cidr:'10.0.5.0/24',  vlan:50,  gateway:'10.0.5.1',  hosts:8,    desc:'Splunk ES, EDR management console, SOAR. Read-only access to all other VLANs for log collection.', tags:['SOC tools','Log collection','Splunk ES'], acls:['Allow: syslog/UDP 514 from all','Allow: Splunk forwarder 9997 from all','Deny: outbound to Internet'] },
    { id:'seg-admin', name:'Admin / Privileged',  icon:'🔑', sensitivity:'critical', cidr:'10.0.9.0/24',  vlan:90,  gateway:'10.0.9.1',  hosts:4,    desc:'Jump hosts, PAM solution, admin workstations. Requires MFA + privileged session recording.', tags:['Tier-0 access','PAM enforced','Session recorded'], acls:['Allow: DC VLAN','Allow: Server Farm','Allow: Splunk ES (read)','Deny: Internet direct'] },
    { id:'seg-iot',   name:'IoT / OT',            icon:'📡', sensitivity:'medium',   cidr:'10.0.6.0/24',  vlan:60,  gateway:'10.0.6.1',  hosts:312,  desc:'Building management, printers, physical security cameras. Isolated from corp network.', tags:['Isolated','No domain join','Unmanaged endpoints'], acls:['Allow: outbound NTP/DNS only','Deny: all inbound','Deny: corp subnets'] },
    { id:'seg-dr',    name:'DR Site',             icon:'🔄', sensitivity:'high',     cidr:'10.10.0.0/16', vlan:100, gateway:'10.10.0.1', hosts:220,  desc:'Disaster recovery site. Site-to-site VPN to HQ. Replication traffic only during off-hours.', tags:['DR site','VPN tunnel','Replication VLAN'], acls:['Allow: replication ports from HQ DCs','Allow: backup traffic from svc-backup','Deny: user traffic'] },
  ],
  assets:[
    { hostname:'WIN-DC01',   ip:'10.0.1.10',  role:'dc',  os:'Windows Server 2022',  segment:'Domain Controllers', owner:'IT Ops',   lastSeen:'2 min ago',  status:'online', details:{ fqdn:'WIN-DC01.corp.local',   sysmon:'v15.0', edr:'CrowdStrike 7.1', patch:'2026-04-15', criticality:'Tier-0',    notes:'Primary DC. FSMO roles: PDC, RID, Infrastructure. Kerberos KDC.' } },
    { hostname:'WIN-DC02',   ip:'10.0.1.11',  role:'dc',  os:'Windows Server 2022',  segment:'Domain Controllers', owner:'IT Ops',   lastSeen:'3 min ago',  status:'online', details:{ fqdn:'WIN-DC02.corp.local',   sysmon:'v15.0', edr:'CrowdStrike 7.1', patch:'2026-04-15', criticality:'Tier-0',    notes:'Secondary DC. DNS secondary. AD replication partner to WIN-DC01.' } },
    { hostname:'WIN-FS01',   ip:'10.0.2.20',  role:'srv', os:'Windows Server 2019',  segment:'Server Farm',        owner:'IT Ops',   lastSeen:'1 min ago',  status:'online', details:{ fqdn:'WIN-FS01.corp.local',   sysmon:'v15.0', edr:'CrowdStrike 7.1', patch:'2026-04-15', criticality:'High',      notes:'Primary file server. DFS namespace root.' } },
    { hostname:'WIN-APP01',  ip:'10.0.2.21',  role:'srv', os:'Windows Server 2019',  segment:'Server Farm',        owner:'App Team', lastSeen:'4 min ago',  status:'online', details:{ fqdn:'WIN-APP01.corp.local',  sysmon:'v15.0', edr:'CrowdStrike 7.1', patch:'2026-04-10', criticality:'High',      notes:'Internal ERP application server (SAP). Service account: svc-erp.' } },
    { hostname:'SQL-DB01',   ip:'10.0.2.30',  role:'srv', os:'Windows Server 2019',  segment:'Server Farm',        owner:'DBA Team', lastSeen:'2 min ago',  status:'online', details:{ fqdn:'SQL-DB01.corp.local',   sysmon:'v15.0', edr:'CrowdStrike 7.1', patch:'2026-03-20', criticality:'Critical',  notes:'SQL Server 2019. Hosts ERP and HR databases. SA disabled. Named pipes disabled.' } },
    { hostname:'SPLUNK-ES',  ip:'10.0.5.20',  role:'sec', os:'Linux (RHEL 8)',        segment:'Security / SOC',     owner:'SOC',      lastSeen:'< 1 min',    status:'online', details:{ fqdn:'splunk-es.corp.local',  sysmon:'N/A',   edr:'CrowdStrike 7.1', patch:'2026-04-20', criticality:'Critical',  notes:'Splunk Enterprise Security 8.x. Ingest: ~80 GB/day.' } },
    { hostname:'WIN-WS041',  ip:'10.0.3.41',  role:'ws',  os:'Windows 11 Pro',       segment:'Corp Workstations',  owner:'jsmith',   lastSeen:'18 min ago', status:'online', details:{ fqdn:'WIN-WS041.corp.local',  sysmon:'v15.0', edr:'CrowdStrike 7.1', patch:'2026-04-08', criticality:'Medium',    notes:'⚠ ALERT: Unusual LSASS access detected. Under investigation (TH-2026-041).' } },
    { hostname:'WIN-WS042',  ip:'10.0.3.42',  role:'ws',  os:'Windows 11 Pro',       segment:'Corp Workstations',  owner:'mwebb',    lastSeen:'7 min ago',  status:'online', details:{ fqdn:'WIN-WS042.corp.local',  sysmon:'v15.0', edr:'CrowdStrike 7.1', patch:'2026-04-15', criticality:'Low',       notes:'Standard workstation assigned to Marcus Webb (SOC analyst).' } },
    { hostname:'JUMP-01',    ip:'10.0.9.10',  role:'net', os:'Windows Server 2022',  segment:'Admin / Privileged', owner:'IT Ops',   lastSeen:'5 min ago',  status:'online', details:{ fqdn:'JUMP-01.corp.local',    sysmon:'v15.0', edr:'CrowdStrike 7.1', patch:'2026-04-15', criticality:'High',      notes:'Privileged access workstation. CyberArk PSM installed. MFA enforced via Duo.' } },
  ],
  accounts:[
    { name:'jsmith',     type:'User',    status:'active', groups:['Domain Users','Finance-RW','VPN-Users'],                  normal:'Business hours · Corp Workstations · WIN-WS041',                       anomaly:'⚠ Off-hours logons from 3 source IPs in 6h — matches T1078.002 pattern (TH-2026-041)', lastLogon:'2026-04-27 02:41 UTC', pwdAge:'47 days',  mfa:'Duo · enrolled'    },
    { name:'mwebb',      type:'User',    status:'active', groups:['Domain Users','SOC-Analysts','Splunk-Users'],              normal:'Business hours · Corp Workstations + JUMP-01',                          anomaly:null,                                                                                 lastLogon:'2026-04-27 09:12 UTC', pwdAge:'12 days',  mfa:'Duo · enrolled'    },
    { name:'svc-backup', type:'Service', status:'active', groups:['Domain Users','Backup Operators'],                        normal:'Non-interactive · scheduled tasks only · Server Farm + DC VLAN',        anomaly:'⚠ Interactive logon detected on WIN-WS041 at 02:18 UTC — service accounts must not log on interactively', lastLogon:'2026-04-27 02:18 UTC', pwdAge:'180 days', mfa:'N/A'               },
    { name:'svc-sql',    type:'Service', status:'active', groups:['Domain Users','SQL-Service'],                              normal:'Non-interactive · SQL-DB01 only',                                       anomaly:null,                                                                                 lastLogon:'2026-04-26 22:00 UTC', pwdAge:'90 days',  mfa:'N/A'               },
    { name:'svc-splunk', type:'Service', status:'active', groups:['Domain Users','Splunk-Service'],                          normal:'Non-interactive · SPLUNK-ES only · read-only domain access',             anomaly:null,                                                                                 lastLogon:'2026-04-27 09:05 UTC', pwdAge:'60 days',  mfa:'N/A'               },
    { name:'adm-itops',  type:'Admin',   status:'active', groups:['Domain Admins','Enterprise Admins','Schema Admins'],       normal:'Business hours · JUMP-01 only · PAM session required',                  anomaly:null,                                                                                 lastLogon:'2026-04-25 14:30 UTC', pwdAge:'30 days',  mfa:'Duo · hardware token'},
    { name:'krbtgt',     type:'Service', status:'active', groups:['Domain Users'],                                           normal:'Never logged on interactively — Kerberos KDC account',                   anomaly:null,                                                                                 lastLogon:'Never',                pwdAge:'364 days', mfa:'N/A'               },
  ],
  topology:`CORP.LOCAL — Network Topology
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

  IoT  VLAN 60  10.0.6.0/24  — isolated · no corp routing`,
  infrastructure:[
    { icon:'🏛️', name:'WIN-DC01 / WIN-DC02', role:'Domain Controllers · FSMO roles · KDC', ip:'10.0.1.10–11', crit:'Tier-0'   },
    { icon:'🛡️', name:'SPLUNK-ES',            role:'SIEM · Hunt agent MCP endpoint',         ip:'10.0.5.20',    crit:'Critical' },
    { icon:'🔑', name:'JUMP-01',              role:'Privileged Access Workstation · PAM',     ip:'10.0.9.10',    crit:'High'     },
    { icon:'🔥', name:'Palo Alto PA-5220',    role:'Perimeter firewall · IPS · URL filtering',ip:'203.0.113.1',  crit:'Critical' },
    { icon:'🔀', name:'Cisco Nexus 9000',     role:'Core switch · Inter-VLAN routing · SPAN', ip:'10.0.0.1',     crit:'Critical' },
    { icon:'🗄️', name:'SQL-DB01',             role:'SQL Server 2019 · ERP + HR databases',    ip:'10.0.2.30',    crit:'Critical' },
  ],
};
const crownJewels = {
  assets:[
    { tier:0, icon:'🏛️', name:'WIN-DC01',     role:'Primary Domain Controller',     ip:'10.0.1.10', segment:'DC VLAN',       blast:'Domain dominance · Golden Ticket · DCSync · extract all credential hashes from AD',                                    exposure:'high',   ttp:'T1078.002 · T1003.001' },
    { tier:0, icon:'🏛️', name:'WIN-DC02',     role:'Secondary Domain Controller',   ip:'10.0.1.11', segment:'DC VLAN',       blast:'AD replication access · offline database copy · Tier-0 redundancy path',                                              exposure:'medium', ttp:'T1003.001'             },
    { tier:0, icon:'🔐', name:'PKI-01',        role:'Root Certificate Authority',    ip:'10.0.2.5',  segment:'Mgmt VLAN',     blast:'Certificate forgery · impersonate any identity · ESC1–8 ADCS attack surface · HTTPS interception',                     exposure:'low',    ttp:null                    },
    { tier:0, icon:'💾', name:'BACKUP-01',     role:'Enterprise Backup Server',      ip:'10.0.3.15', segment:'Mgmt VLAN',     blast:'Full data corpus · stored credentials · offline AD database copy · ransomware primary target',                         exposure:'medium', ttp:'T1570'                 },
    { tier:1, icon:'⚙️', name:'SCCM-01',       role:'SCCM / ConfigMgr Server',       ip:'10.0.5.20', segment:'Mgmt VLAN',     blast:'Code execution on ~2,400 endpoints · software push · local admin rights across all workstations',                       exposure:'low',    ttp:null                    },
    { tier:1, icon:'🔍', name:'SIEM-01',       role:'Splunk Enterprise Security',    ip:'10.0.4.10', segment:'Security VLAN', blast:'Security visibility manipulation · log tampering · detection blind spots · hunt data access',                           exposure:'low',    ttp:null                    },
    { tier:1, icon:'🗄️', name:'SQL-PROD-01',  role:'Production SQL Server',         ip:'10.0.6.5',  segment:'Server VLAN',   blast:'Financial records · customer PII · business-critical operational data · exfiltration target',                           exposure:'low',    ttp:null                    },
  ],
  accounts:[
    { icon:'👑',  name:'Administrator', type:'Built-in Domain Admin',  group:'Domain Admins',   desc:'Full domain control if compromised — primary adversary target for privilege escalation endpoint',                             exposure:'medium', ttp:'T1078.002'           },
    { icon:'🔑',  name:'krbtgt',        type:'Kerberos TGT Account',   group:'Domain Users',    desc:'Golden Ticket via NTLM hash extraction — DCSync prerequisite · compromise = unrestricted domain access',                    exposure:'medium', ttp:'T1003.006'           },
    { icon:'🛡️', name:'svc-backup',    type:'Service Account',         group:'Backup Operators',desc:'Access to BACKUP-01 and the full backup data corpus · SPN registered · Kerberoasting target',                              exposure:'low',    ttp:'T1558.003'           },
    { icon:'⚠️', name:'jsmith',         type:'Domain User',             group:'Corp Workstations',desc:'Current hunt subject · off-hours logon anomaly · touched 14 hosts · MFA enrolled · elevated exposure',                   exposure:'high',   ttp:'T1078.002 · T1570'   },
  ],
};
