// ════════════════════════════════════════════════════════════════════════════
// IOC REPOSITORY  —  kb/iocs.js
// ════════════════════════════════════════════════════════════════════════════
// All indicators of compromise across hunts.
// Add new IOCs by appending to the array below.
//
// Each entry:
//   id       {string}  Unique ID, e.g. 'IOC-010'
//   type     {string}  'IP' | 'Domain' | 'Hash' | 'JA3' | 'Account'
//   value    {string}  The indicator value
//   hunt     {string}  Hunt ID, e.g. 'TH-2026-041'
//   ttp      {string}  MITRE TTP, e.g. 'T1071.001'
//   sev      {string}  'c' (critical) | 'h' (high) | 'm' (medium) | 'l' (low)
//   status   {string}  'blocked' | 'monitoring' | 'suspended' | 'isolated' | 'archived'
//   analyst  {string}  Username who added the IOC
//   ts       {string}  Timestamp 'YYYY-MM-DD HH:MM'
//   note     {string}  Free-text context / analysis note
// ════════════════════════════════════════════════════════════════════════════

const iocRepository = [
  { id:'IOC-001', type:'IP',      value:'185.220.101.47',              hunt:'TH-2026-041', ttp:'T1071.001', sev:'c', status:'blocked',    analyst:'alice',  ts:'2026-04-27 09:52', note:'Cobalt Strike C2 — JA3 watermark 0x4e4b5547 confirmed' },
  { id:'IOC-002', type:'JA3',     value:'769c10b06a1a2b7b7a26b0a2be2e88a4', hunt:'TH-2026-041', ttp:'T1071.001', sev:'c', status:'blocked',    analyst:'alice',  ts:'2026-04-27 09:43', note:'Malleable C2 profile — matching known CS kit' },
  { id:'IOC-003', type:'Hash',    value:'7f3a9c2b1e44d0f8a6c3b2d9e1f441', hunt:'TH-2026-041', ttp:'T1003.001', sev:'c', status:'blocked',  analyst:'marcus', ts:'2026-04-27 09:45', note:'Unsigned rundll32 variant — LSASS handle access' },
  { id:'IOC-004', type:'Account', value:'jsmith',                       hunt:'TH-2026-041', ttp:'T1078.002', sev:'h', status:'suspended',  analyst:'alice',  ts:'2026-04-27 09:47', note:'Lateral movement — 14 hosts in session, off-hours' },
  { id:'IOC-005', type:'IP',      value:'10.0.8.44',                    hunt:'TH-2026-040', ttp:'T1486',     sev:'c', status:'isolated',   analyst:'priya',  ts:'2026-04-24 14:25', note:'WIN-FS02 — payroll data encrypted, isolated by EDR' },
  { id:'IOC-006', type:'Domain',  value:'update-cdn.microsoftx.com',    hunt:'TH-2026-040', ttp:'T1566.001', sev:'h', status:'blocked',    analyst:'marcus', ts:'2026-04-24 13:55', note:'Phishing lure domain — typosquat of Microsoft CDN' },
  { id:'IOC-007', type:'Hash',    value:'b2e7f1a4c03d8e92f1b7c4a5d3e309', hunt:'TH-2026-040', ttp:'T1574.002', sev:'h', status:'monitoring', analyst:'marcus', ts:'2026-04-24 14:10', note:'DLL sideloading payload via signed binary' },
  { id:'IOC-008', type:'IP',      value:'91.108.56.183',                 hunt:'TH-2026-039', ttp:'T1195.002', sev:'h', status:'monitoring', analyst:'priya',  ts:'2026-04-14 11:30', note:'Supply chain C2 — attributed to APT cluster via CTI' },
  { id:'IOC-009', type:'Domain',  value:'pkg-update.npmjs-cdn.com',      hunt:'TH-2026-039', ttp:'T1195.002', sev:'h', status:'blocked',    analyst:'priya',  ts:'2026-04-14 11:45', note:'Malicious NPM mirror domain — used in supply chain implant' },
];
