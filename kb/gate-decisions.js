// ════════════════════════════════════════════════════════════════════════════
// GATE DECISION LOG  —  kb/gate-decisions.js
// ════════════════════════════════════════════════════════════════════════════
// Per-hunt log of analyst decisions at each agent gate.
// Keys match the short hunt ID (e.g. '041' for TH-2026-041).
//
// Each entry:
//   gate        {number}  Gate index (1-based)
//   name        {string}  Gate label shown in the UI
//   agent       {string}  Agent key (orchestrator | hypothesis | tradecraft | ...)
//   agentColor  {string}  CSS color token (blue | teal | yellow | green | purple)
//   analyst     {string}  Username who made the decision
//   ts          {string}  Human-readable timestamp
//   decision    {string}  'approved' | 'modified' | 'rejected'
//   original    {string}  What the agent proposed
//   change      {string|null}  What the analyst changed (null if approved unchanged)
//   reason      {string}  Analyst rationale
// ════════════════════════════════════════════════════════════════════════════

const gateDecisionLog = {
  '041': [
    { gate:1, name:'Scope Approval',        agent:'orchestrator', agentColor:'blue',   analyst:'alice',  ts:'09:22 · Apr 27', decision:'modified',
      original:'Proposed scope: T1078.002 · T1570 · T1003.001 · T1558.003',
      change:'Removed T1558.003 — existing rule DR-2041 covers this with 97% fidelity. Agent cycles redirected to uncovered TTPs.',
      reason:'No value in re-hunting a technique with a deployed high-fidelity rule. Kept remaining 3 TTPs.' },
    { gate:2, name:'Hypothesis Review',     agent:'hypothesis',   agentColor:'teal',   analyst:'alice',  ts:'09:31 · Apr 27', decision:'approved',
      original:'H-01 (LSASS access) · H-02 (Kerberoasting) · H-03 (C2 beacon)',
      change:null,
      reason:'All three hypotheses well-scoped. H-01 carries prior confirmed findings — elevated confidence warranted.' },
    { gate:3, name:'RAA Supervisor Validation', agent:'tradecraft',   agentColor:'yellow', analyst:'marcus', ts:'09:38 · Apr 27', decision:'modified',
      original:'Default FP threshold: 5%',
      change:'FP threshold lowered to 2% — DC VLAN Tier-0 assets in scope. Pre-loaded jsmith exclusion from TH-2026-038 FP list.',
      reason:'Tier-0 assets justify tighter threshold. One FP on a DC is worse than alert fatigue.' },
  ],
  '040': [
    { gate:1, name:'Scope Approval',        agent:'orchestrator', agentColor:'blue',   analyst:'marcus', ts:'13:22 · Apr 24', decision:'approved',
      original:'Proposed scope: T1566.001 · T1204 · T1574.002 · T1486 · T1490',
      change:null,
      reason:'Scope matches BEC pre-cursor playbook exactly. Finance VLAN telemetry covers all TTPs.' },
    { gate:2, name:'Hypothesis Review',     agent:'hypothesis',   agentColor:'teal',   analyst:'marcus', ts:'13:35 · Apr 24', decision:'modified',
      original:'H-01 (phishing lure) · H-02 (DLL sideload)',
      change:'Added H-03: ransomware pre-cursor (shadow copy deletion via vssadmin) — not in original CTI but flagged by Hypothesis Agent branch logic from TH-2026-038.',
      reason:'FIN7 cluster reliably deletes shadow copies before encryption. CTI miss corrected by agent recall.' },
  ],
  '039': [
    { gate:1, name:'Scope Approval',        agent:'orchestrator', agentColor:'blue',   analyst:'priya',  ts:'10:08 · Apr 14', decision:'approved',
      original:'Proposed scope: T1195.002 · T1059.001 · T1105',
      change:null,
      reason:'Supply chain TTPs confirmed in external CTI feed. DevOps pipeline telemetry available.' },
    { gate:2, name:'Hypothesis Review',     agent:'hypothesis',   agentColor:'teal',   analyst:'priya',  ts:'10:18 · Apr 14', decision:'modified',
      original:'H-01 (malicious package) · H-02 (C2 via CI/CD runner)',
      change:'Confidence on H-02 lowered to medium — runner logs show no anomalies in past 7 days.',
      reason:'Evidence does not yet support high confidence on H-02. Keeping it in scope but flagging for analyst attention.' },
  ],
};
