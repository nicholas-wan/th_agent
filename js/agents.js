/* ── agents.js ────────────────────────────────────────────────────────────
   Agent drawer data (agentData). Loaded after app.js.
   ──────────────────────────────────────────────────────────────────────── */

// ── Drawer data ──
const agentData = {
  hypothesis: { title:'Hypothesis Agent', sub:'Threat Hypothesis Generation · Completed · spawned by Orchestrator', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">The Hypothesis Agent is the first agent in the hunt pipeline. It reads incoming CTI reports, maps extracted TTPs to the MITRE ATT&CK framework, cross-references past hunt findings via the Past Hunts MCP tool, and generates structured, evidence-backed hunt hypotheses. Each hypothesis includes a confidence score, linked TTPs, supporting CTI sentences, and pre-applied analyst notes from prior runs. Output is handed off to the Orchestrator for scoping and routing.</div></div>
    <div class="ds"><div class="ds-head">🔌 Tools Used</div>
      <div class="ioc-row"><span class="ioc-t">📖</span>Technique Runbook — <code style="font-size:10px;color:var(--green);">get_runbook(ttp_id)</code> × 14 calls</div>
      <div class="ioc-row"><span class="ioc-t">🗂️</span>Past Hunts — <code style="font-size:10px;color:var(--blue);">search_hunts(ttp)</code> × 3 calls · <code style="font-size:10px;color:var(--blue);">get_hunt(id)</code> × 2 calls</div>
      <div class="ioc-row"><span class="ioc-t">🛡️</span>Coverage Checker — <code style="font-size:10px;color:#f59e0b;">check_coverage(ttp)</code> × 14 calls</div>
      <div class="ioc-row"><span class="ioc-t">🏗️</span>Environment Context — <code style="font-size:10px;color:var(--indigo);">get_topology()</code> · <code style="font-size:10px;color:var(--indigo);">get_asset(host)</code> × 2 · <code style="font-size:10px;color:var(--indigo);">get_account(user)</code> × 1</div>
    </div>
    <div class="ds"><div class="ds-head">Environment Loaded</div>
      <div class="ioc-row"><span class="ioc-t">🌐</span>10.0.0.0/8 scope · 8 segments · 2,412 endpoints · 34 servers</div>
      <div class="ioc-row"><span class="ioc-t">🖥</span>WIN-DC01 — Tier-0 DC · 10.0.1.10 · high-value asset · CrowdStrike 7.1</div>
      <div class="ioc-row"><span class="ioc-t">👤</span>jsmith — Corp Workstations · <span style="color:var(--yellow);">off-hours anomaly</span> · MFA enrolled</div>
    </div>
    <div class="ds"><div class="ds-head">Past Hunt Branch Decisions</div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:3px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="font-size:10px;font-weight:700;color:var(--sub);min-width:28px;">H-01</span>
          <span style="font-size:12px;">🎯</span>
          <span class="hyp-branch-label hbl-confirmed">Confirmed</span>
          <code style="font-size:10px;color:var(--muted);">TH-2026-038 · TH-2026-035</code>
        </div>
        <div style="font-size:10px;color:var(--sub);padding-left:35px;line-height:1.5;">PsExec confirmed across 9 hosts · jsmith pivot validated</div>
        <div style="font-size:10px;color:#a78bfa;padding-left:35px;">↳ Confidence elevated · single-hop threshold + batch exclusion pre-applied</div>
      </div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:3px;margin-top:6px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="font-size:10px;font-weight:700;color:var(--sub);min-width:28px;">H-02</span>
          <span style="font-size:12px;">🔔</span>
          <span class="hyp-branch-label hbl-fp">FPs in prior run</span>
          <code style="font-size:10px;color:var(--muted);">TH-2026-035</code>
        </div>
        <div style="font-size:10px;color:var(--sub);padding-left:35px;line-height:1.5;">Kerberoasting returned 22% FP rate — BackupExec/MSSQLSvc SPNs</div>
        <div style="font-size:10px;color:#a78bfa;padding-left:35px;">↳ CMDB SPN exclusion list pre-loaded · FP threshold tuned</div>
      </div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:3px;margin-top:6px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="font-size:10px;font-weight:700;color:var(--sub);min-width:28px;">H-03</span>
          <span style="font-size:12px;">❄️</span>
          <span class="hyp-branch-label hbl-clean">Clean prior run</span>
          <code style="font-size:10px;color:var(--muted);">TH-2025-091</code>
        </div>
        <div style="font-size:10px;color:var(--sub);padding-left:35px;line-height:1.5;">No JA3 match in prior run · technique variant possible · Alice flagged cert chain gap</div>
        <div style="font-size:10px;color:#a78bfa;padding-left:35px;">↳ Net-new · cert chain validation added · confidence Medium</div>
      </div>
    </div>
    <div class="ds"><div class="ds-head">Coverage Gaps Flagged</div>
      <div style="font-size:11px;color:var(--sub);line-height:1.7;">
        <span style="color:var(--yellow);">T1547.001</span> Registry Run Key — no existing rule · flagged to Detection Logic Agent<br>
        <span style="color:var(--yellow);">T1053.005</span> Scheduled Task — RAA partial · 0 hits · new rule queued<br>
        <span style="color:var(--red);">T1021.006</span> WMI Lateral Movement — no telemetry · logging gap raised
      </div>
    </div>
    <div class="ds"><div class="ds-head">Run Stats</div>
      <div class="kv-grid">
        <span class="kv-k">TTPs analysed</span><span class="kv-v">14</span>
        <span class="kv-k">Past hunts recalled</span><span class="kv-v">3</span>
        <span class="kv-k">Runbook lookups</span><span class="kv-v">14</span>
        <span class="kv-k">Coverage checks</span><span class="kv-v">14</span>
        <span class="kv-k">Env context calls</span><span class="kv-v">4</span>
        <span class="kv-k">Branch: 🎯 Confirmed</span><span class="kv-v" style="color:var(--red);">1</span>
        <span class="kv-k">Branch: 🔔 FPs</span><span class="kv-v" style="color:var(--yellow);">1</span>
        <span class="kv-k">Branch: ❄️ Clean</span><span class="kv-v" style="color:var(--blue);">1</span>
        <span class="kv-k">Hypotheses output</span><span class="kv-v">3</span>
        <span class="kv-k">Completed</span><span class="kv-v">09:14</span>
      </div>
    </div>` },

  orchestrator: { title:'Orchestrator Agent', sub:'Hunt Coordination & Synthesis · Active', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">The Orchestrator is the central controller of the agentic pipeline. It receives the parsed CTI from the Data Engineering Agent, assigns analytical tasks to the RAA Supervisor Agent and Detection Logic Agent, collects their outputs, and synthesises a unified hunt picture for the analyst. It also manages escalation routing — currently flagging 3 critical signals to the IR queue.</div></div>
    <div class="ds"><div class="ds-head">Agent Topology</div>
      <div style="font-size:11px;color:var(--sub);line-height:2;">
        🎛️ Orchestrator<br>
        &nbsp;&nbsp;├─ 💡 Hypothesis Agent <span style="color:var(--muted);font-size:10px;">(spawned first · generates hypotheses)</span><br>
        &nbsp;&nbsp;├─ 🗄️ Data Engineering Agent<br>
        &nbsp;&nbsp;├─ 🧠 RAA Supervisor Agent<br>
        &nbsp;&nbsp;├─ ⚙️ Detection Logic Agent<br>
        &nbsp;&nbsp;└─ ✅ Rule Validation Agent
      </div>
    </div>` },

  dataeng: { title:'Data Engineering Agent', sub:'Telemetry Ingestion & Normalization · Streaming', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">Connects to Splunk Enterprise Security via MCP (Model Context Protocol) and makes enriched, CIM-normalised telemetry available to all downstream agents. It translates hunt hypotheses into SPL queries, exposes relevant data models and field extractions, and streams event context into the shared agent workspace so the RAA Supervisor Agent and Detection Logic Agent can operate on structured, hunt-ready data.</div></div>
    <div class="ds"><div class="ds-head">🔌 MCP Connection</div>
      <div style="display:flex;align-items:center;gap:8px;padding:6px 0 4px;">
        <span style="font-size:18px;">🟠</span>
        <div>
          <div style="font-weight:600;font-size:12px;">Splunk Enterprise Security</div>
          <div style="font-size:10px;color:var(--green);">MCP Server v2.1 · Connected · REST API</div>
        </div>
      </div>
      <div class="ioc-row" style="margin-top:4px;"><span class="ioc-t">Auth</span>Service account · TLS 1.3</div>
      <div class="ioc-row"><span class="ioc-t">Host</span>splunk-es.corp:8089</div>
      <div class="ioc-row"><span class="ioc-t">Role</span>hunt_agent_ro (read-only)</div>
    </div>
    <div class="ds"><div class="ds-head">Indices Available</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">main</code> — general endpoint &amp; system events</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">security</code> — Windows Security Event Log</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">windows</code> — Sysmon + WinEvent (4624, 4688, 7045)</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">sysmon</code> — process create, network, registry</div>
      <div class="ioc-row"><span class="ioc-t">IDX</span><code style="font-size:10px;color:var(--blue);">network</code> — firewall flows, DNS, proxy logs</div>
    </div>
    <div class="ds"><div class="ds-head">CIM Data Models Exposed</div>
      <div class="ioc-row"><span class="ioc-t">DM</span>Authentication · Endpoint · Network Traffic · Intrusion Detection</div>
      <div style="font-size:10px;color:var(--muted);padding:4px 0 0 6px;">Agents query via <code style="color:var(--blue);">datamodel()</code> accelerated search</div>
    </div>
    <div class="ds"><div class="ds-head">Active SPL Context</div>
      <div style="background:rgba(0,0,0,.35);border-radius:5px;padding:8px;font-size:10px;font-family:monospace;color:#86efac;line-height:1.7;overflow-x:auto;">
        index=windows EventCode=4688<br>
        &nbsp;&nbsp;| eval cmdline=lower(CommandLine)<br>
        &nbsp;&nbsp;| where match(cmdline,"powershell|encoded|bypass")<br>
        &nbsp;&nbsp;| stats count by host,ParentProcessName,cmdline<br>
        <span style="color:var(--muted);">— feeding RAA Supervisor Agent · 342 events/min</span>
      </div>
    </div>
    <div class="ds"><div class="ds-head">Normalisation Stats</div>
      <div class="kv-grid">
        <span class="kv-k">Events/min</span><span class="kv-v">342</span>
        <span class="kv-k">CIM Schema</span><span class="kv-v">Splunk CIM 5.x</span>
        <span class="kv-k">Field Coverage</span><span class="kv-v">97.1% mapped</span>
        <span class="kv-k">Drop rate</span><span class="kv-v">0.2% (malformed)</span>
      </div>
    </div>` },

  tradecraft: { title:'RAA Supervisor Agent', sub:'Reasoning Augmented Analytics · ALERTING', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">Applies reasoning-augmented analytics to score process behaviour against adversary tradecraft models. Specialises in two core detections: <b>command-line anomaly scoring</b> (flags unusual flag combinations, encoded payloads, LOLBin abuse) and <b>process chain anomaly</b> (detects unexpected parent-child relationships against a learned baseline). Outputs enriched hypotheses with confidence scores for the Orchestrator.</div></div>
    <div class="ds"><div class="ds-head">📊 Active RAA Analytics</div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:2px;">
        <div style="display:flex;align-items:center;gap:7px;"><span class="chip chip-red" style="font-size:9px;">ALERTING</span><span style="font-size:11px;font-weight:600;color:var(--text);">Process Chain Anomaly</span></div>
        <div style="font-size:10px;color:var(--muted);padding-left:6px;">↳ Detects unexpected parent-child relationships against learned baseline · 3 hits this hunt</div>
      </div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:2px;margin-top:6px;">
        <div style="display:flex;align-items:center;gap:7px;"><span class="chip chip-yellow" style="font-size:9px;">ACTIVE</span><span style="font-size:11px;font-weight:600;color:var(--text);">Command-Line Anomaly Scoring</span></div>
        <div style="font-size:10px;color:var(--muted);padding-left:6px;">↳ Flags unusual flag combos, encoded payloads, LOLBin abuse · scoring threshold 75+</div>
      </div>
      <div class="ioc-row" style="flex-direction:column;align-items:flex-start;gap:2px;margin-top:6px;">
        <div style="display:flex;align-items:center;gap:7px;"><span class="chip chip-green" style="font-size:9px;">ACTIVE</span><span style="font-size:11px;font-weight:600;color:var(--text);">Network Behaviour Baseline</span></div>
        <div style="font-size:10px;color:var(--muted);padding-left:6px;">↳ East-west flow deviation scoring against 30-day rolling baseline · 0 hits this hunt</div>
      </div>
    </div>
` },

  detection: { title:'Detection Logic Agent', sub:'Hunting Rule Creation · Active', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">Translates hypotheses and RAA Supervisor Agent outputs into executable detection rules. Generates multi-format output: KQL for Microsoft Sentinel, Sigma for SIEM-agnostic distribution, Splunk SPL, and YARA-L for endpoint platforms. Rules are automatically passed to the Rule Validation Agent before deployment.</div></div>
    <div class="ds"><div class="ds-head">Output Formats</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;font-size:11px;">
        <span class="chip chip-blue">KQL</span><span class="chip chip-indigo">Sigma</span><span class="chip chip-gray">Splunk SPL</span><span class="chip chip-gray">YARA-L</span>
      </div>
    </div>` },

  validation: { title:'Rule Validation Agent', sub:'Detection Rule QA & Testing · Testing', body:`
    <div class="ds"><div class="ds-head">Role</div><div class="reasoning">Receives draft detection rules from the Detection Logic Agent and runs a multi-stage validation pipeline: syntactic checks, back-testing against historical labelled event data, false-positive rate estimation, and a coverage gap analysis against the active MITRE technique list. Only rules passing all gates are approved for SIEM deployment.</div></div>
    <div class="ds"><div class="ds-head">Validation Gates</div>
      <div style="display:flex;flex-direction:column;gap:4px;font-size:11px;color:var(--sub);">
        <div>① Syntax check &amp; schema validation</div>
        <div>② Back-test against 30-day labelled dataset</div>
        <div>③ FP rate threshold &lt; 5%</div>
        <div>④ MITRE coverage gap analysis</div>
        <div>⑤ Orchestrator approval → SIEM push</div>
      </div>
    </div>` }
};

function openAgentDrawer(key, row) {
  const d = agentData[key]; if (!d) return;
  document.getElementById('drw-title').textContent = d.title;
  document.getElementById('drw-sub').textContent = d.sub;
  document.getElementById('drw-body').innerHTML = d.body;
  document.getElementById('drawer').classList.add('open');
  if (row) {
    document.querySelectorAll('.agent-row').forEach(r => r.classList.remove('sel'));
    row.classList.add('sel');
  }
}

function openHuntDrawer(id) {
  document.getElementById('drw-title').textContent = id;
  document.getElementById('drw-sub').textContent = 'Threat Hunt Details';
  const active = id === 'TH-2026-041';
  document.getElementById('drw-body').innerHTML = `
    <div class="ds"><div class="ds-head">Hunt Info</div>
    <div class="kv-grid">
      <span class="kv-k">Hunt ID</span><span class="kv-v">${id}</span>
      <span class="kv-k">Status</span><span class="kv-v" style="color:${active?'var(--blue)':'var(--green)'}">${active?'● Active':'✓ Complete'}</span>
      <span class="kv-k">CTI Source</span><span class="kv-v">CISA AA24-038A</span>
      <span class="kv-k">Analyst</span><span class="kv-v">jdoe</span>
      <span class="kv-k">LOCK Stage</span><span class="kv-v">${active?'Observe → Check':'Keep (closed)'}</span>
    </div></div>
    ${active ? `<button class="btn btn-primary" style="width:100%;margin-top:6px;" onclick="goTab('observe',document.querySelectorAll('.nav-tab')[1])">Open in Observe →</button>` : ''}`;
  document.getElementById('drawer').classList.add('open');
}

function closeDrawer() { document.getElementById('drawer').classList.remove('open'); }

