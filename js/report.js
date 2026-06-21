/* ── report.js ────────────────────────────────────────────────────────────
   Hunt Report modal functions. Loaded after app.js.
   ──────────────────────────────────────────────────────────────────────── */

// ── Hunt Report ──
function renderHuntReport(id) {
  const d = keepData[id];
  if (!d || !d.report) return;
  const r = d.report;
  const activeSH = (typeof activeSubhunt !== 'undefined' && activeSubhunt) ? activeSubhunt : null;
  const sh = activeSH && d.subhunts ? d.subhunts.find(s => s.id === activeSH) : null;
  const lock = sh ? (d.subhuntLock?.[sh.id] || d.lock) : d.lock;
  const ttpFilter = sh ? sh.ttp : 'all';

  // Filtered findings for this TTP scope
  const scopedFindings = ttpFilter === 'all'
    ? d.findings
    : d.findings.filter(f => f.sh === sh.id || f.ttp === ttpFilter || extractTTP(f.meta || '') === ttpFilter);
  const scopedCrits = scopedFindings.filter(f => f.sev === 'c').length;
  const scopedHighs = scopedFindings.filter(f => f.sev === 'h').length;
  const chip = document.getElementById('report-status-chip');
  if (chip) {
    chip.textContent = r.status;
    chip.className = 'chip ' + r.statusClass;
  }

  // Update collapsed summary
  const rs = document.getElementById('report-summary');
  if (rs) rs.textContent = ttpFilter === 'all'
    ? `${scopedCrits} Critical · ${scopedHighs} High · ${r.status}`
    : `${ttpFilter} · ${scopedCrits} Critical · ${scopedHighs} High`;

  const u = users[d.createdBy] || {};

  const huntTitles = {
    '041': 'Volt Typhoon Lateral Movement & Credential Harvesting — Corp Domain',
    '042': 'Privileged Account Abuse & DCSync Staging — Tier-0 Assets',
    '040': 'Ransomware Pre-cursor BEC Activity — Finance Segment',
    '039': 'Supply Chain Compromise Indicators — DevOps Pipeline',
  };

  const stageText = text =>
    `<div class="report-lock-text">${text || 'No stage content recorded.'}</div>`;

  // TTP filter banner — shown when scoped to a single TTP
  const ttpBanner = ttpFilter !== 'all' ? `
    <div style="display:flex;align-items:center;gap:8px;padding:6px 14px;background:rgba(99,102,241,.07);border-bottom:1px solid rgba(99,102,241,.18);">
      <span style="font-size:10px;color:var(--indigo);">🔍 Filtered to</span>
      <span class="chip chip-indigo" style="font-size:10px;">${ttpFilter}</span>
      <span style="font-size:10px;color:var(--sub);">${ttpShortName(ttpFilter) || ''}</span>
      <span style="margin-left:auto;font-size:10px;color:var(--muted);">${scopedFindings.length} finding${scopedFindings.length!==1?'s':''} · ${scopedCrits} Critical · ${scopedHighs} High</span>
    </div>` : '';

  // Title: show TTP name when filtered, hunt title otherwise
  const reportTitle = ttpFilter !== 'all'
    ? `<span style="font-size:12px;font-weight:700;color:var(--indigo);font-family:monospace;">${d.title} · ${sh.label}</span>
       <span style="font-size:10px;color:var(--muted);">·</span>
       <span style="font-size:11px;color:var(--sub);">${ttpFilter} · ${sh.name}</span>`
    : `<span style="font-size:12px;font-weight:700;color:var(--text);font-family:monospace;">${d.title}</span>
       <span style="font-size:10px;color:var(--muted);">·</span>
       <span style="font-size:11px;color:var(--sub);">${huntTitles[id] || d.title}</span>`;

  document.getElementById('report-doc-body').innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--border);background:rgba(0,0,0,.18);flex-wrap:wrap;border-radius:0;">
      ${reportTitle}
      <div style="margin-left:auto;display:flex;gap:5px;flex-wrap:wrap;">
        <span class="chip chip-red" style="font-size:10px;">${scopedCrits} Critical</span>
        <span class="chip chip-yellow" style="font-size:10px;">${scopedHighs} High</span>
        <span class="chip ${r.statusClass}" style="font-size:10px;">${r.status}</span>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:8px;padding:5px 14px 6px;border-bottom:1px solid var(--border);background:rgba(0,0,0,.08);">
      <span style="font-size:10px;color:var(--muted);">👤 ${u.name || d.createdBy}${u.role ? ' · ' + u.role : ''}</span>
      <span style="color:var(--border2);">·</span>
      <span style="font-size:10px;color:var(--muted);">🗓 ${d.createdAt}</span>
    </div>
    ${ttpBanner}
    <div style="padding:10px 14px 0;">
      <div class="section-agent-line"><b>🎛️ Supervisor Agent</b><span>Hunt Report - LOCK record assembly and IR handoff summary</span></div>
    </div>
    <div class="report-lock-grid">
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-l">L</span><span class="lock-cell-label">Learn</span></div>
        <div class="section-agent-line" style="margin-bottom:8px;"><b>💡 Hypothesis Agent</b><span>Learn - CTI selection, TTP mapping, and hypothesis scope</span><button onclick="openAgentReasoning('hyp')">View reasoning</button></div>
        ${stageText(lock.l)}
      </div>
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-o">O</span><span class="lock-cell-label">Observe</span></div>
        <div class="section-agent-line" style="margin-bottom:8px;"><b>💡 Hypothesis Agent</b><span>Observe - environment baseline and expected observables</span><button onclick="openAgentReasoning('hyp')">View reasoning</button></div>
        ${stageText(lock.o)}
      </div>
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-c">C</span><span class="lock-cell-label">Check</span></div>
        <div class="section-agent-line" style="margin-bottom:8px;"><b>🧠 Investigator Agent + ⚙️ Detection Logic Agent</b><span>Check - alert retrieval, query execution, and detection output</span><button onclick="openAgentReasoning('ts')">View reasoning</button></div>
        ${stageText(lock.c)}
      </div>
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-k">K</span><span class="lock-cell-label">Keep</span></div>
        <div class="section-agent-line" style="margin-bottom:8px;"><b>🎛️ Supervisor Agent</b><span>Keep - findings, report, recommendations, and follow-on hunt</span></div>
        ${stageText(lock.k)}
      </div>
    </div>
  `;
}
