/* ── report.js ────────────────────────────────────────────────────────────
   Hunt Report modal functions. Loaded after app.js.
   ──────────────────────────────────────────────────────────────────────── */

// ── Hunt Report ──
function renderHuntReport(id) {
  const d = keepData[id];
  if (!d || !d.report) return;
  const r = d.report;
  const lock = d.lock;
  const ttpFilter = activeKeepTTP; // read current TTP scope

  const chip = document.getElementById('report-status-chip');
  chip.textContent = r.status;
  chip.className = 'chip ' + r.statusClass;

  // Filtered findings for this TTP scope
  const scopedFindings = ttpFilter === 'all'
    ? d.findings
    : d.findings.filter(f => extractTTP(f.meta) === ttpFilter);
  const scopedCrits = scopedFindings.filter(f => f.sev === 'c').length;
  const scopedHighs = scopedFindings.filter(f => f.sev === 'h').length;

  // Update collapsed summary
  const rs = document.getElementById('report-summary');
  if (rs) rs.textContent = ttpFilter === 'all'
    ? `${d.criticals} Critical · ${d.highs} High · ${r.status}`
    : `${ttpFilter} · ${scopedCrits} Critical · ${scopedHighs} High`;

  const u = users[d.createdBy] || {};

  const huntTitles = {
    '041': 'APT29 Lateral Movement & Credential Harvesting — Corp Domain',
    '040': 'Ransomware Pre-cursor BEC Activity — Finance Segment',
    '039': 'Supply Chain Compromise Indicators — DevOps Pipeline',
  };

  const ri = (items) => items.map(i =>
    `<div class="report-lock-item ${i.cls}">${i.text}</div>`
  ).join('');

  // L — unchanged (hunt-level context always relevant)
  const lItems = [{ cls: 'ri-blue', text: lock.l }];

  // O — show only findings in the current TTP scope
  const critFindings = scopedFindings.filter(f => f.sev === 'c');
  const oItems = [{ cls: 'ri-blue', text: lock.o }];
  critFindings.slice(0, 3).forEach(f => oItems.push({ cls: 'ri-red', text: f.title }));
  if (scopedHighs > 0) oItems.push({ cls: 'ri-yellow',
    text: `+${scopedHighs} High severity finding${scopedHighs > 1 ? 's' : ''}${ttpFilter !== 'all' ? ' for ' + ttpFilter : ' also recorded'}`
  });
  if (ttpFilter !== 'all' && !scopedFindings.length) {
    oItems.push({ cls: 'ri-yellow', text: `No findings recorded for ${ttpFilter} in this hunt.` });
  }

  // C — unchanged
  const raaInfo = lock.raa;
  const raaItem = raaInfo
    ? { cls: raaInfo.relevant && !raaInfo.partial ? 'ri-green' : 'ri-yellow', text: raaInfo.note }
    : { cls: 'ri-yellow', text: 'RAA: no data recorded' };
  const cItems = [
    { cls: 'ri-blue', text: lock.c },
    raaItem,
    ...r.impact.map(i => ({ cls: 'ri-blue', text: `${i.val} ${i.lbl}` })),
  ];

  // K — filter recommendations that mention the active TTP; fall back to all if none match
  let recPool = r.recommendations;
  if (ttpFilter !== 'all') {
    const matched = recPool.filter(rec => rec.includes(ttpFilter) || rec.replace(/<[^>]+>/g,'').toLowerCase().includes(ttpFilter.toLowerCase()));
    if (matched.length) recPool = matched;
  }
  const kItems = recPool.slice(0, 4).map(rec => ({
    cls: 'ri-green', text: rec.replace(/<[^>]+>/g, '')
  }));

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
    ? `<span style="font-size:12px;font-weight:700;color:var(--indigo);font-family:monospace;">${ttpFilter}</span>
       <span style="font-size:10px;color:var(--muted);">·</span>
       <span style="font-size:11px;color:var(--sub);">${ttpShortName(ttpFilter) || huntTitles[id] || d.title}</span>`
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
    <div class="report-lock-grid">
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-l">L</span><span class="lock-cell-label">Learn</span></div>
        <div class="report-lock-items">${ri(lItems)}</div>
      </div>
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-o">O</span><span class="lock-cell-label">Observe</span></div>
        <div class="report-lock-items">${ri(oItems)}</div>
      </div>
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-c">C</span><span class="lock-cell-label">Check</span></div>
        <div class="report-lock-items">${ri(cItems)}</div>
      </div>
      <div class="report-lock-cell">
        <div class="lock-cell-head"><span class="lock-letter lock-k">K</span><span class="lock-cell-label">Keep</span></div>
        <div class="report-lock-items">${ri(kItems)}</div>
      </div>
    </div>
  `;
}

