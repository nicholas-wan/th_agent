/* ── Knowledge Base Tab ─────────────────────────────────────────────────
   All KB tab functions: tradecraft (skills + runbooks), environment pane,
   IOC repository, skills repo modal, runbook modal, rule validation modal.
   Loaded after app.js — references globals declared there.
   ──────────────────────────────────────────────────────────────────────── */
// ─────────────────────────────────────────────
//  KNOWLEDGE BASE TAB
// ─────────────────────────────────────────────
let activeKbTab         = 'tradecraft';
let activeTradecraftTab = 'tactic';
let activeKbSkCat       = 'all';
let activeKbRbTactic    = 'all';
let kbEnvEditMode  = false;
let kbEnvSnapshot  = null; // store original values for cancel

// ── Markdown source cache & load flag ──
let _kbMdLoaded    = false;
let _activeKbMdTab = 'skills';
const _kbMdCache   = { skills: null, runbooks: null, env: null };

// ── Markdown parsers ──────────────────────────────────────────────────────

function _extractMdSections(lines) {
  const map = {};
  let cur = null;
  for (const ln of lines) {
    if (ln.startsWith('### ')) { cur = ln.slice(4).trim(); map[cur] = []; }
    else if (cur !== null)     { map[cur].push(ln); }
  }
  return map;
}

function _extractCodeBlock(lines) {
  let inside = false;
  const out = [];
  for (const ln of lines) {
    if (ln.startsWith('```')) { if (inside) break; inside = true; continue; }
    if (inside) out.push(ln);
  }
  return out.join('\n');
}

function _parseMdSkills(text) {
  const skills = [];
  // Normalise Windows (CRLF) and old Mac (CR) line endings to LF
  const norm = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  for (const sec of norm.split(/\n---\n/)) {
    const lines = sec.trim().split('\n');
    const headLine = lines.find(l => /^## SK-\d+/.test(l));
    if (!headLine) continue;
    const hm = headLine.match(/^## (SK-\d+)\s*[—–-]+\s*(.+)/);
    if (!hm) continue;
    const id   = hm[1];
    const name = hm[2].trim();

    // Parse > key: val | key: val metadata lines
    const meta = {};
    for (const ln of lines) {
      if (!ln.startsWith('> ')) continue;
      for (const part of ln.slice(2).split(' | ')) {
        const i = part.indexOf(':');
        if (i < 0) continue;
        meta[part.slice(0, i).trim()] = part.slice(i + 1).trim();
      }
    }

    // Summary: non-empty lines between heading and first ###, excluding > meta
    const summaryLines = [];
    let pastHead = false;
    for (const ln of lines) {
      if (ln.startsWith('## ')) { pastHead = true; continue; }
      if (!pastHead || ln.startsWith('> ')) continue;
      if (ln.startsWith('### ')) break;
      if (ln.trim()) summaryLines.push(ln.trim());
    }

    const smap = _extractMdSections(lines);
    const patterns    = (smap['Patterns']     || []).filter(l => l.startsWith('- ')).map(l => l.slice(2));
    const exclusions  = (smap['Exclusions']   || []).filter(l => l.startsWith('- ')).map(l => l.slice(2));
    const attackPaths = (smap['Attack Paths'] || []).filter(l => l.startsWith('- ')).map(l => {
      const p = l.slice(2).split(' | ');
      return { ttp: p[0]?.trim()||'', name: p[1]?.trim()||'', likelihood: p[2]?.trim()||'medium', desc: p.slice(3).join(' | ').trim() };
    });
    const ttps   = meta['ttps']   ? meta['ttps'].split(',').map(t => t.trim())   : [];
    const agents = meta['agents'] ? meta['agents'].split(',').map(a => a.trim()) : [];

    skills.push({
      id, name,
      skillType:  meta['type']           || 'tactic',
      cat:        meta['category']       || '',
      catLabel:   meta['category-label'] || '',
      author:     meta['author']         || '',
      version:    meta['version']        || '',
      updated:    meta['updated']        || '',
      ttps, summary: summaryLines.join(' '),
      patterns, spl: _extractCodeBlock(smap['SPL'] || []),
      exclusions, agents, attackPaths,
    });
  }
  return skills;
}

function _parseMdRunbooks(text) {
  const result = {};
  // Normalise Windows (CRLF) and old Mac (CR) line endings to LF
  const norm = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  for (const sec of norm.split(/\n---\n/)) {
    const lines = sec.trim().split('\n');
    const headLine = lines.find(l => /^## T\d{4}/.test(l));
    if (!headLine) continue;
    const hm = headLine.match(/^## (T\d{4}(?:\.\d{3})?)\s*[—–-]+\s*(.+)/);
    if (!hm) continue;
    const ttpId = hm[1];
    const name  = hm[2].trim();

    const meta = {};
    for (const ln of lines) {
      if (!ln.startsWith('> ')) continue;
      for (const part of ln.slice(2).split(' | ')) {
        const i = part.indexOf(':');
        if (i < 0) continue;
        meta[part.slice(0, i).trim()] = part.slice(i + 1).trim();
      }
    }

    const summaryLines = [];
    let pastHead = false;
    for (const ln of lines) {
      if (ln.startsWith('## ')) { pastHead = true; continue; }
      if (!pastHead || ln.startsWith('> ')) continue;
      if (ln.startsWith('### ')) break;
      if (ln.trim()) summaryLines.push(ln.trim());
    }

    const smap = _extractMdSections(lines);

    // Evidence: "- sev | text" — backtick inline code → <code>
    const evidence = (smap['Evidence'] || []).filter(l => l.startsWith('- ')).map(l => {
      const rest    = l.slice(2);
      const pipeIdx = rest.indexOf(' | ');
      const sev     = pipeIdx >= 0 ? rest.slice(0, pipeIdx).trim() : 'info';
      let   txt     = pipeIdx >= 0 ? rest.slice(pipeIdx + 3) : rest;
      txt = txt.replace(/`([^`]+)`/g, '<code>$1</code>');
      return { sev, text: txt };
    });

    // Queries: #### Label\n```spl\n...\n```
    const queries = [];
    const qLines = smap['Queries'] || [];
    let curLabel = null, inCode = false, codeLines = [];
    for (const ln of qLines) {
      if (ln.startsWith('#### ')) {
        if (curLabel !== null && codeLines.length) queries.push({ label: curLabel, spl: codeLines.join('\n') });
        curLabel = ln.slice(5).trim(); inCode = false; codeLines = [];
      } else if (ln.startsWith('```')) {
        inCode = !inCode;
      } else if (inCode) {
        codeLines.push(ln);
      }
    }
    if (curLabel !== null && codeLines.length) queries.push({ label: curLabel, spl: codeLines.join('\n') });

    // Hunt Notes: "- hunt | date | analyst | text..."
    const huntNotes = (smap['Hunt Notes'] || []).filter(l => l.startsWith('- ')).map(l => {
      const p = l.slice(2).split(' | ');
      return { hunt: p[0]?.trim()||'', date: p[1]?.trim()||'', analyst: p[2]?.trim()||'', text: p.slice(3).join(' | ').trim() };
    });

    const fps = (smap['False Positives'] || []).filter(l => l.startsWith('- ')).map(l => l.slice(2));

    result[ttpId] = { name, tactic: meta['tactic'] || '', summary: summaryLines.join(' '), evidence, queries, huntNotes, fps };
  }
  return result;
}

function _parseMdEnvironment(text) {
  const norm = text.replace(/\r\n/g,'\n').replace(/\r/g,'\n');
  const env = { domain:{}, stats:[], anomalies:[], segments:[], assets:[], accounts:[], topology:'', infrastructure:[] };
  const cj  = { assets:[], accounts:[] };

  for (const sec of norm.split(/\n---\n/)) {
    const lines = sec.trim().split('\n');
    const head  = lines.find(l => l.startsWith('## '));
    if (!head) continue;

    // Aggregate all > meta lines into one flat key-value map
    const meta = {};
    for (const ln of lines) {
      if (!ln.startsWith('> ')) continue;
      for (const part of ln.slice(2).split(' | ')) {
        const i = part.indexOf(':'); if (i < 0) continue;
        meta[part.slice(0,i).trim()] = part.slice(i+1).trim();
      }
    }

    const smap = _extractMdSections(lines);

    // Body text: lines after ## heading and > meta lines, before first ###
    const body = (() => {
      let pastH = false; const b = [];
      for (const ln of lines) {
        if (ln.startsWith('## ')) { pastH = true; continue; }
        if (!pastH || ln.startsWith('> ')) continue;
        if (ln.startsWith('### ')) break;
        if (ln.trim()) b.push(ln.trim());
      }
      return b.join(' ');
    })();

    if (head === '## Domain') {
      env.domain = {
        name: meta['name']||'', netbios: meta['netbios']||'', forest: meta['forest']||'',
        functionalLevel: meta['level']||'', adfsUrl: meta['adfs']||'', adSync: meta['ad-sync']||'',
        dcs:    (smap['Domain Controllers']||[]).filter(l=>l.startsWith('- ')).map(l=>l.slice(2)),
        sites:  (smap['Sites']||[]).filter(l=>l.startsWith('- ')).map(l=>l.slice(2)),
        trusts: (smap['Trusts']||[]).filter(l=>l.startsWith('- ')).map(l=>l.slice(2)),
      };

    } else if (head === '## Stats') {
      // Each > line is a separate stat item
      for (const ln of lines) {
        if (!ln.startsWith('> ')) continue;
        const m = {};
        for (const part of ln.slice(2).split(' | ')) {
          const i = part.indexOf(':'); if (i<0) continue;
          m[part.slice(0,i).trim()] = part.slice(i+1).trim();
        }
        if (m['label']) env.stats.push({ label:m['label'], value:m['value']||'', note:m['note']||'', color:m['color']||'blue' });
      }

    } else if (head === '## Anomalies') {
      env.anomalies = lines.filter(l=>l.startsWith('- ')).map(l => {
        const r = l.slice(2), pi = r.indexOf(' | ');
        return { sev: pi>=0 ? r.slice(0,pi).trim() : 'info', text: pi>=0 ? r.slice(pi+3) : r };
      });

    } else if (head.startsWith('## Segment: ')) {
      env.segments.push({
        id: meta['id']||'', name: head.slice('## Segment: '.length).trim(),
        icon: meta['icon']||'', sensitivity: meta['sensitivity']||'',
        cidr: meta['cidr']||'', vlan: parseInt(meta['vlan'])||0,
        gateway: meta['gateway']||'', hosts: parseInt(meta['hosts'])||0,
        desc: body,
        tags: (smap['Tags']||[]).filter(l=>l.startsWith('- ')).map(l=>l.slice(2)),
        acls: (smap['ACLs']||[]).filter(l=>l.startsWith('- ')).map(l=>l.slice(2)),
      });

    } else if (head.startsWith('## Asset: ')) {
      env.assets.push({
        hostname: head.slice('## Asset: '.length).trim(),
        ip: meta['ip']||'', role: meta['role']||'', os: meta['os']||'',
        segment: meta['segment']||'', owner: meta['owner']||'',
        lastSeen: meta['last-seen']||'', status: meta['status']||'online',
        details: {
          fqdn: meta['fqdn']||'', mac: meta['mac']||'', cpu: meta['cpu']||'',
          ram: meta['ram']||'', disk: meta['disk']||'', uptime: meta['uptime']||'',
          sysmon: meta['sysmon']||'', edr: meta['edr']||'', patch: meta['patch']||'',
          criticality: meta['criticality']||'', notes: body,
        },
      });

    } else if (head.startsWith('## Account: ')) {
      let normal = '', anomaly = null;
      for (const ln of lines) {
        if (ln.startsWith('Normal: '))  normal  = ln.slice(8).trim();
        if (ln.startsWith('Anomaly: ')) anomaly = ln.slice(9).trim();
      }
      env.accounts.push({
        name: head.slice('## Account: '.length).trim(),
        type: meta['type']||'', status: meta['status']||'active',
        groups: meta['groups'] ? meta['groups'].split(',').map(g=>g.trim()) : [],
        normal, anomaly,
        lastLogon: meta['last-logon']||'', pwdAge: meta['pwd-age']||'', mfa: meta['mfa']||'',
      });

    } else if (head === '## Topology') {
      env.topology = _extractCodeBlock(lines) || body;

    } else if (head === '## Infrastructure') {
      env.infrastructure = lines.filter(l=>l.startsWith('- ')).map(l => {
        const p = l.slice(2).split(' | ');
        return { icon:p[0]?.trim()||'', name:p[1]?.trim()||'', role:p[2]?.trim()||'', ip:p[3]?.trim()||'', crit:p[4]?.trim()||'' };
      });

    } else if (head.startsWith('## Crown Jewel: ')) {
      let role='', blast='';
      for (const ln of lines) {
        if (ln.startsWith('Role: '))  role  = ln.slice(6).trim();
        if (ln.startsWith('Blast: ')) blast = ln.slice(7).trim();
      }
      cj.assets.push({
        tier: parseInt(meta['tier'])||0, icon: meta['icon']||'',
        name: head.slice('## Crown Jewel: '.length).trim(),
        role, ip: meta['ip']||'', segment: meta['segment']||'',
        blast, exposure: meta['exposure']||'', ttp: meta['ttp']||null,
      });

    } else if (head.startsWith('## Crown Account: ')) {
      let desc='';
      for (const ln of lines) {
        if (ln.startsWith('Desc: ')) desc = ln.slice(6).trim();
      }
      cj.accounts.push({
        icon: meta['icon']||'', name: head.slice('## Crown Account: '.length).trim(),
        type: meta['type']||'', group: meta['group']||'',
        desc, exposure: meta['exposure']||'', ttp: meta['ttp']||null,
      });
    }
  }
  return { env, cj };
}

// ── KB init (async — fetches .md files once) ─────────────────────────────

async function initKbTab() {
  // Seed the per-tab description for the default active tab
  const desc = document.getElementById('kb-tc-desc');
  if (desc) desc.innerHTML = _tcDesc[activeTradecraftTab] || '';

  // Render immediately using inline JS data (always available, works on file://)
  renderKbSkillList(activeKbSkCat);
  renderKbDraftList();
  renderKbRunbooks();
  renderKbEnvPane();
  renderKbIocPane();

  // Fetch .md files in the background as an optional enhancement.
  // If successful, parsed data overrides the inline JS objects and re-renders.
  // If fetch fails (file:// protocol, CORS, etc.) the inline data is used as-is.
  if (!_kbMdLoaded) {
    _kbMdLoaded = true; // prevent re-entrancy
    // Each file fetched independently — one failure does not block the others.
    const tryFetch = url => fetch(url).then(r => r.ok ? r.text() : null).catch(() => null);
    const [skillsMd, runbooksMd, envMd] = await Promise.all([
      tryFetch('kb/skills.md'), tryFetch('kb/runbooks.md'), tryFetch('kb/environment.md'),
    ]);

    if (skillsMd) {
      _kbMdCache.skills = skillsMd;
      const parsedSkills = _parseMdSkills(skillsMd);
      skillsData.splice(0, skillsData.length, ...parsedSkills);
      renderKbSkillList(activeKbSkCat);
      renderKbDraftList();
    }
    if (runbooksMd) {
      _kbMdCache.runbooks = runbooksMd;
      const parsedRunbooks = _parseMdRunbooks(runbooksMd);
      Object.keys(runbookData).forEach(k => delete runbookData[k]);
      Object.assign(runbookData, parsedRunbooks);
      renderKbRunbooks();
    }
    if (envMd) {
      _kbMdCache.env = envMd;
      const { env: parsedEnv, cj: parsedCj } = _parseMdEnvironment(envMd);
      Object.keys(envData).forEach(k => delete envData[k]);
      Object.assign(envData, parsedEnv);
      Object.keys(crownJewels).forEach(k => delete crownJewels[k]);
      Object.assign(crownJewels, parsedCj);
      renderKbEnvPane();
    }
  }
}

// ── KB sub-tab switch ──
function switchKbTab(tab) {
  activeKbTab = tab;
  // If searching, exit search mode first
  const sr = document.getElementById('kb-search-results');
  const sb = document.getElementById('kb-subtab-bar');
  if (sr) sr.classList.remove('active');
  if (sb) sb.style.display = '';
  ['tradecraft','env','ioc'].forEach(k => {
    const stab = document.getElementById('kb-stab-' + k);
    const pane = document.getElementById('kb-pane-' + k);
    if (stab) stab.classList.toggle('on', k === tab);
    if (pane) pane.classList.toggle('on', k === tab);
  });
  if (tab === 'tradecraft') { renderKbSkillList(activeKbSkCat); renderKbRunbooks(); }
  if (tab === 'env') renderKbEnvPane();
  if (tab === 'ioc') renderKbIocPane();
}

// ── Global KB search ──
let kbSearchQuery = '';

function kbSearch(val) {
  kbSearchQuery = val.trim().toLowerCase();
  const clearBtn = document.getElementById('kb-search-clear');
  if (clearBtn) clearBtn.style.display = kbSearchQuery ? '' : 'none';
  const sr = document.getElementById('kb-search-results');
  const sb = document.getElementById('kb-subtab-bar');
  if (!kbSearchQuery) {
    if (sr) sr.classList.remove('active');
    if (sb) sb.style.display = '';
    // restore panes
    ['tradecraft','env','ioc'].forEach(k => {
      const pane = document.getElementById('kb-pane-' + k);
      if (pane) pane.classList.toggle('on', k === activeKbTab);
    });
    return;
  }
  // hide normal panes + subtab bar, show results
  if (sb) sb.style.display = 'none';
  ['tradecraft','env','ioc'].forEach(k => {
    const pane = document.getElementById('kb-pane-' + k);
    if (pane) pane.classList.remove('on');
  });
  if (sr) {
    sr.classList.add('active');
    sr.innerHTML = _kbSearchRender(kbSearchQuery);
  }
}

function clearKbSearch() {
  kbSearchQuery = '';
  const input = document.getElementById('kb-global-search');
  if (input) input.value = '';
  kbSearch('');
  switchKbTab(activeKbTab);
}

function _kbSearchRender(q) {
  const skills   = (typeof skillsData   !== 'undefined' ? skillsData   : [])
    .filter(s => s.name.toLowerCase().includes(q) || s.summary.toLowerCase().includes(q) || s.ttps.some(t => t.toLowerCase().includes(q)));
  const runbooks = Object.entries(typeof runbookData !== 'undefined' ? runbookData : {})
    .filter(([id, r]) => id.toLowerCase().includes(q) || r.name.toLowerCase().includes(q) || (r.summary||'').toLowerCase().includes(q));
  const iocs     = (typeof iocRepository !== 'undefined' ? iocRepository : [])
    .filter(r => r.value.toLowerCase().includes(q) || r.hunt.toLowerCase().includes(q) || (r.ttp||'').toLowerCase().includes(q) || (r.note||'').toLowerCase().includes(q));

  const total = skills.length + runbooks.length + iocs.length;
  if (!total) return `<div class="kb-search-empty">No results for "<b>${q}</b>"</div>`;

  let html = `<div class="kb-search-meta">${total} result${total===1?'':'s'} for "<b>${q}</b>"</div>`;

  if (skills.length) {
    html += `<div class="kb-search-group-head">🎯 Skills <span>${skills.length}</span></div>`;
    html += skills.map(s => {
      const ttps = s.ttps.slice(0,3).join(', ') + (s.ttps.length > 3 ? '…' : '');
      const dest = s.skillType === 'domain' ? 'domain' : 'tactic';
      return `<div class="kb-search-row" onclick="clearKbSearch();switchKbTab('tradecraft');switchTradecraftTab('${dest}');setTimeout(()=>{const c=document.querySelector('[data-skillid=&quot;${s.id}&quot;]');if(c){c.classList.add('open');c.scrollIntoView({behavior:'smooth',block:'start'});}},120)">
        <span class="kb-sr-badge kb-sr-skill">${s.skillType==='domain'?'Domain':'Tactic'}</span>
        <span class="kb-sr-name">${s.name}</span>
        <span class="kb-sr-meta">${ttps}</span>
        <span class="kb-sr-action">Open →</span>
      </div>`;
    }).join('');
  }

  if (runbooks.length) {
    html += `<div class="kb-search-group-head">📖 Runbooks <span>${runbooks.length}</span></div>`;
    html += runbooks.map(([id, r]) => `<div class="kb-search-row" onclick="clearKbSearch();jumpToRunbook('${id}',null)">
        <span class="kb-sr-badge kb-sr-runbook">${r.tactic||'ATT&CK'}</span>
        <span class="kb-sr-name"><b>${id}</b> — ${r.name}</span>
        <span class="kb-sr-meta">${(r.summary||'').slice(0,70)}…</span>
        <span class="kb-sr-action">Open →</span>
      </div>`).join('');
  }

  if (iocs.length) {
    html += `<div class="kb-search-group-head">🔍 IOCs <span>${iocs.length}</span></div>`;
    html += iocs.map(r => `<div class="kb-search-row" onclick="clearKbSearch();switchKbTab('ioc')">
        <span class="kb-sr-badge kb-sr-ioc">${r.type}</span>
        <span class="kb-sr-name">${r.value}</span>
        <span class="kb-sr-meta">${r.hunt} · ${r.ttp||'—'}</span>
        <span class="kb-sr-action">Show →</span>
      </div>`).join('');
  }
  return html;
}

// ── Cross-link navigation ──
function jumpToRunbook(ttpId, evt) {
  if (evt && evt.stopPropagation) evt.stopPropagation();
  switchKbTab('tradecraft');
  switchTradecraftTab('runbooks');
  setTimeout(() => {
    const card = document.getElementById('rbkb-' + ttpId);
    if (card) { card.classList.add('open'); card.scrollIntoView({ behavior:'smooth', block:'start' }); }
  }, 80);
}

function jumpToSkill(skillId, evt) {
  if (evt && evt.stopPropagation) evt.stopPropagation();
  const sk = typeof skillsData !== 'undefined' ? skillsData.find(s => s.id === skillId) : null;
  switchKbTab('tradecraft');
  switchTradecraftTab(sk?.skillType === 'domain' ? 'domain' : 'tactic');
  setTimeout(() => {
    const card = document.querySelector(`[data-skillid="${skillId}"]`);
    if (card) { card.classList.add('open'); card.scrollIntoView({ behavior:'smooth', block:'start' }); }
  }, 100);
}

// ── IOC → hunt navigation ──
function goToHuntKeep(huntId) {
  openHunt(huntId);
  setTimeout(() => goSubTab('keep', document.getElementById('subtab-keep')), 60);
}

// ── Tradecraft inner tab switch ──
const _tcDesc = {
  tactic:   '<span class="ib-icon">🎯</span><span><b>Tactic Skills</b> are generic ATT&CK technique patterns that apply across any organisation. They encode hunter intuition as SPL templates, detection logic, and FP exclusion lists — use these as a starting point when hunting a technique you haven\'t seen in this environment before.</span>',
  domain:   '<span class="ib-icon">🏢</span><span><b>Domain Skills</b> are tuned to <em>this</em> environment. They encode your team\'s knowledge of this network\'s topology, tooling, service accounts, and known-good baselines — the exclusions, thresholds, and naming conventions that cut false positives in your specific org.</span>',
  runbooks: '<span class="ib-icon">📖</span><span><b>TTP Runbooks</b> are technique-level hunt guides, one per ATT&CK technique. Each covers adversary evidence indicators, hunting SPL, prior hunt notes from this environment, and known false positives. The Hypothesis Agent pulls these via <code style="font-size:10px;">get_runbook(ttp_id)</code> when generating hypotheses.</span>',
  author:   '<span class="ib-icon">✏️</span><span>Propose a new skill or an edit to an existing one. Fill in the form on the left — include behavioural patterns, an SPL template, and known FP exclusions. Submissions go into the draft queue for senior hunter review before being merged into the live knowledge base.</span>',
};

function switchTradecraftTab(tab) {
  activeTradecraftTab = tab;
  ['tactic','domain','runbooks','author'].forEach(k => {
    const stab = document.getElementById('kb-tc-stab-' + k);
    if (stab) stab.classList.toggle('on', k === tab);
  });
  const isSkills = tab === 'tactic' || tab === 'domain';
  const catBar  = document.getElementById('kb-tc-cat-bar');
  const skillsP = document.getElementById('kb-tc-pane-skills');
  const rbP     = document.getElementById('kb-tc-pane-runbooks');
  const authP   = document.getElementById('kb-tc-pane-author');
  const desc    = document.getElementById('kb-tc-desc');
  if (catBar)  catBar.style.display  = isSkills          ? '' : 'none';
  if (skillsP) skillsP.style.display = isSkills          ? '' : 'none';
  if (rbP)     rbP.style.display     = tab === 'runbooks' ? '' : 'none';
  if (authP)   authP.style.display   = tab === 'author'   ? '' : 'none';
  if (desc)    desc.innerHTML        = _tcDesc[tab] || '';
  if (isSkills) {
    // Reset filter to 'all' when switching between tactic/domain — previous cat may not exist in new tab.
    activeKbSkCat = 'all';
    renderKbSkillList('all');
  }
  if (tab === 'runbooks') renderKbRunbooks();
  if (tab === 'author')   renderKbDraftList();
}

// ── KB Markdown Source Viewer ─────────────────────────────────────────────

// Generate skills.md text from the live skillsData array (fallback when fetch unavailable)
function _genSkillsMd() {
  const lines = [
    '# Tradecraft Skills Repository',
    '',
    'Analyst-authored hunting skills. Each skill is a reusable detection pattern with SPL, exclusions, and downstream attack-path context.',
    '',
    '`skillType` values:',
    '- `tactic` — Generic MITRE ATT&CK technique knowledge, applies cross-org',
    '- `domain` — Environment/org-specific: tuned to THIS network\'s topology, tooling, naming conventions, and known-good baselines',
    '',
    'To add a new skill, copy any section below, paste it before the last `---`, and fill in the fields.',
    '',
  ];
  skillsData.forEach(sk => {
    lines.push('---', '');
    lines.push(`## ${sk.id} — ${sk.name}`, '');
    const ttps = Array.isArray(sk.ttps) ? sk.ttps.join(', ') : sk.ttps;
    const agents = Array.isArray(sk.agents) ? sk.agents.join(', ') : (sk.agents || '');
    lines.push(`> type: ${sk.skillType} | category: ${sk.cat} | category-label: ${sk.catLabel} | ttps: ${ttps}`);
    lines.push(`> author: ${sk.author} | version: ${sk.version} | updated: ${sk.updated} | agents: ${agents}`, '');
    lines.push(sk.summary || '', '');
    if (sk.patterns && sk.patterns.length) {
      lines.push('### Patterns');
      sk.patterns.forEach(p => lines.push('- ' + p));
      lines.push('');
    }
    if (sk.spl) {
      lines.push('### SPL');
      lines.push('```spl');
      lines.push(sk.spl);
      lines.push('```', '');
    }
    if (sk.exclusions && sk.exclusions.length) {
      lines.push('### Exclusions');
      sk.exclusions.forEach(e => lines.push('- ' + e));
      lines.push('');
    }
    if (sk.attackPaths && sk.attackPaths.length) {
      lines.push('### Attack Paths');
      sk.attackPaths.forEach(a => lines.push(`- ${a.ttp} | ${a.name} | ${a.likelihood} | ${a.desc}`));
      lines.push('');
    }
  });
  lines.push('---');
  return lines.join('\n');
}

// Generate runbooks.md text from the live runbookData object (fallback when fetch unavailable)
function _genRunbooksMd() {
  const sevLabel = { crit:'crit', high:'high', info:'info' };
  const lines = [
    '# TTP Runbooks',
    '',
    'Per-technique hunt guides — one entry per MITRE ATT&CK technique.',
    '',
    'Evidence severity levels: `crit` · `high` · `info`',
    '',
  ];
  Object.entries(runbookData).forEach(([id, rb]) => {
    lines.push('---', '');
    lines.push(`## ${id} — ${rb.name}`, '');
    lines.push(`> tactic: ${rb.tactic}`, '');
    lines.push(rb.summary || '', '');
    if (rb.evidence && rb.evidence.length) {
      lines.push('### Evidence');
      rb.evidence.forEach(ev => {
        // Strip HTML tags for display in raw markdown
        const txt = ev.text.replace(/<code>(.*?)<\/code>/g, '`$1`').replace(/<[^>]+>/g, '');
        lines.push(`- ${ev.sev} | ${txt}`);
      });
      lines.push('');
    }
    if (rb.queries && rb.queries.length) {
      lines.push('### Queries', '');
      rb.queries.forEach(q => {
        lines.push(`#### ${q.label}`);
        lines.push('```spl');
        lines.push(q.spl);
        lines.push('```', '');
      });
    }
    if (rb.huntNotes && rb.huntNotes.length) {
      lines.push('### Hunt Notes');
      rb.huntNotes.forEach(n => lines.push(`- ${n.hunt} | ${n.date} | ${n.analyst} | ${n.text}`));
      lines.push('');
    }
    if (rb.fps && rb.fps.length) {
      lines.push('### False Positives');
      rb.fps.forEach(f => lines.push('- ' + f));
      lines.push('');
    }
  });
  lines.push('---');
  return lines.join('\n');
}

// Show the markdown modal with arbitrary filename + content (single-item mode, no tabs)
function _showMdModal(filename, content) {
  const modal = document.querySelector('.kb-md-modal');
  const pre   = document.getElementById('kb-md-content');
  const name  = document.getElementById('kb-md-filename');
  if (modal) modal.classList.add('kb-md-single');
  if (name)  name.textContent = filename;
  if (pre)   pre.textContent  = content;
  document.getElementById('kb-md-overlay').classList.add('open');
}

// Generate markdown for a single skill (uses cached .md section if available)
function _genOneSkillMd(sk) {
  if (_kbMdCache.skills) {
    const norm = _kbMdCache.skills.replace(/\r\n/g,'\n').replace(/\r/g,'\n');
    const parts = norm.split(/\n---\n/);
    const section = parts.find(p => { const m = p.match(/^## (SK-\d+)/m); return m && m[1] === sk.id; });
    if (section) return section.trim();
  }
  const ttps   = Array.isArray(sk.ttps)   ? sk.ttps.join(', ')   : sk.ttps;
  const agents = Array.isArray(sk.agents) ? sk.agents.join(', ') : (sk.agents || '');
  const lines  = [
    `## ${sk.id} — ${sk.name}`, '',
    `> type: ${sk.skillType} | category: ${sk.cat} | category-label: ${sk.catLabel} | ttps: ${ttps}`,
    `> author: ${sk.author} | version: ${sk.version} | updated: ${sk.updated} | agents: ${agents}`, '',
    sk.summary || '', '',
  ];
  if (sk.patterns?.length) { lines.push('### Patterns'); sk.patterns.forEach(p => lines.push('- '+p)); lines.push(''); }
  if (sk.spl)               { lines.push('### SPL','```spl',sk.spl,'```',''); }
  if (sk.exclusions?.length){ lines.push('### Exclusions'); sk.exclusions.forEach(e => lines.push('- '+e)); lines.push(''); }
  if (sk.attackPaths?.length){ lines.push('### Attack Paths'); sk.attackPaths.forEach(a => lines.push(`- ${a.ttp} | ${a.name} | ${a.likelihood} | ${a.desc}`)); lines.push(''); }
  return lines.join('\n');
}

// Open view-source modal for a single skill card
function openSkillSource(id, evt) {
  if (evt) evt.stopPropagation();
  const sk = skillsData.find(s => s.id === id);
  if (!sk) return;
  _showMdModal(`kb/skills.md  ·  ${id}`, _genOneSkillMd(sk));
}

// Generate markdown for a single runbook (uses cached .md section if available)
function _genOneRunbookMd(ttpId, rb) {
  if (_kbMdCache.runbooks) {
    const norm = _kbMdCache.runbooks.replace(/\r\n/g,'\n').replace(/\r/g,'\n');
    const parts = norm.split(/\n---\n/);
    const section = parts.find(p => { const m = p.match(/^## (T\d{4}(?:\.\d{3})?)/m); return m && m[1] === ttpId; });
    if (section) return section.trim();
  }
  const lines = [
    `## ${ttpId} — ${rb.name}`, '',
    `> tactic: ${rb.tactic}`, '',
    rb.summary || '', '',
  ];
  if (rb.evidence?.length) {
    lines.push('### Evidence');
    rb.evidence.forEach(ev => {
      const txt = ev.text.replace(/<code>(.*?)<\/code>/g,'`$1`').replace(/<[^>]+>/g,'');
      lines.push(`- ${ev.sev} | ${txt}`);
    });
    lines.push('');
  }
  if (rb.queries?.length) {
    lines.push('### Queries','');
    rb.queries.forEach(q => { lines.push(`#### ${q.label}`,'```spl',q.spl,'```',''); });
  }
  if (rb.huntNotes?.length) {
    lines.push('### Hunt Notes');
    rb.huntNotes.forEach(n => lines.push(`- ${n.hunt} | ${n.date} | ${n.analyst} | ${n.text}`));
    lines.push('');
  }
  if (rb.fps?.length) {
    lines.push('### False Positives');
    rb.fps.forEach(f => lines.push('- '+f));
    lines.push('');
  }
  return lines.join('\n');
}

// Open view-source modal for a single runbook card
function openRunbookSource(ttpId, evt) {
  if (evt) evt.stopPropagation();
  const rb = runbookData[ttpId];
  if (!rb) return;
  _showMdModal(`kb/runbooks.md  ·  ${ttpId}`, _genOneRunbookMd(ttpId, rb));
}

function openKbMarkdown() {
  // Full-file view — show both tabs, clear single-item mode
  const modal = document.querySelector('.kb-md-modal');
  if (modal) modal.classList.remove('kb-md-single');
  const which = (activeTradecraftTab === 'runbooks') ? 'runbooks' : 'skills';
  _setKbMdTab(which);
  document.getElementById('kb-md-overlay').classList.add('open');
}

function closeKbMarkdown() {
  document.getElementById('kb-md-overlay').classList.remove('open');
  const modal = document.querySelector('.kb-md-modal');
  if (modal) modal.classList.remove('kb-md-single');
}

// Reconstructs environment.md markdown from the in-memory envData / crownJewels objects.
// Used as a fallback when the server cannot serve .md files directly.
function _buildEnvMd() {
  const d = envData, cj = crownJewels;
  const L = [];
  const sep = () => { L.push('', '---', ''); };

  L.push('# Environment Context', '', '---', '');

  // Domain
  const dom = d.domain || {};
  L.push('## Domain', '');
  L.push(`> name: ${dom.name||''} | netbios: ${dom.netbios||''} | forest: ${dom.forest||''} | level: ${dom.functionalLevel||''}`);
  L.push(`> adfs: ${dom.adfsUrl||''} | ad-sync: ${dom.adSync||''}`);
  if (dom.dcs?.length)    { L.push('', '### Domain Controllers'); dom.dcs.forEach(s   => L.push(`- ${s}`)); }
  if (dom.sites?.length)  { L.push('', '### Sites');               dom.sites.forEach(s => L.push(`- ${s}`)); }
  if (dom.trusts?.length) { L.push('', '### Trusts');              dom.trusts.forEach(s => L.push(`- ${s}`)); }
  sep();

  // Stats
  if (d.stats?.length) {
    L.push('## Stats', '');
    d.stats.forEach(s => L.push(`> label: ${s.label} | value: ${s.value} | note: ${s.note} | color: ${s.color}`));
    sep();
  }

  // Anomalies
  if (d.anomalies?.length) {
    L.push('## Anomalies', '');
    d.anomalies.forEach(a => L.push(`- ${a.sev} | ${a.text}`));
    sep();
  }

  // Segments
  (d.segments||[]).forEach(s => {
    L.push(`## Segment: ${s.name}`, '');
    L.push(`> id: ${s.id} | sensitivity: ${s.sensitivity} | cidr: ${s.cidr} | vlan: ${s.vlan} | gateway: ${s.gateway} | hosts: ${s.hosts} | icon: ${s.icon}`);
    if (s.desc) L.push('', s.desc);
    if (s.tags?.length) { L.push('', '### Tags'); s.tags.forEach(t => L.push(`- ${t}`)); }
    if (s.acls?.length) { L.push('', '### ACLs'); s.acls.forEach(a => L.push(`- ${a}`)); }
    sep();
  });

  // Assets
  (d.assets||[]).forEach(a => {
    const det = a.details || {};
    L.push(`## Asset: ${a.hostname}`, '');
    L.push(`> ip: ${a.ip} | role: ${a.role} | os: ${a.os} | segment: ${a.segment} | owner: ${a.owner} | status: ${a.status} | last-seen: ${a.lastSeen||''}`);
    if (det.fqdn) L.push(`> fqdn: ${det.fqdn} | mac: ${det.mac||''} | cpu: ${det.cpu||''} | ram: ${det.ram||''} | disk: ${det.disk||''}`);
    L.push(`> uptime: ${det.uptime||''} | sysmon: ${det.sysmon||''} | edr: ${det.edr||''} | patch: ${det.patch||''} | criticality: ${det.criticality||''}`);
    if (det.notes) L.push('', det.notes);
    sep();
  });

  // Accounts
  (d.accounts||[]).forEach(a => {
    L.push(`## Account: ${a.name}`, '');
    L.push(`> type: ${a.type} | status: ${a.status} | last-logon: ${a.lastLogon||''} | pwd-age: ${a.pwdAge||''} | mfa: ${a.mfa||''}`);
    if (a.groups?.length) L.push(`> groups: ${a.groups.join(', ')}`);
    if (a.normal)  L.push('', `Normal: ${a.normal}`);
    if (a.anomaly) L.push(`Anomaly: ${a.anomaly}`);
    sep();
  });

  // Topology
  if (d.topology) {
    L.push('## Topology', '', '```');
    L.push(d.topology);
    L.push('```');
    sep();
  }

  // Infrastructure
  if (d.infrastructure?.length) {
    L.push('## Infrastructure', '');
    d.infrastructure.forEach(i => L.push(`- ${i.icon} | ${i.name} | ${i.role} | ${i.ip} | ${i.crit}`));
    sep();
  }

  // Crown Jewels
  (cj.assets||[]).forEach(a => {
    L.push(`## Crown Jewel: ${a.name}`, '');
    const ttpPart = a.ttp ? ` | ttp: ${a.ttp}` : '';
    L.push(`> tier: ${a.tier} | ip: ${a.ip} | segment: ${a.segment} | exposure: ${a.exposure}${ttpPart} | icon: ${a.icon}`);
    L.push('', `Role: ${a.role}`, `Blast: ${a.blast}`);
    sep();
  });

  // Crown Accounts
  (cj.accounts||[]).forEach(a => {
    L.push(`## Crown Account: ${a.name}`, '');
    const ttpPart = a.ttp ? ` | ttp: ${a.ttp}` : '';
    L.push(`> type: ${a.type} | group: ${a.group} | exposure: ${a.exposure}${ttpPart} | icon: ${a.icon}`);
    L.push('', `Desc: ${a.desc}`);
    sep();
  });

  return L.join('\n');
}

async function openEnvSource() {
  if (!_kbMdCache.env) {
    // Try to fetch the actual file first; fall back to reconstructing from in-memory data.
    const txt = await fetch('kb/environment.md').then(r => r.ok ? r.text() : null).catch(() => null);
    _kbMdCache.env = txt || _buildEnvMd();
  }
  _showMdModal('kb/environment.md', _kbMdCache.env);
}

function switchKbMdTab(which) {
  _setKbMdTab(which);
}

function _setKbMdTab(which) {
  _activeKbMdTab = which;
  ['skills','runbooks'].forEach(k => {
    const t = document.getElementById('kb-md-tab-' + k);
    if (t) t.classList.toggle('on', k === which);
  });
  const pre  = document.getElementById('kb-md-content');
  const name = document.getElementById('kb-md-filename');
  const fname = which === 'runbooks' ? 'kb/runbooks.md' : 'kb/skills.md';
  if (name) name.textContent = fname;
  // Use fetched .md content if available, otherwise generate from inline JS data
  const content = _kbMdCache[which] ||
    (which === 'skills' ? _genSkillsMd() : _genRunbooksMd());
  if (pre) pre.textContent = content;
}

// ── KB Skills — filter ──
// Ordered display config for categories (controls pill order + display names).
const _catMeta = [
  { id:'lateral-movement',    label:'Lateral Movement'    },
  { id:'credential-access',   label:'Credential Access'   },
  { id:'execution',           label:'Execution'           },
  { id:'persistence',         label:'Persistence'         },
  { id:'defense-evasion',     label:'Defense Evasion'     },
  { id:'privilege-escalation',label:'Privilege Escalation'},
  { id:'c2',                  label:'Command & Control'   },
  { id:'discovery',           label:'Discovery'           },
  { id:'impact',              label:'Impact'              },
];

// Rebuild the category filter bar to match the current tab's skills + correct counts.
function renderKbCatBar() {
  const bar = document.getElementById('kb-tc-cat-bar');
  if (!bar) return;
  const type = activeTradecraftTab === 'domain' ? 'domain' : 'tactic';
  const relevant = skillsData.filter(s => s.skillType === type);
  const counts = {};
  relevant.forEach(s => { counts[s.cat] = (counts[s.cat] || 0) + 1; });

  const pills = [{ id:'all', label:'All', n: relevant.length }];
  _catMeta.forEach(m => { if (counts[m.id]) pills.push({ id:m.id, label:m.label, n:counts[m.id] }); });

  bar.innerHTML = pills.map(p => {
    const on = activeKbSkCat === p.id ? ' sk-cat-on' : '';
    return `<span class="sk-cat-pill${on}" data-kbcat="${p.id}" onclick="filterKbSkills('${p.id}',this)">${p.label} <span style="opacity:.6;">${p.n}</span></span>`;
  }).join('');
}

function filterKbSkills(cat, el) {
  activeKbSkCat = cat;
  renderKbSkillList(cat);
}

function renderKbSkillList(cat) {
  const el = document.getElementById('kb-sk-list');
  if (!el || typeof skillsData === 'undefined') return;
  // Rebuild the filter bar so counts stay in sync.
  renderKbCatBar();
  let filtered = cat === 'all' ? skillsData : skillsData.filter(s => s.cat === cat);
  // Filter to the active inner tab type (tactic or domain)
  const type = activeTradecraftTab === 'domain' ? 'domain' : 'tactic';
  filtered = filtered.filter(s => s.skillType === type);
  if (!filtered.length) {
    el.innerHTML = '<div style="text-align:center;padding:30px 0;font-size:12px;color:var(--muted);">No skills match this filter.</div>';
    return;
  }
  el.innerHTML = filtered.map(s => renderSkillCard(s)).join('');
}


// ── TTP Runbooks ──
// MITRE ATT&CK kill-chain order for the runbook tactic filter bar
const _rbTacticOrder = [
  'Initial Access','Execution','Persistence','Privilege Escalation',
  'Defense Evasion','Credential Access','Discovery','Collection',
  'Lateral Movement','Command & Control','Exfiltration','Impact',
];

function renderKbRunbookTacticBar() {
  const bar = document.getElementById('rb-kb-tactic-filter');
  if (!bar) return;
  const all = Object.values(runbookData);
  const counts = {};
  all.forEach(r => {
    if (!r.tactic) return;
    _rbTacticOrder.forEach(t => { if (r.tactic.includes(t)) counts[t] = (counts[t] || 0) + 1; });
  });
  const pills = [{ id:'all', label:'All', n: all.length }];
  _rbTacticOrder.forEach(t => { if (counts[t]) pills.push({ id:t, label:t, n:counts[t] }); });
  bar.innerHTML = pills.map(p => {
    const on = activeKbRbTactic === p.id ? ' sk-cat-on' : '';
    return `<span class="sk-cat-pill${on}" data-rbtactic="${p.id}" onclick="filterKbRunbooks('${p.id}')">${p.label} <span style="opacity:.6;">${p.n}</span></span>`;
  }).join('');
}

function filterKbRunbooks(tactic) {
  activeKbRbTactic = tactic;
  renderKbRunbooks();
}

function renderKbRunbooks() {
  const el = document.getElementById('kb-rb-list');
  if (!el || typeof runbookData === 'undefined') return;
  renderKbRunbookTacticBar();
  const sevColor = { crit:'var(--red)', high:'var(--yellow)', info:'var(--blue)' };
  let entries = Object.entries(runbookData);
  if (activeKbRbTactic !== 'all') {
    entries = entries.filter(([, r]) => r.tactic && r.tactic.includes(activeKbRbTactic));
  }
  if (!entries.length) {
    el.innerHTML = '<div style="text-align:center;padding:30px 0;font-size:12px;color:var(--muted);">No runbooks match this tactic filter.</div>';
    return;
  }
  el.innerHTML = entries.map(([ttpId, r]) => {
    const evHTML = (r.evidence||[]).map(e =>
      `<div class="rb-kb-ev">
        <div class="rb-kb-ev-dot" style="background:${sevColor[e.sev]||'var(--sub)'}"></div>
        <div>${e.text.replace(/<code>/g,'<code style="font-size:10px;background:rgba(0,0,0,.3);padding:0 3px;border-radius:2px;color:#93c5fd;">').replace(/<\/code>/g,'</code>')}</div>
      </div>`
    ).join('');
    const qHTML = (r.queries||[]).map(q =>
      `<div class="rb-kb-query">
        <div class="rb-kb-qlabel">${q.label}</div>
        <div class="rb-kb-qspl">${q.spl.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
      </div>`
    ).join('');
    const noteHTML = (r.huntNotes||[]).map(n =>
      `<div class="rb-kb-hunt-note">
        <b>${n.hunt}</b> · ${n.analyst} · ${n.date}<br>
        <span style="margin-top:4px;display:block;">${n.text}</span>
      </div>`
    ).join('');
    const fpHTML = (r.fps||[]).map(f => `<div class="rb-kb-fp-item">${f}</div>`).join('');
    // Related skills that reference this TTP
    const relSkills = (typeof skillsData !== 'undefined' ? skillsData : []).filter(s => s.ttps.includes(ttpId));
    const relSkillsHTML = relSkills.length
      ? `<div class="rb-kb-section" style="margin-top:14px;">Related Skills</div>
         <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;">
           ${relSkills.map(s=>`<button class="kb-rb-skill-link" onclick="jumpToSkill('${s.id}',event)">${s.id} — ${s.name}</button>`).join('')}
         </div>`
      : '';
    return `<div class="rb-kb-card" id="rbkb-${ttpId}">
      <div class="rb-kb-head" onclick="this.closest('.rb-kb-card').classList.toggle('open')">
        <span class="rb-kb-ttp-id">${ttpId}</span>
        <span class="rb-kb-name">${r.name}</span>
        <span class="rb-kb-tactic">${r.tactic||''}</span>
        <span class="chip chip-indigo" style="font-size:9px;flex-shrink:0;">${(r.queries||[]).length} quer${(r.queries||[]).length===1?'y':'ies'}</span>
        <button class="kb-vs-btn" onclick="openRunbookSource('${ttpId}',event)" title="View raw Markdown for this runbook">📄 .md</button>
        <span class="rb-kb-chev">▾</span>
      </div>
      <div class="rb-kb-body">
        <p class="rb-kb-summary">${r.summary||''}</p>
        ${evHTML ? `<div class="rb-kb-section">Evidence Indicators</div>${evHTML}` : ''}
        ${qHTML  ? `<div class="rb-kb-section" style="margin-top:14px;">Hunting Queries</div>${qHTML}` : ''}
        ${noteHTML ? `<div class="rb-kb-section" style="margin-top:14px;">Prior Hunt Notes — This Environment</div>${noteHTML}` : ''}
        ${fpHTML  ? `<div class="rb-kb-section" style="margin-top:14px;">Known False Positives</div>${fpHTML}` : ''}
        ${relSkillsHTML}
      </div>
    </div>`;
  }).join('');
}

// ── KB Draft queue ──
function renderKbDraftList() {
  const el = document.getElementById('kb-draft-list');
  const ct = document.getElementById('kb-draft-count');
  if (!el) return;
  if (ct) ct.textContent = skillDrafts.length + ' pending';
  const catLabels = { 'credential-access':'Credential Access', 'lateral-movement':'Lateral Movement',
    'c2':'C2', 'execution':'Execution', 'persistence':'Persistence', 'defense-evasion':'Defense Evasion' };
  el.innerHTML = !skillDrafts.length
    ? '<div style="font-size:11px;color:var(--muted);text-align:center;padding:20px 0;">No drafts pending review.</div>'
    : skillDrafts.map(dr => `
        <div class="sk-draft-item">
          <div style="flex:1;min-width:0;">
            <div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:2px;">${dr.name}</div>
            <div style="font-size:10px;color:var(--muted);">${catLabels[dr.cat]||dr.cat} · by ${dr.author} · ${dr.ts}</div>
          </div>
          <span class="chip chip-yellow" style="font-size:9px;flex-shrink:0;">Pending</span>
        </div>`).join('');
}

function clearKbDraft() {
  ['kb-draft-name','kb-draft-summary','kb-draft-patterns','kb-draft-spl','kb-draft-exclusions','kb-draft-ttps']
    .forEach(id => { const e = document.getElementById(id); if(e) e.value = ''; });
  const c = document.getElementById('kb-draft-cat'); if(c) c.value = '';
}

function submitKbDraft() {
  const name = (document.getElementById('kb-draft-name')?.value||'').trim();
  const cat  = document.getElementById('kb-draft-cat')?.value||'';
  if (!name || !cat) { alert('Please fill in at least Skill Name and Category.'); return; }
  const now = new Date();
  const ts = now.toISOString().slice(0,10) + ' ' + now.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  skillDrafts.push({ id:'SK-' + (8+skillDrafts.length) + '-draft', name, cat, author:currentUser||'analyst', ts, status:'pending' });
  clearKbDraft();
  renderKbDraftList();
  renderSkillDrafts(); // also update the modal's draft list
  const btn = document.getElementById('kb-submit-btn');
  if (btn) { const o=btn.textContent; btn.textContent='✓ Submitted!'; btn.style.background='var(--green)';
    setTimeout(()=>{ btn.textContent=o; btn.style.background=''; },2000); }
}

// ── KB Environment pane ──
function renderKbEnvPane() {
  const d = envData;
  if (!d) return;

  // Overview fields
  const set = (id, val) => { const e = document.getElementById(id); if(e) e.value = val ?? ''; };
  const getStat = label => (d.stats||[]).find(s=>s.label===label)?.value || '';
  set('kb-env-domain',    d.domain?.name || 'CORP.LOCAL');
  set('kb-env-endpoints', getStat('Endpoints')  || '2,412');
  set('kb-env-servers',   getStat('Servers')    || '34');
  set('kb-env-scope',     d.domain?.sites?.join(' · ') || '10.0.0.0/8 · 8 segments');
  set('kb-env-siem',      'Splunk Enterprise Security 7.3');
  set('kb-env-edr',       'CrowdStrike Falcon 7.1');
  set('kb-env-topo',      d.topology ? d.topology.replace(/<[^>]+>/g,'') : '');

  // Segments table
  const segs = d.segments || [];
  const segCount = document.getElementById('kb-seg-count');
  if (segCount) segCount.textContent = segs.length + ' segments';
  const segBody = document.getElementById('kb-seg-body');
  if (segBody) {
    segBody.innerHTML = segs.map((s,i) => {
      const cls = kbEnvEditMode ? 'kb-cell-input' : '';
      const attr = kbEnvEditMode ? '' : ' readonly style="background:transparent;border:none;color:var(--sub);font-size:11px;font-family:inherit;width:100%;outline:none;"';
      return `<tr>
        <td><input class="${cls}" data-seg="${i}" data-field="name" value="${s.name}"${attr}></td>
        <td><input class="${cls}" data-seg="${i}" data-field="cidr" value="${s.cidr||''}"${attr}></td>
        <td><input class="${cls}" data-seg="${i}" data-field="sensitivity" value="${s.sensitivity||''}"${attr}></td>
      </tr>`;
    }).join('');
  }

  // Assets table
  const assets = d.assets || [];
  const assetCount = document.getElementById('kb-asset-count');
  if (assetCount) assetCount.textContent = assets.length + ' assets';
  const assetBody = document.getElementById('kb-asset-body');
  if (assetBody) {
    assetBody.innerHTML = assets.map((a,i) => {
      const cls = kbEnvEditMode ? 'kb-cell-input' : '';
      const attr = kbEnvEditMode ? '' : ' readonly style="background:transparent;border:none;color:var(--sub);font-size:11px;font-family:inherit;width:100%;outline:none;"';
      return `<tr>
        <td><input class="${cls}" data-asset="${i}" data-field="hostname" value="${a.hostname}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="ip"       value="${a.ip}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="role"     value="${a.role||''}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="os"       value="${a.os||''}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="segment"  value="${a.segment||''}"${attr}></td>
        <td><input class="${cls}" data-asset="${i}" data-field="owner"    value="${a.owner||''}"${attr}></td>
      </tr>`;
    }).join('');
  }

  // Accounts table
  const accounts = d.accounts || [];
  const acctCount = document.getElementById('kb-acct-count');
  if (acctCount) acctCount.textContent = accounts.length + ' accounts';
  const acctBody = document.getElementById('kb-acct-body');
  if (acctBody) {
    acctBody.innerHTML = accounts.map((a,i) => {
      const cls = kbEnvEditMode ? 'kb-cell-input' : '';
      const attr = kbEnvEditMode ? '' : ' readonly style="background:transparent;border:none;color:var(--sub);font-size:11px;font-family:inherit;width:100%;outline:none;"';
      return `<tr>
        <td><input class="${cls}" data-acct="${i}" data-field="name"   value="${a.name}"${attr}></td>
        <td><input class="${cls}" data-acct="${i}" data-field="type"   value="${a.type||''}"${attr}></td>
        <td><input class="${cls}" data-acct="${i}" data-field="status" value="${a.status||''}"${attr}></td>
        <td><input class="${cls}" data-acct="${i}" data-field="normal" value="${(a.normal||'').replace(/'/g,"&#39;")}"${attr}></td>
      </tr>`;
    }).join('');
  }
}

function toggleKbEnvEdit() {
  // snapshot current values
  kbEnvSnapshot = {
    domain:   { ...envData.domain },
    stats:    (envData.stats||[]).map(s=>({...s})),
    segments: envData.segments.map(s=>({...s})),
    assets:   envData.assets.map(a=>({...a})),
    accounts: envData.accounts.map(a=>({...a})),
    topology: envData.topology,
  };
  kbEnvEditMode = true;
  document.getElementById('kb-env-edit-btn').style.display   = 'none';
  document.getElementById('kb-env-save-btn').style.display   = '';
  document.getElementById('kb-env-cancel-btn').style.display = '';
  document.getElementById('kb-env-hint').innerHTML = '🖊 Edit mode active — all fields are now editable. Click <b>Save Changes</b> when done.';
  renderKbEnvPane();
}

function cancelKbEnvEdit() {
  if (kbEnvSnapshot) {
    envData.domain   = { ...kbEnvSnapshot.domain };
    envData.stats    = kbEnvSnapshot.stats.map(s=>({...s}));
    envData.segments = kbEnvSnapshot.segments.map(s=>({...s}));
    envData.assets   = kbEnvSnapshot.assets.map(a=>({...a}));
    envData.accounts = kbEnvSnapshot.accounts.map(a=>({...a}));
    envData.topology = kbEnvSnapshot.topology;
  }
  kbEnvEditMode = false;
  kbEnvSnapshot = null;
  document.getElementById('kb-env-edit-btn').style.display   = '';
  document.getElementById('kb-env-save-btn').style.display   = 'none';
  document.getElementById('kb-env-cancel-btn').style.display = 'none';
  document.getElementById('kb-env-hint').innerHTML = 'Click <b>Edit</b> to modify any environment field. Agents will pick up changes on the next hunt.';
  renderKbEnvPane();
}

function saveKbEnvChanges() {
  // Flush overview fields
  const g = id => document.getElementById(id)?.value || '';
  if (!envData.domain) envData.domain = {};
  envData.domain.name = g('kb-env-domain');
  const setStat = (label, val) => { const s = (envData.stats||[]).find(s=>s.label===label); if(s) s.value=val; };
  setStat('Endpoints', g('kb-env-endpoints'));
  setStat('Servers',   g('kb-env-servers'));
  // Flush segment table inputs
  document.querySelectorAll('[data-seg]').forEach(inp => {
    const i = parseInt(inp.dataset.seg), f = inp.dataset.field;
    if (envData.segments[i]) envData.segments[i][f] = inp.value;
  });
  // Flush asset table inputs
  document.querySelectorAll('[data-asset]').forEach(inp => {
    const i = parseInt(inp.dataset.asset), f = inp.dataset.field;
    if (envData.assets[i]) envData.assets[i][f] = inp.value;
  });
  // Flush account table inputs
  document.querySelectorAll('[data-acct]').forEach(inp => {
    const i = parseInt(inp.dataset.acct), f = inp.dataset.field;
    if (envData.accounts[i]) envData.accounts[i][f] = inp.value;
  });
  // Flush topology
  const topoEl = document.getElementById('kb-env-topo');
  if (topoEl) envData.topology = topoEl.value;

  kbEnvEditMode = false;
  kbEnvSnapshot = null;
  document.getElementById('kb-env-edit-btn').style.display   = '';
  document.getElementById('kb-env-save-btn').style.display   = 'none';
  document.getElementById('kb-env-cancel-btn').style.display = 'none';
  const hint = document.getElementById('kb-env-hint');
  hint.innerHTML = '✓ Changes saved — agents will use updated context on next invocation.';
  hint.style.color = 'var(--green)';
  setTimeout(() => {
    hint.innerHTML = 'Click <b>Edit</b> to modify any environment field. Agents will pick up changes on the next hunt.';
    hint.style.color = '';
  }, 3000);
  renderKbEnvPane();
}

// ── IOC Repository ──
function renderKbIocPane() {
  const tbody = document.getElementById('ioc-table-body');
  if (!tbody) return;

  // Filtered set
  let rows = iocRepository.filter(r => {
    const typeMatch   = activeIocTypeFilter   === 'all' || r.type   === activeIocTypeFilter;
    const statusMatch = activeIocStatusFilter === 'all' || r.status === activeIocStatusFilter;
    return typeMatch && statusMatch;
  });

  // Stats (always whole set)
  const all = iocRepository;
  const setText = (id, v) => { const e = document.getElementById(id); if(e) e.textContent = v; };
  setText('ioc-stat-total',  all.length);
  setText('ioc-stat-ip',     all.filter(r=>r.type==='IP'     && (r.status==='blocked'||r.status==='isolated')).length);
  setText('ioc-stat-domain', all.filter(r=>r.type==='Domain' && r.status==='blocked').length);
  setText('ioc-stat-hash',   all.filter(r=>r.type==='Hash'||r.type==='JA3').length);
  setText('ioc-stat-acct',   all.filter(r=>r.type==='Account').length);

  const sevColor  = { c:'var(--red)', h:'var(--orange)', m:'var(--yellow)', l:'var(--green)' };
  const sevLabel  = { c:'Critical',   h:'High',          m:'Medium',        l:'Low'         };
  const typeClass = { IP:'ioc-t-ip', Domain:'ioc-t-domain', Hash:'ioc-t-hash', JA3:'ioc-t-ja3', Account:'ioc-t-account' };
  const statusIco = { blocked:'🚫', monitoring:'👁️', isolated:'🔒', suspended:'⛔', cleared:'✓' };

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:30px;color:var(--muted);font-size:12px;">No IOCs match the current filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(r => {
    const u = users[r.analyst] || { initials:'?', bg:'rgba(100,116,139,.2)', color:'var(--sub)' };
    return `<tr>
      <td style="padding-left:24px;"><span class="ioc-type ${typeClass[r.type]||''}">${r.type}</span></td>
      <td><span class="ioc-val">${r.value}</span></td>
      <td><button class="ioc-hunt-link" onclick="goToHuntKeep('${r.hunt}')">${r.hunt}</button></td>
      <td><span style="font-size:10px;color:var(--sub);">${r.ttp||'—'}</span></td>
      <td><span style="font-size:11px;font-weight:600;color:${sevColor[r.sev]||'var(--sub)'};">${sevLabel[r.sev]||r.sev}</span></td>
      <td><span class="ioc-status ioc-s-${r.status}">${statusIco[r.status]||''} ${r.status.charAt(0).toUpperCase()+r.status.slice(1)}</span></td>
      <td><div style="display:flex;align-items:center;gap:5px;">
        <div class="user-av" style="width:16px;height:16px;font-size:7px;background:${u.bg};color:${u.color};flex-shrink:0;">${u.initials}</div>
        <span>${r.analyst}</span>
      </div></td>
      <td style="font-size:10px;white-space:nowrap;color:var(--muted);">${r.ts}</td>
      <td style="max-width:200px;font-size:10px;color:var(--muted);line-height:1.4;">${r.note}</td>
    </tr>`;
  }).join('');
}

function filterKbIoc(dimension, value, el) {
  if (dimension === 'type') {
    activeIocTypeFilter = value;
    document.querySelectorAll('[data-ioctype]').forEach(b => b.classList.toggle('on', b.dataset.ioctype === value));
  } else {
    activeIocStatusFilter = value;
    document.querySelectorAll('[data-iocstatus]').forEach(b => b.classList.toggle('on', b.dataset.iocstatus === value));
  }
  renderKbIocPane();
}

function addKbIoc() {
  const type   = document.getElementById('ioc-add-type')?.value || 'IP';
  const value  = (document.getElementById('ioc-add-value')?.value || '').trim();
  const ttp    = (document.getElementById('ioc-add-ttp')?.value   || '').trim();
  const status = document.getElementById('ioc-add-status')?.value || 'monitoring';
  if (!value) { alert('Please enter an IOC value.'); return; }
  const now = new Date();
  const ts  = now.toISOString().slice(0,10) + ' ' + now.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  iocRepository.push({
    id: 'IOC-' + String(iocRepository.length + 1).padStart(3,'0'),
    type, value, hunt: 'TH-2026-' + activeKeepHunt,
    ttp: ttp || '—', sev: 'h', status,
    analyst: currentUser || 'analyst', ts, note: 'Manually added',
  });
  document.getElementById('ioc-add-value').value = '';
  document.getElementById('ioc-add-ttp').value   = '';
  renderKbIocPane();
}

function exportKbIoc() {
  const headers = ['ID','Type','Value','Hunt','TTP','Severity','Status','Analyst','Added','Note'];
  const rows = iocRepository.map(r =>
    [r.id,r.type,r.value,r.hunt,r.ttp,r.sev,r.status,r.analyst,r.ts,r.note].map(v=>`"${(v||'').replace(/"/g,'""')}"`).join(',')
  );
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type:'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'ioc-repository-' + new Date().toISOString().slice(0,10) + '.csv';
  a.click(); URL.revokeObjectURL(url);
}

function openSkillsRepo() {
  // Navigate to Knowledge Base tab
  const kbTab = Array.from(document.querySelectorAll('.nav-tab')).find(t => t.textContent.includes('Knowledge Base'));
  if (kbTab) { goTab('kb', kbTab); initKbTab(); }
  else { document.getElementById('sk-overlay').classList.add('open'); switchSkillTab('browse'); }
}
function closeSkillsRepo() {
  document.getElementById('sk-overlay').classList.remove('open');
}
function filterSkills(cat, el) {
  activeSkillCat = cat;
  document.querySelectorAll('.sk-cat-pill').forEach(p => p.classList.remove('sk-cat-on'));
  el.classList.add('sk-cat-on');
  renderSkillsRepo(cat);
}
function renderSkillsRepo(cat) {
  const list = document.getElementById('sk-list');
  if (!list) return;
  const filtered = cat === 'all' ? skillsData : skillsData.filter(s => s.cat === cat);
  list.innerHTML = filtered.map(renderSkillCard).join('');
}
function toggleSkillCard(el) { el.classList.toggle('open'); }
function toggleDetChain(el) { el.closest('.det-chain').classList.toggle('open'); }
function renderSkillCard(sk) {
  const agentColor = {orchestrator:'blue',hypothesis:'teal',dataeng:'indigo',tradecraft:'yellow',detection:'green',validation:'purple'};
  const agentIcon  = {orchestrator:'🎛️',hypothesis:'💡',dataeng:'🗄️',tradecraft:'🧠',detection:'⚙️',validation:'✅'};
  const ttpChips = sk.ttps.map(t=>`<span class="chip chip-indigo" style="font-size:9px;padding:1px 5px;">${t}</span>`).join('');
  const rbLinks  = sk.ttps.filter(t => typeof runbookData !== 'undefined' && runbookData[t])
    .map(t=>`<button class="kb-rb-link" onclick="jumpToRunbook('${t}',event)">📖 ${t}</button>`).join('');
  const agentChips = sk.agents.map(a=>`<span class="chip chip-${agentColor[a]||'gray'}" style="font-size:10px;">${agentIcon[a]||''} ${a}</span>`).join('');
  const patterns = sk.patterns.map(p=>`<li>${p}</li>`).join('');
  const excl = sk.exclusions.map(e=>`<li>${e}</li>`).join('');
  return `
  <div class="sk-card sk-border-${sk.cat}" data-skillid="${sk.id}" onclick="toggleSkillCard(this)">
    <div class="sk-card-head">
      <span class="sk-id">${sk.id}</span>
      <span class="sk-name">${sk.name}</span>
      <span class="sk-cat-badge sk-cat-${sk.cat}">${sk.catLabel}</span>
      <span class="chip chip-gray" style="font-size:9px;margin-left:4px;">${sk.version}</span>
      <button class="kb-vs-btn" onclick="openSkillSource('${sk.id}',event)" title="View raw Markdown for this skill">📄 .md</button>
      <span class="sk-chevron" style="margin-left:2px;">▼</span>
    </div>
    <div class="sk-card-body">
      <div class="sk-meta-row">
        <span>✍️ <strong>${sk.author}</strong></span>
        <span>Updated ${sk.updated}</span>
        <span style="display:flex;gap:3px;flex-wrap:wrap;">${ttpChips}</span>
      </div>
      <p class="sk-summary">${sk.summary}</p>
      ${rbLinks ? `<div class="sk-section-lbl">Runbooks</div><div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:8px;">${rbLinks}</div>` : ''}
      <div class="sk-section-lbl">Behavioral Patterns</div>
      <ul class="sk-patterns">${patterns}</ul>
      <div class="sk-section-lbl">SPL Template</div>
      <pre class="sk-spl">${sk.spl}</pre>
      <div class="sk-section-lbl">FP Exclusions</div>
      <ul class="sk-excl">${excl}</ul>
      <div class="sk-section-lbl">Suggested Attack Paths</div>
      <div class="sk-path-list">
        ${sk.attackPaths.map(p=>`
        <div class="sk-path-item ${p.likelihood}">
          <div class="sk-path-top">
            <span class="sk-path-ttp">${p.ttp}</span>
            <span class="sk-path-name">${p.name}</span>
            <span class="sk-path-lhood ${p.likelihood}">${p.likelihood}</span>
          </div>
          <div class="sk-path-desc">${p.desc}</div>
        </div>`).join('')}
      </div>
      <div class="sk-ver-row">
        <span>Consumed by:</span>
        <div class="sk-agents-row">${agentChips}</div>
      </div>
    </div>
  </div>`;
}

function toggleToolTile(tile) {
  const grid = tile.parentElement;
  const tiles = Array.from(grid.querySelectorAll(':scope > .tool-tile'));
  const idx = tiles.indexOf(tile);
  const pairIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
  const pair = tiles[pairIdx];
  const willOpen = !tile.classList.contains('open');
  tile.classList.toggle('open', willOpen);
  if (pair) pair.classList.toggle('open', willOpen);
}

function openRunbook(ttpId) {
  const rb = runbookData[ttpId] || runbookFallback(ttpId);
  const modal = document.getElementById('rb-modal');
  if (!modal) return;

  document.getElementById('rb-modal-ttp-id').textContent = ttpId;
  document.getElementById('rb-modal-title-text').textContent = rb.name;
  document.getElementById('rb-tactic-chip').textContent = rb.tactic;
  document.getElementById('rb-summary').textContent = rb.summary;

  // Evidence tips
  const evEl = document.getElementById('rb-evidence');
  evEl.innerHTML = rb.evidence.length
    ? rb.evidence.map(e => `
      <div class="rb-tip rb-tip-${e.sev === 'crit' ? 'crit' : e.sev === 'high' ? 'high' : 'info'}">
        <span class="rb-tip-icon">${e.icon}</span>
        <div class="rb-tip-body">
          <div class="rb-tip-label ${e.sev === 'crit' ? 'crit' : e.sev === 'high' ? 'high' : 'info'}">${e.label}</div>
          <div class="rb-tip-text">${e.text}</div>
        </div>
      </div>`).join('')
    : '<div style="font-size:11px;color:var(--muted);">No evidence tips for this technique.</div>';

  // Detection queries
  const qEl = document.getElementById('rb-queries');
  qEl.innerHTML = rb.queries.length
    ? rb.queries.map((q, i) => `
      <div class="rb-query-label">${q.label}</div>
      <div class="rb-query" id="rb-q-${i}">${q.spl.replace(/</g,'&lt;').replace(/>/g,'&gt;')}
        <button class="rb-use-query-btn" onclick="useRunbookQuery(${i},'${ttpId}')">Use in Check ↗</button>
      </div>`).join('')
    : '<div style="font-size:11px;color:var(--muted);">No query templates for this technique.</div>';

  // Hunt notes
  const hnEl = document.getElementById('rb-hunt-notes');
  hnEl.innerHTML = rb.huntNotes.length
    ? rb.huntNotes.map(n => `
      <div class="rb-note">
        <div class="rb-note-meta">
          <span class="rb-note-hunt">${n.hunt}</span>
          <span class="rb-note-date">${n.date}</span>
          <span class="rb-note-analyst">— ${n.analyst}</span>
        </div>
        <div class="rb-note-text">${n.text.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
      </div>`).join('')
    : '<div style="font-size:11px;color:var(--muted);">No prior hunt notes for this technique.</div>';

  // FP guidance
  const fpEl = document.getElementById('rb-fps');
  fpEl.innerHTML = rb.fps.length
    ? rb.fps.map(fp => `<div class="rb-fp">${fp.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>`).join('')
    : '<div style="font-size:11px;color:var(--muted);">No false positive guidance recorded.</div>';

  document.getElementById('rb-overlay').classList.add('open');

  // Log a feed entry to show the MCP tool was called
  const agentFeed = document.getElementById('agent-feed');
  if (agentFeed) {
    const el = document.createElement('div');
    el.className = 'feed-entry fe-runbook';
    el.innerHTML = `<span class="fe-prefix">📖</span>
      <div class="fe-body"><b>Runbook</b> → <code style="font-size:10px;color:var(--indigo);">get_runbook("${ttpId}")</code> — ${rb.name} · ${rb.evidence.length} evidence tips, ${rb.huntNotes.length} prior hunt note(s)</div>`;
    agentFeed.appendChild(el);
    agentFeed.scrollTop = agentFeed.scrollHeight;
  }
}

function closeRunbook() {
  document.getElementById('rb-overlay').classList.remove('open');
}

function useRunbookQuery(idx, ttpId) {
  const rb = runbookData[ttpId] || runbookFallback(ttpId);
  const q = rb.queries[idx];
  if (!q) return;
  const editor = document.getElementById('spl-editor') || document.querySelector('.query-editor');
  if (editor) {
    editor.value = q.spl;
    editor.focus();
    closeRunbook();
    // Navigate to Check tab
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('on'));
    const checkTab = document.querySelector('[onclick*="check"]') || document.querySelector('.nav-tab:nth-child(4)');
    if (checkTab) checkTab.click();
  }
}

// Wire up TTP chips in the UI to open the runbook on click
(function() {
  function attachRunbookTriggers() {
    document.querySelectorAll('.chip[data-ttp], .ttp-id[data-ttp], .mt[data-ttp]').forEach(el => {
      if (el.dataset.rbBound) return;
      el.dataset.rbBound = '1';
      el.style.cursor = 'pointer';
      el.title = 'Open Technique Runbook';
      el.addEventListener('click', e => {
        e.stopPropagation();
        openRunbook(el.dataset.ttp);
      });
    });
  }
  // Run once now and again after any pipeline step renders new chips
  attachRunbookTriggers();
  const obs = new MutationObserver(attachRunbookTriggers);
  obs.observe(document.body, { childList: true, subtree: true });
})();

// ════════════════════════════════════════
// RULE VALIDATION  (MCP tool)
// ════════════════════════════════════════
const rvData = {
  meta: {
    runAt: '2026-05-18T09:14:22Z',
    source: 'Detection Logic Agent',
    index: 'main, windows, sysmon, network',
    lookback: '30d',
  },
  stats: { total: 9, pass: 6, warn: 2, fail: 1 },
  rules: [
    {
      id: 'RV-001', ttp: 'T1053.005', name: 'Scheduled Task — schtasks.exe /create',
      format: 'spl', status: 'pass',
      detail: 'Schema validated. All fields resolve in current CIM Endpoint data model.',
      fpRate: 1.8, coverage: 94,
      query: `index=sysmon EventCode=1
| where process_name="schtasks.exe" AND match(process_commandline, "/create")
| where NOT match(process_commandline, "ConfigMgr_*|SCCM|MicrosoftEdge")
| stats count by host, user, process_commandline
| where count < 3`,
      warnings: [],
      backtest: { hits: 14, fps: 1, days: 30, peakDay: '2026-05-12', peakHits: 4 },
      deploy: { status: 'queued', severity: 'High', schedule: '5m', approvalRequired: false },
    },
    {
      id: 'RV-002', ttp: 'T1547.001', name: 'Registry Run Key Persistence',
      format: 'spl', status: 'warn',
      detail: 'Field registry_value_data not present in all forwarder versions — consider registry_value or Registry.registry_value_data.',
      fpRate: 3.2, coverage: 78,
      query: `index=sysmon EventCode=13
| where registry_key_path IN ("*\\\\Run\\\\*","*\\\\RunOnce\\\\*")
| where NOT match(registry_value_data, "OneDrive|Teams|CrowdStrike|Splunk")
| stats values(registry_value_data) as values by host, user, registry_key_path`,
      warnings: ['registry_value_data field absent on legacy UF 8.x agents — 22% coverage gap'],
      backtest: { hits: 7, fps: 2, days: 30, peakDay: '2026-05-09', peakHits: 3 },
      deploy: { status: 'pending-fix', severity: 'Medium', schedule: '10m', approvalRequired: false },
    },
    {
      id: 'RV-003', ttp: 'T1558.003', name: 'Kerberoasting — RC4 TGS-REQ',
      format: 'spl', status: 'pass',
      detail: 'Schema validated. BackupExec and MSSQLSvc SPN exclusions applied.',
      fpRate: 0.4, coverage: 99,
      query: `index=windows EventCode=4769
| where ticket_encryption_type=0x17
| where NOT match(service_name, "BackupExec|MSSQLSvc|krbtgt")
| bucket span=5m _time
| stats dc(service_name) as uniq_spns, count by _time, src_ip, user
| where uniq_spns > 3 OR count > 10`,
      warnings: [],
      backtest: { hits: 3, fps: 0, days: 30, peakDay: '2026-05-06', peakHits: 2 },
      deploy: { status: 'queued', severity: 'Critical', schedule: '5m', approvalRequired: true },
    },
    {
      id: 'RV-004', ttp: 'T1078.002', name: 'Valid Domain Accounts — Off-Hours Logon',
      format: 'spl', status: 'pass',
      detail: 'Schema OK. Baseline comparison using lookup table corp_logon_baseline.',
      fpRate: 2.1, coverage: 91,
      query: `index=windows EventCode=4624 Logon_Type=3
| eval hour=tonumber(strftime(_time,"%H"))
| where hour < 6 OR hour > 21
| lookup corp_logon_baseline user OUTPUT expected_hours
| where isnull(expected_hours) OR hour NOT IN (expected_hours)
| stats count, values(src_ip) as sources by user, host`,
      warnings: [],
      backtest: { hits: 22, fps: 3, days: 30, peakDay: '2026-05-14', peakHits: 9 },
      deploy: { status: 'queued', severity: 'High', schedule: '15m', approvalRequired: false },
    },
    {
      id: 'RV-005', ttp: 'T1570', name: 'Lateral Tool Transfer — SMB Drop',
      format: 'spl', status: 'pass',
      detail: 'Schema validated. File extension allow-list tightly scoped.',
      fpRate: 1.1, coverage: 88,
      query: `index=sysmon EventCode=11
| where match(target_filename, "\\\\(ADMIN|C|IPC)\\$\\\\.*\\.(exe|dll|bat|ps1|vbs)$")
| where NOT match(process_image, "\\\\msiexec\\.exe|\\\\wusa\\.exe|\\\\svchost\\.exe")
| stats values(target_filename) as files, count by host, user, process_image
| where count > 1`,
      warnings: [],
      backtest: { hits: 5, fps: 0, days: 30, peakDay: '2026-05-10', peakHits: 3 },
      deploy: { status: 'queued', severity: 'High', schedule: '5m', approvalRequired: false },
    },
    {
      id: 'RV-006', ttp: 'T1003.001', name: 'LSASS Memory Access — Suspicious Handle',
      format: 'spl', status: 'pass',
      detail: 'Schema OK. AV/EDR process exclusions applied from runbook FP list.',
      fpRate: 0.6, coverage: 96,
      query: `index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"
| where NOT match(SourceImage, "MsMpEng|CrowdStrike|SentinelOne|AVP|bdservicehost")
| eval suspicious_access=if(match(GrantedAccess,"0x1fffff|0x1010|0x143a"),1,0)
| where suspicious_access=1
| stats count, values(SourceImage) as sources by host, user`,
      warnings: [],
      backtest: { hits: 1, fps: 0, days: 30, peakDay: '2026-05-15', peakHits: 1 },
      deploy: { status: 'queued', severity: 'Critical', schedule: '1m', approvalRequired: true },
    },
    {
      id: 'RV-007', ttp: 'T1558.001', name: 'Golden Ticket — TGT Unusual Lifetime',
      format: 'sigma', status: 'warn',
      detail: 'Sigma rule translates correctly. Splunk-translated SPL missing field: TicketOptions — requires custom extraction.',
      fpRate: 0.2, coverage: 62,
      query: `title: Golden Ticket Detection
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketOptions: '0x40810000'
    TicketEncryptionType: '0x12'
  filter:
    ServiceName: 'krbtgt'
  condition: selection and not filter
falsepositives:
  - Legitimate privileged service accounts`,
      warnings: ['TicketOptions field not extracted in current Splunk TA — add props.conf transform before deploy'],
      backtest: { hits: 0, fps: 0, days: 30, peakDay: null, peakHits: 0 },
      deploy: { status: 'pending-fix', severity: 'Critical', schedule: '1m', approvalRequired: true },
    },
    {
      id: 'RV-008', ttp: 'T1059.001', name: 'PowerShell — Encoded Command Execution',
      format: 'kql', status: 'pass',
      detail: 'KQL validated against Defender for Endpoint schema. All fields present.',
      fpRate: 4.3, coverage: 85,
      query: `DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc","-EncodedCommand","-ec ")
| where not(ProcessCommandLine has_any ("WindowsUpdate","MicrosoftEdge","ConfigMgr"))
| summarize count(), dcount(DeviceName) by InitiatingProcessFileName, ProcessCommandLine, bin(Timestamp, 5m)
| where count_ > 2`,
      warnings: [],
      backtest: { hits: 31, fps: 7, days: 30, peakDay: '2026-05-11', peakHits: 12 },
      deploy: { status: 'queued', severity: 'Medium', schedule: '5m', approvalRequired: false },
    },
    {
      id: 'RV-009', ttp: 'T1562.001', name: 'Disable Windows Defender via Registry',
      format: 'yara', status: 'fail',
      detail: 'YARA rule references private string variable $disable_key before declaration. Compilation fails.',
      fpRate: null, coverage: 0,
      query: `rule Disable_WindowsDefender_Registry {
  meta:
    description = "Detects registry modification to disable Windows Defender"
    author = "Detection Logic Agent"
    ttp = "T1562.001"
  strings:
    $reg_path = "SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender" ascii wide
    $disable_val = "DisableAntiSpyware" ascii
  condition:
    all of them
}`,
      warnings: ['YARA compilation failed: string $disable_key referenced before declaration (line 14)', 'Deploy blocked until syntax error resolved'],
      backtest: { hits: 0, fps: 0, days: 30, peakDay: null, peakHits: 0 },
      deploy: { status: 'blocked', severity: 'High', schedule: null, approvalRequired: false },
    },
  ],
};

function renderRvResults() {
  const s = rvData.stats;
  document.getElementById('rv-stats').innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px;">
      <div style="background:var(--s2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:var(--text);">${s.total}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px;">Total Rules</div>
      </div>
      <div style="background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:var(--radius-sm);padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:#4ade80;">${s.pass}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px;">Pass</div>
      </div>
      <div style="background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2);border-radius:var(--radius-sm);padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:#fbbf24;">${s.warn}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px;">Warn</div>
      </div>
      <div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:var(--radius-sm);padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:#f87171;">${s.fail}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px;">Fail</div>
      </div>
    </div>`;

  const statusOrder = { fail: 0, warn: 1, pass: 2 };
  const sorted = [...rvData.rules].sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);

  document.getElementById('rv-rules-list').innerHTML = sorted.map(r => `
    <div class="rv-rule">
      <div style="display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap;">
        <span class="rv-status rv-${r.status}">${r.status.toUpperCase()}</span>
        <span class="rv-format rv-fmt-${r.format}">${r.format.toUpperCase()}</span>
        <div style="flex:1;min-width:160px;">
          <div style="font-weight:700;font-size:12px;">${r.name}</div>
          <div style="font-size:10px;color:var(--muted);margin-top:1px;">${r.id} · ${r.ttp}</div>
        </div>
        ${r.fpRate !== null ? `<div style="text-align:right;flex-shrink:0;">
          <div style="font-size:11px;font-weight:700;color:${r.fpRate > 3 ? '#fbbf24' : 'var(--green)'};">${r.fpRate}% FP</div>
          <div style="font-size:10px;color:var(--muted);">${r.coverage}% cov</div>
        </div>` : ''}
      </div>
      <div style="margin-top:8px;font-size:11px;color:var(--muted);">${r.detail}</div>
      ${r.warnings.map(w => `<div style="margin-top:6px;padding:5px 8px;background:rgba(234,179,8,.08);border-left:2px solid #fbbf24;border-radius:3px;font-size:10px;color:#fbbf24;">⚠ ${w}</div>`).join('')}
      <pre class="rv-query" style="margin-top:10px;">${r.query.trim()}</pre>
    </div>`).join('');
}

function renderRvBacktest() {
  document.getElementById('rv-backtest-list').innerHTML = rvData.rules.map(r => `
    <div class="rv-rule">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
        <span class="rv-status rv-${r.status}">${r.status.toUpperCase()}</span>
        <div style="flex:1;">
          <div style="font-weight:700;font-size:12px;">${r.name}</div>
          <div style="font-size:10px;color:var(--muted);">${r.id} · ${r.ttp} · lookback: ${r.backtest.days}d</div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:8px;">
        <div style="background:var(--s2);border:1px solid var(--border);border-radius:4px;padding:8px;text-align:center;">
          <div style="font-size:18px;font-weight:700;">${r.backtest.hits}</div>
          <div style="font-size:9px;color:var(--muted);">Total Hits</div>
        </div>
        <div style="background:${r.backtest.fps > 0 ? 'rgba(234,179,8,.07)' : 'var(--s2)'};border:1px solid ${r.backtest.fps > 0 ? 'rgba(234,179,8,.25)' : 'var(--border)'};border-radius:4px;padding:8px;text-align:center;">
          <div style="font-size:18px;font-weight:700;color:${r.backtest.fps > 0 ? '#fbbf24' : 'inherit'}">${r.backtest.fps}</div>
          <div style="font-size:9px;color:var(--muted);">False Positives</div>
        </div>
        <div style="background:var(--s2);border:1px solid var(--border);border-radius:4px;padding:8px;text-align:center;">
          <div style="font-size:18px;font-weight:700;">${r.backtest.peakHits}</div>
          <div style="font-size:9px;color:var(--muted);">Peak / Day</div>
        </div>
      </div>
      ${r.backtest.peakDay ? `<div style="font-size:10px;color:var(--muted);">Peak activity day: <b>${r.backtest.peakDay}</b></div>` : '<div style="font-size:10px;color:var(--muted);">No hits in lookback period</div>'}
    </div>`).join('');
}

function renderRvDeploy() {
  const statusLabel = { queued:'Queued', 'pending-fix':'Pending Fix', blocked:'Blocked', deployed:'Deployed' };
  const statusColor = { queued:'var(--blue)', 'pending-fix':'#fbbf24', blocked:'#f87171', deployed:'#4ade80' };

  document.getElementById('rv-deploy-list').innerHTML = rvData.rules.map(r => `
    <div class="rv-rule" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
      <div style="flex:1;min-width:160px;">
        <div style="font-weight:700;font-size:12px;">${r.name}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:1px;">${r.id} · ${r.ttp}</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        ${r.deploy.schedule ? `<span style="font-size:10px;color:var(--muted);font-family:monospace;">every ${r.deploy.schedule}</span>` : ''}
        <span class="chip chip-${r.deploy.severity === 'Critical' ? 'red' : r.deploy.severity === 'High' ? 'yellow' : 'blue'}" style="font-size:10px;">${r.deploy.severity}</span>
        ${r.deploy.approvalRequired ? `<span class="chip" style="font-size:10px;background:rgba(139,92,246,.1);color:#a78bfa;border:1px solid rgba(139,92,246,.25);">Approval Required</span>` : ''}
        <span style="font-size:11px;font-weight:700;color:${statusColor[r.deploy.status]};">${statusLabel[r.deploy.status] || r.deploy.status}</span>
      </div>
    </div>`).join('');
}

function openRuleValidation() {
  renderRvResults();
  renderRvBacktest();
  renderRvDeploy();
  switchRvTab('results');
  document.getElementById('rv-overlay').classList.add('open');

  const agentFeed = document.getElementById('agent-feed');
  if (agentFeed) {
    const el = document.createElement('div');
    el.className = 'feed-entry fe-rv';
    const s = rvData.stats;
    el.innerHTML = `<span class="fe-prefix">✅</span><div class="fe-body"><b>RuleVal</b> → <code style="font-size:10px;color:var(--blue);">validate_all()</code> — ${s.total} rules · ${s.pass} pass · ${s.warn} warn · ${s.fail} fail</div>`;
    agentFeed.appendChild(el);
    agentFeed.scrollTop = agentFeed.scrollHeight;
  }
}

function closeRuleValidation() {
  document.getElementById('rv-overlay').classList.remove('open');
}

function switchRvTab(tab) {
  document.querySelectorAll('.rv-tab').forEach(t => t.classList.toggle('on', t.dataset.rvTab === tab));
  document.querySelectorAll('.rv-pane').forEach(p => p.classList.toggle('on', p.id === `rv-pane-${tab}`));
}
