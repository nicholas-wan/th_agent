# PrimeTH ATHF — Project Reference

## File Structure

```
index.html               HTML only — no inline CSS or JS
css/styles.css           All styles
js/app.js                Core: nav, hunt open, chat, pivot, TTP form, FAQ filter, init
js/agents.js             agentData{} drawer content
js/observe.js            Hunt Observe stage — data, edit mode, CRUD functions
js/report.js             Hunt Report modal functions
js/pipeline.js           LOCK pipeline feed — steps, pills, topology, play
js/check.js              Check stage — rules, queries, RAA, velocityData, findingComments
js/keep.js               Keep stage — findings, timeline, TTP selector, notes
js/kb-tab.js             KB tab — platform attack techniques, runbooks, env pane, RV modal
kb/
  skills.md              Source of truth for skillsData[]          (edit here)
  runbooks.md            Source of truth for runbookData{}         (edit here)
  environment.md         Source of truth for envData{} + crownJewels{}
  skills-fallback.js     skillsData[] + skillDrafts[]              (local-dev fallback)
  runbooks-fallback.js   runbookData{}                             (local-dev fallback)
  environment-fallback.js envData{} + crownJewels{}               (local-dev fallback)
  iocs.js                iocRepository[]
  gate-decisions.js      gateDecisionLog{}
```

**Script load order:**
```
kb/gate-decisions.js  kb/iocs.js  kb/skills-fallback.js  kb/runbooks-fallback.js  kb/environment-fallback.js
js/app.js  js/agents.js  js/observe.js  js/report.js  js/pipeline.js
js/check.js   ← declares velocityData, findingComments
js/keep.js    ← uses velocityData, findingComments
js/kb-tab.js
```
Fallback files declare globals as `const`. Never redeclare in `app.js`. HTTP serving overwrites from `.md` files at runtime via `initKbTab()`. No build step — use any static server (not `file://`).

---

## Where to Edit

| Task | File | How |
|---|---|---|
| Style / layout | `css/styles.css` | Grep class name |
| JS function | `js/*.js` | Grep function name → Read at offset |
| HTML structure | `index.html` | Grep `#region PANE: <name>` |
| Add platform attack technique | `kb/skills.md` + `kb/skills-fallback.js` | Copy any `## SK-…` block; keep both in sync |
| Add TTP runbook | `kb/runbooks.md` | Copy any `## T…` block, fill fields |
| Add IOC | `kb/iocs.js` | Append to `iocRepository[]` |
| Edit environment | `kb/environment.md` | Edit fields directly; parser reads on load |
| Gate decision log | `kb/gate-decisions.js` | Append to hunt's array |
| Edit FAQ content | `index.html` | Grep `#region PANE: FAQ` |

**`index.html` region map:**
```
#region PANE: Hunts            hunt list cards
#region PANE: Hunt Detail      L/O/C/K pipeline + Keep stage
#region MODALS: Hunt           report-overlay + history-overlay
#region PANE: Agents           agent dashboard (Observe pane)
#region PANE: Coverage         coverage tab
#region PANE: Knowledge Base   KB tab + launch modal
#region PANE: FAQ              FAQ accordion + search
#region MODALS: Tools          rv-overlay · ec-overlay · rb-overlay · sk-overlay · kb-md-overlay
```

---

## CSS Variables
```
--bg #080d18  --s1 #0f1623  --s2 #141d2e  --s3 #1a2338
--border #1f2d47  --border2 #263550
--blue #3b82f6  --indigo #6366f1  --green #10b981
--yellow #f59e0b  --red #ef4444  --orange #f97316  --teal #14b8a6
--text #e2e8f0  --sub #94a3b8  --muted #4e6180
--radius 8px  --radius-sm 5px
```

---

## Key Data Globals

| Variable | File | Notes |
|---|---|---|
| `skillsData[]` / `skillDrafts[]` | `kb/skills-fallback.js` | `skillType: 'domain'` (platform attack techniques only) |
| `runbookData{}` | `kb/runbooks-fallback.js` | Keyed by TTP ID e.g. `'T1003.001'` |
| `envData{}` / `crownJewels{}` | `kb/environment-fallback.js` | monitoring, techStack; overwritten from environment.md at runtime |
| `iocRepository[]` | `kb/iocs.js` | IOCs — displayed as "IOC Repository" in UI |
| `observeData{}` | `js/observe.js` | Normal/suspicious/observables per hunt; editable in-place |
| `gateDecisionLog{}` | `kb/gate-decisions.js` | Keyed by short hunt ID e.g. `'041'` |
| `agentData{}` | `js/agents.js` | Drawer content keyed by agent key |
| `keepData{}` | `js/keep.js` | Findings, timeline, evidence per hunt |
| `velocityData{}` | `js/check.js` | MTTD, FP rate, sparklines per hunt |
| `findingComments{}` | `js/check.js` | Threaded comments per finding |

---

## Agents (fixed order)

| # | Icon | Name | Key | Color |
|---|---|---|---|---|
| 1 | 🎛️ | Orchestrator Agent | `orchestrator` | blue |
| 2 | 💡 | Hypothesis Agent | `hypothesis` | teal |
| 3 | 🗄️ | Data Engineering Agent | `dataeng` | indigo |
| 4 | 🧠 | RAA Supervisor Agent | `tradecraft` | yellow |
| 5 | ⚙️ | Detection Logic Agent | `detection` | green |

Orchestrator spawns all. Hypothesis runs first. `agentData` keyed by agent key → `{ title, sub, body }`. `openAgentDrawer(key, row)`.

> ✅ **Rule Validation** is a **tool** (not an agent) — `rv-tool-` CSS prefix, `rv-overlay` modal. Never add to agent lists, topology, feed pills, or `agentModels`.

**Adding a new agent:** update `agentData` (agents.js), Observe pane rows, pipeline sidebar pills, apick grid, `feedAgents`, `updateAgentPills` steps, and feed timeline.

---

## Tools Available (sidebar)

Card title = **"Tools Available"**. Subtitles = version only (e.g. `v2.1`).

| Icon | Name | CSS prefix | Color |
|---|---|---|---|
| 🟠 | Splunk Enterprise Security | inline | orange |
| 📚 | Tradecraft | `kb-tool-` | teal |
| 🏗️ | Environment Context | `ec-tool-` | indigo |
| ✅ | Rule Validation | `rv-tool-` | purple |
| 🗂️ | Past Hunts | `ph-tool-` | blue |
| 🛡️ | Coverage Checker | `cc-tool-` | amber |

Learn sidebar and Observe panel both show these — keep in sync. Adding a tool: add CSS pairs, HTML in both panels, bump count chip.

---

## LOCK Pipeline Stages

| Stage | ID | Role |
|---|---|---|
| Learn | L | CTI → TTP extraction → hypotheses |
| Observe | O | Editable environment baseline per hunt |
| Check | C | SPL rule testing + RAA analysis |
| Keep | K | Findings, timeline, evidence, hunt report |

---

## Modals

Open/close: `el.classList.add/remove('open')`. IDs: `history-overlay` `report-overlay` `rb-overlay` `ec-overlay` `rv-overlay`

---

## Rules / Don'ts

- ❌ "MCP Connected Tools" → ✅ "Tools Available"
- ❌ "MCP Server · vX.Y" subtitles → ✅ version only
- ❌ ev/min → ✅ ev/hr
- ❌ Inline `<style>` or `<script>` in `index.html`
- ❌ Redeclare globals from `kb/*.js` in `app.js`
- ❌ Edit `kb/*-fallback.js` for data — edit `.md` files instead (keep both in sync for skills)
- ❌ Edit `kb/skills.js` / `kb/runbooks.js` / `kb/environment.js` — legacy empty shells
- ❌ Add "Tactic Techniques" tab — KB has Platform Attack Techniques only (`skillType: 'domain'`)

---

## Operational Notes & Handoff

**Repo / deploy**
- Remote: `https://github.com/nicholas-wan/th_agent.git` · branch `main` · served via GitHub Pages.
- No build step. Serve any static server (not `file://`). HTTP serving overwrites `kb/*-fallback.js` globals from the `.md` files at runtime via `initKbTab()`.
- **Never push to GitHub unless the user explicitly says "push".** Commit only when asked.
- Commit trailer: `Co-Authored-By: Claude <noreply@anthropic.com>`.
- `watchorread.html` is an unrelated standalone file — leave it out of commits (don't `git add .`).
- Windows checkout: Git warns LF→CRLF on commit — harmless, ignore.

**Editing the demo data — source-of-truth order**
When numbers/facts conflict across files, `js/pipeline.js` (the agent reasoning feed) is the authoritative tie-breaker — it walks the actual evidence step by step. Reconcile other files to it. The 041 narrative spans 8 files that must agree: `index.html`, `js/app.js`, `js/check.js`, `js/keep.js`, `js/observe.js`, `js/pipeline.js`, `js/report.js`, `kb/iocs.js`. After any data edit, grep the old value across all of these to catch stragglers.

**Vestigial fields:** `keepData.NNN.criticals`/`highs` are NOT displayed — severity chips are computed live from the findings array (`f.sev === 'h'` etc). Edit the findings, not the counters.

**Canonical facts — TH-2026-041 (Volt Typhoon, CISA AA24-038A)**
Lateral Movement & Credential Harvesting. 8 TTPs extracted / 4 selected as hypotheses:
- **H-01 T1570** Lateral Tool Transfer (PsExec) — conf 92% · 14 hosts · single CORP\jsmith pivot chain.
- **H-02 T1003.001** LSASS Credential Dumping — conf 82% · **1 critical full-access (0x1fffff) hit on WIN-DC01 within 3 total ProcessAccess events** (other 2 are read-only `0x1410`, benign). rundll32 variant.
- **H-03 T1558.003** Kerberoasting — conf 74% · **11 SPNs in 1 burst / 3 bursts total** · RC4 TGS-REQ (EventCode 4769) · threshold **>3 SPNs/user/5m** (NOT "15/hr") · 147 CMDB SPN exclusions · FP 22%→<2%.
- **H-04 T1071.001** C2 Beacon (HTTPS) — conf **78%** · 2 Cobalt Strike sessions · 185.220.101.47:443/:8443 · beacon ~60s · **JA3 `769c10b06a1a2b7b7a26b0a2be2e88a4`** (the deployed-query hash — this is canonical, supersedes older `3b5074b1…` / `769c10b3d4…`).
- Supporting signal: T1078.002 (off-hours valid-account auth) — merged into T1570 scope, not a separate hypothesis.
- 4 rules deployed: `DL-2026-041-001..004`. Threat actor is **Volt Typhoon** everywhere (not APT29 — one generic "APT29" placeholder in the New-Hunt form input is intentional example text).
