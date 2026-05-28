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
js/kb-tab.js             KB tab — platform skills, runbooks, env pane, RV modal
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
| Add platform skill | `kb/skills.md` + `kb/skills-fallback.js` | Copy any `## SK-…` block; keep both files in sync |
| Add TTP runbook | `kb/runbooks.md` | Copy any `## T…` block, fill fields |
| Add artifact / IOC | `kb/iocs.js` | Append to `iocRepository[]` |
| Edit environment | `kb/environment.md` | Copy `## Segment:` or `## Asset:` block |
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
| `skillsData[]` / `skillDrafts[]` | `kb/skills-fallback.js` | `skillType: 'domain'` (platform skills only) |
| `runbookData{}` | `kb/runbooks-fallback.js` | Keyed by TTP ID e.g. `'T1003.001'` |
| `envData{}` / `crownJewels{}` | `kb/environment-fallback.js` | Segments, assets, accounts |
| `iocRepository[]` | `kb/iocs.js` | Artifacts/IOCs — displayed as "Artifacts Repository" in UI |
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

Orchestrator spawns all. Hypothesis runs first, completes before rest of pipeline. `agentData` keyed by agent key → `{ title, sub, body }`. `openAgentDrawer(key, row)`.

> ✅ **Rule Validation** is a **tool** (not an agent) — `rv-tool-` CSS prefix, `rv-overlay` modal. Never add it to agent lists, topology, feed filter pills, or `agentModels`.

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

L tab stages: CTI/TTP extraction → Hypotheses → Tradecraft → Detection Logic.

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
- ❌ Edit `kb/*-fallback.js` for data — edit the `.md` files instead (keep both in sync for skills)
- ❌ Edit `kb/skills.js` / `kb/runbooks.js` / `kb/environment.js` — legacy empty shells
- ❌ Add "Tactic Skills" tab — KB has Platform Skills only (`skillType: 'domain'`)
