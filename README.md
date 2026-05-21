# HuntForge ATHF — Project Skills & Context

## File Structure

```
index.html          3,244 lines  HTML structure only — no inline CSS or JS
css/styles.css      1,530 lines  All styles
js/app.js           4,759 lines  All application logic
kb/
  skills.js           200 lines  skillsData[] + skillDrafts[]
  runbooks.js         161 lines  runbookData{} — one entry per TTP
  environment.js      216 lines  envData{} + crownJewels{}
  iocs.js              30 lines  iocRepository[]
  gate-decisions.js    55 lines  gateDecisionLog{}
```

**Script load order in index.html:**
```html
<link rel="stylesheet" href="css/styles.css">   ← in <head>
...HTML body...
<script src="kb/gate-decisions.js"></script>    ← data first
<script src="kb/iocs.js"></script>
<script src="kb/environment.js"></script>
<script src="kb/runbooks.js"></script>
<script src="kb/skills.js"></script>
<script src="js/app.js"></script>               ← logic last
```

No build step. Open `index.html` directly in a browser — all files must be served (not `file://`), use any static server or VS Code Live Server.

---

## Where to Make Edits

| Task | File | How to find the right place |
|---|---|---|
| Change a colour / spacing / layout | `css/styles.css` | Grep for the class name |
| Add a new CSS class | `css/styles.css` | Append near related classes |
| Fix / add a JS function | `js/app.js` | Grep for the function name |
| Edit HTML layout / add a tab pane | `index.html` | Grep for the surrounding element ID |
| Add a TTP runbook | `kb/runbooks.js` | Copy template at top of file |
| Add / edit a skill | `kb/skills.js` | Append before `// ── Add new skills ──` comment |
| Add an IOC | `kb/iocs.js` | Append to `iocRepository` array |
| Edit environment / network segments | `kb/environment.js` | Edit `envData` or `crownJewels` directly |
| Add a gate decision log entry | `kb/gate-decisions.js` | Append to the hunt's array |

**Efficient read pattern:**
1. Grep for the exact line number: `Grep("functionName", path="js/app.js", output_mode="content")`
2. Read only that section: `Read(file, offset=N-5, limit=40)`
3. Edit with a precise match string

---

## CSS Variables

```
--bg #080d18   --s1 #0f1623   --s2 #141d2e   --s3 #1a2338
--border #1f2d47   --border2 #263550
--blue #3b82f6   --indigo #6366f1   --green #10b981
--yellow #f59e0b   --red #ef4444   --orange #f97316   --teal #14b8a6
--text #e2e8f0   --sub #94a3b8   --muted #4e6180
--radius 8px   --radius-sm 5px
```

---

## LOCK Pipeline

| Stage | ID | Role |
|---|---|---|
| Locate / Learn | L | CTI ingestion → TTP extraction → hypotheses |
| Observe | O | Live agent dashboard, data sources, tools |
| Check | C | SPL rule testing, inline rule test |
| Keep | K | Findings, timeline, evidence locker, hunt report |

**Pipeline stages in L tab:** Stage 1 (CTI/TTP extraction) → Stage 2 (Hypotheses) → Stage 3 (Tradecraft) → Stage 4 (Detection Logic)

---

## Navigation Tabs

Tabs: **Hunts · Agents · Coverage · 📚 Knowledge Base**

`goTab(name, el)` in `js/app.js` — generic tab switcher, works for all main tabs.
KB tab additionally calls `initKbTab()` on first open.

---

## Data Objects (all in kb/*.js, loaded as globals)

| Variable | File | Description |
|---|---|---|
| `skillsData[]` | `kb/skills.js` | Hunting skills; each has `skillType: 'tactic'\|'domain'` |
| `skillDrafts[]` | `kb/skills.js` | Pending analyst submissions |
| `runbookData{}` | `kb/runbooks.js` | Keyed by TTP ID (e.g. `'T1003.001'`) |
| `envData{}` | `kb/environment.js` | Domain, segments, assets, accounts, topology |
| `crownJewels{}` | `kb/environment.js` | Tier-0/1 assets + critical accounts |
| `iocRepository[]` | `kb/iocs.js` | All IOCs across hunts |
| `gateDecisionLog{}` | `kb/gate-decisions.js` | Keyed by short hunt ID (e.g. `'041'`) |

**App-state data (in `js/app.js`, not extracted):**
- `keepData{}` — hunt findings, timeline, evidence per hunt ID
- `agentData{}` — agent drawer content keyed by agent key
- `feedSteps{}` / `feedAgents{}` — pipeline animation data
- `velocityData{}` — MTTD, FP rate, sparklines per hunt
- `findingComments{}` — threaded comments per finding per hunt
- `evidenceItems[]` — evidence locker items
- `ttpInfo{}` — TTP display names + tactic labels

---

## Agents (always in this order)

| # | Icon | Name | Key | Color |
|---|---|---|---|---|
| 1 | 🎛️ | Orchestrator Agent | `orchestrator` | blue |
| 2 | 💡 | Hypothesis Agent | `hypothesis` | teal |
| 3 | 🗄️ | Data Engineering Agent | `dataeng` | indigo |
| 4 | 🧠 | RAA Supervisor Agent | `tradecraft` | yellow |
| 5 | ⚙️ | Detection Logic Agent | `detection` | green |
| 6 | ✅ | Rule Validation Agent | `validation` | purple |

**Topology:** Orchestrator spawns all others. Hypothesis Agent runs first, completes before the rest of the pipeline.

**Agent drawer:** `agentData` keyed by agent id → `{ title, sub, body }`. Open with `openAgentDrawer(key, row)`.

**Pipeline sidebar pills:** `ap-{key}` IDs. Animated by `updateAgentPills(stepIndex)`.

**When adding a new agent:** update `agentData`, Observe pane rows, Pipeline sidebar pills, apick grid, `feedAgents`, `updateAgentPills` steps, and agent feed timeline — all in `js/app.js` / `index.html`.

---

## Knowledge Base Tab

**3 sub-tabs:** 📚 Tradecraft | 🏗️ Environment | 🔍 IOC Repository

```js
switchKbTab(tab)          // 'tradecraft' | 'env' | 'ioc'
initKbTab()               // called on first KB tab open; renders all panes
```

**Tradecraft pane** — 4 inner tabs via `switchTradecraftTab(tab)`:

| Inner tab | Key | Content |
|---|---|---|
| 🎯 Tactic Skills | `tactic` | Cross-org ATT&CK technique skills, category-filtered |
| 🏢 Domain Skills | `domain` | Org-specific skills tuned to this environment |
| 📖 TTP Runbooks | `runbooks` | Per-technique hunt guides, tactic-filtered |
| ✏️ Propose Edit | `author` | Skill authoring form + draft review queue |

- State: `activeTradecraftTab` — `'tactic'` (default) | `'domain'` | `'runbooks'` | `'author'`
- Category filter bar `#kb-tc-cat-bar` — visible for tactic/domain, hidden for runbooks/author
- `renderKbSkillList(cat)` — reads `activeTradecraftTab` to know which type to show
- `filterKbSkills(cat, el)` — updates `activeKbSkCat`, re-renders active skills tab
- `filterKbRunbooks(tactic, el)` — updates `activeKbRbTactic`, re-renders runbooks
- `renderKbRunbooks()` — collapsible `.rb-kb-card` per TTP; evidence dots, SPL, hunt notes, FPs

**Environment pane:**
- Edit mode: `toggleKbEnvEdit()`, `saveKbEnvChanges()`, `cancelKbEnvEdit()`
- Renders `envData` sections via `renderKbEnvPane()`

**IOC Repository pane:**
- Filters: `activeIocTypeFilter`, `activeIocStatusFilter`
- Render: `renderKbIocPane()`
- Export: `exportKbIoc()` — CSV blob download

---

## Tools Available (sidebar card)

Card title is always **"Tools Available"** — never "MCP Connected Tools".
Tool card subtitles show version only (e.g. `v2.1`) — never "MCP Server · vX.Y".

| Icon | Name | CSS prefix | Color |
|---|---|---|---|
| 🟠 | Splunk Enterprise Security | inline style | orange `rgba(249,115,22,…)` |
| 📚 | Tradecraft (skills + runbooks) | `kb-tool-` | teal `rgba(20,184,166,…)` |
| 🏗️ | Environment Context | `ec-tool-` | indigo `rgba(99,102,241,…)` |
| ✅ | Rule Validation | `rv-tool-` | purple `rgba(139,92,246,…)` |
| 🗂️ | Past Hunts | `ph-tool-` | blue `rgba(59,130,246,…)` |
| 🛡️ | Coverage Checker | `cc-tool-` | amber `rgba(245,158,11,…)` |

**Tool card pattern:** `{prefix}-card` + `{prefix}-head` + `{prefix}-body` + `{prefix}-row` — CSS in `css/styles.css`, HTML in `index.html`.
Both the Learn sidebar and Observe "Tools Available" panel show the same tools — keep them in sync.

**When adding a new tool card:** add CSS class pairs to `css/styles.css`, add HTML to both Learn sidebar AND Observe panel in `index.html`, bump the active count chip in both.

---

## Key Component Patterns

### Cards
```html
<div class="card">
  <div class="card-head"><span class="card-title">…</span></div>
  <div class="card-body">…</div>
</div>
```

### Chips
`.chip chip-green` / `chip-blue` / `chip-red` / `chip-yellow` / `chip-indigo` / `chip-gray`

### Agent Gate
```html
<div class="agent-gate">
  <div class="agent-gate-who">…icon + name + chip…</div>
  <div class="agent-gate-reasoning">…</div>
  <div class="agent-gate-prompt">…</div>
  <div class="agent-gate-actions">…buttons…</div>
  <div class="agent-gate-modify-panel" id="gate-N-modify">…</div>
</div>
```

### Info Bar
```html
<div class="info-bar"><span class="ib-icon">📌</span><span>…</span></div>
```

### Modals (overlay pattern)
```js
document.getElementById('overlay-id').classList.add('open')    // open
document.getElementById('overlay-id').classList.remove('open') // close
```
Existing modal IDs: `history-overlay`, `report-overlay`, `rb-overlay`, `ec-overlay`, `rv-overlay`

---

## Keep Stage

- `activeKeepHunt` — current hunt id string (e.g. `'TH-2026-041'`)
- `activeKeepTTP` — current TTP filter (`'all'` or `'T1234.001'`)
- `keepData[id]` — `{ title, findings[], timeline[], … }` — in `js/app.js`
- `extractTTP(meta)` — regex `/T\d{4}(?:\.\d{3})?/` on finding.meta string
- TTP selector pills: `.tsp` / `.tsp.tsp-on` / `.tsp.tsp-all`
- `renderKeepHunt(id)`, `renderKeepFindings(d)`, `renderKeepTimeline(d)`, `renderHuntReport(id)`

**Gate Decision Log card** (in Keep): `renderGateDecisionLog(huntId)` — reads from `gateDecisionLog` in `kb/gate-decisions.js`

**Hunt Velocity card:** `renderVelocityCard(huntId)` — reads from `velocityData` in `js/app.js`

**Finding Comments:** `findingComments[activeKeepHunt][findingIndex][]` — inline threaded notes rendered inside `renderKeepFindings(d)`

---

## Hypothesis Agent — Branch Logic

Runs in two phases: **Gather** (parallel tool calls) → **Synthesize** (generate hypotheses).

**Gather phase tools:** Technique Runbook × N TTPs · Past Hunts × N TTPs · Coverage Checker × N TTPs · Environment Context (once)

**Branch decisions** (per TTP, after `search_hunts()`):
| Branch | Icon | CSS label | Trigger |
|---|---|---|---|
| Confirmed findings | 🎯 | `hbl-confirmed` (red) | Prior hunt had confirmed hits |
| Clean prior run | ❄️ | `hbl-clean` (blue) | Prior hunt ran, zero findings |
| FPs in prior run | 🔔 | `hbl-fp` (yellow) | Prior hunt had high FP rate |
| Rule deployed | 🔒 | `hbl-rule` (green) | Existing rule covers TTP |

**CSS classes (in `css/styles.css`):** `.hyp-recall` `.hyp-recall-head` `.hyp-recall-env` `.hyp-branch-row` `.hyp-branch-top` `.hyp-branch-label` `.hyp-branch-body` `.hyp-branch-action` + label variants `hbl-confirmed/clean/fp/rule`

---

## Data Conventions

- Event rates always in **ev/hr** (never ev/min)
- Data source cards: no gap chips, no partial badges
- Severities: `c` = critical, `h` = high, `m` = medium, `l` = low
- Colors: critical→red, high→orange, medium→yellow, low→green

---

## Features Built

1. Evidence Locker — FAB + slide-in drawer (`openEvidenceLocker`, `addEvidence`, `removeEvidence`)
2. Hunt Report Modal — TTP-filterable, pulls live `evidenceItems`
3. Inline Rule Test — mock SPL execution with 1.4s delay
4. Hunt History Modal — 3-run comparison table + diff items
5. TTP selector in Keep — filters findings, timeline, report
6. Knowledge Base tool tile — merged Runbook + Tradecraft Skills tile (`openSkillsRepo`, navigates to KB tab)
7. Environment Context — tool card + modal (`ec-overlay`) with Crown Jewels sub-tab
8. Rule Validation — tool card + modal (`rv-overlay`)
9. Past Hunts — tool card (`ph-tool-*`)
10. Coverage Checker — tool card (`cc-tool-*`) with tactic-level gap scoring bars
11. Hypothesis Agent — pipeline sidebar, Observe pane, agentData drawer, apick grid, feedSteps, branch logic
12. Swimlane timeline toggle — List / Swimlane view in Keep timeline card
13. Agent topology diagram — animated SVG in Observe pane sidebar
14. Finding comments — inline threaded notes on Keep findings
15. Hunt velocity metrics — MTTD / FP rate / sparklines sidebar card in Keep
16. Skills Repository authoring — Propose Edit form + draft queue
17. Knowledge Base main tab — Tradecraft (skills + runbooks) + Environment (editable) + IOC Repository
18. Gate Decision Log — per-hunt analyst decisions in Keep
19. Skills type grouping — `skillType: 'tactic'` vs `'domain'` rendered as labelled sections in Tradecraft pane

---

## Rules / Don'ts

- ❌ "MCP Connected Tools" → ✅ "Tools Available"
- ❌ "MCP Server · vX.Y" in tool subtitles → ✅ just "vX.Y"
- ❌ Event rates in ev/min → ✅ ev/hr
- ❌ Gap chips or partial badges on data sources
- ❌ Inline `<style>` or `<script>` blocks in `index.html` — CSS goes in `css/styles.css`, JS goes in `js/app.js`
- ❌ Declaring data variables in `js/app.js` that live in `kb/*.js` — they're already globals from the earlier `<script src>` tags
- ❌ `const` redeclarations — `kb/*.js` files use `const`; never redeclare same variable in `js/app.js`
