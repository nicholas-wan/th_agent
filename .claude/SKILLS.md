# HuntForge ATHF — Project Skills & Context

## Project
- **Name:** HuntForge ATHF (Automated Threat Hunt Framework)
- **File:** `C:/Users/nicho/Downloads/Claude/index.html` — single-file HTML/CSS/JS prototype, no build step, no framework
- **Purpose:** Dark-themed threat hunting UI. Analysts move CTI through a LOCK pipeline to produce detection rules and hunt findings.

## LOCK Pipeline
| Stage | ID | Role |
|---|---|---|
| Locate / Learn | L | CTI ingestion → TTP extraction → hypotheses |
| Observe | O | Live agent dashboard, data sources, tools |
| Check | C | SPL rule testing, inline rule test |
| Keep | K | Findings, timeline, evidence locker, hunt report |

**Pipeline stages in L tab:** Stage 1 (CTI/TTP extraction) → Stage 2 (Hypotheses) → Stage 3 (Tradecraft) → Stage 4 (Detection Logic)

## CSS Variables
```
--bg #080d18   --s1 #0f1623   --s2 #141d2e   --s3 #1a2338
--border #1f2d47   --border2 #263550
--blue #3b82f6   --indigo #6366f1   --green #10b981
--yellow #f59e0b   --red #ef4444   --orange #f97316   --teal #14b8a6
--text #e2e8f0   --sub #94a3b8   --muted #4e6180
--radius 8px   --radius-sm 5px
```

## Agents (always in this order)
| # | Icon | Name | Key | Color |
|---|---|---|---|---|
| 1 | 🎛️ | Orchestrator Agent | `orchestrator` | blue |
| 2 | 💡 | Hypothesis Agent | `hypothesis` | teal |
| 3 | 🗄️ | Data Engineering Agent | `dataeng` | indigo |
| 4 | 🧠 | Tradecraft Supervisor Agent | `tradecraft` | yellow |
| 5 | ⚙️ | Detection Logic Agent | `detection` | green |
| 6 | ✅ | Rule Validation Agent | `validation` | purple |

**Topology:** Orchestrator spawns all others. Hypothesis Agent is spawned first, completes before the rest of the pipeline runs.

**Agent drawer pattern:** `agentData` object keyed by agent id → `{ title, sub, body }`. Open with `openAgentDrawer(key, row)`.

**Pipeline sidebar pills:** `ap-{key}` IDs. Animated by `updateAgentPills(stepIndex)`. Feed events use `feedAgents` + `feedSteps`.

## Tools Available (sidebar card)
Card title is always **"Tools Available"** — never "MCP Connected Tools".  
Tool card subtitles show version only (e.g. `v2.1`) — never prefix with "MCP Server ·".

| Icon | Name | CSS class prefix | Theme color |
|---|---|---|---|
| 🟠 | Splunk Enterprise Security | inline style | orange `rgba(249,115,22,…)` |
| 📖 | Technique Runbook | `rb-tool-` | green `rgba(16,185,129,…)` |
| 🏗️ | Environment Context | `ec-tool-` | indigo `rgba(99,102,241,…)` |
| ✅ | Rule Validation | `rv-tool-` | purple `rgba(139,92,246,…)` |
| 🗂️ | Past Hunts | `ph-tool-` | blue `rgba(59,130,246,…)` |
| 🛡️ | Coverage Checker | `cc-tool-` | amber `rgba(245,158,11,…)` |

**Tool card pattern:** `{prefix}-card` + `{prefix}-head` + `{prefix}-body` + `{prefix}-row`. CSS defined as paired classes.  
Both the Learn sidebar and Observe "Tools Available" panel show the same tools — keep them in sync.

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

### Agent Gate (pipeline pause for analyst decision)
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

### Keep Stage
- `activeKeepHunt` — current hunt id string (e.g. `'TH-2026-041'`)
- `activeKeepTTP` — current TTP filter (`'all'` or `'T1234.001'`)
- `keepData[id]` — `{ title, findings[], timeline[], … }`
- `extractTTP(meta)` — regex `/T\d{4}(?:\.\d{3})?/` on finding.meta string
- TTP selector pills: `.tsp` / `.tsp.tsp-on` / `.tsp.tsp-all`
- `renderKeepHunt(id)`, `renderKeepFindings(d)`, `renderKeepTimeline(d)`, `renderHuntReport(id)`

### Evidence Locker
FAB button → slide-in drawer. `evidenceItems[]` array. Functions: `openEvidenceLocker()`, `addEvidence()`, `removeEvidence(id)`, `renderEvidenceList()`.

### Modals (overlay pattern)
```js
document.getElementById('overlay-id').classList.add('open')   // open
document.getElementById('overlay-id').classList.remove('open') // close
```
Existing modals: `history-overlay`, `report-overlay`, `rb-overlay`, `ec-overlay`, `rv-overlay`

## Data Conventions
- Event rates always in **ev/hr** (never ev/min)
- Data source cards: no gap chips, no partial badges
- Severities: `c` = critical, `h` = high, `m` = medium, `l` = low
- Colors: critical→red, high→orange, medium→yellow, low→green

## What's Been Built
1. Evidence Locker — FAB + slide-in drawer
2. Hunt Report Modal — TTP-filterable, pulls live evidenceItems
3. Inline Rule Test — mock SPL execution with 1.4s delay
4. Hunt History Modal — 3-run comparison table + diff items
5. TTP selector in Keep stage — filters findings, timeline, report
6. Technique Runbook — tool card + modal (openRunbook, runbookData, renderRunbook)
7. Environment Context — tool card + modal (ec-overlay)
8. Rule Validation — tool card + modal (rv-overlay)
9. Past Hunts — tool card (ph-tool-*)
10. Coverage Checker — tool card (cc-tool-*)
11. Hypothesis Agent — integrated across pipeline sidebar, Observe pane, agentData drawer, apick grid, feedSteps, updateAgentPills
12. Hypothesis Agent branching logic — 4 branches with icons, Stage 2 recall block, Environment Context in Gather phase

## Hypothesis Agent — Branch Logic
Hypothesis Agent runs in two phases: **Gather** (parallel tool calls) → **Synthesize** (generate hypotheses).

**Gather phase tools:** Technique Runbook × N TTPs · Past Hunts × N TTPs · Coverage Checker × N TTPs · Environment Context (once: topology + key assets + key accounts)

**Branch decisions** (per TTP, after `search_hunts()`):
| Branch | Icon | Label CSS | Trigger |
|---|---|---|---|
| Confirmed findings | 🎯 | `hbl-confirmed` (red) | Prior hunt had confirmed hits |
| Clean prior run | ❄️ | `hbl-clean` (blue) | Prior hunt ran, zero findings |
| FPs in prior run | 🔔 | `hbl-fp` (yellow) | Prior hunt had high FP rate |
| Rule deployed | 🔒 | `hbl-rule` (green) | Existing rule covers TTP |

**Branch actions:**
- 🎯 Confirmed → elevate confidence, carry forward confirmed hosts/accounts, pre-apply analyst notes
- ❄️ Clean → note prior miss, check for logging gaps, keep confidence but flag uncertainty
- 🔔 FPs → pre-load exclusions from prior run, tune FP threshold before rule generation
- 🔒 Rule deployed → defer to existing rule or generate variant hypothesis targeting the gap

**CSS classes:** `.hyp-recall` `.hyp-recall-head` `.hyp-recall-env` `.hyp-branch-row` `.hyp-branch-top` `.hyp-branch-label` `.hyp-branch-body` `.hyp-branch-action` + label variants `hbl-confirmed/clean/fp/rule`

## Rules / Don'ts
- ❌ "MCP Connected Tools" → ✅ "Tools Available"
- ❌ "MCP Server · vX.Y" in tool subtitles → ✅ just "vX.Y"
- ❌ Event rates in ev/min → ✅ ev/hr
- ❌ Gap chips or partial badges on data sources
- ❌ Dead code: `_runbookData_REMOVED`, old `activeRunbookTTP` stub functions — already removed
- When adding a new agent: add to `agentData`, Observe pane rows, Pipeline sidebar pills, apick grid, `feedAgents`, `updateAgentPills` steps, and agent feed timeline
- When adding a new tool card: add CSS class pair `{p}-tool-card` + `{p}-tool-head` + `{p}-tool-body` + `{p}-tool-row`, add to Learn sidebar AND Observe "Tools Available" panel, bump the active count chip in both
