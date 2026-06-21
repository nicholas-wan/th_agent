# PrimeTH ATHF Reference

Static HTML/CSS/JS demo. There is no build step. Serve over HTTP; do not rely on `file://` because the KB loader fetches markdown at runtime.

## Files

| Path | Purpose |
|---|---|
| `index.html` | Markup, panes, cards, modals |
| `css/styles.css` | All styling |
| `js/app.js` | Navigation, hunt switching, subhunt selection, Learn filtering |
| `js/pipeline.js` | LOCK pipeline feed, agent pills, topology animation |
| `js/observe.js` | Observe baseline data and inline card editing |
| `js/check.js` | Check summaries, Investigator alert retrieval, detection rules |
| `js/keep.js` | Keep findings, timeline, evidence graph, notes |
| `js/report.js` | Hunt Report / LOCK record rendering |
| `js/agents.js` | Agent drawer content |
| `js/kb-tab.js` | Knowledge Base, tools, skills, runbook/environment modals |
| `kb/*.md` | Source markdown for skills, runbooks, environment |
| `kb/*-fallback.js` | Local fallback data loaded before markdown fetch succeeds |

Script order matters: KB fallback files, then `js/app.js`, `js/agents.js`, `js/observe.js`, `js/report.js`, `js/pipeline.js`, `js/check.js`, `js/keep.js`, `js/kb-tab.js`.

## Current Model

Agents:

| Agent | Key | Owns |
|---|---|---|
| Orchestrator Agent | `orchestrator` / feed `orch` | Coordination, topology, Keep synthesis |
| Hypothesis Agent | `hypothesis` / feed `hyp` | Learn and Observe |
| Investigator Agent | `tradecraft` / feed `ts` | Targeted SOC/Analytics alert retrieval, including RAA |
| Detection Logic Agent | `detection` / feed `dl` | SPL rule generation and tuning |

Rule Validation is a tool, not an agent. Do not add it to agent topology, agent filter pills, or agent model lists.

Tools: Splunk Enterprise Security, Rule Validation, Coverage Checker.

Skills: Tradecraft, Environment Context, Past Hunts.

## LOCK Behavior

| Stage | Owner | Notes |
|---|---|---|
| Learn | Hypothesis Agent | Per selected subhunt, one hypothesis/technique should be visible |
| Observe | Hypothesis Agent | Normal/Suspicious cards are read-only until the small pencil beside the count is clicked |
| Check | Investigator Agent + Detection Logic Agent | Investigator retrieves relevant alerts; Detection Logic renders rules scoped to the selected subhunt |
| Keep | Supervisor Agent | Findings, timeline, evidence graph, and Hunt Report are scoped to the selected subhunt |

The subhunt sidebar has no `All subhunts` option. Opening a hunt selects the first subhunt by default. Switching subhunts must refresh Learn, Observe, Check, Keep, and Hunt Report.

## Hunt Data

To add or modify a hunt, keep these in sync:

| Data | File |
|---|---|
| `huntMeta` and `checkHuntMeta` | `js/app.js` |
| `keepData`, `huntNotes` | `js/keep.js` |
| `observeData` | `js/observe.js` |
| `checkData`, RAA/check summaries, rules | `js/check.js` |
| `closedHuntFeeds`, `closedLearnData` | `js/pipeline.js` |
| Hunt card/table/switcher markup | `index.html` |

For each subhunt, TTPs should align across `keepData.subhunts`, Learn hypotheses, Check generated rules, RAA subhunt data, Observe profiles, and Keep `subhuntLock`.

## Canonical Hunts

- `TH-2026-041`: Volt Typhoon. Four selected hypotheses/subhunts: `T1570`, `T1003.001`, `T1558.003`, `T1071.001`. Live pipeline animation is available only for this hunt.
- `TH-2026-042`: Follow-up DCSync staging. Three subhunts: `T1078.002`, `T1484.001`, `T1003.006`. Active/preloaded; Run Pipeline is hidden.
- `TH-2026-040` and `TH-2026-039`: Closed/preloaded. Run Pipeline is hidden.

## Guardrails

- Do not push or commit unless explicitly asked.
- Do not use `git add .`; `AGENTS.md` may be untracked and should stay out unless requested.
- Ignore LF-to-CRLF warnings on Windows.
- Keep README concise; implementation truth lives in the JS data objects.
- After changing hunt data, run:

```powershell
rg -n "old value|old label" .
git diff --check
```
