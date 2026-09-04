# Summary tab — structure

The Summary tab has a fixed four-block structure so that two assessments of different web ACLs
read the same way. `summary_pane()` in `scripts/waf-report.py` is its only implementation; this
file documents what each block is for and where its values come from, so a change here and a
change there cannot drift apart.

**Nothing in this file is read at runtime.** It is documentation. To change the layout, change
`summary_pane()` and update this file to match.

```
┌─ BUSINESS APPLICATION CONTEXT ──────────────────────────────────────┐
│  6 cards, 3 across:  Application │ Client & Environment │ Market    │
│                      Architecture │ DDoS Protection │ WAF Logging   │
├─ FINDINGS OVERVIEW ─────────────────────────────────────────────────┤
│  5 KPI cards:  Total │ Critical │ Medium │ Low │ Awareness          │
│  3 charts:     donut (severity) │ stacked bar (category) │ gauge    │
├─ CHANGE SINCE LAST ASSESSMENT ─── (only when --diff was supplied) ──┤
├─ HIGHLIGHT FINDINGS ────────────────────────────────────────────────┤
│  the `## @summary` block from findings.md, rendered as markdown     │
├─ ALL FINDINGS ──────────────────────────────────────────────────────┤
│  # │ Severity │ Category │ Finding │ Key impact                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Block 1 — Business Application Context

Six cards, each `label / value / sub-line`. This block answers "what is this thing protecting?"
for a reader who has never seen the web ACL. **Every value is derived** — from `context.json`
where the operator supplied one, from the export otherwise — so the block cannot state something
the assessment does not know. An unanswered field renders as *not supplied* rather than being
omitted, for the same reason Application Context prints its absent group.

| Card | Value from | Sub-line from |
|---|---|---|
| Application | `web_acl.name` | description, else rule count + default action |
| Client & Environment | `context.client_types` | whether a Challenge would verify or block |
| Market & Deployment | `context.markets` + `context.environment` | market count, or that geo cannot be assessed |
| Architecture | `context.protected_resource` + `context.cdn` | `tls_termination`, whether the origin is restricted |
| DDoS Protection | `web_acl.shield_advanced` | **whether the Anti-DDoS group is actually enforcing** |
| WAF Logging | `context.logging.destination` | filter and redaction state |

The DDoS card's sub-line carries a warning style when the Anti-DDoS group is present but
overridden to Count. That combination — Shield Advanced subscribed, its rule group inert — is
the most expensive thing a WAF review finds, and a card reading only "Shield Advanced" would
imply the opposite of the truth.

## Block 2 — Findings Overview

Five KPI cards by severity, then three charts.

**The charts are inline SVG, computed in Python.** The design this came from loaded Highcharts
from a CDN. That cannot be used: a single external script breaks the self-containment
guarantee, and a reader opening the report from an email attachment with no network gets three
empty boxes where the charts should be. The same reasoning already governs the icons. A donut,
a stacked bar and an arc gauge are a few dozen lines of trigonometry, they need no runtime, and
they print — which a canvas-based chart does not.

| Chart | Function | Shows |
|---|---|---|
| Donut | `svg_donut()` | severity split, total in the centre |
| Stacked bar | `svg_stacked_bar()` | findings per protection domain, stacked by severity |
| Arc gauge | `svg_gauge()` | effective WCU against the 5,000 ceiling, with a tick at the 1,500 included allocation |

The gauge's tick is the point of it. 5,000 is the hard ceiling but 1,500 is where the
per-request surcharge starts, so a gauge showing only "64% of 5,000" hides the number that
bills.

## The protection categories

Seven domains, in `CATEGORY_ORDER`. The axis is fixed rather than derived from the findings, so
a category with nothing in it still appears — an empty **Bot / Fraud** row is information.

```
DDoS / Shield · Rule Logic / Bypass · Geo / IP Sets · Rate Limiting
Body Inspection · Logging / Observ. · Bot / Fraud
```

Classification is two-pass. A scripted finding is matched through `findings-metadata.json` to
its `title_key` and looked up in `_CATEGORY_BY_KEY`, which is exact. A finding written during
analysis has no `title_key`, so it falls to the keyword pass in `_CATEGORY_KEYWORDS`, ordered
most-specific-first. **Adding a generator means adding its `title_key` to `_CATEGORY_BY_KEY`**,
or its findings land in the fallback bucket.

## Block 4 — All Findings

Five columns. `Key impact` is the **first bullet of the finding's Problem block**, truncated to
about 165 characters. Generated rather than authored, so it cannot contradict the card it
summarises, and it adds no writing burden per finding. The row carries a left border in its
severity colour, and the table is severity-ordered while each row keeps its original issue
number, so a cross-reference in the prose still resolves.

## What the agent writes

Exactly one thing: the `## @summary` block at the top of `findings.md`, which renders as
**Highlight Findings**. Everything else in this tab is script-owned and must not be restated
in prose — see SKILL.md step 3.3.

The heading is deliberately *Highlight Findings* and not *Executive Summary*. An executive
summary invites a recap of the block above it — the counts, the severity split — all of which
is already on screen and generated, so restating it can only add length or contradict itself.
"Highlight" asks for the opposite: the two or three findings that decide what happens next,
and the reason each earned its place. The marker in `findings.md` is still `## @summary`,
because renaming it would invalidate every findings file already written.
