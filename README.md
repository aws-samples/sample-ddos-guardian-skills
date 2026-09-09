# DDoS Guardian

**Reviews an AWS WAF web ACL as a system — evaluation order, rule interactions, L7 DDoS posture — and hands you a severity-ranked HTML report.** Offline. Read-only. No AWS resource is ever touched.

[![checks](https://github.com/aws-samples/sample-ddos-guardian-skills/actions/workflows/checks.yml/badge.svg)](https://github.com/aws-samples/sample-ddos-guardian-skills/actions/workflows/checks.yml)
[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-yellow?style=flat-square)](LICENSE)
[![Type: Agent Skill](https://img.shields.io/badge/Type-Agent%20Skill-8A2BE2?style=flat-square)](https://agentskills.io/specification)
[![Python 3.9+ · stdlib only](https://img.shields.io/badge/Python-3.9%2B%20%C2%B7%20stdlib%20only-3776AB?style=flat-square&logo=python&logoColor=white)](#prerequisites)
[![AWS writes: none](https://img.shields.io/badge/AWS%20writes-none-brightgreen?style=flat-square)](#blast-radius)

Your Web Application Firewall is your first line of defense against DDoS attacks — but only if
it's configured correctly. Misconfigured rules, wrong evaluation order, or missing baseline
protections can leave your application exposed without anyone realizing it. Manual WAF reviews
are slow, inconsistent, and hard to scale. DDoS Guardian analyzes a WAFv2 web ACL holistically —
not just individual rules, but how they work together — and every finding is severity-rated with
ready-to-apply remediation, so you know exactly what to fix and in what order.

It works from a `get-web-acl` JSON export. Nothing is deployed into your account, no network
calls are made, and no AWS resource is ever modified.

![The Summary tab of a generated report: business application context cards, severity KPIs, a
severity donut, findings grouped by protection category, and a WCU utilisation
gauge](docs/summary-tab.png)

The screenshot is the Summary tab of a real deliverable — an at-a-glance view of the web ACL, the
business application context it was assessed against, and a findings breakdown by severity and
protection category. (That run is a workshop web ACL, so treat the counts as illustrative.)

## Contents

- [Quick start](#quick-start)
- [What you get](#what-you-get)
- [What it checks](#what-it-checks)
- [Severity levels](#severity-levels)
- [How it works](#how-it-works)
- [Verifying it works](#verifying-it-works)
- [Prerequisites](#prerequisites)
- [Blast radius](#blast-radius)
- [Out of scope](#out-of-scope)
- [Repository layout](#repository-layout)

## Quick start

Install the skill:

```bash
npx skills@latest add aws-samples/sample-ddos-guardian-skills --skill ddos-guardian
```

The installer detects your agent runtimes and asks where to put it. Alternatives:

```bash
gh skill install aws-samples/sample-ddos-guardian-skills ddos-guardian
```

<details>
<summary><strong>Manual install — no Node required</strong></summary>

Clone and copy the skill directory into whichever location your runtime reads:

```bash
git clone https://github.com/aws-samples/sample-ddos-guardian-skills.git
cp -r sample-ddos-guardian-skills/skills/ddos-guardian ~/.claude/skills/
```

| Runtime | Personal | Project |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex | `~/.agents/skills/` | `.agents/skills/` |
| Kiro | `~/.kiro/skills/` | `.kiro/skills/` |
| Cursor | — | `.cursor/skills/` |
| Copilot | `~/.copilot/skills/` | `.github/skills/` |

Symlinks are followed, so `ln -s "$PWD/skills/ddos-guardian" ~/.claude/skills/ddos-guardian`
works for development.

</details>

Then ask your agent for a review, pointing it at your export:

```
Review our AWS WAF rules against best practices. The export is at ./webacl.json
```

Natural language is the reliable trigger — the skill's description covers phrasings from "what's
wrong with my web ACL" to "why is our WAF bill rising". If your runtime also exposes skills as
slash commands, `/ddos-guardian <prompt>` works too.

The agent runs the assessment, asks you a short set of questions that change a verdict (client
types, markets served, API paths, logging destination, peak request rate per source IP), re-runs
with your answers, and writes `waf-assessment-report.html` into a `waf-assessments/` directory
beside your input file.

Answer the questions if you can. Each one either gates a finding or is printed back in the
report's Application Context so a reader can see which facts a conclusion rests on. "Don't know"
is a valid answer and costs only coverage — a guess poisons every finding resting on it.

## What you get

| File | Contents |
|---|---|
| `waf-assessment-report.html` | the report — one self-contained file, renders offline, survives email and ticket attachments |
| `context.json` | the operator answers the export cannot contain, kept so a later run can be diffed |
| `waf-summary.json`, `pre-checks.json`, `validation.json` | machine-readable assessment artifacts |

The report has four tabs: **Summary** (application context, severity KPIs and charts, highlight
findings, then every finding in one table), **Current Setup** (the ACL properties and every rule in
evaluation order), **Findings & Recommendations** (one card per finding, severity-ordered), and an
**Appendix** of reference material — crawler rule JSON, the dual-AMR pattern, always-on Challenge,
the baseline priority order, WCU, and common managed-rule overrides.

Findings are grouped into seven protection categories: DDoS / Shield, Rule Logic / Bypass,
Geo / IP Sets, Rate Limiting, Body Inspection, Logging / Observability, and Bot / Fraud.

## What it checks

Behind the assessment: **44 finding templates**, **40 deterministic finding generators**, **9
mechanical pre-checks**, an **18-section checklist**, and a **16-position baseline rule order**
that the web ACL's actual priority order is compared against.

- **Reviews the whole rule set as a system**, not rule by rule: evaluation order, label
  producers and consumers, terminating `Allow` rules that let traffic skip everything below.
- **L7 DDoS posture** — is the Anti-DDoS rule group present, actually enforcing (not left in Count),
  and positioned where AWS says it must be? Is there an always-on Challenge, or does protection
  depend entirely on detection delay?
- **Bot and scraper defence** — Bot Control / ATP / ACFP present, Common vs Targeted level, category
  rules overridden to Allow, and whether verified search crawlers get Challenged during an attack.
- **Non-browser client safety** — will a native mobile app or API caller be blocked or Challenged by
  a control it cannot complete? This is the check that turns a "protection" into an outage.
- **Rate limiting** — rules stuck in Count, thresholds no real client reaches, unsupported evaluation
  windows, wrong aggregation key behind a proxy or carrier NAT, and which of the three recommended
  tiers is missing.
- **Bypass hunting** — every `Allow` rule tested for a forgeable condition, terminating Allows that
  strand the rules below them, dead boolean branches, IPv4-only IP sets, and rules whose name
  contradicts their action.
- **Managed rule group hygiene** — missing baseline groups, sub-rules overridden away from their
  documented defaults in **both** directions, scope-downs that narrow a group to almost nothing, and
  version pinning.
- **Rule interaction** — labels checked in three directions: consumer with no producer, producer that
  evaluates too late, and **producer nothing consumes**. Plus full priority-order comparison against
  the 16-tier baseline.
- **Fix impact and ordering** — for every recommendation, what it breaks, what must land together,
  and in what order.
- **Observability** — is WAF logging on, with enough retention and the right redactions? And it keeps
  *"not configured"* separate from *"cannot be verified from the export"*.
- **Reports cost and capacity**: WCU against the 5,000 per-web-ACL ceiling, with the 1,500 threshold
  where the per-request surcharge starts marked separately.

## Severity levels

| Severity | Means |
|---|---|
| **Critical** | The protection can be bypassed entirely, or a core protection is disabled or ineffective. |
| **Medium** | A real gap that needs specific conditions to exploit, or a known attack vector that is not blocked. |
| **Low** | Suboptimal configuration with no direct security impact; UX or cost only. |
| **Awareness** | Not a misconfiguration. Something worth knowing operationally — a capacity limit, missing observability, version staleness, or a behaviour that would surprise someone during an incident. |

A finding count that goes up as you answer more context questions is the system working
correctly, not a regression.

## How it works

```
   1            2              3            4             5             6            7            8
┌──────┐   ┌──────────┐   ┌─────────┐   ┌─────────┐   ┌───────────┐   ┌────────┐   ┌────────┐   ┌────────┐
│ WAF  │──▶│  ASSESS  │──▶│   ASK   │──▶│   RE-   │──▶│    LLM    │──▶│ VERIFY │──▶│ RENDER │──▶│ REPORT │
│ JSON │   │  SCRIPT  │   │ CONTEXT │   │ ASSESS  │   │ REASONING │   │  + PT  │   │ SCRIPT │   │  HTML  │
└──────┘   └──────────┘   └─────────┘   └─────────┘   └───────────┘   └────────┘   └────────┘   └────────┘
 input      ▓ script        agent        ▓ script        agent          agent      ▓ script    deliverable
                                                                                                     │
                       9  SELF-REVIEW  [agent] ◀──────────────────────────────────────────────────────┘
                       mechanical · adversarial re-derivation · cross-reference

                       ▓ deterministic — same input, same output.  Everything else is judgment.
```

That split is the point. `waf-assess.py` decides everything decidable from the config text and
writes those findings itself, so a finding does not depend on how carefully one reviewer read.
What is left is either judgment about intent — which no script should fake — or a fact only an
operator has, which is what the context questions are for.

## Verifying it works

Ask your agent:

```
Is the ddos-guardian skill available, and what input does it need?
```

A correctly installed skill names the WAFv2 web ACL export it needs and offers to walk you
through `aws wafv2 get-web-acl` — rather than answering generically about firewalls.

## Prerequisites

- **An agent runtime that loads skills** — Claude Code, Kiro, Codex, or any runtime that reads a
  skills directory (see the install table above).
- **Python 3.9 or newer** on your PATH. Standard library only — no virtualenv, no
  `pip install`, no lockfile. 3.9 is the version macOS ships, and CI tests it.
- **An AWS WAF web ACL export.** Either hand the skill a JSON file you already have, or let it
  walk you through producing one.
- **Node.js with `npx`** only if you install via the `npx skills` command above. The manual
  install needs no Node.
- **AWS CLI v2 with read-only credentials**, *optional* — only if you want the export pulled for
  you. The scripts call no AWS API themselves, and the workflow needs no write access at any point:
  - `wafv2:ListWebACLs`
  - `wafv2:GetWebACL`
  - `wafv2:GetLoggingConfiguration`

Accepted input shapes are detected automatically: AWS CLI output with a top-level `WebACL`, a
snake_case export with a top-level `web_acl`, or a bare rules array.

```bash
aws wafv2 list-web-acls --scope REGIONAL --region "$REGION"
aws wafv2 get-web-acl --name "$NAME" --scope "$SCOPE" --id "$ID" --region "$REGION" > webacl.json
aws wafv2 get-logging-configuration --resource-arn "$WEBACL_ARN" --region "$REGION" > logging.json
```

Use `--scope CLOUDFRONT` for a CloudFront distribution and `--scope REGIONAL` for ALB, API Gateway
or AppSync.

The logging configuration is a separate API call and cannot be recovered from the web ACL, so
grab it while you are there — it is cheap to obtain and expensive to guess at.

## Blast radius

- **Never mutates AWS resources.** The scripts call no AWS API at all. Every remediation is
  emitted as JSON and CLI for a human to review and apply.
- **No network access.** Neither the scripts nor the generated HTML make any request — no
  external CSS, JS or fonts.
- **Writes only assessment artifacts** into the output directory.
- **Reads no credentials** and transmits none.

## Out of scope

Non-AWS firewalls (Cloudflare, Akamai, F5, nginx), AWS Network Firewall, security groups and
network ACLs, and IAM policy review. These are different services whose configuration the skill
cannot parse — it will say so and stop rather than produce confident findings about the wrong
thing.

This is a **configuration review**, not a penetration test. A control that exists is not a
control that works: the assessment shows a control exists and is positioned sensibly, never that
it holds up against real traffic. Also unverified unless you check it — whether the web ACL is
associated with any resource at all, whether the origin is reachable around the front door, and
what is inside referenced rule groups and IP sets.

## Repository layout

```
skills/ddos-guardian/
  SKILL.md                    the workflow the agent follows
  scripts/
    waf-assess.py             normalize -> pre-checks -> scripted findings
    waf-report.py             issue map -> validation -> self-contained HTML
    waf_finding_templates.py  44 finding templates and report appendices A-F
  assets/
    summary-tab-template.md   the Summary tab structure and where each value comes from
  references/                 12 reference documents: assessment checklist, context schema,
                              Anti-DDoS AMR, Bot Control, Challenge/CAPTCHA, common patterns,
                              crawler/SEO, IP reputation, managed labels, managed overrides,
                              rate-based rules, cost model
```

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md). It covers the three invariants a change must not break
(standard library only, no network, never mutates AWS), how to add a finding, and how to run the
scripts locally.

## Disclaimer

This repository provides sample code for educational and demonstration purposes only. It is not
intended for direct production use without proper review, testing, and validation.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
