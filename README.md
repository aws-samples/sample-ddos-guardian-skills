# DDoS Guardian

Your Web Application Firewall is your first line of defense against DDoS attacks — but only if it's configured correctly. Misconfigured rules, wrong evaluation order, or missing baseline protections can leave your application exposed without anyone realizing it. Manual WAF reviews are slow, inconsistent, and hard to scale.

DDoS Guardian is an AI agent skill that automates comprehensive WAF security assessment. It analyzes your WAFv2 web ACL configuration holistically — not just individual rules, but how they work together: evaluation order, rule interactions, baseline coverage gaps, rate limiting effectiveness, and WCU cost impact. Every finding is severity-rated with ready-to-apply remediation, so you know exactly what to fix and in what order.

It works from a `get-web-acl` JSON export. Nothing is deployed into your account, no network calls are made, and no AWS resource is ever modified.

## What it does

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
- **Reports cost and capacity**: WCU against the 5,000 per-web-ACL ceiling.
- **Classified Findings**: Findings are classified into four severity levels: **Critical**, **Medium**, **Low**, and **Awareness**.


### How it works

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

### Deliverables

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

![The Summary tab of a generated report: business application context cards, severity KPIs, a
severity donut, findings grouped by protection category, and a WCU utilisation
gauge](docs/summary-tab.png)

The screenshot above is a sample of the Summary tab from the DDOS Guardian Assessment deliverable, providing an at-a-glance overview of the WebACL configuration, business application context, and a findings breakdown across severity levels (Critical, Medium, Low, and Awareness) with visual charts by protection category and WAF capacity utilization.

### Out of scope

Non-AWS firewalls (Cloudflare, Akamai, F5, nginx), AWS Network Firewall, security groups and
network ACLs, and IAM policy review. These are different services whose configuration the skill
cannot parse — it will say so and stop rather than produce confident findings about the wrong
thing.

This is a **configuration review**, not a penetration test. It shows that a control exists and is
positioned sensibly, never that it holds up against real traffic.

## Prerequisites

- **An agent runtime that loads skills** — Claude Code, Kiro, Codex, or any runtime that reads
  from `~/.agents/skills`.
- **Node.js with `npx`**, to install the skill.
- **Python 3** on your PATH. Standard library only — no virtualenv, no `pip install`.
- **An AWS WAF web ACL export.** Either hand the skill a JSON file you already have, or let it
  walk you through producing one.
- **AWS CLI v2 with read-only credentials**, if you want the export pulled for you. The workflow
  needs no write access at any point:
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

The logging configuration is a separate API call and cannot be recovered from the web ACL, so
grab it while you are there — it is cheap to obtain and expensive to guess at.

## Quick start

Install the skill:

```bash
npx skills add https://github.com/aws-samples/sample-ddos-guardian-skills.git --skill ddos-guardian
```

Then ask your agent for a review, pointing it at your export:

```
Review our AWS WAF against best practices. The export is at ./webacl.json
```

The agent will run the assessment, ask you a short set of questions that change a verdict
(client types, markets served, API paths, logging destination, peak request rate per source IP),
re-run with your answers, and write `waf-assessment-report.html` into a `waf-assessments/`
directory beside your input file.

Answer the questions if you can. Each one either gates a finding or is printed back in the
report's Application Context so a reader can see which facts a conclusion rests on. "Don't know"
is a valid answer and costs only coverage — a guess poisons every finding resting on it.

## Blast radius

- **Never mutates AWS resources.** The scripts call no AWS API at all. Every remediation is
  emitted as JSON and CLI for a human to review and apply.
- **No network access.** Neither the scripts nor the generated HTML make any request — no
  external CSS, JS or fonts.
- **Writes only assessment artifacts** into the output directory.
- **Reads no credentials** and transmits none.

## Repository layout

```
skills/ddos-guardian/
  SKILL.md                    the workflow the agent follows
  scripts/
    waf-assess.py             normalize -> pre-checks -> scripted findings
    waf-report.py             issue map -> validation -> self-contained HTML
    waf_finding_templates.py  finding templates and report appendices A-F
  assets/
    summary-tab-template.md   the Summary tab structure and where each value comes from
  references/                 12 reference documents: assessment checklist, context schema,
                              Anti-DDoS AMR, Bot Control, Challenge/CAPTCHA, common patterns,
                              crawler/SEO, IP reputation, managed labels, managed overrides,
                              rate-based rules, cost model
```

## Disclaimer

This repository provides sample code for educational and demonstration purposes only. It is not
intended for direct production use without proper review, testing, and validation.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.