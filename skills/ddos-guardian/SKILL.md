---
name: ddos-guardian
description: >-
  Reviews an existing AWS WAF (a WAFv2 web ACL on ALB, CloudFront, API Gateway or AppSync)
  against AWS best practices and produces a self-contained HTML report: severity-rated
  findings, ready-to-apply remediation, cost and WCU impact. Reach for it even when the
  user never says "WAF" — whenever they ask what is wrong with their web ACL or want one
  reviewed or hardened; hand over a get-web-acl export or any file containing
  WebACL/web_acl rules; report customers or a page being blocked and want the culprit rule
  plus a safe exception; ask whether they are protected against L7 DDoS, bots, scraping,
  scripted signups or credential stuffing, or whether rate-based rules and managed rule
  groups (AntiDDoS, CommonRuleSet, KnownBadInputs, IP reputation, anonymous IP, BotControl,
  ATP, ACFP) exist, run in the right order, or need scope-down statements; ask whether an
  Allow rule can be forged, whether a Challenge is reaching clients that cannot complete
  one, or whether search engine crawlers will be challenged during an attack; question a
  rising WAF bill or a WCU count near its limit; need a write-up with severities for
  compliance; ask what Shield Advanced already entitles them to; or ask about WAF logging.
  Not for non-AWS firewalls (Cloudflare, nginx), AWS Network Firewall, security groups or
  network ACLs, or IAM policy review — different services whose configs this cannot parse.
permissions:
  - file_read
  - file_write
---

# DDoS Guardian — AWS WAF rules assessment

A WAF review fails in two directions. Report a problem that is not real and the customer
stops trusting everything else in the document. Miss a real one and they stay exposed.
Both come from the same root cause: judging a configuration without the facts needed to
judge it.

So the work is split. `waf-assess.py` decides everything decidable from the config text
and writes those findings itself. What is left is either judgment about intent — which
no script should fake — or a fact only an operator has. You gather the facts, verify the
machine's claims, reason about the rest, and `waf-report.py` renders it.

## Language

**All output is English.** Write the report, findings and headings in English regardless
of the language of the user's message.

## Pipeline

```
waf-assess.py  →  ask for context  →  waf-assess.py again  →  YOU write findings  →  waf-report.py
```

`waf-assess.py` writes most of the findings. Your job is to adopt those, resolve the
context that changes them, then cover only the sections it could not decide.

## Deliverables

1. **`waf-assessment-report.html`** — one self-contained file, no external CSS, JS, fonts
   or network calls, so it survives email, a ticket attachment and an offline laptop. This
   is *the* report. Do not also hand over a Markdown version; `findings.md` is an input.
2. **`context.json`** — the answers, kept so a later run can be compared against it.
3. **The assessment artifacts** — `waf-summary.json`, `pre-checks.json`,
   `validation.json`, machine-readable and diffable.

## Scale the response to the ask

- **Full assessment** — "review our WAF", anything headed for a manager or a compliance
  file. Every step below.
- **Targeted question** — "which rule is blocking checkout?", "we are at 4,847 WCU, what
  can we trim?". Run Step 1, then answer the question that was asked. Resolve only the
  context that answer depends on and skip the report unless it has to be circulated.
  **Answer the exact question first**, in a sentence or two, before any broader advice —
  "do we have rate limiting on our signup endpoint?" is a question about that endpoint, not
  an invitation to review the web ACL.

Steps 4 and 6 are not optional at any size. Verifying a claim against the config, and
asking what a recommendation breaks, are what separate an answer from a guess — and a
one-line answer gets quoted just as widely as a report.

**Establish that the stack is AWS WAF before applying any of this.** Do not infer it from the
question alone. Four things are a different service whose config this cannot parse — a non-AWS
firewall (Cloudflare, Akamai, F5, nginx), AWS Network Firewall, security groups or network
ACLs, and IAM policies. Say so briefly and stop; none of the steps below apply.

**Network Firewall is the trap worth knowing.** Its export also has a top-level `Rules` array,
so it looks like an accepted input shape. `waf-assess.py` now rejects it — a rules array is
only accepted if its entries carry a `Statement`, or a `Priority` and an `Action` — but before
that guard existed it parsed a suricata DROP rule as a WAF rule and reported five findings,
led by a Critical about missing rate-limiting tiers, on a config with no WAF in it. **A
confident finding about the wrong service is worse than a refusal**, because nothing in it
looks wrong.

Adjacent asks that *are* in scope, and worth answering: rate limiting currently done in
application code (WAF is usually the better place), what to put in a WAF Terraform module
(advise the rule set and order, leave the HCL), Firewall Manager (step 5 already reasons about
`managed_by_fms`), and explaining a WAF concept with no config to hand — Appendix E and
`references/cost-model.md` cover WCU and pricing.

---

## Step 1: Locate the input and assess

Accepted without conversion: AWS CLI output with a top-level `WebACL`, an internal
snake_case export with a top-level `web_acl`, or a bare unwrapped rules array. All three
are detected automatically.

**Look before concluding there is no input.** If the user says an export exists — "I dumped
it to `webacl.json` in this repo" — read that filename first, and if the path is wrong search
recursively for it rather than reporting it missing. If no filename was named, search the
primary working directory from your environment (never a path carried over from an earlier
session) for `*.json` containing `WebACL`, `web_acl` or a top-level `Rules` array. Only after
that comes back empty is the input genuinely unavailable, and say which paths you searched.

If nothing has been handed over:

```bash
aws wafv2 list-web-acls --scope REGIONAL --region "$REGION"
aws wafv2 get-web-acl --name "$NAME" --scope "$SCOPE" --id "$ID" --region "$REGION" > webacl.json
aws wafv2 get-logging-configuration --resource-arn "$WEBACL_ARN" --region "$REGION" > logging.json
```

The logging configuration is a **separate API call and cannot be recovered from the web
ACL at all**. Ask for it up front; it is cheap to obtain and expensive to guess at.

**Resolve `input_file` to an absolute path before running anything**, then set
`output_dir = {parent of input_file}/waf-assessments`. A relative input path makes the
`---RESULT---` block's `OUTPUT_DIR` relative too, so any later command run from a different
directory silently misses the artifacts. `scripts_dir` is `{skill base directory}/scripts`.
Python 3 standard library only — no virtualenv, no install step.

```bash
python3 "{scripts_dir}/waf-assess.py" "{input_file}" "{output_dir}"
```

Writes:

| File | Contents |
|---|---|
| `waf-summary.json` | normalised rules with one-line statement summaries and `source.lines` back into the original JSON |
| `pre-checks.json` | 9 mechanical checks + 3 flag extractions |
| `scripted-findings.md` | finished Issue sections for everything the script decided |
| `findings-metadata.json` | `llm_sections`, `next_issue_number`, `llm_context`, `context_questions` |

Parse the `---RESULT---` block. `STATUS: OK` → continue. `STATUS: FATAL` → report the
error and stop; `FAILED_STAGE` names the stage and `STAGES_OK` says what completed, so
the artifacts already on disk are worth inspecting.

Read the summary line and `context_questions`. **Do not start writing yet.**

## Step 2: Resolve context

`CONTEXT_QUESTIONS` in the result block lists the answers that change a verdict rather
than only colouring prose. Six fields, plus `cdn` and `client_types` which are read by
the rate-limiting checks, and `references/context-schema.md` gives each one's exact effect.

**Ask them every time. Context belongs to one web ACL, never to the skill.** Client types,
market footprint, logging destination and API paths are facts about *that* application —
carrying them from a previous assessment would gate findings on facts that are not about
the config in front of you, and the report would then present another customer's answers as
this customer's. There is no default context and there must not be one.

An existing `context.json` may be reused **only** when re-assessing the same web ACL, and
even then confirm it rather than assume: answers go stale, and "we added a web front end
last quarter" changes several verdicts. `waf-assess.py` stamps `_webacl_arn` into the
context it echoes and prints `CONTEXT_ARN_MISMATCH` plus a stderr warning if a supplied file
was gathered against a different ARN — if you see that, stop and re-gather rather than
proceeding. Keep the file **beside the input, named after the web ACL**, not in the output
directory, so deleting the output does not destroy the answers.

Also ask again after any material change to the web ACL, not only after a change of
customer: a rule set that has grown a login endpoint or a browser front end invalidates the
earlier answers even though the ARN is unchanged.

**Prefer an interactive picker; fall back to a table only where the runtime has no
picker.** In Claude Code that is `AskUserQuestion`. A markdown table puts the work of
answering back on the reader — they answer two and skip the rest — where a picker turns
each one into a click and gets you the whole set. If you reach for a table in a runtime
that has a picker, that is the bug.

What makes the difference in practice:

- **Put the consequence in every option, not just the label.** "Browser and mobile app"
  tells them nothing. "Browser and mobile app — a native app cannot complete a Challenge,
  so this decides whether an always-on Challenge is a protection or an outage" gets a
  considered answer.
- **Multi-select what is not exclusive.** `client_types`, `api_paths`,
  `landing_page_uris` and `origin_protection` are all "all that apply". `environment` and
  `waf_only_for_ddos` are single-choice. `traffic_profile` is free text — ask for the peak
  request rate **per source IP**, and say so, because an aggregate figure yields a threshold
  far too high.
- **Do not force free text through a picker.** Paths, ARNs, traffic figures and the
  logging configuration are values, not choices. Ask for those in prose — and note that
  declared landing-page paths are rendered **verbatim** into the report, so a placeholder
  you invent appears as though it were the customer's.
- **Always offer an honest "don't know", with the command that would answer it.** Silence
  costs only coverage. A forced guess poisons every finding resting on it.
- **Ask the architecture questions even though no check gates them.** Where the web ACL
  sits, what terminates TLS and whether the origin is reachable around the front door can
  invalidate everything else — a perfect configuration attached to nothing protects
  nothing. They render in Application Context, where a reader can weigh the findings
  against them.
- **Send contradictions back rather than resolving them.** "We have credential stuffing"
  plus "no login endpoint" is not a puzzle to solve quietly.
- **Treat an unanswered question as still unanswered.** If nothing comes back for
  markets, leave it out. Do not infer a footprint from the account region or a hostname.

Write the answers to `context.json` and re-run:

```bash
python3 "{scripts_dir}/waf-assess.py" "{input_file}" "{output_dir}" --context context.json
```

Findings change. Some appear (logging with a real answer becomes Critical or Medium
instead of "unverified"), some disappear (a DDoS-only web ACL stops being told it is
missing the Core rule set). **A finding count that goes up as you learn more is the
system working correctly** — say so in the summary so nobody reads it as a regression.

Where there is nobody to ask, either leave the field out and let the report show the
lower coverage, or state the assumption explicitly. Never assume silently.

**Asking for data is not a substitute for answering.** Declining to invent a fact is right;
stopping there is not. If part of an ask needs something you cannot see, name the missing
artifact and the one command that produces it in a sentence or two, then answer every part
the config and artifacts on disk already cover — in the same reply. State the assumptions the
answer rests on. A methodology outline, a severity scale, or a list of `aws` commands is never
the deliverable; put the answer first and what you need to confirm it last.

## Step 3: Write the findings

**Do not delegate this to a subagent.** Do the analysis yourself in this session.

Read:

- `{output_dir}/scripted-findings.md` — the primary input
- `{output_dir}/findings-metadata.json` — `llm_sections`, `next_issue_number`, `llm_context`
- `{output_dir}/waf-summary.json` — the normalised rules
- `references/assessment-checklist.md` — the 18-section assessment checklist

**3.0 — Adopt the scripted findings.** Copy `scripted-findings.md` to
`{output_dir}/findings.md` verbatim.

**Sanity check first.** Scan the scripted issues against `waf-summary.json`. If any
contradicts it — "missing CRS" when CRS is present — override it: remove or rewrite that
finding. The script is deterministic, not omniscient.

**3.1 — Build the rule execution flow.** Walk the rules in priority order and hold the
request lifecycle in your head: per rule, its action, the labels it applies, its
scope-down, and the labels it depends on. Map label producers to consumers. Note every
Allow that terminates evaluation early. Do not draw a diagram.

**3.2 — Cover the remaining sections.** `llm_sections` in the metadata says which. Number
your findings from `next_issue_number`. Only those sections — the rest are done.

Most of the catalogue is scripted, and the scripted set is deliberately large so that a
finding does not depend on how carefully one reviewer read. Expect `llm_sections` to be
`[1, 5, 8, 17]` on a typical config: the two mechanical sections there have partial
generators that need your judgment on top, and 8 and 17 cannot be scripted at all. **Your
highest-value contribution is section 17b — the fix order — because it is the only finding
that depends on the whole set existing first.** Do not re-derive what the generators
already decided; verify it (Step 4) and add what they could not.

- **Section 1** (Allow audit) when listed: forgeability of each Allow condition. `ip_set`,
  `asn_match`, `geo_match` and the WAF token are unforgeable; User-Agent, cookies, custom
  headers, query arguments and body content are not. Read
  `references/common-patterns.md`.

  **Answering the forgeability question is not the whole of the section.** Read each Allow
  rule's statement in full and ask separately whether it does what it appears to: are any
  two branches identical, does every referenced IP set cover the address families the
  workload actually serves, does the name agree with the action. A rule can be perfectly
  unforgeable and still be broken. Three defects were missed on a real assessment by
  stopping at "IP set, therefore unforgeable" — they are scripted now, but the habit of
  treating a checklist item as the ceiling is what produced them.
- **Section 5** (Bot Control): read `references/bot-control.md`. Common versus Targeted
  level, and what non-browser clients do to the answer. The
  CategorySearchEngine/CategorySeo Allow finding is already scripted — do not duplicate
  it. If `llm_context.ua_allow_found` is true, work through the native-app implication.
- **Section 8** (landing page / cookie logic): read `references/crawler-seo.md`. Whether
  a security decision rests on a forgeable business cookie, and whether a WAF token
  replaces it.
- **Section 17b** (cross-rule fix impact): **you must read
  `references/managed-labels.md`** before writing this section, and
  `references/common-patterns.md` with it. 17a is scripted — skip it.

  The label catalogue is not optional background. A managed rule group applies labels the
  export does not list, so `rule_labels` in `waf-summary.json` shows only the labels
  *custom* rules apply — reasoning about label flow from that field alone will miss every
  managed producer. Two specific traps the catalogue records:

  - `awswaf:managed:token:*` is emitted by **four** rule groups (Anti-DDoS, Bot Control,
    ATP, ACFP), not one, so a scope-down keyed on a token label can fire earlier than
    whoever wrote it expected.
  - A managed sub-rule left at a Count default applies a label and takes no action, so it
    protects nothing unless something consumes it. `AWSManagedIPDDoSList` is the common
    case and is scripted; the catalogue is how you find the others.

  Then, for every fix in the report, scripted or yours, trace the affected traffic through
  the whole chain. Does fix A break rule B? Remove a label a later rule needs? Give the fix
  order and say which changes must land together.

Append to `findings.md`.

**3.3 — Write the highlight findings.** Put a `## @summary` block at the *top* of
`findings.md`, above the first Issue. Markdown works. It renders in the Summary tab as
**Highlight Findings**, above the generated table, and it is the only prose in the report
that is not attached to a single finding.

Highlight, do not summarise. The table below it already lists every finding, so restating
the count or walking the severities adds nothing. Name the two or three that decide what
the reader does on Monday — and say why each one is on the list.

Three things to get right in it:

- **Lead with anything high-impact and free.** If Shield Advanced is present and the
  Anti-DDoS rule group is absent, that is the headline: the subscription already includes
  that rule group and its request fees up to 50 billion requests a month, so the
  strongest L7 DDoS control available costs nothing extra at normal volume. Quote the
  qualifier — an unqualified "it's free" invites a correction that undermines the rest.
  Rule reordering, Bot Control scope-downs, deleting rule groups that do not match the
  stack, and log filtering are all free or cash-positive too.
- **Be equally careful about what Shield Advanced does not cover:** the above-1,500 WCU
  surcharge, Bot Control, Fraud Control, and CAPTCHA/Challenge fees are all still billed.
- **State the limits.** This is a configuration review, not a penetration test. It shows
  a control exists and is positioned sensibly, never that it works against real traffic.
  Also unverified unless you checked it: whether the web ACL is associated with any
  resource at all, whether the origin is reachable around the front door, and what is
  inside referenced rule groups and IP sets.

### Format rules

Each finding, exactly:

```markdown
## Issue N (severity): {title}

**Rule**: {rule name} (priority N)
**Current state**: {current configuration}

**Problem**:
- {what is wrong}

**Recommendation**:
- {what to do}

---
```

- Severity is one of **Critical**, **Medium**, **Low**, **Awareness**.
- Rule lines must read `**Rule**: name (priority N)`, `**Rules**: ...`, or
  `**Rule**: N/A (missing rule)`. `waf-report.py` parses these to link each rule in the
  Current Setup table to the findings against it, and validates that every name and
  priority actually exists.
- Number sequentially from 1 with no gaps. The renderer re-sorts by severity for display
  and keeps your numbers on the cards, so cross-references still resolve.
- Cross-reference earlier findings by number, later ones by description.
- **Do not write a report header, a summary table, or a conclusion paragraph** — the
  renderer generates the first two and the third is padding.
- **Do not include diagrams.** The Current Setup table already lists every rule in
  evaluation order.

## Step 4: Verify every claim against the config

Before rendering, re-read the config and check each finding you intend to keep. This
catches the failure mode that matters most and it is worth the tokens every time.

Does the evidence actually support the conclusion? Are the rule names and priorities
literally present? Does anything in the config contradict the claim? Would this survive
the customer opening the console?

Drop or rewrite anything that does not survive. A thin finding can still be reported — as
a question rather than a verdict. "Four rule groups run ahead of the managed rules and I
could not see inside them" is useful and honest; "your rule order is wrong" on the same
evidence is neither.

## Step 5: Pressure-test the remediation

For every recommendation, ask what it breaks. This is where an assessment either becomes
implementable or gets shelved.

- **Would this block legitimate traffic?** Anything with that risk ships with a
  Count-first staging step. Bot Control, the Core rule set and geo blocking are the usual
  suspects — Bot Control in particular tends to catch the customer's own monitoring,
  partner integrations and payment webhooks.
- **Is the advice self-consistent?** Do not recommend a scope-down on the Anti-DDoS rule
  group; it degrades the traffic baseline the detection depends on. Do not recommend
  pinning managed rule versions without also recommending the expiry alarm — an expired
  version freezes every change to the web ACL until someone selects a valid one.
- **Does the priority arithmetic work?** Priorities are unique within a web ACL and
  `update-web-acl` replaces the whole rule set. Renumber in one call.
- **Does the WCU still fit?** 5,000 is the per-web-ACL ceiling and the surcharge starts
  above 1,500. Appendix E carries the current figure.
- **Is there a rollback?** The `get-web-acl` output taken before any change is the
  rollback artifact. Say where it is.
- **Who can apply it?** When `managed_by_fms` is true, rules may be centrally imposed and
  locally unchangeable, and the recommendation belongs to the policy owner.

## Step 6: Render the report

```bash
python3 "{scripts_dir}/waf-report.py" "{output_dir}" --out waf-assessment-report.html
```

Three stages: the rule-to-issue map, the mechanical validation, then the render.
Idempotent — re-run it after any edit to `findings.md`.

**`waf-report.py` is the sole definition of the report format.** Four tabs, and the split
is what stops the two classic report failures: no number is ever retyped, so it cannot
drift from the assessment, and no prose is ever generated, so it never reads as filler.

| Tab | Owner | Contents |
|---|---|---|
| **Summary** | shared | four fixed blocks: business application context, findings overview (KPIs + three charts), your `## @summary`, then every finding in one table. Structure documented in `assets/summary-tab-template.md` |
| **Current Setup** | script | Application Context, the ACL property table, and every rule in evaluation order |
| **Findings & Recommendations** | you | one card per finding, severity-ordered, paginated |
| **Appendix** | script | reference sections A–F: crawler rule JSON, dual-AMR pattern, always-on Challenge, priority order, WCU, common overrides |

**Current Setup is wholly script-owned and there is nothing for you to write in it.** It
carries what the web ACL *is*, kept apart from what the assessment concludes, so a reader
checking "is this even my web ACL" does not scroll past the verdict. **Do not restate any
of it in prose.**

The Summary tab is **four fixed blocks** so two assessments read the same way:
Business Application Context (six derived cards), Findings Overview (five severity KPIs plus a
severity donut, a per-category stacked bar and a WCU gauge), your Highlight Findings, then All
Findings. Only Highlight Findings is yours — everything else is derived from
`waf-summary.json` and `context.json`, and must not be restated in prose. The charts are inline
SVG computed in Python, never a charting library: an external script would break
self-containment and an offline reader would get empty boxes. `assets/summary-tab-template.md`
documents each block and where its values come from.

Its Short Description column names each rule's **purpose** first and then what has been
done to it. Purpose is inferred from the statement shape — an IP set with Allow is an
allowlist, a geo match inside a `NOT` is an allowlist rather than a denylist, a label match
feeding a Challenge is an always-on Challenge — so a custom rule reads as
"URI prefix match on `/auth/`, `/price/`" rather than as a transcript of its statement. The
qualifier after the em dash is the part that changes behaviour: "whole group overridden to
Count, so it blocks nothing", or "Allow is terminating, so matching traffic skips every rule
below". An unrecognised shape falls back to the statement summary rather than inventing a
purpose.

Application Context prints your answers back in three groups: supplied by the operator,
established from the export, and **not supplied** — the last named explicitly with what
each would have decided, so a finding resting on an unanswered question is legible as
such. It appears only if you passed `--context`.

Do not hand-author HTML to match this. If the format needs to change, change the
renderer.

## Step 7: Self-review

Read `{output_dir}/validation.json`.

**Mechanical.** Any `FAIL` → fix `findings.md`, then re-run validation only:

```bash
python3 "{scripts_dir}/waf-report.py" "{output_dir}" --validate-only
```

Maximum two retries. If it still fails after three attempts, report the remaining errors
and stop.

**Adversarial** — your own findings only; the scripted ones are deterministic and do not
need re-deriving. Take the two highest-severity findings you wrote, go back to
`waf-summary.json` (and the original JSON via `source.lines`) and re-derive each from
scratch. If the re-derivation disagrees with the report, fix the report.

**Cross-reference** — all findings, scripted and yours.

For every label mentioned, check three directions, not one: a consumer with no producer, a
consumer whose producer evaluates *later* (a lower priority number is earlier, so the
producer's number must be lower), and **a producer with no consumer at all** — including
labels applied by managed rule groups, which means having read
`references/managed-labels.md`.

Then account for **every rule the report says nothing about, one at a time**. Enumerate
them from `waf-summary.json` and write a reason per rule for why it needs no finding — "at
group defaults, which is correct", "opaque rule group, covered by Issue N as a limit". If
you cannot state a reason, you have not checked it.

**Do not report this as a count.** "16 of 30 rules correctly carry no finding" is a
sentence that looks like a completed check and can be written without doing one; that
exact sentence was written on a real assessment while three defects sat in rules it
covered. Per-rule reasons or nothing.

**Do not truncate config values while analysing.** ARNs, regexes and match strings are long
and the discriminating part is usually at the end — two IP set ARNs differing only in their
suffix look identical under `[:200]`. Print them in full or compare them programmatically.

State: "Self-review complete. Mechanical: {results}. Adversarial: {N} re-derived, {N}
corrections. Cross-ref: {N} found."

---

## Key principles

- **Never assume a rule is wrong without understanding intent.** A default-Block web ACL
  with terminating Allow rules is a deliberate allowlist, and assessing it as a
  misconfiguration is the most common way this kind of review embarrasses itself.
- **Evaluate rules as a system.** Rules interact; fixing one can break another. Always
  identify the cross-rule dependencies.
- **Distinguish DDoS impact from user-experience impact.** A rule that is bad for UX and
  neutral for DDoS is low severity in a DDoS-focused assessment.
- **Allow is the most dangerous action.** Every Allow rule is a potential bypass.
  Scrutinise what triggers it and whether that condition is forgeable.
- **Missing data is not a failing grade.** When the logging configuration was not
  supplied, the answer is "unverified", not "logging disabled".

## Severity criteria

- **Critical** — the protection can be bypassed entirely, or a core protection is
  disabled or ineffective.
- **Medium** — a real gap that needs specific conditions to exploit, or a known attack
  vector that is not blocked.
- **Low** — suboptimal configuration with no direct security impact; UX or cost only.
- **Awareness** — not a misconfiguration. Something worth knowing operationally: a
  capacity limit, missing observability, version staleness, or a behaviour that would
  surprise someone during an incident.

## Baseline rule order

`references/assessment-checklist.md` §18 and **Appendix D** of the report carry the full table;
both are
generated from `RECOMMENDED_ORDER` in `waf-assess.py`, which is the single definition. The two
things to hold in mind while assessing:

**The Anti-DDoS AMR position is the one ordering rule with a documented AWS answer.** It belongs
at the top of the web ACL, or *directly below custom rules with `Allow` action* — and nothing
else. Its detection is behavioural, baselined from the traffic it observes, so a terminating
rule above it degrades the baseline rather than merely running first. A `Block` rule above it is
the case worth explaining to a customer: during an attack the denylisted traffic **is** the
attack, so blocking it earlier hides the event from the group that would have mitigated it.
`_gen_antiddos_position` reports this on its own rather than as a bullet in the general ordering
list.

**Two positions in the baseline are reviewed judgement calls and are marked as such in the
code.** Count+label rules above the AMR reconcile AWS's wording (which names only `Allow`) with
the crawler-labelling requirement, on the grounds that `Count` removes no traffic. And operator
rate rules ahead of AWS's reputation lists is the doc's convention; the reverse is defensible.
If a customer's config follows the other convention on either, **say so rather than reporting a
violation** — re-resolving a documented divergence silently is how a review loses an argument it
should not be having.

## Three things worth not getting wrong

**Two rule groups cannot be version-pinned.** The Amazon IP reputation and Anonymous IP
rule groups update continuously and have no versions to pin. Never recommend pinning
them; the recommendation is not merely unnecessary, it cannot be carried out.

**Global Accelerator is not a CDN, and treating it as one inverts the answer.** WAF cannot
attach to an accelerator, so a web ACL on the ALB behind one is the correct and only
placement — never recommend moving it to the front door. Client IP preservation is on by
default for internet-facing ALB endpoints, so WAF sees real client addresses and
recommending `ForwardedIPConfig` there actively makes things worse: it swaps a correct
source address for an attacker-settable header.

**A control that exists is not a control that works.** Everything here measures
configuration against best practice. Whether the WAF actually stops an attack is a
question for traffic, a penetration test, or the AWS Security Agent — and that
before-and-after measurement is the natural next step after these recommendations are
applied, not something this assessment substitutes for.

## Files

```
scripts/
  waf-assess.py             phase A — normalize → pre-checks → scripted findings
  waf-report.py             phase B — issue map → validation → self-contained HTML
  waf_finding_templates.py  static Markdown: finding templates + appendix A–F
assets/
  summary-tab-template.md   the Summary tab's four-block structure, and where each value
                            comes from. Documentation only -- nothing reads it at runtime
references/
  assessment-checklist.md   the 18 numbered sections; llm_sections indexes into these
  context-schema.md         context.json: which fields gate which finding
  antiddos-amr.md           detection, sensitivity, exempt regex, dual-instance pattern
  bot-control.md            Common vs Targeted, verified/unverified bots, native apps
  challenge-captcha.md      what can and cannot complete a Challenge, token properties
  common-patterns.md        anti-patterns: forgeable Allow, Count without labels
  crawler-seo.md            ASN+UA labelling, crawler exclusion, always-on Challenge
  ip-reputation.md          the three IP-reputation rules and HostingProviderIPList
  managed-labels.md         which rule group produces which label; shared token labels
  managed-overrides.md      override semantics, version guidance, token domains, WCU
  rate-based.md             windows, thresholds, overlapping scope-downs
  cost-model.md             WCU and pricing structure, how to estimate
```

## Blast radius

- **Writes** only assessment artifacts in `output_dir`. It never edits its own files.
- **Never mutates AWS resources.** Every remediation is emitted as JSON and CLI for a
  human to apply. The scripts call no AWS API at all; the read-only commands above are
  for you to run.
- **No network.** The scripts make none, and the generated HTML makes none either — no
  external CSS, JS or fonts, so it renders offline.
- Reads WAF config exports and its own references. It does not read or transmit
  credentials.

Least-privilege credentials are sufficient. The workflow needs no write access at any
point.
