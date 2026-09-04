# Cost and WCU impact

`waf-assess.py` emits the countable facts and no dollar figures: `web_acl.capacity`,
`actual_capacity` and `effective_capacity` in `waf-summary.json`, the managed rule groups
in `rules[]`, and the `bot_control` / `fraud_control` flags in `pre-checks.json`. This file
explains how to turn those into an estimate, and why the split exists — published rates
change, so a rate baked into a script becomes a confidently wrong number. The inputs are
stable; the rates are not.

**Use `effective_capacity`, not `capacity`.** The published `capacity` understates a web ACL
whose rules were added after the figure was recorded, so billing above the 1,500 WCU
allocation gets computed from the wrong number.

**Always fetch current rates from https://aws.amazon.com/waf/pricing/ before quoting
money, and say in the report which date the rates came from.**

Rates below were read from that page on **2026-08-19** and are recorded so you can sanity-check
a fetched value, not so you can skip the fetch:

| Component | Rate |
|---|---|
| Web ACL | $5.00 / month |
| Rule | $1.00 / month |
| Rule group (managed or your own) added to a web ACL | $1.00 / month |
| Requests inspected | $0.60 / million |
| WCU surcharge | $0.20 / million requests per 500 WCU above 1,500 |
| Body inspection surcharge | $0.30 / million requests per additional 16 KB |
| Fraud Control subscription | $10 / month per web ACL |

Regional variation applies to the base WAF fees; the intelligent-threat-mitigation fees
are the same in all Regions. Monthly fees prorate hourly.

Logging note from the same page: WAF includes 500 MB of CloudWatch Logs and vended-logs
ingestion per 1 million WAF requests, billed by CloudWatch beyond that under the
`VendedLog-Bytes-WAFlogs`, `S3-Egress-Bytes-WAFLogs` and `VendedLogIA-Bytes-WAFlogs`
usage types. Those usage types are the ones to look for in Cost Explorer when a customer
asks why WAF logging is expensive.

## What drives WAF cost

Five components. Only the first three appear in most estimates.

**Web ACL fee** — monthly, per web ACL, prorated hourly.

**Rule fee** — monthly, per rule you create. Separately, each rule group added to the
web ACL carries its own monthly fee, whether it is an AWS managed group, a partner
group, or one of your own. `cost_inputs.billable_rule_count` counts standalone rules;
`managed_or_custom_rule_groups` counts groups.

**Request fee** — per million requests inspected by the web ACL.

**WCU surcharge** — this is the one people miss. The request fee covers up to 1,500 WCU.
Above that, each additional 500 WCU adds a further per-million-request charge. So
capacity is not just a ceiling, it is a recurring multiplier on every request.

```
surcharge_increments = ceil(max(0, effective_wcu - 1500) / 500)
monthly_surcharge    = surcharge_increments x wcu_rate x monthly_requests_in_millions
```

`cost_inputs.wcu_surcharge_increments` is already computed. Where an internal export
reports both `capacity` and a higher `actual_capacity`, the scanner uses the higher one
— bill against real consumption, not the published number.

A second surcharge applies per additional 16 KB of body inspected beyond the default
limit. Relevant only where rules inspect `Body` or `JsonBody` with a raised limit.

**Intelligent threat mitigation** — the paid rule groups, charged as a monthly group fee
plus a per-request analysis fee:

| Feature | Included allowance |
|---|---|
| Bot Control — Common | first 10 million requests/month |
| Bot Control — Targeted | first 1 million requests/month |
| Fraud Control — ATP, ACFP | per pricing page |
| Anti-DDoS rule group | flat + usage, per pricing page |

CAPTCHA and Challenge are charged per attempt and per response served — **except** when
driven by Targeted Bot Control or Fraud Control, where they are free. Attach a CAPTCHA
action to Common Bot Control or a custom rule and it becomes billable. These attempts do
not appear in WAF logs, so this line is hard to reconcile after the fact; flag it as an
estimate rather than a measurement.

## Shield Advanced coverage — get this boundary right

Shield Advanced changes the arithmetic, but it covers **standard** WAF capabilities only.
Getting the boundary wrong in either direction produces a bad recommendation, so the
scanner spells it out in `cost_inputs.shield_advanced_covers` and
`shield_advanced_does_not_cover`.

Covered on protected resources:

- the web ACL monthly fee
- the per-rule monthly fee
- the base per-million-request inspection fee — **up to 1,500 WCU and the default body
  size**
- the **Anti-DDoS managed rule group and its request fees**, for up to **50 billion
  requests per month across the organization**; beyond that it bills per the Shield
  Advanced pricing page

Explicitly **not** covered, even on protected resources:

- the per-request surcharge for WCU above 1,500
- Bot Control request fees
- Fraud Control (ATP, ACFP) subscription and request fees
- CAPTCHA attempt and Challenge response fees
- body inspection beyond the default size
- AWS WAF on any resource *not* protected by Shield Advanced

Two consequences that change what you recommend.

**Anti-DDoS is genuinely free at normal volumes.** Where Shield Advanced is present and
the Anti-DDoS rule group is absent, that is the headline recommendation: the strongest
available L7 DDoS control, included in a subscription already being paid for. State the
50-billion-request qualifier rather than saying "free" unqualified — it is far above
typical volume, but the caveat is what makes the claim credible.

**WCU becomes one of the few remaining WAF levers.** For a Shield Advanced customer above
1,500 WCU, the surcharge is real cash that the subscription does not absorb, so trimming
capacity moves from hygiene to cost saving — raise the severity of any capacity finding
accordingly when you see that combination. Note too that Shield Advanced's automatic
application-layer mitigation rule group itself consumes 150 WCU and counts toward the
total — so part of the overage may be Shield's own footprint.

For request-heavy workloads the reverse calculation is worth raising unprompted: at high
volume, Shield Advanced can cost less than the standard per-request WAF charges it
replaces.

## Logging cost

Logging itself is free. The destination is not, and at high request volume destination
ingest and storage usually dominate the whole WAF bill.

Log filtering is free and is the highest-leverage lever — keep blocked, counted,
CAPTCHA and Challenge records and drop the rest, and volume falls by whatever fraction
of your traffic is ordinary. Keep `COUNT` while you are still tuning staged rules.

Retention is the second lever. Indefinite retention accrues cost forever for logs nobody
reads.

## Estimating a recommendation

State the recurring delta and be explicit about the request volume you assumed, because
that assumption dominates the result. If monthly request volume is unknown, ask for it —
or give the estimate per million requests and let the reader multiply.

Worked shape, with `R` = current published rates:

```
Enable Anti-DDoS managed rule group
  + group monthly fee                          (R.rule_group)
  + per-request analysis fee x volume          (R.antiddos_requests x M)
  - INCLUDED in a Shield Advanced subscription up to 50 billion requests/month
    across the organization -> net zero at normal volume
  WCU: +~200 WCU. Check whether this crosses a 500 WCU boundary; if it does,
       add one surcharge increment across ALL requests, not just matched ones --
       and that surcharge is NOT covered by Shield Advanced.

Scope Bot Control away from static assets
  - saves R.bot_common_requests x (static fraction of M)
  - typical static share of a browser-facing site: 40-70% of requests
  WCU: negligible (a regex scope-down is a few WCU)

Trim rule groups that do not match the stack
  - removes the monthly group fee per group
  - if WCU drops below a 500 boundary, removes a surcharge increment on ALL requests
  This is the recommendation that most often pays for the others.
```

The WCU boundary effect is worth calling out explicitly whenever a recommendation lands
near one: adding 40 WCU is free if you are at 1,400 and costs a full increment across
every request if you are at 1,490.

## Presenting it honestly

Give a range, not a point estimate, and name the driver: "roughly $X–Y per month at the
current ~N million requests, dominated by the Bot Control per-request fee."

Separate one-off from recurring — implementation effort is one-off, group and request
fees are forever.

Say when a security recommendation costs money and is still worth it. A report that
only recommends free changes is not an assessment, it is an upsell in reverse. Equally,
name the changes that are free or cash-positive — reordering rules, scoping Bot Control,
deleting unmatched rule groups, log filtering — because those are the ones that get
approved this quarter.
