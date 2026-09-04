"""Static Markdown for WAF review reports: finding templates + report appendix.

TEMPLATES         — one entry per scripted finding, rendered by waf-assess.py
APPENDIX_SECTIONS — fixed reference sections A-F, rendered by waf-report.py
"""

TEMPLATES = {
"forgeable_allow": """## Issue {n} (Critical): {rule_names} — forgeable Allow rule bypasses all subsequent protections

**Rule**: {rule_line}
**Current state**: {stmt_summary}, action Allow, no scope-down

**Problem**:
- {forgeable_fields} {is_are} fully forgeable — an attacker can add {forgeable_example} to bypass all subsequent rules (IP reputation, Bot Control, rate limiting, etc.)
- The blast radius is global — all traffic paths are affected, no host or URI restriction
{dup_note}{opaque_note}
**Recommendation**:
- Change action to Count+Label (e.g., `custom:native-app` or `custom:probe`) instead of Allow — the traffic does not need to bypass WAF entirely
- If the rule is for internal probes or monitoring, use an unforgeable condition (IP Set or WAF Token) instead
{dup_rec}{opaque_rec}
---
""",
"hosting_provider_allow": """## Issue {n} (Critical): HostingProviderIPList overridden to Allow — cloud-hosted attack traffic bypasses all subsequent rules

**Rule**: {rule_name} (priority {priority})
**Current state**: `HostingProviderIPList` overridden to Allow

**Problem**:
- `HostingProviderIPList` default-Blocks cloud hosting and web hosting provider IPs. Overriding to Allow means all traffic from cloud platforms (AWS, GCP, Azure, etc.) is immediately allowed, skipping all subsequent rules
- Modern DDoS attacks heavily use cloud infrastructure (VPS, cloud functions, containers) — Allow override lets this attack traffic bypass IP reputation, Bot Control, rate limiting, and all other protections
- The correct approach is to override to Count (preserves labels for downstream rules), not Allow

**Recommendation**:
- Change `HostingProviderIPList` override from Allow to Count
- Count mode does not Block — it only adds labels, so enterprise users routed through cloud proxies are not affected

---
""",
"managed_scope_down": """## Issue {n} ({severity}): {rule_names} — a scope-down narrows a rule group that should inspect all requests

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
- The recommended matching condition for a baseline managed rule group is **All requests**. A scope-down means the group inspects a subset, and every request outside that subset passes it untouched
{core_note}- The group still consumes its full WCU whether it inspects one path or all of them, so a narrow scope-down pays the whole cost for part of the protection
- A scope-down is also the part of a managed rule group an operator writes, which makes it the part most likely to drift from the application as paths are added

**Recommendation**:
- Remove the scope-down so the group inspects all requests, unless there is a recorded reason it cannot
- Where the scope-down exists to avoid a false positive on one endpoint, invert the approach: leave the group inspecting everything and add a **label-based exception** for that endpoint. That keeps the protection everywhere else, and is the pattern AWS documents for exactly this case
- Where it exists for cost reasons, check the arithmetic first — a managed group's WCU is charged for its presence, not per request inspected, so narrowing it saves nothing on capacity

---
""",
"scope_down_too_narrow": """## Issue {n} (Medium): IP reputation / Anonymous IP rule groups have overly narrow scope-down — only inspects homepage

**Rule**: {rule_line}
**Current state**: scope-down is `uri_path EXACTLY '/'`, only applies to homepage path

**Problem**:
- Both rule groups only inspect `GET /` requests — all other paths (`/api/*`, `/login`, `/signup`, etc.) are not covered by IP reputation checks
- Malicious IPs only need to target any non-homepage path to completely bypass both rule groups
- This renders IP reputation protection effectively useless, especially for API path attacks

**Recommendation**:
- Remove the scope-down from both rule groups to inspect all traffic
- If scope restriction is needed for performance or cost, at minimum cover all critical paths, not just the homepage

---
""",
"challenge_on_post_api": """## Issue {n} (Medium): Challenge rules target API/POST paths — effectively equivalent to Block

**Rule**: {rule_line}
**Current state**: Challenge action applied to API paths and/or POST requests

**Problem**:
- Challenge can only be completed by browser GET requests (requires JavaScript execution and HTML response)
- API paths are typically accessed by native apps or JavaScript fetch/XHR, which cannot complete Challenge
- POST requests cannot complete Challenge — the client receives HTTP 202 but cannot resubmit the original POST
- Effective result: these rules act as Block for API clients and native apps

**Recommendation**:
- For API abuse prevention: consider rate-based rules instead of Challenge
- For POST endpoints: apply Challenge on the GET landing page before the POST, so users acquire a WAF token first
{dup_rec}
---
""",
"missing_baseline": """## Issue {n} (Medium): Missing {missing_names} baseline protection rule groups

**Rule**: N/A (missing rule)
**Current state**: Web ACL does not contain {missing_names}

**Problem**:
- {missing_detail}
- The current Web ACL focuses on DDoS and Bot protection but lacks application-layer attack protection

**Recommendation**:
{missing_rec}
---
""",
"token_domain": """## Issue {n} (Low): Token Domain configuration contains redundant subdomains

**Rule**: N/A (Web ACL global configuration)
**Current state**: token_domains contains {domain_list}

**Problem**:
- Token Domain uses suffix matching — `{apex}` automatically covers all subdomains at any depth
- Listing subdomains is redundant; it does not cause security issues but adds configuration maintenance cost

**Recommendation**:
- Keep only `{apex}`, remove all subdomain entries

---
""",
"no_logging": """## Issue {n} (Awareness): No WAF logging configuration detected

**Rule**: N/A (Web ACL global configuration)
**Current state**: WAF JSON export does not include logging configuration

**Problem**:
- WAF logging configuration is not included in the Web ACL JSON export — this finding does not mean logging is disabled, only that it cannot be verified from the export
- WAF logs are essential for security incident investigation, rule tuning, and false positive analysis

**Recommendation**:
- Verify that WAF logging is enabled (Kinesis Data Firehose, S3, or CloudWatch Logs) via the AWS Console or CLI
- Recommend retaining at least 90 days of logs and configuring CloudWatch alarms for key metrics (Block rate, Challenge rate)

---
""",
"ip_reputation_action": """## Issue {n} ({severity}): {sub_rule} is overridden to {action}, against its documented default of {default}

**Rule**: {rule_name} (priority {priority})
**Current state**: `{sub_rule}` overridden from **{default}** to **{action}**

**Problem**:
- {why_default}
- {consequence}

**Recommendation**:
- {fix}
- If the override was added to resolve a false positive, scope the exception instead: keep the sub-rule at its default and add a label-based exception for the specific caller or path that was affected. That preserves the protection everywhere else

---
""",
"missing_ip_reputation": """## Issue {n} (Medium): {missing_names} not present, so {gap}

**Rule**: N/A (missing rule)
**Current state**: Web ACL does not reference {missing_names}

**Problem**:
{details}
- Both groups are inexpensive in WCU terms and have low false-positive rates at their default actions, which is why they are recommended as a baseline rather than as a tuning exercise

**Recommendation**:
{recs}
- Add them **after** the Anti-DDoS rule group and **before** the application-layer groups, so cheap address-based filtering runs before signature inspection
- Verify remaining WCU capacity before adding: `AWSManagedRulesAmazonIpReputationList` is 25 WCU and `AWSManagedRulesAnonymousIpList` is 50 WCU

---
""",
"terminating_allow_strands": """## Issue {n} ({severity}): {rule_name} terminates with Allow, so it bypasses {count} below it {scope_desc}

**Rule**: {rule_name} (priority {priority})
**Current state**: {stmt_summary}, action **Allow**{label_note}

**Problem**:
- `Allow` is a **terminating** action. Any matching request is allowed immediately and evaluates **none** of the {count} at a higher priority number{shield_note}
- {scope_problem}
- {forge_note}
{stranded_list}
**Recommendation**:
- Change the action to **Count**. Count is non-terminating: any label is still applied, the request continues through the rules below, and nothing is exempted
- If the traffic genuinely needs an exemption rather than a full bypass, keep the match but add a rule label, then have only the specific rules that were causing the problem exempt that label. That narrows the exemption from every control to the one that needed it
- If the Allow is deliberate, it needs a documented owner and an accepted-risk record, and it should be narrowed from a path prefix to the specific callers involved — an IP set or a WAF token rather than a URI

---
""",
"deliberate_allowlist": """## Issue {n} (Awareness): {rule_name} is a deliberate allowlist, and therefore a standing exemption from every rule below it

**Rule**: {rule_name} (priority {priority})
**Current state**: {stmt_summary}, action **Allow** at priority {priority}, ahead of {count} other rules

**Problem**:
- This is **not** a misconfiguration. An IP or label based allowlist at the front of a Web ACL is the documented correct position, and a terminating Allow is precisely its function. It is recorded here because of what it implies, not because it is wrong
- The condition is one a caller cannot forge, so this is not a bypass anyone can reach at will
- But it is a standing exemption from **every** rule below it, including the managed rule groups and any Shield mitigation. Whoever is in the referenced set is exempt from this entire report
- IP sets outlive the reason they were created: a decommissioned office range reassigned to someone else, a partner's addresses after the integration ended, a contractor's VPN. None of that is visible in the Web ACL
- Allowed traffic is also invisible. It produces no block or count match, so an allowlisted source that starts behaving badly leaves nothing in the WAF metrics — and nothing in the logs either, under a filter that keeps only Block, Count and challenge outcomes

**Recommendation**:
- **Read the contents** and confirm every entry still needs to be there: `aws wafv2 get-ip-set --scope REGIONAL --region <region> --id <id> --name <name>`. The exemption is only as good as what is in the set
- Give the set an owner and a review date. This is the one rule in a Web ACL where staleness is invisible and consequential
- Where an entry needs an exemption from one specific rule rather than from everything, prefer Count plus a rule label, and have that rule exempt the label. That narrows the exemption to what actually needed it
- Consider whether anything in the set should be scoped to particular paths rather than the whole application

---
""",
"antiddos_position": """## Issue {n} ({severity}): The Anti-DDoS rule group evaluates after {count} that reduce the traffic it can inspect

**Rule**: {rule_name} (priority {priority})
**Current state**: {detail}

**Problem**:
- AWS's guidance on this rule group is specific about what may precede it: it should have **either the highest priority in the web ACL, or be placed right below any custom rules with `Allow` action**, such as IP-match allowlists. The reason is that its detection is behavioural — it compares current traffic against a baseline it builds from what it observes — so anything that removes traffic before it evaluates degrades the baseline itself
- Note the specificity: **`Allow` only**. The rules ahead of it here are not all Allow rules:
{offenders}
- A `Block` rule above it is the case most worth understanding. During an attack the denylisted traffic **is** the attack, so blocking it earlier means the rule group observes less of the event — and may not detect it at all. The protection you lose is not the denylist's, it is the AMR's
- When a rule group is first added, AWS places it at the **bottom** of the priority list. A group sitting mid-list usually means someone began moving it up and stopped

**Recommendation**:
- Move it to priority position {target_desc}
- {allow_note}
- A non-terminating `Count` rule above it is harmless to the baseline and may stay — that is how a crawler-labelling rule can precede it, so the group's scope-down can exempt verified crawlers by label
- Do **not** add a scope-down to this rule group to compensate for its position. A scope-down removes traffic from the baseline in exactly the way the position problem does, so it trades one form of the same defect for another
- Priorities are unique within a web ACL and `update-web-acl` replaces the whole rule set, so renumber in one call from a full `get-web-acl` body

---
""",
"group_level_count": """## Issue {n} ({severity}): {group_name} is overridden to Count for the entire rule group — every rule inside it is inert

**Rule**: {rule_name} (priority {priority})
**Current state**: Group-level override action is **Count**{config_note}

**Problem**:
- A group-level Count override forces **every** rule inside the group to Count. Nothing in it blocks, challenges or captchas — the whole group produces labels and CloudWatch metrics only
- {impact}
- This is the worst failure mode during an incident, because the dashboards show the control firing. Attention goes elsewhere while traffic reaches the origin
{shield_note}{intent_note}
**Recommendation**:
- {fix}
- Promote sub-rules individually rather than lifting the whole override at once, reading the per-rule metrics between each. Per-sub-rule metrics are already being collected
- Count without a review date is a control that quietly never turned on. If it is staged, give it a date and an owner

---
""",
"name_action_mismatch": """## Issue {n} (Medium): {rule_names} — the rule name states an intent the action contradicts

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
- The name says one thing and the configuration does another. Anyone reading the rule list — during an incident, or in a compliance review — will draw the wrong conclusion about what this Web ACL does
- {consequence}
- Which side is wrong cannot be determined from the configuration. If the name records the intent, there is an unclosed gap on an endpoint someone deliberately wrote a rule for. If the action is correct, the name is stale and actively misleading

**Recommendation**:
- Resolve the contradiction rather than the symptom: decide what the endpoint should do, then make the name and the action agree
- If it should block, stage the change in Count first and read the metric — a rule that has been allowing traffic may have real callers depending on it
- If the action is right, rename the rule and add a description recording why. A rule called `block-*` that allows will mislead the next person reading it under pressure

---
""",
"rate_layers_missing": """## Issue {n} ({severity}): The layered rate-limiting strategy is incomplete — {have_desc}

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
- AWS recommends three complementary rate-based rules, because each addresses a different attack shape and a gap in any tier is separately exploitable:
  - a **blanket** rule limiting any single source across all endpoints, against volumetric floods
  - **URI-specific** rules with much lower thresholds on sensitive or expensive endpoints — login, search, password reset, token issuance — against targeted brute force
  - a **reputation-scoped** rule applying the lowest limits to sources already identified as malicious by threat intelligence
{missing_detail}
- The tiers are not substitutes. A blanket threshold high enough not to disturb normal traffic is far too high to stop credential stuffing against a login endpoint, which needs a limit in the tens of requests rather than the thousands
{opaque_note}
**Recommendation**:
{recs}
- Deploy each new rule in Count first and read its metric before switching to Block. A URI-specific threshold is the one most likely to be set too low on the first attempt
- Order them cheapest-first and put the reputation-scoped rule after the IP reputation group that produces the label it scopes on, or the label will not exist when it evaluates

---
""",
"rate_threshold_vs_baseline": """## Issue {n} ({severity}): {rule_names} threshold is {verdict} the declared traffic baseline

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
- AWS's method is to take the observed peak request rate for a single source, add a 50–100% buffer, and use that as the threshold. The declared peak here is {peak_desc}, which puts the recommended range at **{lo:,}–{hi:,} requests per {window}s**
{problem}
**Recommendation**:
- {fix}
- Re-derive the threshold whenever the traffic baseline changes materially. A threshold set against last year's peak silently becomes either ineffective or hostile
- Confirm the declared peak is per **source**, not aggregate. An aggregate figure divided across many clients gives a threshold far too high, and this is the most common error in applying the method

---
""",
"rate_forwarded_ip": """## Issue {n} ({severity}): {rule_names} aggregate on the source IP while {front} sits in front, so every request appears to come from one address

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
- A rate-based rule aggregating on `IP` uses the address of whatever connected to the protected resource. With {front} in front, that is its address, not the client's
- The effect is not a weaker rule, it is an inverted one: **all traffic aggregates into a handful of edge addresses**, so the threshold is crossed by ordinary traffic and legitimate users are limited while a real attacker spread across many clients stays under it
- This is the misconfiguration AWS's own guidance calls out most often for rate-based rules, precisely because nothing about the rule looks wrong
{fallback_note}
**Recommendation**:
- Change the aggregation to **IP address in header**, with the header set to `X-Forwarded-For`
- **Set the fallback behaviour explicitly.** It governs requests whose header is absent or malformed: `MATCH` groups them together and rate-limits them as one bucket, `NO_MATCH` skips rate limiting for them entirely. Leaving it unset is how a header-stripping client ends up exempt
- Only trust the forwarded header when the front door is one you control and it overwrites the header. If clients can reach the resource directly, the header is attacker-settable and this change makes matters worse rather than better — lock the origin down first
{ga_note}
---
""",
"rate_fallback_unset": """## Issue {n} (Medium): {rule_names} aggregate on a forwarded header with no fallback behaviour set

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
- The fallback behaviour governs what happens to a request whose forwarded header is **absent or malformed**, and it is not set here
- The two options are opposite: `MATCH` groups those requests together and rate-limits them as one bucket; `NO_MATCH` skips rate limiting for them entirely. Leaving it unset means the outcome is whatever the service defaults to rather than what was intended
- `NO_MATCH` semantics are the dangerous direction: a client that simply omits the header is exempt from the rate limit, and omitting a header is trivial

**Recommendation**:
- Set `FallbackBehavior` explicitly. `MATCH` is the safer default — a request that cannot be attributed is still counted, rather than being waved through
- Choose `NO_MATCH` only where a legitimate client population genuinely cannot supply the header and being rate-limited as one bucket would break them, and record why
- Confirm the front door overwrites the header rather than appending to it. If clients can reach the resource directly, the header is attacker-settable and no fallback setting repairs that

---
""",
"rate_window_out_of_range": """## Issue {n} (Medium): {rule_names} — evaluation window outside the supported 60–600 second range

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
- AWS WAF supports evaluation windows of 60, 120, 300 or 600 seconds. A value outside that set is either being silently coerced or is a transcription error, and in either case the rule is not limiting over the period whoever wrote it intended
- The window is the other half of the threshold: 2,000 requests per 60 seconds and 2,000 per 600 seconds are a tenfold difference in the rate actually permitted

**Recommendation**:
- Set the window to one of the four supported values. 300 seconds is the default and suits most volumetric cases; 60 seconds detects a burst faster at the cost of more sensitivity to legitimate spikes
- Restate the threshold when changing the window, since the pair only means something together

---
""",
"rate_shared_ip_keys": """## Issue {n} (Awareness): {rule_names} — IP-only aggregation, and this client base shares addresses

**Rule**: {rule_line}
**Current state**: Aggregation key is `{key}` with no composite or fingerprint keys configured{client_note}

**Problem**:
- Aggregating on IP alone assumes one address is one client. {why_shared}
- The consequence is a threshold that cannot be set well: high enough not to catch a whole shared gateway, and therefore too high to catch an individual abuser behind one
- This is not a defect in the rule — IP aggregation is the correct default — but it is the reason a threshold that looks generous still produces complaints

**Recommendation**:
- Add a second aggregation key so the rule can distinguish clients sharing an address. `JA3Fingerprint` or `JA4Fingerprint` characterise the TLS client and cannot be set by the caller; `HTTPHeaderOrder` is a weaker but cheaper signal
- Where the application sets a session cookie, a composite key of source IP plus that cookie separates users behind one NAT gateway precisely
- Keep an IP-only rule as well, at a higher threshold, as the floor against a single abusive source. The two answer different questions

---
""",
"rate_rule_ineffective": """## Issue {n} (Medium): {rule_names} — rate limiting that does not limit

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
{problems}
- A per-IP rate limit is also the wrong shape for the distributed attacks an Anti-DDoS rule group exists for. It is still worth having as a floor against a single abusive source, which is exactly the case an unreachable threshold misses

**Recommendation**:
- Bring the threshold down to something a real client cannot reach but an abusive one can. Deploy the new threshold in Count first and read the metric for a week before switching to an enforcing action
- Then change the action to Block, or to a custom response if the application needs to distinguish rate limiting from other failures
- Consider a second rate-based rule aggregated on something other than IP — a header or a JA4 fingerprint — since mobile clients behind carrier NAT share addresses, so a per-IP limit either catches whole carriers or nobody
- Do not add a scope-down to the Anti-DDoS rule group to compensate; it degrades the traffic baseline that group's detection depends on

---
""",
"managed_count_overrides": """## Issue {n} (Medium): {count} overridden to Count{body_title}

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
{body_problem}{pairing_problem}- Each Count override records matches and blocks nothing. The usual reason is a false positive that was resolved by switching the whole sub-rule off rather than by scoping the exception, and nothing in the configuration records which endpoint caused it
- Some Count overrides are legitimate and widely recommended — `SizeRestrictions_BODY` in particular, because the 8 KB default causes false positives on uploads and large payloads. Those should stay, and be distinguished from the ones with no such justification

**Recommendation**:
- Keep the overrides that have a general justification: `SizeRestrictions_BODY`, and `NoUserAgent_HEADER` where non-browser clients are expected
- For the rest, find the endpoint that was producing false positives and scope the exception to it — a label-based exception, or a scope-down excluding that one path — rather than disabling the rule across the whole application
- Promote them one at a time, reading the per-rule CloudWatch metric between each. If the false positive cannot be identified, run the rule in Count and sample the matched requests in the console before deciding
{pairing_rec}
- Sub-rules switched off with no recorded reason are a worse position than sub-rules with documented exceptions

---
""",
"geo_vs_markets": """## Issue {n} (Medium): {rule_name} uses a {codes_count}-country denylist for a service operating in {markets_desc}, where an allowlist would be free and far more effective

**Rule**: {rule_name} (priority {priority})
**Current state**: Blocks {codes_list}

**Problem**:
- The declared market footprint is {markets_desc}. A denylist blocks the countries it names and admits every other, so the overwhelming majority of hostile traffic reaching this Web ACL arrives from countries the rule does not cover
- A denylist assembled from whichever sources caused trouble in the past lags the threat by however long it takes someone to notice and edit it
- Geo matching is **free** and evaluates before every paid rule group, so traffic dropped there is never inspected by the managed rule groups. Widening it reduces cost as well as exposure
- This is usually the cheapest available improvement in a review of this kind

**Recommendation**:
- Invert it to an allowlist — `NOT GeoMatchStatement([{markets_codes}])` with action Block — keeping the same priority. Add any further countries the business genuinely needs: partner integrations, offshore engineering access, app-store review traffic
- **Stage this in Count first, and for longer than the other changes.** Geo allowlisting is the change most likely to cut off a real user population nobody remembered — roaming customers, a payment provider's callback from outside the footprint, an internal team travelling. Read the metric for at least a full business cycle
- Keep any IP allowlist ahead of it, which is how a known partner outside the footprint stays reachable
- If an allowlist is judged too risky, the denylist needs a review date and an owner, because its value decays

---
""",
"opaque_rule_groups": """## Issue {n} (Awareness): {count} referenced rule groups are outside this export{wcu_title}

**Rule**: {rule_line}
**Current state**: {count} customer-owned rule groups referenced by ARN only. {wcu_state}

**Problem**:
- Their contents are not in this export, so nothing in this assessment can say whether the rules inside them are well chosen, whether they overlap, or whether they cover the endpoints that matter. That is a limit of the assessment rather than a defect in the configuration
{stranded_note}- {count} separate rule groups is unusual and suggests one per endpoint or per limit. Where several rate-based rules have overlapping scope-downs, only the lowest threshold ever triggers for the overlapping traffic and the rest are inert — worth checking once the contents are visible
{wcu_problem}
**Recommendation**:
- Retrieve the contents and re-run this assessment: `aws wafv2 get-rule-group --scope REGIONAL --region <region> --id <id> --name <name>` for each
- While auditing them, check for consolidation. If they are variations on one statement differing only in path and threshold, fewer rule groups with scope-downs would cost less capacity and be easier to reason about
{wcu_rec}
---
""",
"no_bot_management": """## Issue {n} (Awareness): No bot or fraud management on this Web ACL{client_title}

**Rule**: N/A (missing rule)
**Current state**: No `AWSManagedRulesBotControlRuleSet`, `AWSManagedRulesATPRuleSet` or `AWSManagedRulesACFPRuleSet` present

**Problem**:
- There is no bot classification of any kind. Credential stuffing on login, price or inventory scraping, and scripted account creation are the threats these rule groups address, and nothing here addresses them
{client_problem}- Bot Control is billed per request, at a level where placement matters: it belongs last in the Web ACL so cheaper rules filter traffic before it. That constraint interacts with any terminating Allow, since anything placed last is the first thing a bypass strands
- Raised for awareness rather than as a defect. {caveat}

**Recommendation**:
{recommendation}
---
""",
"duplicate_branch": """## Issue {n} (Medium): {rule_names} — a boolean branch repeats itself, so the duplicate is dead code

**Rule**: {rule_line}
**Current state**: {detail}

**Problem**:
- An `OR` of a condition with itself is a no-op: `a OR a` is `a`. The repeated branch can never change the outcome, so the rule evaluates fewer conditions than it appears to
- Nothing in the configuration looks wrong, which is what makes this survive review. Both branches are syntactically valid and reference real objects
{family_note}
**Recommendation**:
- {fix}
- Confirm the intended second condition and point the duplicate branch at it. If there is genuinely only one condition, remove the `OR` wrapper so the rule states what it does

---
""",
"single_address_family": """## Issue {n} (Medium): {rule_names} — every referenced IP set is IPv4, so IPv6 clients match nothing

**Rule**: {rule_line}
**Current state**: References {n_sets} IP set(s), all IPv4: {set_names}

**Problem**:
- An AWS WAF IP set holds a single address family, so covering both requires two sets. Only IPv4 is referenced here
- The consequence is asymmetric and both halves are bad. For an **allowlist**, IPv6 clients are not exempted, so a trusted partner or office range on IPv6 is subject to every rule below. For a **denylist**, IPv6 clients are not blocked, so any address deliberately denied can reach the application over IPv6
- ALBs and CloudFront are both dual-stack capable, and mobile carriers allocate IPv6 widely, so this is not a theoretical address family

**Recommendation**:
- List the account's IP sets (`aws wafv2 list-ip-sets --scope REGIONAL`) and check whether an IPv6 companion set already exists but is not referenced
- If none exists, create one and reference it in an `OR` branch alongside the IPv4 set. An empty IPv6 set is still worth referencing: it makes the intent explicit and gives somewhere to add an entry under pressure
- Read the contents of the existing sets while you are there. An allowlist is a standing exemption from the whole Web ACL, and IP sets outlive the reason they were created

---
""",
"orphan_managed_label": """## Issue {n} (Awareness): {sub_rule} produces a label that no rule consumes, so it contributes no protection

**Rule**: {rule_name} (priority {priority})
**Current state**: `{sub_rule}` runs at its default action of **Count**, and no rule in this Web ACL matches the label `{label}`

**Problem**:
- `{sub_rule}` defaults to Count by design: {why_count}
- In Count it adds a label and takes no action, so it protects nothing unless a later rule consumes that label. No rule in this Web ACL matches on any label
{subsume_note}
- This is Awareness rather than a defect. Copying the AWS default is not a misconfiguration — but it is worth knowing that a list you might assume is protecting you is currently only a metric, and why

**Recommendation**:
- {fix}
- Do not simply override the sub-rule to Block; the Count default is AWS declining to block these addresses on your behalf, and overriding it discards that judgement. A rate-based rule scoped down to the label limits a flagged address rather than refusing it
- A consuming rule must evaluate **after** priority {priority} to see the label, and must not sit below any terminating Allow

---
""",
"challenge_not_ready": """## Issue {n} (Awareness): No token domains and default Challenge immunity, so Challenge-based protection is not ready to switch on

**Rule**: N/A (Web ACL global configuration)
**Current state**: `token_domains` is {td_state}. {immunity_state}

**Problem**:
- With no token domains set, the WAF token is scoped to the protected resource's own domain. Correct for a single domain, and a real constraint if the application spans several — a client calling `api.example.com` with a token issued for `www.example.com` would not have it accepted
- Challenge immunity at the 300-second default re-verifies a client every five minutes. That is sized for a Challenge that fires on suspicion, not one that fires continuously
- Neither matters while nothing issues a Challenge, and nothing in this Web ACL currently does. Both become live decisions the moment a Challenge-based protection is enabled
- Raised as Awareness for that reason: this is not a gap in current protection, it is a pair of settings that will need answers, and finding them at the point of enabling a control is worse than knowing now

**Recommendation**:
- No action required while no rule issues a Challenge
- Before enabling any Challenge: set `token_domains` to the **apex** domain — suffix matching covers every subdomain at any depth, so listing subdomains is unnecessary and a wildcard is not supported — and raise immunity to at least 14400 seconds for an always-on Challenge
- Record the decision either way. "Challenge is deliberately off because our clients cannot complete one" is a useful sentence for the next reviewer, and its absence is what makes this ambiguous

---
""",
"logging_disabled": """## Issue {n} (Critical): WAF logging is not enabled

**Rule**: N/A (Web ACL global configuration)
**Current state**: Logging is confirmed not configured for this Web ACL

**Problem**:
- Without logs there is no record of what WAF blocked, challenged or allowed. A false positive cannot be diagnosed, a rule cannot be tuned, and an incident cannot be reconstructed after the fact
- Sampled requests in the console cover a rolling three-hour window and a sample rather than the full stream, so they are not a substitute
- This is stated as a fact rather than as an unverified gap, because the application context supplied for this assessment says logging is not configured

**Recommendation**:
- Enable logging to CloudWatch Logs, S3, or Kinesis Data Firehose. Firehose suits high volume and onward delivery to a SIEM; CloudWatch Logs is the quickest to query with Logs Insights and the easiest to over-retain by accident
- Redact the authorization header, session cookies and any token-bearing query argument in the logging configuration
- Set retention explicitly — at least 90 days for investigation — and consider a logging filter that keeps Block, Count and challenge outcomes while dropping plain Allows, which removes most of the volume and none of the records anyone reads

---
""",
"logging_gaps": """## Issue {n} (Medium): WAF logging is enabled but incompletely configured

**Rule**: N/A (Web ACL global configuration)
**Current state**: Logging to {destination}

**Problem**:
- {gap_detail}

**Recommendation**:
{gap_rec}
---
""",
"default_action_redundancy": """## Issue {n} (Low): {rule_name} rule is redundant with default Allow action

**Rule**: {rule_name} (priority {priority})
**Current state**: `{stmt_summary}` → Allow, while Web ACL default_action is already Allow

**Problem**:
- This rule matches all requests (any URI starts with `/`), action is Allow
- The Web ACL default_action is already Allow, making this rule completely redundant
- The rule consumes WCU and adds evaluation overhead with no practical effect

**Recommendation**:
- Remove the {rule_name} rule

---
""",
"count_without_labels": """## Issue {n} (Awareness): {rule_names} — Count rules without labels, metric-only

**Rule**: {rule_line}
**Current state**: Count action, no RuleLabels

**Problem**:
- Count rules without labels only produce CloudWatch metrics — downstream rules cannot act on the match result
- If the intent is to take action based on these matches, the current configuration cannot achieve it
{dup_note}
**Recommendation**:
- If these rules are for monitoring only, keep one and add descriptive naming; remove duplicates
- If the intent is to act on matches (Block, Challenge, etc.), either change the action or add labels for downstream rules to consume
{dup_rec}
---
""",
"challenge_all_during_event": """## Issue {n} (Medium): ChallengeAllDuringEvent overridden to Count — soft mitigation disabled during DDoS events

**Rule**: {rule_name} (priority {priority})
**Current state**: `ChallengeAllDuringEvent` overridden to Count

**Problem**:
- `ChallengeAllDuringEvent` is AntiDDoS AMR's core soft mitigation — during DDoS events, it Challenges all challengeable requests, filtering attack tools that cannot execute JavaScript
- Overriding to Count means this rule only produces metrics during DDoS events, with no mitigation action
- With `sensitivity_to_block: {block_sens}`, only {block_desc} DDoS requests are Blocked; disabling ChallengeAllDuringEvent leaves {remaining_desc} attack traffic with no soft mitigation

**Recommendation**:
- **Best**: if architecture supports it, use separate Web ACLs for frontend (browser) and backend (API/native app) traffic. Frontend Web ACL enables ChallengeAllDuringEvent with default config; backend Web ACL disables Challenge and raises Block sensitivity
- **If frontend and API share the same domain**: deploy dual AMR instances in the same Web ACL — one for browser traffic (ChallengeAllDuringEvent enabled), one for API/native app traffic (Challenge disabled, Block sensitivity MEDIUM). See Appendix B for implementation steps
- Do NOT use the "single instance + all Count + custom label rules" pattern — it requires understanding 6+ AMR labels, disables AMR's internal coordination logic, and still requires answering which paths can Challenge

---
""",
"unanchored_exempt_regex": """## Issue {n} (Medium): AntiDDoS AMR exempt URI regex is unanchored — attackers can bypass via path injection

**Rule**: {rule_name} (priority {priority})
**Current state**: Exempt regex `{regex}`, API path branches are not anchored with `^`

**Problem**:
- The following regex branches are not anchored with `^`, meaning they are "contains" matches rather than "starts-with": {unanchored_list}
- Attackers can craft paths containing these keywords to bypass `ChallengeAllDuringEvent`, e.g.: {examples}
- This allows attack requests to be exempted from Challenge during DDoS events

**Recommendation**:
- Add `^` anchoring to all API path branches: {anchored_suggestion}
- Static asset suffix matching (e.g., `\\.(css|js|png)$`) is already correctly anchored with `$` — no change needed

---
""",
"missing_crawler_labeling": """## Issue {n} (Medium): Missing crawler labeling rule — search engine crawlers may be Challenged during DDoS events

**Rule**: N/A (missing rule)
**Current state**: No ASN + UA crawler labeling rule in the Web ACL

**Problem**:
- `ChallengeAllDuringEvent` will Challenge all challengeable requests during DDoS events, including search engine crawlers (Googlebot, Bingbot, etc.)
- Real-world cases show crawlers may index the Challenge interstitial page (HTTP 202) instead of actual content during DDoS events, severely damaging SEO rankings
- Bot Control's `bot:verified` label can identify verified crawlers, but Bot Control must be placed last in the rule chain (cost optimization) — by then AntiDDoS AMR has already evaluated the request

**Recommendation**:
- Add an ASN + UA crawler labeling rule before AntiDDoS AMR to label Google (ASN 15169), Bing (ASN 8075), and other crawlers with `crawler:verified` (full rule JSON in Appendix A)
- Add a scope-down to AntiDDoS AMR excluding the `crawler:verified` label

---
""",
"bot_control_search_allow": """## Issue {n} (Low): Bot Control CategorySearchEngine/CategorySeo overridden to Allow

**Rule**: {rule_name} (priority {priority})
**Current state**: `{override_names}` overridden to Allow

**Problem**:
- These Allow overrides only affect "unverified" search engine bots — requests claiming to be search engine crawlers but failing reverse DNS verification
- Real Googlebot/Bingbot (verified) are already not Blocked by these rules — they pass through with `bot:verified` label regardless of the override
- Forged Googlebot UAs (reverse DNS fails) do NOT match `CategorySearchEngine` — they fall through to `SignalNonBrowserUserAgent` and are Blocked, regardless of the override
- The Allow override lets unverified search engine bots bypass all subsequent WAF rules — limited blast radius, but unnecessary

**Recommendation**:
- Remove the Allow overrides on `{override_names}`, restore default Block
- For SEO protection during DDoS events, use the ASN + UA crawler labeling rule (see Appendix A) instead of Bot Control Allow overrides

---
""",
"duplicate_rules": """## Issue {n} (Awareness): Duplicate {rule_type} rules — each pair has identical logic

**Rule**: {rule_line}
**Current state**: {pair_count} pairs of {rule_type} rules with identical {match_desc}

**Problem**:
- {dup_problem}
- Duplicate rules consume WCU and increase maintenance cost

**Recommendation**:
- Remove the lower-priority duplicate from each pair, keeping the higher-priority version
- If the pairs have different business intent (e.g., one for monitoring, one for enforcement), differentiate them in naming and configuration

---
""",
"managed_versions": """## Issue {n} (Low): {detail}

**Rule**: {rule_name} (priority {priority})
**Current state**: Using {current_version}

**Problem**:
- {version_problem}

**Recommendation**:
- {version_rec}
- Test in a staging environment before upgrading to confirm no increase in false positives

---
""",
"missing_always_on_challenge": """## Issue {n} (Medium): Missing Always-on Challenge — DDoS protection relies on reactive detection delay

**Rule**: N/A (missing rule)
**Current state**: No Always-on Challenge rules for landing pages in the Web ACL

**Problem**:
- All reactive protections (AntiDDoS AMR, rate-based rules) have an inherent delay between attack start and mitigation activation
- Always-on Challenge is proactive — it continuously requires browser verification on landing page paths, filtering non-browser attack traffic from the first request with zero detection delay
- Without Always-on Challenge, non-browser DDoS traffic can reach the origin unimpeded during the detection delay window

**Recommendation**:
- Add two rules to implement Always-on Challenge (see Appendix C):
  1. Count+Label rule: match landing page URIs ({uri_list}), add label `custom:landing-page`
  2. Challenge rule: match `custom:landing-page` label, apply Challenge action; exclude `crawler:verified` label (requires crawler labeling rule from Appendix A)
- Set Challenge rule token immunity time to at least 4 hours (14400 seconds) to minimize impact on real users

---
""",
"priority_order": """## Issue {n} (Medium): Rule priority order issues — {summary}

**Rule**: Multiple rules
**Current state**: {current_state}

**Problem**:
{problems}

**Recommendation**:
- After cleaning up duplicate rules, reorganize priority order
- Reorder to the baseline in **Appendix D**. The two moves that matter most are the Anti-DDoS AMR to the top (or directly below any `Allow` rules) and the false-positive exceptions below the rule group whose label they consume

---
""",
"opaque_search_string": """## Issue {n} (Awareness): {rule_name} contains opaque/hash-like search_string value

**Rule**: {rule_name} (priority {priority})
**Current state**: {stmt_summary}

**Problem**:
- The match value `{value}` appears to be a shared secret, hash, or token
- {risk_note}
- Anyone with read access to the Web ACL configuration (including IAM users with overly broad permissions) can obtain this value

**Recommendation**:
- {rec_note}
- Periodically rotate the value and audit IAM access to WAF configuration

---
""",
"managed_allow_override": """## Issue {n} (Awareness): Managed rule group has Allow override — bypasses all subsequent rules

**Rule**: {rule_name} (priority {priority})
**Current state**: {override_detail}

**Problem**:
- Overriding a managed rule to Allow means matching requests are immediately allowed and skip ALL remaining rules — both within the rule group and in the Web ACL
- This is the most dangerous override type; it creates a potential bypass path

**Recommendation**:
- Review whether Allow is truly needed; in most cases, Count (preserves labels, request continues) is the safer choice
- If Allow is intentional, document the business justification

---
""",
}


# ── Report appendix (sections A-F) ────────────────────────────────────

APPENDIX_SECTIONS = r"""
---

# Appendix

## Appendix A: ASN + UA Crawler Labeling Rule

Place this rule **before** AntiDDoS AMR and Always-on Challenge. It labels verified search engine crawlers so downstream rules can exclude them via scope-down.

```json
{{
  "Name": "label-verified-crawlers",
  "Priority": "<place before AntiDDoS AMR>",
  "Action": {{
    "Count": {{}}
  }},
  "RuleLabels": [
    {{ "Name": "crawler:verified" }}
  ],
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "label-verified-crawlers"
  }},
  "Statement": {{
    "OrStatement": {{
      "Statements": [
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "googlebot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [15169] }} }}
            ]
          }}
        }},
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "bingbot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [8075] }} }}
            ]
          }}
        }},
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "yandexbot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [13238, 208722] }} }}
            ]
          }}
        }}
      ]
    }}
  }}
}}
```

Confirmed ASNs: Google 15169, Bing 8075, Yandex 13238 + 208722. For other search engines (Baidu, Yahoo Japan, etc.), verify current ASNs from their official documentation before adding.

---

## Appendix B: Dual AntiDDoS AMR Instance Pattern

When browser and native app traffic need different AntiDDoS strategies:

1. **Add a Count+Label rule before both AMR instances** to label native app traffic (e.g., label `native-app:identified`). This rule must have a higher priority (lower number) than both AMR instances.
2. **AMR instance 1 (browser traffic)**: scope-down excludes the native app label. `ChallengeAllDuringEvent` enabled. Block sensitivity: LOW (default).
3. **AMR instance 2 (native app traffic)**: scope-down matches the native app label only. `ChallengeAllDuringEvent` disabled. Block sensitivity: MEDIUM (since Challenge is unavailable, raise Block sensitivity for adequate protection).
4. **Implementation**: The AWS console does not allow adding the same managed rule group twice. First copy the existing AMR rule's JSON. Then create a new **custom rule** in the Web ACL, open its **JSON editor**, paste the copied AMR JSON, change `Name` and `MetricName` to unique values (e.g., `AntiDDoS-NativeApp`), then save.

Crawler exclusion scope-down (add to AMR scope-down via `AndStatement` if AMR already has one):

```json
{{
  "NotStatement": {{
    "Statement": {{
      "LabelMatchStatement": {{
        "Scope": "LABEL",
        "Key": "crawler:verified"
      }}
    }}
  }}
}}
```

---

## Appendix C: Always-on Challenge for Landing Pages

Two-rule pattern for proactive DDoS defense on landing page URIs:

1. **Label rule** (Count+Label): matches landing page URIs (e.g., `/`, `/login`, `/signup`) and adds label `custom:landing-page`. Action: Count (request continues).
2. **Challenge rule**: matches `custom:landing-page` label and applies Challenge action. Exclude verified crawlers by adding a `NotStatement` for `crawler:verified` label.

The user must define their own landing page URI list based on their application.

Recommended token immunity time: ≥ 4 hours (14400 seconds). Real users complete JS verification once and browse uninterrupted for the entire immunity period.

---

## Appendix D: Baseline Rule Priority Order

Reconciled from AWS's Anti-DDoS placement guidance, the AWS WAF rule-order best practice, and
this skill's own additions. Reviewed 2026-08-29.

| Position | Rule type | Rationale |
|----------|-----------|-----------|
| 1 | Custom rules with **Allow** action (IP allowlists) | The only thing AWS sanctions above the Anti-DDoS AMR. Optional — if you have none, the AMR goes first |
| 2 | **Count + label** rules (crawler labelling, client-type tagging) | Non-terminating, so they reduce what the AMR inspects by nothing, and every downstream scope-down depends on the label existing |
| 3 | **Anti-DDoS AMR** | Detection is behavioural and baselined from observed traffic, so anything terminating above it degrades the baseline |
| 4 | Operator explicit **Block** (IP denylist, geo block) | Below the AMR deliberately: during an attack the denylisted traffic *is* the attack, and blocking it earlier hides the event from the AMR |
| 5 | Rate-based — country / bad-source scoped | Your own reputation judgment before the vendor's |
| 6 | Rate-based — specific URI | Most specific first: a rate rule that Blocks is terminating, so the stricter threshold must get its chance |
| 7 | Rate-based — blanket | Least specific of the three |
| 8 | Amazon IP reputation list | Vendor reputation, higher confidence |
| 9 | Anonymous IP list | Vendor reputation, lower confidence and more false positives |
| 10 | Always-on Challenge | Filters non-browser traffic before paid inspection; Challenge fees apply only to requests actually challenged |
| 11 | Core Rule Set (and Known Bad Inputs) | Broad baseline signature inspection |
| 12 | Use-case AMRs (SQLi, Linux, Windows, PHP, WordPress) | Stack-specific, narrower than CRS |
| 13 | **False-positive exception** rules | Consumes a label its target group emits, so it can only work *after* that group |
| 14 | Application-specific custom rules | Business logic |
| 15 | Bot Control | Per-request priced, so it belongs after everything that can filter for free |
| 16 | Fraud Control (ATP, ACFP) | Narrowest and most expensive per request |
| — | Shield mitigation rule group | Placed by Shield Advanced automatically, always last. Leave it |

**The five principles this encodes.** Label producers before consumers. Non-terminating rules
may precede the Anti-DDoS AMR; terminating ones should not. Operator decisions before vendor
decisions. Most specific before most general. Free, then WCU-costly, then per-request priced.

**Two positions are reviewed judgement calls, not AWS's words.** Position 2 reconciles the
Anti-DDoS placement guidance (which names only `Allow` rules) with the crawler-labelling
requirement, on the grounds that a `Count` rule removes no traffic. And positions 5–7 versus
8–9 put your own rate rules ahead of AWS's reputation lists; the reverse is also defensible,
since a reputation `Block` would keep known-bad traffic out of the rate counters, and neither
ordering carries a per-request fee.

---

## Appendix E: WCU Capacity Reminder

{wcu_text}

After implementing any recommended changes, verify the new WCU total does not exceed 5000. Check in the AWS Console: WAF → Web ACLs → select your Web ACL → the capacity is shown in the overview.

---

## Appendix F: Common Override Recommendations

When adding or reviewing managed rule groups, consider these common overrides:

**AWSManagedRulesCommonRuleSet (CRS):**
- Override `SizeRestrictions_Body` to **Count**. This rule blocks request bodies larger than 8KB, which frequently causes false positives on file upload endpoints, API endpoints with large payloads, and form submissions with rich content.

**AWSManagedRulesBotControlRuleSet (Bot Control Common level):**
- Override `SignalNonBrowserUserAgent` to **Count**. Default Block will block legitimate non-browser clients (native apps using okhttp/gohttp, API clients, monitoring tools).
- Override `CategoryHttpLibrary` to **Count**. Same reason — legitimate HTTP libraries used by native apps and API clients will be blocked.

**AWSManagedRulesAnonymousIpList:**
- Review `HostingProviderIPList` carefully. Default Block will block requests from cloud platforms and hosting providers. If your clients may originate from cloud-hosted environments (e.g., enterprise users behind cloud proxies, SaaS integrations), override to **Count**. Never override to Allow — that lets cloud-hosted attack traffic bypass all subsequent rules.
"""
