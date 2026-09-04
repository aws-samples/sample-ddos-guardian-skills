# WAF Rules Assessment Checklist

Evaluate each item. Skip items irrelevant to the Web ACL's purpose.

Phase 1 (sections 1–16): Independent checks.
Phase 2 (sections 17–18): Global cross-checks — require Phase 1 findings as input.

**These section numbers are the contract between the script and the agent.** `llm_sections`
in `findings-metadata.json` and `checklist_sections` on each finding are indexes into this
file, and `ALWAYS_LLM_SECTIONS = {5, 8, 17}` in `waf-assess.py` names three of them
directly. Renumbering a section silently changes what the agent is asked to cover, so add
at the end rather than inserting.

---

## Phase 1: Independent Checks

### 1. Allow Rules Audit

For every Allow rule:
- [ ] Is the matching condition forgeable? (UA, cookie, header = forgeable; IP set, WAF token, ASN = unforgeable)
- [ ] Does bypassing all subsequent rules create a security gap?
- [ ] For managed rule group Allow overrides: does the default already handle the case?

If a UA-based Allow rule is found, note `UA_ALLOW_FOUND` — referenced by section 5.

### 2. Scope-down Statements

For every managed rule group with a scope-down:
- [ ] Does the scope-down make the rule group ineffective? (e.g., `URI EXACTLY "/"` = only homepage checked)
- [ ] Is the scope-down too broad?
- [ ] Regex anchoring: unanchored patterns are `contains` matches

### 3. AntiDDoS AMR Configuration

- [ ] Is `ChallengeAllDuringEvent` enabled (not overridden to Count)?
- [ ] If disabled for native app reasons → recommend dual AMR instance (read antiddos-amr.md for details)
- [ ] Exempt URI regex: are API path branches anchored with `^`? Unanchored = attackers can bypass via paths containing the keyword
- [ ] Regex `|` precedence: `$` only anchors the last branch unless grouped with `()`
- [ ] **SEO**: is there a crawler labeling rule before AMR? Without it, crawlers get challenged during DDoS events (read crawler-seo.md)

### 4. Challenge Action Applicability

For every Challenge or CAPTCHA rule:
- [ ] Does it target requests that can complete Challenge? (Only browser GET text/html)
- [ ] POST/API/native app = effectively Block. Intended?
- [ ] Challenge on rate-limit for API paths: low severity if users won't exceed threshold

**Count rules with Challenge/Block intent:**
- [ ] If a Count rule's name suggests Challenge/Block intent: evaluate statement as if action were already switched. Flag as Medium if broad match would Block POST/API/native app traffic.

### 5. Bot Control Configuration

- [ ] Common level only → Awareness finding (read bot-control.md for capability description)
- [ ] Allow override on category rules → lets unverified bots bypass all subsequent rules
- [ ] CategorySearchEngine/CategorySeo Allow → Low severity, limited blast radius. Correct approach: crawler labeling rule
- [ ] SignalNonBrowserUserAgent and CategoryHttpLibrary → best practice: override to Count

If `UA_ALLOW_FOUND`: native app traffic will enter Bot Control after fix.
- Short-term: scope-down Bot Control with unforgeable label (bypasses entire rule group)
- Medium-term: integrate WAF Mobile SDK (read bot-control.md for details)
- **NEVER override TGT_TokenAbsent to Count**

### 6. Rate-based Rules

- [ ] Activation delay exists — not instantaneous
- [ ] Challenge on API paths = effectively Block (low severity)
- [ ] Thresholds reasonable? (payment APIs < static pages)
- [ ] Rate limiting coverage for native app traffic?
- [ ] Overlapping scope-downs: only lowest threshold triggers for overlapping traffic

### 7. IP Reputation and Anonymous IP Rules

- [ ] Are rule groups inspecting all traffic? (Check scope-down)
- [ ] AWSManagedIPDDoSList at default Count: only adds label. If no downstream rule uses it → no protection (read ip-reputation.md)
- [ ] HostingProviderIPList: default Block → override to Count. Override to Allow → dangerous.

### 8. Landing Page and Cookie-based Logic

- [ ] Business cookies used for security decisions? (forgeable)
- [ ] Better: Count+Label rule on landing page URIs → always-on Challenge on labeled requests
- [ ] WAF token replaces cookie-based user detection (unforgeable)
- [ ] Exclude verified crawlers from Challenge (requires crawler labeling rule)

### 9. Missing Baseline Protections

- [ ] CRS present? If recommending: override SizeRestrictions_Body to Count
- [ ] KnownBadInputsRuleSet present? (Log4j, Java deserialization)
- [ ] Is absence intentional? (DDoS-only Web ACL)

### 10. WCU Awareness

Remind user to verify WCU ≤ 5000 after adding recommended rules.

### 11. Token Domain Configuration

- [ ] Apex domain covers all subdomains at any depth automatically (suffix-based matching)
- [ ] Wildcard (*) not needed

### 12. Managed Rule Group Versions

- [ ] SQLiRuleSet pinned below 2.0 → recommend upgrade
- [ ] BotControlRuleSet pinned below 5.0 → recommend upgrade
- Other rule groups: no action needed on version numbers

### 13. Logging and Monitoring

If no WAF logging config visible → remind user logging is essential for diagnostics.

### 14. Hashed or Opaque search_string

For byte_match rules with hash/random-token search_string:
- [ ] Evaluate rule normally first (Allow audit, forgeability, etc.)
- [ ] Emit Awareness: value may be shared secret or redacted. Warn about leakage risk.
- [ ] Especially warn if action is Allow — leaked secret = full WAF bypass

### 15. Default Action

- [ ] default_action Allow or Block? CustomRequestHandling is normal.
- [ ] Redundant trailing Allow-all rule: if default is Allow and last rule is Allow-all → recommend removing

### 16. Always-on Challenge for Landing Pages

- [ ] Is there an always-on Challenge targeting landing page URIs? (read crawler-seo.md for implementation)
- [ ] If absent + DDoS protection objectives → Medium severity. Recommend two-rule pattern: Count+Label on landing page URIs → Challenge on label (exclude crawlers)
- [ ] Token immunity time ≥ 4 hours (14400s)?
- [ ] Crawler labeling rule placed before Challenge rule?

---

## Phase 2: Global Cross-checks

### 17. Cross-rule and Label Dependency Analysis

**17a. Label source verification:**
- [ ] Token labels (`token:absent/accepted/rejected`) = shared, produced by Bot Control, ATP, ACFP, AND AntiDDoS AMR
- [ ] `challengeable-request` = produced by AntiDDoS AMR
- [ ] Custom Count rules without labels → Awareness (metric-only or missing labels?)

**17b. Fix impact analysis:**
- [ ] For each fix: trace affected traffic through full rule chain
- [ ] Does fix A break rule B? Remove a label? Prevent downstream rules from working?
- [ ] Document recommended fix order and simultaneous changes needed

### 18. Rule Priority Ordering

The baseline order is **Appendix D** of the report, reviewed 2026-08-29. It is enforced by
`_gen_priority_order`, and the Anti-DDoS position has its own check (`_gen_antiddos_position`)
because it is the only tier whose effectiveness depends on what precedes it.

```
 1 Custom rules with Allow action (IP allowlists)   -- the only sanctioned exception
 2 Count + label rules                              -- non-terminating, costs the baseline nothing
 3 Anti-DDoS AMR
 4 Operator explicit Block (IP denylist, geo block)
 5 Rate-based - country / bad-source scoped
 6 Rate-based - specific URI
 7 Rate-based - blanket
 8 Amazon IP reputation list
 9 Anonymous IP list
10 Always-on Challenge
11 Core Rule Set (and Known Bad Inputs)
12 Use-case AMRs (SQLi, Linux, Windows, PHP, WordPress)
13 False-positive exception rules
14 Application-specific custom rules
15 Bot Control
16 Fraud Control (ATP, ACFP)
-- Shield mitigation rule group (AWS places it, always last)
```

- [ ] **Anti-DDoS AMR at the top, or directly below `Allow` rules only.** AWS's wording is
      specific: *"either the highest priority inside your web ACL ... or ... right below any
      custom rules with Allow action"*. A `Block` rule above it is not sanctioned — during an
      attack the denylisted traffic *is* the attack, so blocking it earlier hides the event
      from the AMR. When first added the group sits at the **bottom**; mid-list usually means
      someone started moving it up and stopped.
- [ ] Count+Label rules before every rule that consumes the label
- [ ] Rate tiers most-specific first (country/bad-source, then URI, then blanket) — a rate rule
      that Blocks is terminating, so the stricter threshold must get its chance
- [ ] **False-positive exceptions below the group whose label they consume.** Placing one
      earlier is the exact failure the label-ordering rule exists to prevent, and it looks like
      working configuration
- [ ] Amazon IP reputation before Anonymous IP (higher confidence first)
- [ ] Bot Control and Fraud Control last — per-request pricing
- [ ] Could a high-priority Allow skip critical protections? (see section 1)

**Two positions are reviewed judgement calls, not AWS's words.** Position 2 reconciles the
Anti-DDoS placement guidance with `crawler-seo.md`'s requirement that the ASN+UA labelling rule
precede the AMR, on the grounds that a `Count` rule removes no traffic. Positions 5–7 before
8–9 put operator rate rules ahead of AWS's reputation lists; the reverse is defensible and
neither carries a per-request fee. Do not silently re-resolve either — if a customer's config
follows the other convention, say so rather than reporting a violation.
