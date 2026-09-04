# context.json — schema and field semantics

`waf-assess.py --context context.json` takes the answers a Web ACL export cannot
contain. The file does two jobs, and they are worth keeping apart in your head:

- **Six fields change a scripted finding.** Four gate one outright, `landing_page_uris` is
  rendered into a recommendation, and `traffic_profile` supplies the arithmetic for the
  rate-limit threshold check. Answer them and a verdict or its wording changes. Leave them
  out and the generator either stays silent or says "unverified" — never guesses.
- **Two more are read by rate-limiting checks** even though they are primarily descriptive:
  `cdn` decides whether a rate rule is aggregating on the wrong address, and `client_types`
  decides whether IP-only aggregation is defensible.
- **Everything else is printed back to the reader** in the report's Application Context
  section, so someone reading a finding can see which facts it rests on.

Every field is optional. The report prints the absent ones too, under **Not supplied**,
with what each would have decided — so a gap in the answers is visible rather than
invisible.

## Absent is not the same as null

```jsonc
{ "logging": null }   // asserts logging is NOT configured  -> Critical finding
{ }                   // nobody has looked                  -> "unverified" awareness note
```

`waf-assess.py` tests for key *presence*, not truthiness. This distinction is the reason
the file exists: reporting a critical failure for something nobody was shown is the
fastest way to have an entire assessment dismissed, and the finding text reads almost
identically either way.

The corollary is that you must not add a key to look thorough. An unanswered question
costs coverage; a guessed answer poisons every finding resting on it.

---

## The six fields that change a finding

### `client_types`
`array<string>` — how clients reach the application. Recognised tokens contain
`browser`, `web`, `site` or `desktop` (any of which means a Challenge can be completed);
anything else (`mobile_app`, `native_app`, `api_client`, `server`, `iot`) means it cannot.

```json
"client_types": ["browser", "mobile_app"]
```

**Gates:** the missing-always-on-Challenge finding. If every declared client is a
non-browser, the finding is withheld entirely — a Challenge that a native app cannot
complete is not a protection, it is an outage, so recommending one would be wrong rather
than merely unhelpful. If any browser client is present the finding applies as normal.

Also read during analysis for the Bot Control sections: a native app arriving at Bot
Control Common level meets `SignalNonBrowserUserAgent` at default Block.

### `landing_page_uris`
`array<string>` — the paths a browser hits first.

```json
"landing_page_uris": ["/", "/login", "/signup"]
```

**Gates:** nothing on its own, but the values are rendered **verbatim** into the
always-on-Challenge recommendation. That is the reason to supply them and the reason not
to invent them: a placeholder path you make up appears in the customer's report as
though it were theirs. Absent, the recommendation says `/`, `/login`, `/signup` and
explicitly asks for the real list.

### `api_paths`
`array<string>` — path prefixes served to non-browser clients.

```json
"api_paths": ["/api/", "/v2/graphql", "/rides/stream"]
```

**Gates:** the Challenge-on-API finding. `/api` is a convention rather than a rule, so a
GraphQL endpoint at `/v2/graphql` is equally unable to complete a Challenge and nothing
in its path says so. Supplying these catches Challenge rules the `/api` heuristic misses.

### `logging`
`object | null` — the `get-logging-configuration` answer, which the Web ACL export cannot
carry at all.

```json
"logging": {
  "destination": "Kinesis Data Firehose -> S3 -> Splunk",
  "retention_days": 90,
  "redacted_fields": ["authorization", "cookie", "single-query-argument:token"],
  "filtered": true
}
```

**Gates:** three outcomes.

| Value | Finding |
|---|---|
| key absent | Awareness — "not in the export, cannot be verified" |
| `null` / `false` / `"none"` | **Critical** — logging is not enabled |
| object | Medium if retention is unset or under 90 days, or nothing is redacted; otherwise no finding |

`filtered` is advisory: absent, the recommendation suggests a filter as a cost measure,
which is usually the largest single WAF log saving available.

### `traffic_profile`
`object` — the observed request rate, which is what AWS's threshold method takes as its input.

```json
"traffic_profile": { "peak_rps_per_ip": 8, "normal_rps": 1.5 }
```

**Gates:** the blanket rate-limit threshold check. AWS's method is peak-per-source plus a
50–100% buffer, so with `peak_rps_per_ip: 8` and a 300-second window the recommended range is
3,600–4,800 per window; a threshold far above that cannot fire, and one below it blocks real
traffic at its normal high-water mark.

**Use `peak_rps_per_ip`, not `peak_rps`, wherever you can.** The distinction is the most common
error in applying the method: an aggregate figure divided across many clients yields a
per-source threshold far too high. If only an aggregate is available the check still runs, and
says explicitly in the finding that the per-source status was unstated.

Absent, the threshold check falls back to a flat 50 requests/second heuristic in
`_gen_rate_rule_ineffective`, which can tell an unreachable threshold from a plausible one but
cannot tell a busy application from a misconfigured one.

### `waf_only_for_ddos`
`boolean` — is this Web ACL deliberately scoped to DDoS, with application-layer attacks
handled by another Web ACL or another layer?

```json
"waf_only_for_ddos": true
```

**Gates:** the missing-CRS / missing-KnownBadInputs finding, suppressed entirely when
`true`. Only an operator can distinguish a deliberate split from an omission, and the
rule set looks identical either way — so this is never inferred.

---

## Displayed fields

None of these change a verdict. They appear in Application Context so a reader can judge
the findings, and several are worth having during analysis.

| Field | Type | What it tells a reader |
|---|---|---|
| `protected_resource` | string | What the Web ACL is associated with (`alb`, `cloudfront`, `apigateway`, `appsync`). The export gives scope, not the service |
| `intended_protected_resource` | string | What it *should* protect. A mismatch means something is unprotected, and no rule tuning fixes it |
| `cdn` | string | `cloudfront`, another CDN, `global accelerator`, or `none`. **Also read by a check:** a proxy that rewrites the source address makes IP aggregation wrong, and Global Accelerator is deliberately excluded because it preserves the client IP |
| `tls_termination` | string | Where client TLS terminates. WAF only inspects where TLS terminates and traffic is proxied onward |
| `origin_protection` | array | How the origin is restricted to front-door traffic: VPC origins, prefix list, custom origin header, OAC, API key, or nothing |
| `markets` | array | Countries served, which decides whether geo restriction is available — it is free and evaluates early |
| `environment` | string | `production`, `staging`, `dev`. How much risk a staged change carries |
| `shield_advanced` | boolean | Forces the Shield Advanced flag on when the export shows no Shield mitigation rule group |
| `custom_rule_groups` | object | `{"<rule group name>": "ip_lists" \| "app_rules" \| "mixed" \| "unknown"}` — what is inside the groups the export shows only as an ARN |
| `known_issues` | array<string> | **The highest-value field here, and the one people skip.** Renders verbatim as history and caveats |

### On `known_issues`

This is where a Count override's story goes. The difference between the two findings
below is entirely this field:

> Bot Control is overridden to Count. Consider Block mode.

> Bot Control was set to Count in March after it blocked the partner payment webhook, and
> was never reverted. The fix is a label-based exception for that one caller, not a
> group-wide Count.

The first is worth little. The second is actionable, and it is only writable because
somebody said what happened.

---

## Worked example

```json
{
  "client_types": ["browser", "mobile_app"],
  "landing_page_uris": ["/", "/login", "/booking"],
  "api_paths": ["/api/", "/v2/rides"],
  "logging": {
    "destination": "CloudWatch Logs",
    "retention_days": 30,
    "redacted_fields": []
  },
  "waf_only_for_ddos": false,

  "protected_resource": "alb",
  "intended_protected_resource": "alb",
  "cdn": "cloudfront",
  "tls_termination": "cloudfront",
  "origin_protection": ["custom_origin_header"],
  "markets": ["VN", "SG"],
  "environment": "production",
  "traffic_profile": { "peak_rps": 4200, "normal_rps": 900 },
  "shield_advanced": true,
  "custom_rule_groups": { "corp-ip-allowlist": "ip_lists" },
  "known_issues": [
    "Bot Control was set to Count in March after it blocked the partner payment webhook; never reverted.",
    "The /v2/rides stream is a long-lived connection; rate limits on it are measured in connections, not requests."
  ]
}
```

That file turns the logging awareness note into a Medium finding (30-day retention, no
redaction), keeps the always-on-Challenge finding live because a browser client exists,
and renders the two `known_issues` entries where a reader will see them next to the rule
table.

## Adding a field

Two edits, and both are required or the field silently never appears:

1. `waf-assess.py` — add to `CONTEXT_QUESTIONS` only if it gates a finding, and read it
   in the generator that it gates.
2. `waf-report.py` — add to `_CTX_FIELDS`, which drives both the *supplied* and the *not
   supplied* branches of Application Context.

Then document it here.
