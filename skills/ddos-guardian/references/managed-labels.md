# AWS Managed Rule Group Labels

Label catalogue for cross-rule dependency analysis (assessment-checklist.md section 17a).
A label is only usable by a rule with a **higher priority number** than its producer.

## Label producers

**AWSManagedRulesAntiDDoSRuleSet**
- `awswaf:managed:aws:anti-ddos:challengeable-request`
- `awswaf:managed:aws:anti-ddos:event-detected`
- `awswaf:managed:aws:anti-ddos:ddos-request`
- `awswaf:managed:aws:anti-ddos:high-suspicion-ddos-request`
- `awswaf:managed:aws:anti-ddos:medium-suspicion-ddos-request`
- `awswaf:managed:aws:anti-ddos:low-suspicion-ddos-request`
- `awswaf:managed:aws:anti-ddos:ChallengeAllDuringEvent`
- `awswaf:managed:aws:anti-ddos:ChallengeDDoSRequests`
- `awswaf:managed:aws:anti-ddos:DDoSRequests`

**AWSManagedRulesAmazonIpReputationList**
- `awswaf:managed:aws:amazon-ip-list:AWSManagedIPReputationList`
- `awswaf:managed:aws:amazon-ip-list:AWSManagedReconnaissanceList`
- `awswaf:managed:aws:amazon-ip-list:AWSManagedIPDDoSList`

**AWSManagedRulesAnonymousIpList**
- `awswaf:managed:aws:anonymous-ip-list:AnonymousIPList`
- `awswaf:managed:aws:anonymous-ip-list:HostingProviderIPList`

**AWSManagedRulesBotControlRuleSet**
- `awswaf:managed:aws:bot-control:bot:verified`
- `awswaf:managed:aws:bot-control:bot:unverified`
- `awswaf:managed:aws:bot-control:signal:non_browser_user_agent`

## Label namespace prefixes

| Prefix | Rule group |
|---|---|
| `awswaf:managed:aws:anti-ddos:` | AWSManagedRulesAntiDDoSRuleSet |
| `awswaf:managed:aws:amazon-ip-list:` | AWSManagedRulesAmazonIpReputationList |
| `awswaf:managed:aws:anonymous-ip-list:` | AWSManagedRulesAnonymousIpList |
| `awswaf:managed:aws:bot-control:` | AWSManagedRulesBotControlRuleSet |
| `awswaf:managed:aws:atp:` | AWSManagedRulesATPRuleSet |
| `awswaf:managed:aws:acfp:` | AWSManagedRulesACFPRuleSet |
| `awswaf:managed:aws:core-rule-set:` | AWSManagedRulesCommonRuleSet |
| `awswaf:managed:aws:known-bad-inputs:` | AWSManagedRulesKnownBadInputsRuleSet |

## Shared token labels

These are **not** owned by one rule group — any of the producers below can emit them,
so a scope-down keyed on a token label may fire earlier than you expect.

- `awswaf:managed:token:absent`
- `awswaf:managed:token:accepted`
- `awswaf:managed:token:rejected`

Produced by:

- AWSManagedRulesAntiDDoSRuleSet
- AWSManagedRulesBotControlRuleSet
- AWSManagedRulesATPRuleSet
- AWSManagedRulesACFPRuleSet

## Forgeability

The authoritative copy of these lists lives in `scripts/waf-assess.py`
(`FORGEABLE_FIELDS`, `UNFORGEABLE_STMT_TYPES`, `UNFORGEABLE_FIELDS`) — the
pre-checks stage reads them from there, not from this file. Kept here for review.

**Forgeable field types**: `single_header`, `single_query_argument`, `cookie`, `cookies`, `body`, `json_body`, `uri_path`, `query_string`, `method`, `header_order`, `headers`

**Unforgeable statement types**: `ip_set`, `asn_match`, `geo_match`, `rate_based`

**Unforgeable field types**: `ja3_fingerprint`, `ja4_fingerprint`
