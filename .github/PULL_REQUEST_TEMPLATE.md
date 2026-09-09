<!-- The whole description's target audience is humans, not AI agents: write it in plain, simple,
     everyday engineering language, extremely parsable and readable at a glance. This goes double for
     the TLDR, User Flow, and Caveats sections -->

## TLDR

<!-- Fill in the bullets below and keep each one short and concrete: one line per bullet, roughly 10 words max -->

Problem this solves:

- <blah>
- ...

How it solves it:

- <blah>
- ...

## User Flow

<!-- Two ordered lists, Before and After, walking the same person through the same task, written strictly from that person's seat
     The user here is whoever runs the skill: a TAM, SA, security engineer or application owner reviewing a web ACL
     Lead each list with one plain sentence saying where the flow fails (Before) or succeeds (After), then number the steps
     Every step is something they do or observe: the prompt they type, the command they run, the file that appears, the finding or error text they see on screen
     No internals: never name functions, generator names, dict keys, or code paths. "The report shows the Anti-DDoS group as enforcing when it is actually in Count" is right, "_gen_group_level_count returned None" is wrong
     Keep the two lists step-for-step identical until they diverge, so the changed step is obvious
     If the change alters a finding's severity or whether it fires at all, say what the reader would have concluded before and concludes now
     Regenerate this section whenever new commits change the PR's behavior, so it never describes an older revision

Example:

Before: an SA reviewing a customer web ACL on a Mac gets a traceback instead of an assessment

1. They run `python3 skills/ddos-guardian/scripts/waf-assess.py webacl.json out/`
2. It exits 1 with `TypeError: unsupported operand type(s) for |: 'type' and 'NoneType'`
3. No `waf-summary.json` is written and there is nothing to report to the customer

After: the same command produces the assessment

1. They run the same `python3 skills/ddos-guardian/scripts/waf-assess.py webacl.json out/`
2. It prints `STATUS: OK` with a rule count and a scripted-finding count
3. `out/waf-summary.json` and `out/scripted-findings.md` exist, ready for the report step
-->

## Relevant issues

<!-- e.g., "Fixes #000" -->

## Which invariants does this touch?

<!-- The three properties that make this skill safe to point at a customer's configuration.
     They are documented in CONTRIBUTING.md#invariants-that-must-not-break and enforced by CI.
     Tick any this change comes near and explain below how it stays within them -->

- [ ] Standard library only — no import outside the Python 3.9+ stdlib
- [ ] No network — neither the scripts nor the generated HTML make any request
- [ ] Never mutates AWS — no AWS API call is added
- [ ] This change touches none of the three

## Pre-Submission checklist

**Please complete all items before asking a maintainer to review your PR**

- [ ] `python3 -m compileall -q skills/ddos-guardian/scripts` passes
- [ ] `python3 .github/scripts/check_invariants.py skills/ddos-guardian` passes
- [ ] `npx skills-ref validate skills/ddos-guardian` passes
- [ ] Both phases run end to end on a real web ACL export and the report opens
- [ ] The generated report still opens correctly with no network access
- [ ] My PR's scope is as isolated as possible; it only solves 1 specific problem
- [ ] My PR passes all required CI checks

## If this adds or changes a finding

<!-- Delete this section if it does not apply. These four places have to agree or the finding
     will not render, will render uncategorised, or will contradict the checklist -->

- [ ] Template added to `TEMPLATES` in `waf_finding_templates.py`
- [ ] Generator added to `waf-assess.py`, deciding only from the config text
- [ ] Numbered section added or updated in `references/assessment-checklist.md`
- [ ] Category key added to `_CATEGORY_BY_KEY` in `waf-report.py`
- [ ] The finding distinguishes `"not configured"` from `"cannot be verified from the export"`

## Proof of Fix

<!-- Include commands plus output, or screenshots, demonstrating that your change works
     The proof must be end to end against a real run, not a description of one. A claim that it works is not proof
     Show ONLY the latest run: capture Before at the merge base and After at the PR's current tip. When new commits change behavior, replace this whole section with the fresh run rather than stacking it on older ones
     Structure the section exactly as below: Before and After one heading level below this section, each naming the commit hash it was captured at, one lower-level heading per case inside each, the same case names in the same order on both sides, and numbered steps (command, observed output) under every case, never loose prose. Shared setup (the export used, any context file) goes above Before. With a single case, drop the case headings and number the steps directly

### Before (<hash>)

#### <case 1>

1. ...
2. ...

### After (<hash>)

#### <case 1>

1. ...
2. ...

     For bug fixes: Before shows the reproduction, After shows the same steps passing
     For a new finding: Before shows it going unreported on a web ACL that has the defect, After shows it reported at the right severity, and also shows a web ACL WITHOUT the defect staying clean so the check is not simply always-on
     Redact before pasting. A get-web-acl export carries account IDs, ARNs, IP set contents, header and cookie names and URI paths; use a synthetic export where you can
     For report or README changes: before/after screenshots under the same headings -->

## Type

<!-- Keep only the ones that apply -->

New Feature
Bug Fix
New or changed finding
Refactoring
Documentation
Infrastructure
Test

## Caveats (if any)

<!-- Group caveats under severity subheadings (### Severe, ### High, ### Medium, ### Low), with
     short bullet points inside each, just like the TLDR: one line per bullet, roughly 10 words max
     Call out known limitations, follow-up work, or anything a reviewer should watch out for
     Include only the tiers that have caveats; drop the empty ones
     - Severe: inherent to what the PR deliberately ships, there even when the code works as intended.
       It changes what the assessment tells a customer: a finding's severity moves, a check starts or
       stops firing, or remediation advice changes. A reviewer must agree with the judgement, not just
       the code
     - High: an unintended hole: a wrong finding, a missed defect, a broken invariant, or a
       compatibility break. Unsafe to ship as is
     - Medium: a real gap someone can hit, but with a workaround or a narrow blast radius
     - Low: anything else worth noting: naming, cleanup, an edge case nobody hits
     Nest bullets as deep as helps: hierarchy beats one long line when it makes things clearer to a
     human reader
     Leave this section empty if there are none -->

## Final Attestation

- [ ] A human has read the complete diff, not just this description
- [ ] No accuracy percentage, effectiveness claim, or AWS price was added; this remains a configuration review, not a penetration test
- [ ] No customer ARNs, account IDs, IP set contents or URI paths appear in the diff or in this description

---

*By submitting this pull request, I confirm that you can use, modify, copy, and redistribute this contribution, under the terms of your choice.*
