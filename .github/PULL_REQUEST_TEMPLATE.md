## Summary

<!-- What does this change do, and why is it needed? -->

## Invariants

This project's three invariants are documented in
[CONTRIBUTING](../CONTRIBUTING.md#invariants-that-must-not-break). Tick the ones this change
touches, and explain below how it stays within them.

- [ ] Standard library only — no new imports outside the Python 3 stdlib
- [ ] No network — neither the scripts nor the generated HTML make any request
- [ ] Never mutates AWS — no AWS API call is added
- [ ] This change touches none of the above

## Test plan

<!-- How was this verified? Paste the ---RESULT--- block if you ran an assessment. -->

- [ ] Ran `python3 -m compileall -q skills/ddos-guardian/scripts`
- [ ] Ran `python3 .github/scripts/check_invariants.py skills/ddos-guardian`
- [ ] Ran `npx skills-ref validate skills/ddos-guardian`
- [ ] Ran both phases end to end on a real web ACL export and opened the report
- [ ] The generated report still opens with no network access

## If this adds or changes a finding

- [ ] Template added to `TEMPLATES` in `waf_finding_templates.py`
- [ ] Generator added to `waf-assess.py`, deciding only from the config text
- [ ] Numbered section added or updated in `references/assessment-checklist.md`
- [ ] Category key added to `_CATEGORY_BY_KEY` in `waf-report.py`

## Checks

- [ ] No AWS prices added — cost *structure* only, per `references/cost-model.md`
- [ ] No accuracy percentage or effectiveness claim added; this is a configuration review, not a
      penetration test
- [ ] `"not configured"` and `"cannot be verified from the export"` are still distinct
- [ ] No customer ARNs, account IDs, IP sets or URI paths in the diff or the description

---

*By submitting this pull request, I confirm that you can use, modify, copy, and redistribute this contribution, under the terms of your choice.*
