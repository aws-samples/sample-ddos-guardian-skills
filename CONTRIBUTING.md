# Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.


## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment


## Contributing via Pull Requests
Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *main* branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code, it will be hard for us to focus on your change.
3. Run the local checks in [Running it locally](#running-it-locally) — the same ones CI runs.
4. Commit to your fork using clear commit messages, following [Commit messages](#commit-messages).
5. Send us a pull request, answering any default questions in the pull request interface.
6. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.

GitHub provides additional document on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).


## Finding contributions to work on
Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted' issues is a great place to start.


## Invariants that must not break

Three properties are the reason this skill is safe to point at a customer's configuration. A
change that breaks one is rejected on principle, not on style. CI enforces all three.

1. **Standard library only, Python 3.9+.** The scripts import nothing outside the standard
   library. No `pip install`, no virtualenv, no lockfile. Someone must be able to run
   `waf-assess.py` on a locked-down laptop with nothing but a system Python — and 3.9 is what
   macOS ships, so it is the floor CI tests. Note that `compileall` does **not** catch
   version-specific runtime errors: a PEP 604 `X | None` annotation without
   `from __future__ import annotations` compiles fine and then fails to load on 3.9. That is why
   CI also runs each entry point and asserts it exits 2 with its usage message rather than 1
   with a traceback.
2. **No network — from the scripts *or* the report.** The scripts make no requests, and the
   generated HTML embeds all of its CSS, JavaScript, SVG charts and icons. The report has to
   render correctly from an email attachment on an offline machine. A single CDN `<script>` or
   webfont breaks the guarantee and leaves the reader with empty boxes where the charts were.
3. **Never mutates AWS.** The scripts call no AWS API at all. Remediation is *emitted* as JSON and
   CLI for a human to review and apply. Do not add a boto3 dependency, a write call, or an
   "apply this fix for me" path.

Keep `"not configured"` distinct from `"cannot be verified from the export"` — conflating them
produces a confident finding about something nobody checked, which is the failure mode the whole
design is built to avoid.


## Running it locally

Two phases. Phase A reads the export and writes the scripted findings; phase B renders the HTML.

```bash
# Phase A — normalize, pre-checks, scripted findings
python3 skills/ddos-guardian/scripts/waf-assess.py <input.json> <output_dir> [--context <context.json>]

# Phase B — validate, map issues to rules, render the report
python3 skills/ddos-guardian/scripts/waf-report.py <output_dir> [--out report.html] [--validate-only]
```

`waf-assess.py` ends with a machine-readable `---RESULT---` block; `STATUS: OK` means continue,
`STATUS: FATAL` means stop and fix the input. Phase B needs `waf-summary.json`,
`findings-metadata.json` and a `findings.md` in the output directory.

Before opening a PR, run what CI runs:

```bash
python3 -m compileall -q skills/ddos-guardian/scripts
python3 .github/scripts/check_invariants.py skills/ddos-guardian
npx skills-ref validate skills/ddos-guardian
```

`check_invariants.py` is the machine-readable form of the three rules above: it parses each script
and fails on a non-stdlib import, a network- or subprocess-capable import, an `os.system`-style
escape hatch, or a mutating `wafv2` verb.

There is no unit-test suite yet. Adding one — starting with a committed fixture web ACL and an
assertion that phase A exits `STATUS: OK` — is a welcome contribution.


## Adding a finding

Findings flow through three places that must agree:

1. **`scripts/waf_finding_templates.py`** — add an entry to `TEMPLATES`. The template owns the
   title, severity, explanation and remediation text.
2. **`scripts/waf-assess.py`** — add a `_gen_*` generator that decides, from the config text
   alone, whether the finding applies. If the answer depends on something only an operator knows,
   it belongs in the LLM sections instead; add the question to `CONTEXT_QUESTIONS` and document it
   in `references/context-schema.md`.
3. **`references/assessment-checklist.md`** — add or update the numbered section. Those section
   numbers are the contract between the script and the agent; `llm_sections` refers to them.

Two things are single definitions — change them in one place only:

- `RECOMMENDED_ORDER` in `waf-assess.py` is the sole definition of the 16-position baseline rule
  order. Both the assessment and the report appendix are generated from it.
- `summary_pane()` in `waf-report.py` is the sole definition of the report layout.
  `assets/summary-tab-template.md` documents it and must be updated to match.

Categorise the finding by adding its key to `_CATEGORY_BY_KEY` in `waf-report.py`, using one of
the seven categories in `CATEGORY_ORDER`.


## Skill authoring rules

From the [Agent Skills specification](https://agentskills.io/specification):

- `name` — max 64 characters, lowercase letters, numbers and hyphens only, no leading, trailing or
  consecutive hyphens, and **must match the parent directory name**.
- `description` — **max 1024 characters**, and it is the only text an agent sees at startup when
  deciding whether to load the skill. Write it as trigger phrases, not as a summary. Exceeding the
  limit is a hard validation failure, so check the length before committing.
- Only `name`, `description`, `license`, `compatibility`, `metadata` and `allowed-tools` are valid
  frontmatter keys. Anything else fails validation — non-spec keys go under `metadata`, which is a
  map of string to string.
- Keep `SKILL.md` under 500 lines and move detail into `references/`. Give each reference file an
  explicit load trigger ("read `references/rate-based.md` when the web ACL has a rate-based rule")
  rather than a generic "see references/ for details" — the agent loads on demand and needs to
  know when.

Validate before pushing: `npx skills-ref validate skills/ddos-guardian`.


## Reference document conventions

- **No AWS prices.** `references/cost-model.md` documents cost *structure* deliberately: published
  rates change, so a rate baked into a file becomes a confidently wrong number. Describe the
  inputs that drive a cost, not the dollar amount.
- **Qualify claims that invite correction.** Shield Advanced including the Anti-DDoS rule group is
  bounded ("up to 50 billion requests a month"); an unqualified "it's free" invites a correction
  that undermines everything around it.
- Mark judgement calls as judgement calls. Two positions in the baseline rule order are reviewed
  opinions and are labelled as such in the code — if a configuration follows the other convention,
  the assessment says so rather than reporting a violation.


## Commit messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/) with the skill or
area as the scope. This is a **new convention introduced with these contributor docs** — the
existing history does not follow it, so do not use it as a reference.

```
feat(ddos-guardian): add crawler labelling check
fix(scripts): correct stale pre-check count in the docstring
docs(readme): lead with the report and the install
```

Subject in the imperative, under 70 characters, no trailing period. Body wrapped at 72 columns and
explaining **why** — the diff already shows what. A commit template is included:

```bash
git config commit.template .gitmessage
```


## Known quirks

- `SKILL.md` previously carried a non-spec `permissions` frontmatter key. It now lives under
  `metadata` so the frontmatter validates. It is not translated to the spec's `allowed-tools`
  field, which is still marked experimental and would change runtime tool gating.
- `assets/summary-tab-template.md` describes a `CHANGE SINCE LAST ASSESSMENT` block gated on a
  `--diff` flag. That flag does not exist; the block is a design note, marked as such in the file.


## Code of Conduct
This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any additional questions or comments.


## Security issue notifications
If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.


## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.
