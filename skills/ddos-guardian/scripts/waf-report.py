#!/usr/bin/env python3
"""WAF Report (phase B of 2): render the assessment as a self-contained HTML report.

Usage: python3 waf-report.py <output_dir> [--out waf-assessment-report.html] [--validate-only]
  output_dir:      the directory waf-assess.py wrote to; must also contain findings.md
                   with the Issue sections (scripted, plus whatever the agent appended)
  --out:           report path (default: <output_dir>/waf-assessment-report.html)
  --validate-only: skip the render and re-run validation only, for the retry loop after
                   a reported failure is fixed

Stages:
  1. validate  → validation.json           (3 mechanical checks, on document order)
  2. issue map → issue-rule-mapping.json   (rule -> issue index, scripted + agent)
  3. render    → waf-assessment-report.html   (four tabs, no external assets)

All three are idempotent: a re-run rewrites the map, the validation and the report from
whatever findings.md currently says.

Where the structure comes from
------------------------------
The numbers, statuses, rule names and evidence all come from waf-summary.json and
findings.md. Nothing in the layout is hand-authored, and nothing in findings.md is
generated -- so a figure cannot drift from the assessment, and the prose cannot read as
filler. This script is the sole definition of the report format; to change how a report
looks, change it here rather than writing HTML by hand.

Four tabs, in this order:

  Summary       an optional `## @summary` prose block from findings.md, then the KPI
                cards, the severity distribution, and one row per issue
  Current Setup what the web ACL *is*, wholly script-owned: the application context that
                was supplied, the ACL properties, and every rule in evaluation order
                annotated with the issues raised against it
  Findings &    one card per issue, severity-ordered, paginated. Rule, current state,
  Recommendations  problem and recommendation, parsed out of findings.md
  Appendix      the fixed reference sections A-F from waf_finding_templates

Icons are inline SVG rather than a webfont, and the CSS and JS are inlined. That is
deliberate: a single external stylesheet would break the self-containment guarantee, and
a report opened from an email attachment on a machine with no network would show empty
boxes exactly where the section headings are.
"""
import html
import json
import os
import re
import sys
from datetime import date
from pathlib import Path

from waf_finding_templates import APPENDIX_SECTIONS

STAGES = ("validate", "issue-map", "render")
_done = []

FINDINGS_FILE = "findings.md"
WCU_CEILING = 5000


def fatal(msg: str):
    """Print FATAL result block and exit with code 2."""
    print(msg, file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: FATAL")
    print("ACTION: FIX")
    if _done:
        print(f"STAGES_OK: {','.join(_done)}")
    print(f"CONTEXT: {msg}")
    sys.exit(2)


def _load_json(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        fatal(f"Failed to read {path}: {e}")


# ════════════════════════════════════
# SEVERITY
# ════════════════════════════════════

# v2's four levels. Awareness is not a defect -- it is something worth knowing that a
# reader would otherwise have to discover during an incident -- so it sorts last and is
# styled apart from the three that are.
SEVERITY = {
    "critical": ("Critical", 0, "crit"),
    "medium":   ("Medium",   1, "med"),
    "low":      ("Low",      2, "low"),
    "awareness": ("Awareness", 3, "awa"),
}


def sev_key(raw: str) -> str:
    """Normalise a severity label, tolerating the emoji forms v2 also accepts."""
    s = re.sub(r"[^a-z]", "", str(raw or "").lower())
    for name in SEVERITY:
        if name in s:
            return name
    return "awareness"


# ════════════════════════════════════
# MARKDOWN
#
# Deliberately small, and deliberately not a dependency: the skill has to stay portable
# to runtimes with no package install step. It covers exactly what the findings and the
# appendix use -- fenced code, tables, headings, nested bullets, ordered lists, bold,
# italic, inline code and links. Fenced blocks are extracted first so that a `|` or a `#`
# inside a JSON payload is not mistaken for a table or a heading.
# ════════════════════════════════════

def esc(v) -> str:
    return html.escape(str(v if v is not None else ""), quote=False)


def _inline(text: str) -> str:
    """Inline markdown only. Escapes first, so `<script>` in a config value is inert."""
    t = esc(text)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![*\w])\*([^*\n]+)\*(?!\w)", r"<em>\1</em>", t)
    t = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
               r'<a href="\2" rel="noopener noreferrer" target="_blank">\1</a>', t)
    # Bare URLs, which the appendix uses. Done after the link form so an already-linked
    # URL is not wrapped twice.
    t = re.sub(r'(?<!["\'>=])\b(https?://[^\s<)]+)',
               r'<a href="\1" rel="noopener noreferrer" target="_blank">\1</a>', t)
    return t


def markdown(src: str) -> str:
    """Block-level markdown -> HTML."""
    if not src or not src.strip():
        return ""

    # Pull fenced blocks out before anything else looks at the text.
    fences = []

    def _stash(m):
        fences.append((m.group(1) or "", m.group(2)))
        return f"\x00FENCE{len(fences) - 1}\x00"

    src = re.sub(r"```([A-Za-z0-9]*)\n(.*?)```", _stash, src, flags=re.S)

    out = []
    lines = src.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        m = re.match(r"^\x00FENCE(\d+)\x00$", stripped)
        if m:
            lang, body = fences[int(m.group(1))]
            out.append(f'<pre class="code"><code>{esc(body.rstrip())}</code></pre>')
            i += 1
            continue

        if re.fullmatch(r"-{3,}|\*{3,}|_{3,}", stripped):
            i += 1                      # section separators; the cards supply their own
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            lvl = min(6, len(m.group(1)) + 2)   # never emit an <h1>; the header owns it
            out.append(f"<h{lvl}>{_inline(m.group(2))}</h{lvl}>")
            i += 1
            continue

        # Table: a pipe row followed by a separator row.
        if stripped.startswith("|") and i + 1 < len(lines) \
                and re.fullmatch(r"\|[\s:|-]+\|?", lines[i + 1].strip()):
            def cells(row):
                return [c.strip() for c in row.strip().strip("|").split("|")]
            head = cells(stripped)
            i += 2
            body = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                body.append(cells(lines[i]))
                i += 1
            th = "".join(f"<th>{_inline(c)}</th>" for c in head)
            rows = "".join(
                "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>"
                for r in body)
            out.append('<div class="table-wrap"><table><thead><tr>'
                       f"{th}</tr></thead><tbody>{rows}</tbody></table></div>")
            continue

        # Lists, including one level of nesting and ordered items.
        if re.match(r"^\s*([-*+]|\d+\.)\s+", line):
            block, base = [], len(line) - len(line.lstrip())
            def _continues(ln):
                return (re.match(r"^\s*([-*+]|\d+\.)\s+", ln)
                        or (ln.strip() and ln.startswith(" " * (base + 2))))
            while i < len(lines) and _continues(lines[i]):
                block.append(lines[i])
                i += 1
            out.append(_render_list(block, base))
            continue

        # Paragraph: consume until a blank line or the start of another block.
        para = []
        while i < len(lines) and lines[i].strip() \
                and not re.match(r"^\s*([-*+]|\d+\.)\s+|^#{1,6}\s|^\|", lines[i]) \
                and not re.match(r"^\x00FENCE\d+\x00$", lines[i].strip()):
            para.append(lines[i].strip())
            i += 1
        if para:
            out.append(f"<p>{_inline(' '.join(para))}</p>")
        else:
            i += 1
    return "".join(out)


def _render_list(block, base):
    """One list level, recursing for indented children."""
    ordered = bool(re.match(r"^\s*\d+\.\s+", block[0]))
    items, cur, child = [], None, []

    def flush():
        if cur is None:
            return
        body = _inline(cur)
        if child:
            inner_base = len(child[0]) - len(child[0].lstrip())
            body += _render_list(child, inner_base)
        items.append(f"<li>{body}</li>")

    for line in block:
        m = re.match(r"^(\s*)([-*+]|\d+\.)\s+(.*)$", line)
        if m and len(m.group(1)) <= base:
            flush()
            cur, child = m.group(3), []
        elif cur is not None:
            child.append(line)
    flush()
    tag = "ol" if ordered else "ul"
    return f"<{tag}>{''.join(items)}</{tag}>"


# ════════════════════════════════════
# ICONS
#
# Inline SVG on a 24x24 grid using currentColor, so each inherits the surrounding text
# colour and needs no network. An unknown name renders nothing rather than breaking a
# layout, which is the right failure for a decoration.
# ════════════════════════════════════

_ICONS = {
    "shield": "M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3Zm0 2.2 6 2.2v4.6c0 4-2.6 7.6-6 9.1V4.2Z",
    "file": "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6Zm0 2.5L18.5 9H14V4.5ZM8 13h8v2H8v-2Zm0 4h8v2H8v-2Z",
    "server": "M4 4h16v6H4V4Zm0 10h16v6H4v-6Zm2-8v2h2V6H6Zm0 10v2h2v-2H6Z",
    "table": "M3 4h18v16H3V4Zm2 2v3h5V6H5Zm7 0v3h7V6h-7ZM5 11v3h5v-3H5Zm7 0v3h7v-3h-7ZM5 16v2h5v-2H5Zm7 0v2h7v-2h-7Z",
    "warn": "M12 2 1 21h22L12 2Zm0 4.5 7.5 12.5h-15L12 6.5ZM11 10v5h2v-5h-2Zm0 6v2h2v-2h-2Z",
    "chart": "M11 2v9H2a9 9 0 0 0 9 9 9 9 0 0 0 9-9h-9V2h-1Zm2 0v7h7a7 7 0 0 0-7-7Z",
    "book": "M4 3h7a3 3 0 0 1 3 3v15a3 3 0 0 0-3-3H4V3Zm16 0h-4a3 3 0 0 0-3 3v15a3 3 0 0 1 3-3h4V3Z",
    "person": "M12 2a5 5 0 1 0 0 10A5 5 0 0 0 12 2Zm0 12c-4.4 0-8 2.2-8 5v3h16v-3c0-2.8-3.6-5-8-5Z",
    "bolt": "M13 2 4 14h5l-1 8 9-12h-5l1-8Z",
    "circle": "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z",
}


def icon(name, size=14):
    p = _ICONS.get(name)
    if not p:
        return ""
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="currentColor" '
            f'aria-hidden="true" class="ico"><path d="{p}"/></svg>')


# ════════════════════════════════════
# STAGE 1 — ISSUE PARSING AND THE RULE MAP
# ════════════════════════════════════

_ISSUE_RE = re.compile(r"^##\s+Issue\s+#?(\d+)\s*\(([^)]+)\)\s*:\s*(.+)$", re.M)
_REF_RE = re.compile(r"([\w.\-:]+)\s*\((?:priority\s*|P)(\d+)\)")


def read_findings(output_dir):
    """Split findings.md into the optional `@summary` prose and the Issue sections."""
    path = os.path.join(output_dir, FINDINGS_FILE)
    if not os.path.isfile(path):
        fatal(f"Required file not found: {path}. Copy scripted-findings.md to "
              f"{FINDINGS_FILE} and append your own Issue sections before rendering.")
    text = Path(path).read_text(encoding="utf-8")

    # Prose before the first Issue heading is the highlight-findings block, if there is any.
    first = _ISSUE_RE.search(text)
    head = text[:first.start()] if first else text
    summary = ""
    m = re.search(r"^##\s+@summary\s*$(.*?)(?=\Z)", head, re.M | re.S)
    if m:
        summary = m.group(1).strip()
    elif head.strip():
        summary = head.strip()

    issues = []
    marks = list(_ISSUE_RE.finditer(text))
    for idx, m in enumerate(marks):
        body = text[m.end():marks[idx + 1].start() if idx + 1 < len(marks) else len(text)]
        issues.append(_parse_issue(int(m.group(1)), m.group(2), m.group(3), body))
    if not issues:
        fatal(f"No `## Issue N (Severity): title` sections found in {path}")
    return summary, issues


def _parse_issue(number, severity_raw, title, body):
    """One Issue section into the parts the card renders from.

    The four labelled parts are lifted out rather than passed through as one blob, so
    every card has the same shape whoever wrote it -- a scripted finding and one the
    agent wrote cannot present the same issue differently. Anything unlabelled is kept
    as trailing prose rather than dropped.
    """
    def grab(label):
        m = re.search(rf"^\*\*{label}\*\*\s*:\s*(.*?)(?=^\*\*|\Z)", body, re.M | re.S)
        return m.group(1).strip() if m else ""

    rules_line = grab(r"Rules?")
    refs = []
    for name, pri in _REF_RE.findall(rules_line):
        if (name, int(pri)) not in refs:
            refs.append((name, int(pri)))

    consumed = []
    for label in (r"Rules?", "Current state", "Problem", "Recommendation"):
        m = re.search(rf"^\*\*{label}\*\*\s*:.*?(?=^\*\*|\Z)", body, re.M | re.S)
        if m:
            consumed.append((m.start(), m.end()))
    extra = body
    for start, end in sorted(consumed, reverse=True):
        extra = extra[:start] + extra[end:]
    extra = re.sub(r"^\s*-{3,}\s*$", "", extra, flags=re.M).strip()

    key = sev_key(severity_raw)
    return {
        "number": number,
        # Filled in main() once findings-metadata.json has been read, because the mapping from
        # a scripted finding's title to its title_key lives there.
        "category": "",
        "sev": key,
        "sev_label": SEVERITY[key][0],
        "sev_cls": SEVERITY[key][2],
        "title": title.strip(),
        "rules_line": rules_line,
        "refs": refs,
        "now": grab("Current state"),
        "problem": grab("Problem"),
        "action": grab("Recommendation"),
        "extra": extra,
    }


def _stage_issue_map(output_dir, summary_json, metadata, issues):
    """Rule name -> the issues raised against it. Merges scripted and agent findings."""
    valid = {r["name"] for r in summary_json.get("rules", [])}
    mapping = {}
    for iss in issues:
        for name, _pri in iss["refs"]:
            if name not in valid:
                continue
            mapping.setdefault(name, []).append(iss["number"])
    # Scripted findings record their rules in metadata, which is more reliable than
    # re-parsing their own rendered text -- a rule named in prose but not in the
    # **Rule** line would otherwise be missed.
    for name, annotation in (metadata.get("issue_rule_mapping") or {}).items():
        if name not in valid:
            continue
        for num in re.findall(r"#(\d+)", str(annotation)):
            n = int(num)
            if n not in mapping.setdefault(name, []):
                mapping[name].append(n)

    out = {name: sorted(set(nums)) for name, nums in mapping.items()}
    Path(os.path.join(output_dir, "issue-rule-mapping.json")).write_text(
        json.dumps({"annotations": out}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Mapped {len(out)} rules to issues", file=sys.stderr)
    return out


# ════════════════════════════════════
# STAGE 2 — VALIDATION
#
# Three mechanical checks. v2's fourth compared the Markdown summary table against the
# Issue sections; the table is now generated from those sections by this script, so the
# check could only ever pass and has been dropped rather than kept as decoration.
# ════════════════════════════════════

def _check_numbering(issues):
    """Issue numbers run 1..N with no gaps and no repeats."""
    nums = [i["number"] for i in issues]
    problems = []
    if len(set(nums)) != len(nums):
        dupes = sorted({n for n in nums if nums.count(n) > 1})
        problems.append(f"duplicate issue numbers: {dupes}")
    for pos, n in enumerate(nums, start=1):
        if n != pos:
            problems.append(f"issue #{n} is in position {pos}; expected #{pos}")
            break
    return ({"status": "PASS", "count": len(nums)} if not problems
            else {"status": "FAIL", "problems": problems})


def _check_rule_refs(issues, summary_json):
    """Every rule named in a **Rule** line exists, at the priority claimed."""
    lookup = {r["name"]: r["priority"] for r in summary_json.get("rules", [])}
    bad = []
    for iss in issues:
        if iss["rules_line"].startswith("N/A"):
            continue
        for name, pri in iss["refs"]:
            if name not in lookup:
                bad.append(f"issue #{iss['number']}: rule '{name}' is not in the web ACL")
            elif lookup[name] != pri:
                bad.append(f"issue #{iss['number']}: rule '{name}' is at priority "
                           f"{lookup[name]}, not {pri}")
    return {"status": "PASS", "invalid_refs": []} if not bad else \
           {"status": "FAIL", "invalid_refs": bad}


def _check_precheck_coverage(issues, prechecks):
    """Every failing pre-check has its rule named in some issue's **Rule** line."""
    named = {n.lower() for iss in issues for n, _ in iss["refs"]}
    missing = []
    for name, check in (prechecks or {}).get("pre_checks", {}).items():
        if check.get("status") != "FAIL":
            continue
        rules = [check["rule"]] if "rule" in check else []
        rules += [r.get("name", "") if isinstance(r, dict) else str(r)
                  for r in check.get("rules", [])]
        rules = [r for r in rules if r]
        if not rules:
            continue                    # a web-ACL-level check names no rule
        if not any(r.lower() in named for r in rules):
            missing.append({"check": name, "rules": rules})
    return {"status": "PASS", "missing": []} if not missing else \
           {"status": "FAIL", "missing": missing,
            "detail": f"{len(missing)} failing pre-check(s) are not covered by any issue"}


def _stage_validate(output_dir, summary_json, issues):
    prechecks_path = os.path.join(output_dir, "pre-checks.json")
    prechecks = _load_json(prechecks_path) if os.path.isfile(prechecks_path) else None
    checks = {
        "issue_numbering": _check_numbering(issues),
        "rule_references": _check_rule_refs(issues, summary_json),
    }
    if prechecks:
        checks["precheck_coverage"] = _check_precheck_coverage(issues, prechecks)
    Path(os.path.join(output_dir, "validation.json")).write_text(
        json.dumps(checks, indent=2, ensure_ascii=False), encoding="utf-8")
    passed = sum(1 for v in checks.values() if v["status"] == "PASS")
    failed = sum(1 for v in checks.values() if v["status"] == "FAIL")
    print(f"Validation: {passed} passed, {failed} failed", file=sys.stderr)
    return checks


# ════════════════════════════════════
# STAGE 3 — RENDER
# ════════════════════════════════════

CSS = """
:root{
  --bg:#f7f8fa; --surface:#fff; --border:#e4e6ec; --border-soft:#eef0f4;
  --text:#16192b; --text-2:#4a5169; --text-3:#8b93a7;
  --accent:#3b4ce0; --head-1:#1a1a2e; --head-2:#2d2d5a;
  --crit:#dc2626; --crit-bg:#fef2f2; --med:#d97706; --med-bg:#fffbeb;
  --low:#16a34a; --low-bg:#f0fdf4; --awa:#2563eb; --awa-bg:#eff6ff;
  --code-bg:#f4f5f8;
}
:root[data-theme="dark"]{
  --bg:#101220; --surface:#181b2c; --border:#2a2e44; --border-soft:#232739;
  --text:#e9ebf2; --text-2:#a8b0c5; --text-3:#767e95;
  --accent:#7c8cff; --head-1:#0d0f1a; --head-2:#1b1d33;
  --crit:#f87171; --crit-bg:#3a1d1d; --med:#fbbf24; --med-bg:#3a2e12;
  --low:#4ade80; --low-bg:#12321f; --awa:#7dabff; --awa-bg:#16264a;
  --code-bg:#0e1020;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:24px 20px 64px}
.ico{vertical-align:-2px;margin-right:7px;flex:none}

.themebtn{position:fixed;top:14px;right:16px;z-index:20;display:flex;align-items:center;
  gap:6px;padding:6px 12px;font-size:12px;border:1px solid var(--border);border-radius:99px;
  background:var(--surface);color:var(--text-2);cursor:pointer}
.themebtn:hover{border-color:var(--accent);color:var(--accent)}

.header{background:linear-gradient(135deg,var(--head-1),var(--head-2));color:#fff;
  border-radius:12px;padding:26px 28px;margin-bottom:20px}
.header h1{margin:0;font-size:21px;font-weight:650;display:flex;align-items:center}
.header .sub{margin-top:5px;font-size:15px;font-weight:500;opacity:.92}
.header .meta{margin-top:14px;display:flex;flex-wrap:wrap;gap:8px 20px;font-size:12.5px;
  opacity:.85}
.header .meta span{display:flex;align-items:center}

.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:14px;
  margin-bottom:20px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 18px}
.kpi .lbl{font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;
  color:var(--text-3)}
.kpi .val{font-size:27px;font-weight:680;margin:6px 0 2px;line-height:1.15}
.kpi .val .u{font-size:14px;font-weight:600;color:var(--text-3);margin-left:3px}
.kpi .bar{height:5px;border-radius:99px;background:var(--border-soft);overflow:hidden;margin:8px 0 7px}
.kpi .bar span{display:block;height:100%;border-radius:99px}
.kpi .note{font-size:11.5px;color:var(--text-3)}

.section{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:20px 22px;margin-bottom:16px}
.section > h2{margin:0 0 16px;font-size:14.5px;font-weight:650;display:flex;align-items:center;
  color:var(--text)}
.section h3{font-size:13.5px;font-weight:640;margin:20px 0 8px}
.section h4{font-size:12.5px;font-weight:640;margin:16px 0 6px;color:var(--text-2)}
.section p{margin:0 0 10px;color:var(--text-2)}
.section p strong{color:var(--text)}
.section ul,.section ol{margin:0 0 10px;padding-left:22px;color:var(--text-2)}
.section li{margin-bottom:4px}
.section li strong{color:var(--text)}
code{background:var(--code-bg);border:1px solid var(--border-soft);border-radius:3px;
  padding:.5px 5px;font-size:12px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre.code{background:var(--code-bg);border:1px solid var(--border);border-radius:8px;
  padding:13px 15px;overflow-x:auto;margin:0 0 12px;font-size:11.5px;line-height:1.55}
pre.code code{background:none;border:none;padding:0;font-size:inherit}
a{color:var(--accent)}

.stat{display:flex;height:26px;border-radius:6px;overflow:hidden;margin-bottom:10px}
.stat span{display:flex;align-items:center;justify-content:center;font-size:11px;
  font-weight:600;color:#fff;min-width:0}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:12px;color:var(--text-2)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px}
.bg-crit{background:var(--crit)} .bg-med{background:var(--med)}
.bg-low{background:var(--low)} .bg-awa{background:var(--awa)}

.tabs{display:flex;gap:3px;flex-wrap:wrap;border-bottom:1px solid var(--border);
  margin-bottom:18px}
.tab{padding:9px 15px;font-size:13px;font-weight:550;border:none;background:none;
  color:var(--text-3);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab:hover{color:var(--text-2)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab .badge{display:inline-block;margin-left:6px;padding:1px 7px;border-radius:99px;
  background:var(--border-soft);color:var(--text-2);font-size:11px;font-weight:600}
.tab.active .badge{background:var(--accent);color:#fff}
.pane{display:none} .pane.active{display:block}

.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{background:var(--border-soft);color:var(--text-2);font-size:11px;font-weight:640;
  letter-spacing:.04em;text-transform:uppercase;text-align:left;padding:9px 12px;
  white-space:nowrap}
td{padding:9px 12px;border-top:1px solid var(--border-soft);color:var(--text-2);
  vertical-align:top}
td strong{color:var(--text)}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tbody tr:hover td{background:var(--border-soft)}

.pill{display:inline-block;padding:1.5px 9px;border-radius:99px;font-size:10.5px;
  font-weight:650;letter-spacing:.02em;white-space:nowrap}
.sv-crit{background:var(--crit-bg);color:var(--crit)}
.sv-med{background:var(--med-bg);color:var(--med)}
.sv-low{background:var(--low-bg);color:var(--low)}
.sv-awa{background:var(--awa-bg);color:var(--awa)}
.tag{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10.5px;
  font-weight:600;border:1px solid var(--border);color:var(--text-3);white-space:nowrap}

.card{border:1px solid var(--border);border-left-width:3px;border-radius:9px;
  margin-bottom:14px;overflow:hidden}
.card.lv-crit{border-left-color:var(--crit)} .card.lv-med{border-left-color:var(--med)}
.card.lv-low{border-left-color:var(--low)} .card.lv-awa{border-left-color:var(--awa)}
.card-h{display:flex;align-items:center;gap:9px;flex-wrap:wrap;padding:12px 16px;
  background:var(--border-soft)}
.card-h .n{font-size:11.5px;font-weight:680;color:var(--text-3);
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.card-h .t{font-size:13.5px;font-weight:620;color:var(--text);flex:1;min-width:200px}
.card-b{padding:4px 16px 14px}
.card-b dt{font-size:10.5px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;
  color:var(--text-3);margin:14px 0 5px}
.card-b dd{margin:0}
.refs{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 2px}
.ref{font-size:11px;padding:2px 8px;border-radius:5px;background:var(--border-soft);
  color:var(--text-2)}
.ref.none{background:none;border:1px dashed var(--border);color:var(--text-3)}
.pager{display:flex;align-items:center;justify-content:space-between;gap:12px;
  flex-wrap:wrap;margin-top:14px}
.pager .info{font-size:12px;color:var(--text-3)}
.pager .btns{display:flex;gap:4px}
.pg{min-width:29px;height:29px;padding:0 8px;font-size:12px;border:1px solid var(--border);
  border-radius:6px;background:var(--surface);color:var(--text-2);cursor:pointer}
.pg:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
.pg.active{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
.pg:disabled{opacity:.4;cursor:default}

.ctx{list-style:none;padding:0;margin:0 0 14px}
.ctx li{padding:7px 0 7px 24px;border-bottom:1px solid var(--border-soft);position:relative;
  font-size:13px;color:var(--text-2)}
.ctx li:last-child{border-bottom:none}
.ctx li:before{position:absolute;left:2px;top:7px;font-size:12px}
.ctx li.given:before{content:"\\2713";color:var(--low)}
.ctx li.derived:before{content:"\\25CF";color:var(--awa);font-size:9px;top:9px}
.ctx li.absent:before{content:"\\2014";color:var(--text-3)}
.ctx li.absent{color:var(--text-3)}
.ctx-key{font-weight:600;color:var(--text)}
.lead{font-size:12.5px;color:var(--text-3);margin-bottom:14px}
/* ════ Summary tab: business context, KPIs, charts, findings table ════ */
.exec-sec-label{font-size:10px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;
  color:var(--text-3);margin:22px 0 10px;display:flex;align-items:center;gap:8px}
.exec-sec-label:first-child{margin-top:0}
.exec-sec-label:after{content:'';flex:1;height:1px;background:var(--border)}

.biz-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.biz-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:13px 15px}
.biz-card .blbl{font-size:9.5px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;
  color:var(--text-3);margin-bottom:5px}
.biz-card .bval{font-size:13px;font-weight:650;color:var(--text);line-height:1.3}
.biz-card .bsub{font-size:11px;color:var(--text-3);margin-top:3px;line-height:1.4}
.biz-card .bsub.warn{color:var(--med);font-weight:600}

.exec-kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.ekpi{background:var(--surface);border:1px solid var(--border);border-radius:11px;padding:15px 16px;
  position:relative;overflow:hidden}
.ekpi:before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:11px 11px 0 0}
.ekpi.ek-tot:before{background:linear-gradient(90deg,#6366f1,#8b5cf6)}
.ekpi.ek-crit:before{background:var(--crit)} .ekpi.ek-med:before{background:var(--med)}
.ekpi.ek-low:before{background:var(--low)}   .ekpi.ek-awa:before{background:var(--awa)}
.ekpi .eklbl{font-size:9.5px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;
  color:var(--text-3);margin-bottom:5px}
.ekpi .ekval{font-size:32px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.ekpi.ek-tot .ekval{color:#6366f1} .ekpi.ek-crit .ekval{color:var(--crit)}
.ekpi.ek-med .ekval{color:var(--med)} .ekpi.ek-low .ekval{color:var(--low)}
.ekpi.ek-awa .ekval{color:var(--awa)}
.ekpi .eknote{font-size:11px;color:var(--text-3);margin-top:3px;line-height:1.3}

.exec-charts{display:grid;grid-template-columns:270px 1fr 220px;gap:12px}
.echart-card{background:var(--surface);border:1px solid var(--border);border-radius:11px;padding:16px}
.echart-card h3{font-size:12px;font-weight:700;color:var(--text);margin:0 0 2px}
.echart-card .ecsub{font-size:11px;color:var(--text-3);margin-bottom:10px}
.echart-card svg{display:block;width:100%;height:auto;overflow:visible}
.chart-lg{display:flex;flex-wrap:wrap;gap:5px 14px;margin-top:10px;font-size:10.5px;color:var(--text-3)}
.chart-lg i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}

.highlight-narrative{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:20px 22px}
.highlight-narrative p{color:var(--text-2);font-size:13px;line-height:1.75;margin:0 0 10px}
.highlight-narrative p:last-child{margin-bottom:0}
.highlight-narrative strong{color:var(--text)}
.highlight-narrative h3,.highlight-narrative h4{font-size:12.5px;font-weight:700;color:var(--text);
  margin:16px 0 7px}
.highlight-narrative ul,.highlight-narrative ol{color:var(--text-2);font-size:13px;line-height:1.7;
  margin:0 0 10px;padding-left:22px}

.efind-wrap{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  overflow:hidden}
.efind-hdr{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;
  padding:12px 16px;border-bottom:1px solid var(--border);background:var(--border-soft)}
.efind-hdr h3{font-size:13px;font-weight:700;color:var(--text);margin:0}
.elf-legend{display:flex;gap:12px;flex-wrap:wrap}
.elf-leg{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text-3)}
.elf-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.efind-wrap table{width:100%;border-collapse:collapse;font-size:12px}
.efind-wrap thead th{background:var(--border-soft);color:var(--text-3);font-size:9.5px;
  font-weight:800;letter-spacing:.08em;text-transform:uppercase;padding:9px 13px;
  border-bottom:1px solid var(--border);white-space:nowrap;text-align:left}
.efind-wrap tbody td{padding:9px 13px;border-bottom:1px solid var(--border-soft);
  color:var(--text-2);vertical-align:top}
.efind-wrap tbody td strong{color:var(--text)}
.efind-wrap tbody tr:last-child td{border-bottom:none}
.efind-wrap tbody tr:hover td{background:var(--border-soft)}
.efind-wrap tbody tr.rf-crit td:first-child{border-left:3px solid var(--crit)}
.efind-wrap tbody tr.rf-med td:first-child{border-left:3px solid var(--med)}
.efind-wrap tbody tr.rf-low td:first-child{border-left:3px solid var(--low)}
.efind-wrap tbody tr.rf-awa td:first-child{border-left:3px solid var(--awa)}
@media(max-width:900px){
  .biz-grid,.exec-kpis,.exec-charts{grid-template-columns:1fr}
}
@media print{
  .themebtn,.tabs,.pager{display:none!important}
  .pane{display:block!important}
  body{background:#fff}
  .section,.card{break-inside:avoid}
}
"""

JS = """
(function(){
  var root=document.documentElement, btn=document.getElementById('themebtn');
  function store(k,v){try{localStorage.setItem(k,v)}catch(e){}}
  function load(k){try{return localStorage.getItem(k)}catch(e){return null}}
  var saved=load('waf-theme');
  var dark = saved ? saved==='dark'
    : (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  function apply(d){
    root.setAttribute('data-theme', d?'dark':'light');
    if(btn){btn.setAttribute('aria-pressed',d?'true':'false');
      btn.querySelector('.tl').textContent = d?'Light mode':'Dark mode';}
  }
  apply(dark);
  if(btn) btn.addEventListener('click',function(){
    dark=!dark; apply(dark); store('waf-theme',dark?'dark':'light');
  });
})();

document.querySelectorAll('.tab').forEach(function(t){
  t.addEventListener('click',function(){
    document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active')});
    document.querySelectorAll('.pane').forEach(function(x){x.classList.remove('active')});
    t.classList.add('active');
    var p=document.getElementById('pane-'+t.dataset.tab);
    if(p) p.classList.add('active');
    window.scrollTo({top:0,behavior:'smooth'});
  });
});

var D = window.__REPORT__ || {};
var PAGE = 10;
var CL='<svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor"><path d="M15.4 4.6 13.9 3 5 12l8.9 9 1.5-1.6L8 12l7.4-7.4Z"/></svg>';
var CR='<svg width="9" height="9" viewBox="0 0 24 24" fill="currentColor"><path d="M8.6 4.6 10.1 3 19 12l-8.9 9-1.5-1.6L16 12 8.6 4.6Z"/></svg>';

function pager(page,total,fn){
  var h='<button class="pg" aria-label="Previous" onclick="'+fn+'('+Math.max(1,page-1)+')"'
        +(page===1?' disabled':'')+'>'+CL+'</button>';
  for(var i=1;i<=total;i++)
    h+='<button class="pg'+(i===page?' active':'')+'" onclick="'+fn+'('+i+')">'+i+'</button>';
  h+='<button class="pg" aria-label="Next" onclick="'+fn+'('+Math.min(total,page+1)+')"'
     +(page===total||total===0?' disabled':'')+'>'+CR+'</button>';
  return h;
}

// One card template for every issue, whoever wrote it. Scripted findings and the ones
// written during analysis render through this same function, so the two cannot present
// the same issue in two different shapes.
function card(f){
  var refs = f.refs && f.refs.length
    ? '<div class="refs">'+f.refs.map(function(r){
        return '<span class="ref"><strong>p'+r.priority+'</strong> '+r.name+'</span>';
      }).join('')+'</div>'
    : '<div class="refs"><span class="ref none">'+(f.rules_line||'no rule &mdash; decided from the web ACL body or the absence of a rule')+'</span></div>';
  return '<div class="card lv-'+f.sev_cls+'">'
    + '<div class="card-h"><span class="n">#'+f.number+'</span>'
    + '<span class="pill sv-'+f.sev_cls+'">'+f.sev_label+'</span>'
    + '<span class="t">'+f.title+'</span></div>'
    + '<div class="card-b">'
    + '<dt>Current state</dt><dd>'+(f.now||'<p>Not stated.</p>')+refs+'</dd>'
    + '<dt>Problem</dt><dd>'+(f.problem||'<p>Not stated.</p>')+'</dd>'
    + '<dt>Recommended action</dt><dd>'+(f.action||'<p>Not stated.</p>')+'</dd>'
    + (f.extra?'<dt>Notes</dt><dd>'+f.extra+'</dd>':'')
    + '</div></div>';
}

var fPage=1;
function goFindings(p){fPage=p;renderFindings();}
function renderFindings(){
  var el=document.getElementById('findings');
  if(!el) return;
  var data=D.issues||[], total=data.length, pages=Math.ceil(total/PAGE)||1;
  if(fPage>pages) fPage=pages;
  var start=(fPage-1)*PAGE;
  el.innerHTML=data.slice(start,start+PAGE).map(card).join('') || '<p>No findings.</p>';
  var info=document.getElementById('findings-info');
  if(info) info.textContent='Showing '+(total?start+1:0)+'\\u2013'
    +Math.min(start+PAGE,total)+' of '+total+' findings, most severe first';
  var pg=document.getElementById('findings-pages');
  if(pg) pg.innerHTML = pages>1 ? pager(fPage,pages,'goFindings') : '';
}
renderFindings();

var rPage=1;
function goRules(p){rPage=p;renderRules();}
function renderRules(){
  var body=document.getElementById('rules-body');
  if(!body) return;
  var data=D.rules||[], total=data.length, pages=Math.ceil(total/PAGE)||1;
  if(rPage>pages) rPage=pages;
  var start=(rPage-1)*PAGE;
  body.innerHTML=data.slice(start,start+PAGE).map(function(r){
    return '<tr><td class="num">'+r.n+'</td><td><strong>'+r.name+'</strong></td>'
      +'<td class="num">'+r.priority+'</td><td>'+r.type+'</td><td>'+r.action+'</td>'
      +'<td>'+r.desc+'</td><td>'+r.issues+'</td></tr>';
  }).join('');
  var info=document.getElementById('rules-info');
  if(info) info.textContent='Showing '+(total?start+1:0)+'\\u2013'
    +Math.min(start+PAGE,total)+' of '+total+' rules, in evaluation order';
  var pg=document.getElementById('rules-pages');
  if(pg) pg.innerHTML = pages>1 ? pager(rPage,pages,'goRules') : '';
}
renderRules();
"""


def section(title, icon_name, body):
    return (f'<div class="section"><h2>{icon(icon_name)}{title}</h2>{body}</div>')


# ── Current Setup: rule descriptions ────────────────────────────────────
# A plain-language gloss per rule, so the table says what a rule does rather than only
# what type it is. Keyed by managed rule group where one is recognised, and falling back
# to the statement class -- an unknown group gets the generic gloss rather than nothing.

_GROUP_DESC = {
    "AWSManagedRulesAntiDDoSRuleSet":
        "AWS Anti-DDoS: per-IP behavioural detection, with Challenge and Block "
        "mitigation during a detected event",
    "AWSManagedRulesAmazonIpReputationList":
        "Amazon threat intelligence: known malicious and reconnaissance source addresses",
    "AWSManagedRulesAnonymousIpList":
        "Anonymising infrastructure: Tor, public proxies, VPNs and hosting providers",
    "AWSManagedRulesCommonRuleSet":
        "Core rule set: OWASP-class injection, traversal and malformed-request coverage",
    "AWSManagedRulesKnownBadInputsRuleSet":
        "Known exploit payloads, including Log4Shell and Java deserialisation",
    "AWSManagedRulesSQLiRuleSet": "Extended SQL injection coverage",
    "AWSManagedRulesLinuxRuleSet": "Linux local file inclusion and command injection",
    "AWSManagedRulesUnixRuleSet": "POSIX local file inclusion and command injection",
    "AWSManagedRulesWindowsRuleSet": "Windows and PowerShell command injection",
    "AWSManagedRulesPHPRuleSet": "Unsafe PHP function and superglobal injection",
    "AWSManagedRulesWordPressRuleSet": "WordPress-specific attack patterns",
    "AWSManagedRulesBotControlRuleSet":
        "Bot Control: self-declared bot classification, billed per request",
    "AWSManagedRulesATPRuleSet":
        "Account Takeover Prevention: credential stuffing and stolen-credential use",
    "AWSManagedRulesACFPRuleSet":
        "Account Creation Fraud Prevention: scripted and fraudulent signups",
}

_TYPE_DESC = {
    "managed_rule_group": "Managed rule group",
    "rate_based": "Rate-based rule",
    "custom": "Custom rule",
}


def _values_for(summary, field):
    """Literal values a statement matches on for one FieldToMatch, in summary order.

    Reads the summary string rather than the raw statement because waf-assess.py has
    already done the work there -- including base64-decoding SearchString, which the
    WAFv2 API carries as a blob. Without that decode this returns identifiers like
    `L2F1dGgv` and the description is worse than useless.
    """
    # Two shapes reach here. A single leaf renders as "uri_path STARTS_WITH '/a'"; a
    # collapsed same-type OR renders as "uri_path STARTS_WITH '/a', '/b', '/c'". Anchor on
    # the field and constraint, then take every quoted value that follows in that run.
    anchor = rf"{field}\s+(?:EXACTLY|STARTS_WITH|ENDS_WITH|CONTAINS)\s+((?:'[^']*'(?:,\s*)?)+)"
    out = []
    for run in re.findall(anchor, summary):
        for v in re.findall(r"'([^']*)'", run):
            if v not in out:
                out.append(v)
    return out


def _plural(n, word):
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _join(vals, limit=4):
    shown = ", ".join(f"<code>{esc(v)}</code>" for v in vals[:limit])
    return shown + (f" and {len(vals) - limit} more" if len(vals) > limit else "")


def _purpose(r):
    """What a custom rule is *for*, inferred from the shape of its statement.

    The statement summary alone is a mechanical transcript -- `OR(ip_set 'arn:aws:...')`
    tells a reader nothing they wanted to know. This names the intent instead: an IP set
    plus Allow is an allowlist, a geo match inside a NOT is an allowlist rather than a
    denylist, a label match feeding a Challenge is an always-on Challenge. Returns None
    when the shape is not recognised, and the caller falls back to the transcript rather
    than inventing a purpose.
    """
    st = r.get("statement") or {}
    summary = st.get("summary") or ""
    leaves = st.get("leaf_types") or []
    action = r.get("action")
    negated = summary.startswith("NOT(")

    if summary.startswith("rule_group "):
        if "ShieldMitigationRuleGroup" in summary:
            return ("Shield Advanced automatic L7 mitigations &mdash; placed last by "
                    "Shield, managed by AWS, and evidence that Shield Advanced is "
                    "subscribed")
        return "Customer-owned rule group (contents not in this export)"

    if "geo_match" in leaves:
        codes = re.findall(r"'([A-Z]{2})'", summary)
        kind = ("allowlist" if (negated and action == "block")
                or (not negated and action == "allow") else "denylist")
        return (f"Geographic {kind}"
                + (f": {', '.join(codes)}" if codes else "")
                + (f" ({len(codes)} countries)" if len(codes) > 6 else ""))

    if "ip_set" in leaves:
        # Count *distinct* ARNs, not occurrences. A rule that ORs one IP set with itself
        # reads as "2 IP sets" on an occurrence count, which is both wrong and reassuring
        # -- it hides a dead branch, and usually a missing IPv6 companion set with it.
        arns = re.findall(r"ip_set '([^']*)'", summary)
        distinct = list(dict.fromkeys(arns))
        kind = {"allow": "allowlist", "block": "denylist"}.get(action, "list")
        bits = []
        if len(arns) > len(distinct):
            bits.append(f"{_plural(len(distinct), 'set')} referenced "
                        f"{len(arns)} times, so the duplicate branch is dead")
        else:
            bits.append(_plural(len(distinct), "IP set"))
        families = {("v6" if re.search(r"v6", a, re.I) else "v4") for a in distinct}
        if families == {"v4"}:
            bits.append("IPv4 only, no IPv6 set")
        bits.append("contents not in this export")
        return f"IP {kind} &mdash; " + ", ".join(bits)

    if "asn_match" in leaves:
        asns = re.findall(r"\b(\d{3,6})\b", summary)
        return ("Network (ASN) match" + (f" on AS{', AS'.join(asns[:4])}" if asns else ""))

    if "label_match" in leaves:
        keys = re.findall(r"label_match '([^']+)'", summary)
        return ("Acts on traffic labelled by an earlier rule"
                + (f": {_join(keys, 2)}" if keys else ""))

    if "byte_match" in leaves or "regex_match" in leaves or "regex_pattern_set" in leaves:
        paths = _values_for(summary, "uri_path")
        methods = _values_for(summary, "method")
        headers = re.findall(r"single_header:([\w-]+)", summary)
        bits = []
        if paths:
            verb = ("URI prefix" if "STARTS_WITH" in summary
                    else "URI" if "EXACTLY" in summary else "URI substring")
            bits.append(f"{verb} match on {_join(paths)}")
        if methods:
            bits.append(f"HTTP method {_join(methods, 3)}")
        if headers:
            bits.append(f"header {_join(sorted(set(headers)), 2)}")
        if "regex_match" in leaves or "regex_pattern_set" in leaves:
            bits.append("regular-expression match")
        if bits:
            return "; ".join(bits)
        return "Request-content match"

    if "size_constraint" in leaves:
        return "Request size constraint"
    if "sqli_match" in leaves:
        return "SQL injection pattern match"
    if "xss_match" in leaves:
        return "Cross-site scripting pattern match"
    return None


#: What each action means for the rules that follow. The terminating ones are the point of
#: this column: a reader scanning the table needs to see where evaluation can stop.
_ACTION_CONSEQUENCE = {
    "allow": "Allow is terminating, so matching traffic skips every rule below",
    "block": "Block is terminating, so matching traffic is rejected here",
    "count": "Count only &mdash; records the match and changes nothing",
    "challenge": "Challenge &mdash; only a browser GET accepting HTML can complete it",
    "captcha": "CAPTCHA &mdash; only a browser GET accepting HTML can complete it",
}


def describe_rule(r):
    """The Short Description cell: what this rule is for, then what has been done to it.

    Purpose first, mechanics second. The managed rule groups get their gloss from
    _GROUP_DESC; custom rules get theirs from _purpose(), which reads the statement shape.
    Everything after the em dash is a qualifier that changes how the rule actually behaves
    -- a group overridden to Count, a terminating Allow, a missing metric -- because those
    are what a rule that reads as ordinary hides.
    """
    mg = r.get("managed") or {}
    group = mg.get("group_name") or ""
    base = _GROUP_DESC.get(group)
    if base is None:
        if r.get("type") == "rate_based":
            rb = r.get("rate_based") or {}
            limit, win = rb.get("limit"), rb.get("evaluation_window_sec")
            key = rb.get("aggregate_key_type") or "IP"
            if isinstance(limit, int) and win:
                per_sec = limit / win
                base = esc(f"Rate limit: {limit:,} requests per {win}s per {key} "
                           f"(~{per_sec:,.0f}/second)")
            else:
                base = "Rate limit"
        elif group:
            base = esc(f"Managed rule group {group}")
        else:
            base = _purpose(r)          # already HTML
            if base is None:
                raw = (r.get("statement") or {}).get("summary") or "Custom rule"
                if len(raw) > 110:
                    raw = raw[:107] + "..."
                base = esc(raw)
    else:
        base = esc(base)                # _GROUP_DESC is plain text

    notes = []
    consequence = _ACTION_CONSEQUENCE.get(r.get("action"))
    # Only worth saying where it is load-bearing. A Block on a denylist is doing exactly
    # what the name says, so restating it is noise; an Allow, or a Count on a rule whose
    # name implies enforcement, is the thing a reader is scanning for.
    if consequence and r.get("action") in ("allow", "challenge", "captcha"):
        notes.append(consequence)
    elif r.get("action") == "count" and r.get("type") != "managed_rule_group":
        notes.append(consequence)
    if r.get("action") == "count" and r.get("type") == "managed_rule_group":
        notes.append("whole group overridden to Count, so it blocks nothing")
    if r.get("scope_down"):
        notes.append("narrowed by a scope-down")
    overrides = mg.get("overrides") or []
    allows = [o["rule_name"] for o in overrides if o.get("action") == "allow"]
    counts = [o["rule_name"] for o in overrides if o.get("action") == "count"]
    if allows:
        notes.append(f"{_plural(len(allows), 'sub-rule')} overridden to Allow "
                     f"({esc(', '.join(allows[:3]))}), which ends evaluation")
    if counts:
        notes.append(f"{_plural(len(counts), 'sub-rule')} overridden to Count")
    if mg.get("excluded_rules"):
        notes.append(_plural(len(mg["excluded_rules"]), "sub-rule") + " excluded")
    if r.get("rule_labels"):
        notes.append("applies label " + _join(r["rule_labels"], 2))
    if not (r.get("visibility_config") or {}).get("cloudwatch_metrics_enabled", True):
        notes.append("no CloudWatch metric")

    if notes:
        return base + " &mdash; " + "; ".join(notes)
    return base


_ACTION_PILL = {
    "block": ("sv-crit", "Block"), "allow": ("sv-low", "Allow"),
    "count": ("sv-awa", "Count"), "challenge": ("sv-med", "Challenge"),
    "captcha": ("sv-med", "CAPTCHA"),
    "managed_default": ("tag", "Group defaults"),
}


def rules_data(summary_json, issue_map):
    out = []
    rules = sorted(summary_json.get("rules", []),
                   key=lambda r: (r.get("priority") if r.get("priority") is not None
                                  else 10 ** 9))
    for n, r in enumerate(rules, start=1):
        cls, label = _ACTION_PILL.get(r.get("action"), ("tag", r.get("action") or "?"))
        pill = (f'<span class="{"pill " + cls if cls != "tag" else "tag"}">'
                f"{esc(label)}</span>")
        nums = issue_map.get(r["name"]) or []
        out.append({
            "n": n,
            "name": esc(r.get("name") or "unnamed"),
            "priority": esc(r.get("priority")),
            "type": esc(_TYPE_DESC.get(r.get("type"), r.get("type") or "")),
            "action": pill,
            "desc": describe_rule(r),
            "issues": ("".join(f'<span class="pill sv-med">#{i}</span> ' for i in nums)
                       if nums else '<span class="tag">clear</span>'),
        })
    return out


# ── Current Setup: application context ────────────────────────────────────
# Every field is printed, including the ones nobody answered. The absent ones are the
# point: a reader can see which findings rest on an answer somebody gave, and which
# questions were never put. Add a field to context-schema.md and it must be added here
# too, in both branches, or it silently never appears.

_CTX_FIELDS = [
    ("client_types", "Client types",
     "Decides whether a Challenge verifies a visitor or blocks one"),
    ("landing_page_uris", "Landing page paths",
     "The paths an always-on Challenge would cover"),
    ("api_paths", "API / non-browser paths",
     "Which Challenge rules are effectively Block"),
    ("logging", "WAF logging",
     "Cannot be read from the Web ACL export at all"),
    ("waf_only_for_ddos", "Scope of this web ACL",
     "Whether missing application-layer rule groups is a gap or a design choice"),
    ("protected_resource", "Protected resource",
     "What this web ACL is associated with"),
    ("intended_protected_resource", "Resource it should protect",
     "A mismatch means something is unprotected and no rule tuning fixes it"),
    ("cdn", "CDN in front",
     "Decides whether rate rules are aggregating on the client address or the proxy's"),
    ("tls_termination", "TLS termination",
     "WAF can only inspect where TLS terminates"),
    ("origin_protection", "Origin lock-down",
     "A directly reachable origin can make every rule here optional"),
    ("markets", "Markets served",
     "Whether geo restriction is available and free"),
    ("environment", "Environment",
     "How much risk a staged change carries"),
    ("traffic_profile", "Traffic profile",
     "Supplies the arithmetic for the rate-limit threshold check: peak per source plus a "
     + "50-100% buffer"),
    ("shield_advanced", "Shield Advanced",
     "What is already paid for, and what is still billed"),
    ("custom_rule_groups", "Custom rule group contents",
     "What is inside the rule groups the export shows only as an ARN"),
    ("known_issues", "History and caveats",
     "Operator-supplied facts that change how a finding should read"),
]


def _ctx_value(v):
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, dict):
        return "; ".join(f"{k}: {_ctx_value(val)}" for k, val in v.items() if val is not None)
    if isinstance(v, (list, tuple)):
        return ", ".join(str(i) for i in v)
    return str(v)


def app_context(summary_json):
    ctx = summary_json.get("context") or {}
    acl = summary_json.get("web_acl") or {}
    given, derived, absent = [], [], []

    for key, label, why in _CTX_FIELDS:
        if key in ctx and ctx[key] is not None and ctx[key] != [] and ctx[key] != {}:
            given.append(f'<li class="given"><span class="ctx-key">{esc(label)}:</span> '
                         f"{_inline(_ctx_value(ctx[key]))}</li>")
        else:
            absent.append(f'<li class="absent"><span class="ctx-key">{esc(label)}:</span> '
                          f"not supplied &mdash; {esc(why)}</li>")

    # Facts the export settles on its own, so a reader can tell them from the answers.
    arn = acl.get("arn") or ""
    region = arn.split(":")[3] if len(arn.split(":")) > 3 else None
    scope = ("CloudFront (global)" if "global" in arn
             else "Regional" if arn else None)
    for label, val in (
            ("Scope", scope),
            ("Region", region),
            ("Account", arn.split(":")[4] if len(arn.split(":")) > 4 else None),
            ("Default action", (acl.get("default_action") or "").upper() or None),
            ("Rules", summary_json.get("rule_count")),
            ("Capacity", (f"{acl['effective_capacity']:,} WCU of {WCU_CEILING:,}"
                          if acl.get("effective_capacity") else None)),
            ("Shield Advanced",
             "subscribed (Shield mitigation rule group present)"
             if acl.get("shield_advanced") else None),
            ("Firewall Manager",
             "this web ACL is managed centrally, so some rules may not be locally "
             "changeable" if acl.get("managed_by_fms") else None)):
        if val not in (None, ""):
            derived.append(f'<li class="derived"><span class="ctx-key">{esc(label)}:</span> '
                           f"{esc(val)}</li>")

    parts = ['<p class="lead">Three groups: what an operator told us, what the export '
             + 'settles on its own, and what nobody answered. The last group is printed '
             + 'rather than omitted &mdash; a finding that rests on an unanswered question '
             + 'should be legible as such.</p>']
    if given:
        parts.append(f"<h3>Supplied by the operator</h3><ul class=\"ctx\">{''.join(given)}</ul>")
    parts.append(f"<h3>Established from the export</h3><ul class=\"ctx\">{''.join(derived)}</ul>")
    if absent:
        parts.append(f"<h3>Not supplied</h3><ul class=\"ctx\">{''.join(absent)}</ul>")
    return "".join(parts)


def _default_action_note(acl):
    """Qualifier after the default-action pill.

    A Block with a 2xx custom response is the case worth naming: the request is
    genuinely blocked, but every downstream monitor, load balancer log and uptime
    check reads a success, so the blocks are invisible to whoever is on call.
    """
    if not acl.get("default_action_custom_handling"):
        return ""
    code = acl.get("default_action_response_code")
    if acl.get("default_action") == "block" and isinstance(code, int):
        if 200 <= code < 300:
            return (f' with a custom response returning <strong>HTTP {code}</strong> '
                    f'&mdash; blocked requests report success downstream')
        return f" with a custom response returning HTTP {code}"
    return " with custom response handling"


def acl_table(summary_json):
    acl = summary_json.get("web_acl") or {}
    cap, actual = acl.get("capacity"), acl.get("actual_capacity")
    cap_txt = f"{cap:,} WCU published" if isinstance(cap, int) else "unknown"
    if isinstance(actual, int) and isinstance(cap, int) and actual != cap:
        cap_txt += (f", {actual:,} WCU actually consumed &mdash; cost and the "
                    f"{WCU_CEILING:,} ceiling both follow the higher figure")
    ch = acl.get("challenge_config") or {}
    cp = acl.get("captcha_config") or {}
    rows = [
        ("Name", esc(acl.get("name"))),
        ("ARN", f"<code>{esc(acl.get('arn'))}</code>" if acl.get("arn") else "&mdash;"),
        ("Description", esc(acl.get("description")) or "&mdash;"),
        ("Default action", f'<span class="pill '
                           + f'{"sv-crit" if acl.get("default_action") == "block" else "sv-low"}">'
                           + f'{esc((acl.get("default_action") or "?").upper())}</span>'
                           + _default_action_note(acl)),
        ("Capacity", cap_txt),
        ("Rules", esc(summary_json.get("rule_count"))),
        ("Token domains", ", ".join(f"<code>{esc(d)}</code>"
                                    for d in acl.get("token_domains") or [])
                          or ("none set &mdash; the token is scoped to the protected "
                              + "resource's own domain")),
        ("Challenge immunity", f"{ch['immunity_time']}s"
                               if ch.get("immunity_time") else
                               "not set &mdash; the 300s service default applies"),
        ("CAPTCHA immunity", f"{cp['immunity_time']}s"
                             if cp.get("immunity_time") else
                             "not set &mdash; the 300s service default applies"),
        ("Shield Advanced", "subscribed" if acl.get("shield_advanced")
                            else "not detected in this export"),
        ("Managed by Firewall Manager", "yes" if acl.get("managed_by_fms") else "no"),
        ("Source format", esc(summary_json.get("input_format"))),
    ]
    body = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)
    return f'<div class="table-wrap"><table><tbody>{body}</tbody></table></div>'


def kpis(summary_json, issues):
    acl = summary_json.get("web_acl") or {}
    counts = {k: 0 for k in SEVERITY}
    for i in issues:
        counts[i["sev"]] += 1
    defects = counts["critical"] + counts["medium"] + counts["low"]
    wcu = acl.get("effective_capacity") or 0
    wcu_pct = min(100, round(wcu / WCU_CEILING * 100, 1)) if wcu else 0

    cards = [
        ("Findings", f'{len(issues)}<span class="u">total</span>',
         "100%", "var(--accent)",
         f"{defects} to act on &middot; {counts['awareness']} for awareness"),
        ("Critical", f'{counts["critical"]}',
         f"{min(100, counts['critical'] * 25)}%",
         "var(--crit)" if counts["critical"] else "var(--low)",
         "full bypass or a disabled core protection" if counts["critical"]
         else "no full-bypass findings"),
        ("Capacity", f'{wcu:,}<span class="u">WCU</span>' if wcu
         else '<span class="u">unknown</span>',
         f"{wcu_pct}%", "var(--med)" if wcu_pct > 70 else "var(--low)",
         (f"{wcu_pct}% of the {WCU_CEILING:,} ceiling &middot; "
          + f"{WCU_CEILING - wcu:,} left") if wcu
         else "not in this export; check the console before adding rules"),
        ("DDoS posture",
         "Shield Advanced" if acl.get("shield_advanced") else "WAF only",
         "100%", "var(--awa)",
         _inline(_ctx_value(acl.get("ddos_protection_config") or {}))
         or "no automatic mitigation configured"),
    ]
    out = []
    for label, val, width, fill, note in cards:
        size = ' style="font-size:19px"' if not val[0].isdigit() else ""
        out.append(f'<div class="kpi"><div class="lbl">{label}</div>'
                   f'<div class="val"{size}>{val}</div>'
                   f'<div class="bar"><span style="width:{width};background:{fill}"></span></div>'
                   f'<div class="note">{note}</div></div>')
    return f'<div class="kpis">{"".join(out)}</div>'


def severity_bar(issues):
    counts = {k: 0 for k in SEVERITY}
    for i in issues:
        counts[i["sev"]] += 1
    total = sum(counts.values()) or 1
    bars, legend = [], []
    for key, (label, _order, cls) in sorted(SEVERITY.items(), key=lambda kv: kv[1][1]):
        n = counts[key]
        if n:
            bars.append(f'<span class="bg-{cls}" style="width:{n / total * 100:.2f}%">'
                        f"{n}</span>")
        legend.append(f'<span><i class="bg-{cls}"></i>{label} &mdash; {n}</span>')
    return (f'<div class="stat">{"".join(bars)}</div>'
            f'<div class="legend">{"".join(legend)}</div>')


def summary_table(issues):
    rows = []
    for i in issues:
        # First bullet of the Problem block, as the one-line "why this matters".
        m = re.search(r"^\s*[-*]\s+(.+)$", i["problem"], re.M)
        impact = m.group(1).strip() if m else ""
        impact = re.sub(r"\s+", " ", impact)
        if len(impact) > 150:
            impact = impact[:147] + "..."
        rows.append(
            f'<tr><td class="num">#{i["number"]}</td>'
            f'<td><span class="pill sv-{i["sev_cls"]}">{i["sev_label"]}</span></td>'
            f'<td><strong>{_inline(i["title"])}</strong></td>'
            f"<td>{_inline(impact)}</td></tr>")
    return ('<div class="table-wrap"><table><thead><tr><th>#</th><th>Severity</th>'
            "<th>Finding</th><th>Why it matters</th></tr></thead>"
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def appendix_html(summary_json):
    acl = summary_json.get("web_acl") or {}
    wcu = acl.get("effective_capacity")
    if wcu:
        wcu_text = (f"Current capacity: **{wcu:,} WCU** of the {WCU_CEILING:,} maximum, "
                    f"leaving **{WCU_CEILING - wcu:,} WCU** of headroom.")
    else:
        wcu_text = ("Capacity is not present in this export. Check it in the console "
                    "before adding rules.")
    # .format rather than .replace: the appendix doubles its braces so that the JSON
    # payloads survive being a format template, and only .format undoubles them. Using
    # .replace here would emit `{{` into the report and every JSON block in Appendix A
    # would be malformed.
    return markdown(APPENDIX_SECTIONS.format(wcu_text=wcu_text))


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY TAB
#
# Four blocks, in this order: business application context, findings overview
# (KPIs + three charts), the Highlight Findings prose, then every finding in one table.
# The structure comes from assets/summary-tab-template.md; this module is its only
# implementation, so the layout cannot drift between assessments.
#
# The charts are **inline SVG, computed here**. The design they came from loaded Highcharts
# from a CDN, which cannot be used: a single external script would break the
# self-containment guarantee, and a reader opening the report from an email attachment with
# no network would get three empty boxes where the charts should be. Three shapes -- a
# donut, a stacked bar and an arc gauge -- are a few dozen lines of trigonometry, and they
# print, which a canvas-based chart does not.
# ══════════════════════════════════════════════════════════════════════════════

#: Protection domain per finding, keyed by the template's `title_key`. This is what the
#: "Category" column and the stacked bar chart group by. A scripted finding is looked up
#: exactly; anything written during analysis falls through to the keyword pass below.
_CATEGORY_BY_KEY = {
    "group_level_count": "DDoS / Shield", "antiddos_position": "DDoS / Shield",
    "unanchored_exempt_regex": "DDoS / Shield",
    "challenge_all_during_event": "DDoS / Shield",
    "missing_crawler_labeling": "DDoS / Shield",
    "missing_always_on_challenge": "DDoS / Shield",
    "challenge_not_ready": "DDoS / Shield", "challenge_on_post_api": "DDoS / Shield",

    "forgeable_allow": "Rule Logic / Bypass",
    "terminating_allow_strands": "Rule Logic / Bypass",
    "deliberate_allowlist": "Rule Logic / Bypass",
    "hosting_provider_allow": "Rule Logic / Bypass",
    "managed_allow_override": "Rule Logic / Bypass",
    "ip_reputation_action": "Rule Logic / Bypass",
    "name_action_mismatch": "Rule Logic / Bypass",
    "default_action_redundancy": "Rule Logic / Bypass",
    "duplicate_branch": "Rule Logic / Bypass", "priority_order": "Rule Logic / Bypass",
    "opaque_search_string": "Rule Logic / Bypass",

    "geo_vs_markets": "Geo / IP Sets", "single_address_family": "Geo / IP Sets",
    "token_domain": "Geo / IP Sets", "missing_ip_reputation": "Geo / IP Sets",

    "rate_rule_ineffective": "Rate Limiting", "rate_forwarded_ip": "Rate Limiting",
    "rate_fallback_unset": "Rate Limiting", "rate_window_out_of_range": "Rate Limiting",
    "rate_shared_ip_keys": "Rate Limiting", "rate_layers_missing": "Rate Limiting",
    "rate_threshold_vs_baseline": "Rate Limiting", "duplicate_rules": "Rate Limiting",

    "managed_count_overrides": "Body Inspection", "missing_baseline": "Body Inspection",
    "managed_versions": "Body Inspection", "scope_down_too_narrow": "Body Inspection",
    "managed_scope_down": "Body Inspection",

    "no_logging": "Logging / Observ.", "logging_disabled": "Logging / Observ.",
    "logging_gaps": "Logging / Observ.", "count_without_labels": "Logging / Observ.",
    "orphan_managed_label": "Logging / Observ.", "opaque_rule_groups": "Logging / Observ.",

    "bot_control_search_allow": "Bot / Fraud", "no_bot_management": "Bot / Fraud",
}

#: Display order for the bar chart, so the axis is stable across assessments even when a
#: category has no findings in a given run.
CATEGORY_ORDER = ["DDoS / Shield", "Rule Logic / Bypass", "Geo / IP Sets", "Rate Limiting",
                  "Body Inspection", "Logging / Observ.", "Bot / Fraud"]

#: Keyword fallback, checked in order. Only reached for findings written during analysis,
#: which carry no title_key. Deliberately ordered most-specific-first.
_CATEGORY_KEYWORDS = [
    ("Rate Limiting", ("rate limit", "rate-limit", "rate-based", "ratebase", "threshold",
                       "aggregation", "aggregate")),
    ("DDoS / Shield", ("anti-ddos", "antiddos", "shield", "challenge", "crawler", "ddos")),
    ("Bot / Fraud", ("bot control", "bot management", "atp", "acfp", "fraud")),
    ("Logging / Observ.", ("logging", "log ", "label", "metric", "observab")),
    ("Geo / IP Sets", ("geo", "ip set", "ipv6", "ipv4", "denylist", "allowlist", "country",
                       "token domain")),
    ("Body Inspection", ("body", "core rule set", "crs", "sqli", "injection", "scope-down",
                         "known bad")),
    ("Rule Logic / Bypass", ("allow", "bypass", "priority", "order", "name", "override")),
]


def finding_category(title, title_key=None):
    if title_key and title_key in _CATEGORY_BY_KEY:
        return _CATEGORY_BY_KEY[title_key]
    low = re.sub(r"<[^>]+>", "", str(title or "")).lower()
    for cat, words in _CATEGORY_KEYWORDS:
        if any(w in low for w in words):
            return cat
    return "Rule Logic / Bypass"


_SEV_HEX = {"critical": "#dc2626", "medium": "#d97706", "low": "#16a34a",
            "awareness": "#2563eb"}


def _arc(cx, cy, r, a0, a1):
    """SVG arc path points for a circle segment, angles in degrees clockwise from 12 o'clock."""
    import math
    def pt(a):
        rad = math.radians(a - 90)
        return cx + r * math.cos(rad), cy + r * math.sin(rad)
    return pt(a0), pt(a1)


def svg_donut(counts, total):
    """Severity breakdown as a donut. Inline SVG so it survives an offline reader."""
    import math
    cx = cy = 74
    ro, ri = 66, 43
    segs, a = [], 0.0
    present = [(k, counts[k]) for k in ("critical", "medium", "low", "awareness") if counts[k]]
    if not present:
        return '<svg viewBox="0 0 148 148" role="img"><circle cx="74" cy="74" r="54" ' \
               'fill="none" stroke="var(--border)" stroke-width="23"/></svg>'
    if len(present) == 1:
        k, _n = present[0]
        segs.append(f'<circle cx="{cx}" cy="{cy}" r="{(ro + ri) / 2:.1f}" fill="none" '
                    f'stroke="{_SEV_HEX[k]}" stroke-width="{ro - ri}"/>')
    else:
        for k, n in present:
            sweep = n / total * 360.0
            (x0, y0), (x1, y1) = _arc(cx, cy, ro, a, a + sweep)
            (u0, v0), (u1, v1) = _arc(cx, cy, ri, a + sweep, a)
            large = 1 if sweep > 180 else 0
            segs.append(
                f'<path d="M{x0:.2f},{y0:.2f} A{ro},{ro} 0 {large} 1 {x1:.2f},{y1:.2f} '
                f'L{u0:.2f},{v0:.2f} A{ri},{ri} 0 {large} 0 {u1:.2f},{v1:.2f} Z" '
                f'fill="{_SEV_HEX[k]}"/>')
            a += sweep
    legend = "".join(
        f'<span><i style="background:{_SEV_HEX[k]}"></i>{SEVERITY[k][0]} {counts[k]}</span>'
        for k, _n in present)
    return (f'<svg viewBox="0 0 148 148" role="img" aria-label="Severity breakdown">'
            f'{"".join(segs)}'
            f'<text x="{cx}" y="{cy - 3}" text-anchor="middle" font-size="30" '
            f'font-weight="800" fill="var(--text)">{total}</text>'
            f'<text x="{cx}" y="{cy + 15}" text-anchor="middle" font-size="10" '
            f'font-weight="700" letter-spacing="1" fill="var(--text-3)">FINDINGS</text>'
            f'</svg><div class="chart-lg">{legend}</div>')


def svg_stacked_bar(by_cat):
    """Findings per protection domain, stacked by severity. Fixed 100-unit x-scale."""
    rows = [(c, by_cat.get(c, {})) for c in CATEGORY_ORDER]
    peak = max([sum(v.values()) for _c, v in rows] + [1])
    rowh, gap, labw, barw = 22, 8, 132, 300
    h = len(rows) * (rowh + gap)
    out = []
    for i, (cat, sev) in enumerate(rows):
        y = i * (rowh + gap)
        out.append(f'<text x="{labw - 8}" y="{y + 15}" text-anchor="end" font-size="10.5" '
                   f'fill="var(--text-2)">{esc(cat)}</text>')
        x = labw
        tot = sum(sev.values())
        if not tot:
            out.append(f'<rect x="{x}" y="{y + 4}" width="{barw}" height="{rowh - 8}" rx="3" '
                       f'fill="var(--border-soft)"/>')
            out.append(f'<text x="{x + 7}" y="{y + 15}" font-size="9.5" '
                       f'fill="var(--text-3)">none</text>')
            continue
        for k in ("critical", "medium", "low", "awareness"):
            n = sev.get(k, 0)
            if not n:
                continue
            w = n / peak * barw
            out.append(f'<rect x="{x:.1f}" y="{y + 3}" width="{w:.1f}" height="{rowh - 6}" '
                       f'fill="{_SEV_HEX[k]}"><title>{SEVERITY[k][0]}: {n}</title></rect>')
            if w > 15:
                out.append(f'<text x="{x + w / 2:.1f}" y="{y + 16}" text-anchor="middle" '
                           f'font-size="10" font-weight="700" fill="#fff">{n}</text>')
            x += w
        out.append(f'<text x="{x + 7:.1f}" y="{y + 16}" font-size="10.5" font-weight="700" '
                   f'fill="var(--text-2)">{tot}</text>')
    return (f'<svg viewBox="0 0 {labw + barw + 34} {h}" role="img" '
            f'aria-label="Findings by protection category">{"".join(out)}</svg>')


def svg_gauge(used, ceiling, included):
    """WCU utilisation as a 270-degree arc gauge."""
    import math
    if not used:
        return ('<svg viewBox="0 0 200 150" role="img"><text x="100" y="80" '
                'text-anchor="middle" font-size="13" fill="var(--text-3)">capacity not in '
                'this export</text></svg>')
    pct = min(100.0, used / ceiling * 100)
    cx, cy, r, sw = 100, 100, 68, 15
    start, span = -135.0, 270.0

    def pol(a):
        rad = math.radians(a - 90)
        return cx + r * math.cos(rad), cy + r * math.sin(rad)
    (bx0, by0), (bx1, by1) = pol(start), pol(start + span)
    end = start + span * pct / 100
    (fx0, fy0), (fx1, fy1) = pol(start), pol(end)
    col = "#dc2626" if pct >= 90 else "#d97706" if used > included else "#16a34a"
    # the included-allocation tick, since the surcharge boundary is the number that bills
    ta = start + span * min(100.0, included / ceiling * 100) / 100
    (tx0, ty0), (tx1, ty1) = pol(ta), pol(ta)
    import math as _m
    rad = _m.radians(ta - 90)
    inner = (cx + (r - sw) * _m.cos(rad), cy + (r - sw) * _m.sin(rad))
    outer = (cx + (r + 5) * _m.cos(rad), cy + (r + 5) * _m.sin(rad))
    return (f'<svg viewBox="0 0 200 152" role="img" aria-label="WCU utilisation">'
            f'<path d="M{bx0:.1f},{by0:.1f} A{r},{r} 0 1 1 {bx1:.1f},{by1:.1f}" fill="none" '
            f'stroke="var(--border-soft)" stroke-width="{sw}" stroke-linecap="round"/>'
            f'<path d="M{fx0:.1f},{fy0:.1f} A{r},{r} 0 {1 if pct > 66.7 else 0} 1 '
            f'{fx1:.1f},{fy1:.1f}" fill="none" stroke="{col}" stroke-width="{sw}" '
            f'stroke-linecap="round"/>'
            f'<line x1="{inner[0]:.1f}" y1="{inner[1]:.1f}" x2="{outer[0]:.1f}" '
            f'y2="{outer[1]:.1f}" stroke="var(--text-3)" stroke-width="1.5"/>'
            f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="26" '
            f'font-weight="800" fill="{col}">{pct:.1f}%</text>'
            f'<text x="{cx}" y="{cy + 14}" text-anchor="middle" font-size="11" '
            f'fill="var(--text-3)">{used:,} / {ceiling:,}</text>'
            f'<text x="{cx}" y="{cy + 42}" text-anchor="middle" font-size="10" '
            f'fill="var(--text-3)">tick = {included:,} included</text>'
            f'</svg>')


def _label(text):
    return f'<div class="exec-sec-label">{text}</div>'


def _card(lbl, val, sub, warn=False):
    return (f'<div class="biz-card"><div class="blbl">{lbl}</div>'
            f'<div class="bval">{val}</div>'
            f'<div class="bsub{" warn" if warn else ""}">{sub}</div></div>')


def biz_context_grid(summary_json, issues):
    """Six cards naming what this web ACL protects, for a reader who has never seen it.

    Every value is derived -- from the context file where the operator supplied one, from the
    export otherwise -- so this block cannot state something the assessment does not know.
    An absent answer says so rather than being omitted.
    """
    acl = summary_json.get("web_acl") or {}
    ctx = summary_json.get("context") or {}
    unknown = '<span style="color:var(--text-3)">not supplied</span>'

    clients = ctx_list_display(ctx, "client_types")
    browser = any(k in c.lower() for c in clients for k in ("browser", "web", "site"))
    markets = ctx_list_display(ctx, "markets")
    env = str(ctx.get("environment") or "").strip()

    arch_bits = [str(ctx.get("protected_resource") or "").upper() or None]
    cdn = str(ctx.get("cdn") or "")
    if "accelerator" in cdn.lower():
        arch_bits.append("Global Accelerator")
    elif cdn and "none" not in cdn.lower():
        arch_bits.append(cdn.split("—")[0].split(",")[0].strip())
    arch = " + ".join(b for b in arch_bits if b) or unknown
    arch_sub = []
    if ctx.get("tls_termination"):
        arch_sub.append(f'TLS at {esc(str(ctx["tls_termination"]).upper())}')
    if ctx.get("origin_protection"):
        arch_sub.append("origin restricted")
    
    # Is the Anti-DDoS group actually enforcing? The KPI is meaningless without it.
    amr = next((r for r in summary_json.get("rules", [])
                if "AntiDDoS" in ((r.get("managed") or {}).get("group_name") or "")), None)
    amr_off = bool(amr) and amr.get("action") == "count"
    if acl.get("shield_advanced"):
        ddos_val, ddos_sub = "Shield Advanced", "subscription includes the Anti-DDoS rule group"
    else:
        ddos_val, ddos_sub = "WAF only", "no Shield Advanced detected in this export"
    if amr_off:
        ddos_sub = "Anti-DDoS rule group present but overridden to Count"
    elif amr is None:
        ddos_sub = "Anti-DDoS rule group not present"

    log = ctx.get("logging")
    if isinstance(log, dict):
        log_val = esc(str(log.get("destination") or "configured").split("—")[0].strip())
        bits = []
        if log.get("filtered"):
            bits.append("filtered, so plain Allows are not logged")
        if log.get("redacted_fields"):
            bits.append(f'{len(log["redacted_fields"])} field(s) redacted')
        log_sub = "; ".join(bits) or "no filter or redaction stated"
    elif "logging" in ctx:
        log_val, log_sub = "Not configured", "no record of blocks, challenges or allows"
    else:
        log_val, log_sub = unknown, "cannot be read from the Web ACL export"

    return ('<div class="biz-grid">'
            + _card("Application", esc(acl.get("name") or "unnamed"),
                    esc(acl.get("description") or "") or f'{summary_json.get("rule_count", 0)} '
                    f'rules, default action {esc((acl.get("default_action") or "?").upper())}')
            + _card("Client &amp; Environment",
                    ", ".join(esc(c) for c in clients).title() or unknown,
                    ("no browser traffic — a Challenge would block, not verify"
                     if clients and not browser else
                     "browser traffic present — Challenge-based controls are viable"
                     if browser else "decides whether Challenge-based controls are usable"))
            + _card("Market &amp; Deployment",
                    (", ".join(esc(m).upper() for m in markets) or unknown)
                    + (f' · {esc(env).title()}' if env else ""),
                    (f'{len(markets)} market(s) — geo restriction is free and evaluates early'
                     if markets else "geo restriction cannot be assessed without this"))
            + _card("Architecture", esc(arch), "; ".join(arch_sub) or unknown)
            + _card("DDoS Protection", esc(ddos_val), esc(ddos_sub), warn=amr_off)
            + _card("WAF Logging", log_val, esc(log_sub))
            + "</div>")


def ctx_list_display(ctx, key):
    v = (ctx or {}).get(key)
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    return [str(i).replace("_", " ").strip() for i in v if str(i).strip()]


def severity_kpis(counts, total):
    actionable = counts["critical"] + counts["medium"] + counts["low"]
    spec = [
        ("ek-tot", "Total Findings", total,
         f"{actionable} actionable &middot; {counts['awareness']} awareness"),
        ("ek-crit", "Critical", counts["critical"],
         "full bypass or a core protection disabled" if counts["critical"]
         else "no full-bypass findings"),
        ("ek-med", "Medium", counts["medium"],
         "a real gap needing specific conditions" if counts["medium"]
         else "no medium-severity findings"),
        ("ek-low", "Low", counts["low"],
         "hygiene, no direct security impact" if counts["low"]
         else "no low-severity findings"),
        ("ek-awa", "Awareness", counts["awareness"],
         "worth knowing — no immediate action" if counts["awareness"]
         else "nothing raised for awareness"),
    ]
    return ('<div class="exec-kpis">' + "".join(
        f'<div class="ekpi {cls}"><div class="eklbl">{lbl}</div>'
        + f'<div class="ekval">{val}</div><div class="eknote">{note}</div></div>'
        for cls, lbl, val, note in spec) + "</div>")


def findings_overview(issues):
    """Every finding in one table: number, severity, protection domain, title, key impact.

    Key impact is the first bullet of the finding's Problem block, truncated. Generated
    rather than authored, so it cannot contradict the card it summarises.
    """
    counts = {k: 0 for k in SEVERITY}
    for i in issues:
        counts[i["sev"]] += 1
    legend = "".join(
        f'<span class="elf-leg"><span class="elf-dot" style="background:{_SEV_HEX[k]}"></span>'
        + f'{SEVERITY[k][0]} ({counts[k]})</span>'
        for k in sorted(SEVERITY, key=lambda x: SEVERITY[x][1]))
    rows = []
    for i in issues:
        m = re.search(r"^\s*[-*]\s+(.+)$", i["problem"], re.M)
        impact = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
        if len(impact) > 165:
            impact = impact[:162].rsplit(" ", 1)[0] + "…"
        rows.append(
            f'<tr class="rf-{i["sev_cls"]}"><td><strong>#{i["number"]}</strong></td>'
            f'<td><span class="pill sv-{i["sev_cls"]}">{i["sev_label"]}</span></td>'
            f'<td style="white-space:nowrap">{esc(i["category"])}</td>'
            f'<td><strong>{_inline(i["title"])}</strong></td>'
            f'<td>{_inline(impact)}</td></tr>')
    return ('<div class="efind-wrap">'
            f'<div class="efind-hdr"><h3>{len(issues)} Findings &middot; Most Severe First</h3>'
            f'<div class="elf-legend">{legend}</div></div>'
            '<div class="table-wrap" style="border:none;border-radius:0">'
            '<table><thead><tr><th>#</th><th>Severity</th><th>Category</th>'
            '<th>Finding</th><th>Key impact</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div></div>')


def summary_pane(summary_json, issues, highlights, diff_block=""):
    """The Summary tab, in four fixed blocks. This function is the layout's definition."""
    acl = summary_json.get("web_acl") or {}
    counts = {k: 0 for k in SEVERITY}
    by_cat = {}
    for i in issues:
        counts[i["sev"]] += 1
        by_cat.setdefault(i["category"], {})
        by_cat[i["category"]][i["sev"]] = by_cat[i["category"]].get(i["sev"], 0) + 1
    total = len(issues)
    wcu = acl.get("effective_capacity") or 0

    charts = (
        '<div class="exec-charts">'
        '<div class="echart-card"><h3>Severity Breakdown</h3>'
        f'<div class="ecsub">{total} finding(s) across severity levels</div>'
        f'{svg_donut(counts, total)}</div>'
        '<div class="echart-card"><h3>Findings by Protection Category</h3>'
        '<div class="ecsub">Distribution across AWS WAF security domains</div>'
        f'{svg_stacked_bar(by_cat)}</div>'
        '<div class="echart-card"><h3>WAF Capacity (WCU)</h3>'
        '<div class="ecsub">Current utilisation</div>'
        f'{svg_gauge(wcu, WCU_CEILING, 1500)}</div>'
        '</div>')

    out = [_label("Business Application Context"), biz_context_grid(summary_json, issues),
           _label("Findings Overview"), severity_kpis(counts, total), charts]
    if diff_block:
        out += [_label("Change Since Last Assessment"), diff_block]
    if highlights:
        out += [_label("Highlight Findings"),
                f'<div class="highlight-narrative">{markdown(highlights)}</div>']
    out += [_label("All Findings"), findings_overview(issues)]
    return "".join(out)


def render(summary_json, issues, highlights, issue_map, generated=None):
    acl = summary_json.get("web_acl") or {}
    generated = generated or date.today().isoformat()
    name = acl.get("name") or "unnamed web ACL"
    title = f"AWS WAF Assessment — {name}"
    arn = acl.get("arn") or ""
    bits = [
        ("file", generated),
        ("server", arn.split(":")[3] if len(arn.split(":")) > 3 else "n/a"),
        ("table", f"{summary_json.get('rule_count', 0)} rules"),
        ("bolt", f"{acl['effective_capacity']:,} WCU" if acl.get("effective_capacity")
                 else "capacity unknown"),
        ("person", arn.split(":")[4] if len(arn.split(":")) > 4 else "n/a"),
    ]
    header = (f'<div class="header"><h1>{icon("shield", 20)}AWS WAF Assessment</h1>'
              f'<div class="sub">{esc(name)}</div>'
              f'<div class="meta">'
              + "".join(f"<span>{icon(i, 12)}{esc(v)}</span>" for i, v in bits)
              + "</div></div>")

    # ---- Tab: Summary --------------------------------------------------
    # Four fixed blocks, defined by summary_pane(): business context, findings overview
    # (KPIs + three inline-SVG charts), Highlight Findings, then every finding.
    diff_block = ""
    pane_summary = summary_pane(summary_json, issues, highlights, diff_block)

    # ---- Tab: Current Setup    # ---- Tab: Current Setup ------------------------------------
    # What the web ACL *is*, kept apart from what the assessment concludes. A reader
    # checking "is this even my web ACL" should not have to scroll past the verdict.
    pane_setup = (
        section("Application Context", "person", app_context(summary_json))
        + section("Web ACL Properties", "server", acl_table(summary_json))
        + section("Rules in Evaluation Order", "table",
                  '<p class="lead">Evaluation order, not configuration order. The Short '
                  'Description column is generated from each rule\'s type, managed rule '
                  'group, action and overrides, so a rule that reads as ordinary but has '
                  'been overridden to Count says so here. The last column links each rule '
                  'to the findings raised against it.</p>'
                  '<div class="table-wrap"><table><thead><tr><th>#</th><th>Rule</th>'
                  "<th>Priority</th><th>Type</th><th>Action</th>"
                  "<th>Short description</th><th>Findings</th></tr></thead>"
                  '<tbody id="rules-body"></tbody></table></div>'
                  '<div class="pager"><div class="info" id="rules-info"></div>'
                  '<div class="btns" id="rules-pages"></div></div>'))

    # ---- Tab: Findings & Recommendations -----------------------------
    pane_findings = section(
        "Findings &amp; Recommendations", "warn",
        '<p class="lead">Most severe first. Every card has the same four parts &mdash; '
        'what is true now, what is wrong with it, what to do, and any notes &mdash; '
        'whether it was decided by the scanner or during analysis.</p>'
        '<div id="findings"></div>'
        '<div class="pager"><div class="info" id="findings-info"></div>'
        '<div class="btns" id="findings-pages"></div></div>')

    # ---- Tab: Appendix ------------------------------------
    pane_appendix = section("Reference Appendix", "book", appendix_html(summary_json))

    counts = {k: 0 for k in SEVERITY}
    for i in issues:
        counts[i["sev"]] += 1
    tabs = [
        ("summary", "Summary", None),
        ("setup", "Current Setup", summary_json.get("rule_count")),
        ("findings", "Findings &amp; Recommendations", len(issues)),
        ("appendix", "Appendix", None),
    ]
    tabs_html = "".join(
        f'<button class="tab{" active" if n == 0 else ""}" data-tab="{k}">{lab}'
        + (f' <span class="badge">{b}</span>' if b is not None else "")
        + "</button>"
        for n, (k, lab, b) in enumerate(tabs))

    data = {
        "issues": [{
            "number": i["number"], "sev_label": i["sev_label"], "sev_cls": i["sev_cls"],
            "title": _inline(i["title"]),
            "rules_line": _inline(i["rules_line"]) or "",
            "refs": [{"name": esc(n), "priority": p} for n, p in i["refs"]],
            "now": markdown(i["now"]), "problem": markdown(i["problem"]),
            "action": markdown(i["action"]), "extra": markdown(i["extra"]),
        } for i in issues],
        "rules": rules_data(summary_json, issue_map),
    }

    body = ('<div class="wrap">'
            '<button id="themebtn" class="themebtn" type="button" aria-pressed="false">'
            + icon("circle", 10) + '<span class="tl">Dark mode</span></button>'
            + header + f'<div class="tabs">{tabs_html}</div>'
            + f'<div class="pane active" id="pane-summary">{pane_summary}</div>'
            + f'<div class="pane" id="pane-setup">{pane_setup}</div>'
            + f'<div class="pane" id="pane-findings">{pane_findings}</div>'
            + f'<div class="pane" id="pane-appendix">{pane_appendix}</div>'
            + "</div>")

    return (f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}</style>
</head><body>
{body}
<script>window.__REPORT__ = {json.dumps(data)};</script>
<script>{JS}</script>
</body></html>
""")


def severity_bar_section(issues):
    return section("Severity Distribution", "chart", severity_bar(issues))


# ════════════════════════════════════
# MAIN
# ════════════════════════════════════

def main():
    args = sys.argv[1:]
    validate_only = "--validate-only" in args
    args = [a for a in args if a != "--validate-only"]
    out_path = None
    if "--out" in args:
        i = args.index("--out")
        if i + 1 >= len(args):
            fatal("--out requires a file path")
        out_path = args[i + 1]
        del args[i:i + 2]
    if not args:
        fatal("Usage: waf-report.py <output_dir> [--out waf-assessment-report.html] "
              "[--validate-only]")

    output_dir = args[0]
    summary_path = os.path.join(output_dir, "waf-summary.json")
    meta_path = os.path.join(output_dir, "findings-metadata.json")
    for p in (summary_path, meta_path):
        if not os.path.isfile(p):
            fatal(f"Required file not found: {p}")

    summary_json = _load_json(summary_path)
    metadata = _load_json(meta_path)
    highlights, issues = read_findings(output_dir)

    # Protection domain per finding. A scripted finding is matched to its title_key through
    # findings-metadata.json, which is exact; anything the agent wrote falls back to the
    # keyword pass. Done here rather than in the parser because it needs the metadata.
    key_of_title = {si["title"]: si.get("title_key")
                    for si in (metadata.get("scripted_issues") or [])}
    for i in issues:
        i["category"] = finding_category(i["title"], key_of_title.get(i["title"]))

    # Validation runs on *document* order, because that is what the numbering check is
    # about: findings.md must number 1..N with no gaps. Sorting first made the check read
    # display order and report a false failure on any file whose severities were not
    # already ascending -- which is most of them.
    checks = _stage_validate(output_dir, summary_json, issues)
    _done.append("validate")

    # Severity order for display. The numbering the agent assigned is preserved on each
    # card, so a reader can still cite "#7" and a cross-reference in the prose resolves.
    issues = sorted(issues, key=lambda i: (SEVERITY[i["sev"]][1], i["number"]))

    issue_map = _stage_issue_map(output_dir, summary_json, metadata, issues)
    _done.append("issue-map")

    dest = None
    if not validate_only:
        dest = out_path or os.path.join(output_dir, "waf-assessment-report.html")
        doc = render(summary_json, issues, highlights, issue_map)
        Path(dest).write_text(doc, encoding="utf-8")
        _done.append("render")
        print(f"Report: {dest} ({len(doc) // 1024} KB, self-contained)", file=sys.stderr)

    passed = sum(1 for v in checks.values() if v["status"] == "PASS")
    failed = sum(1 for v in checks.values() if v["status"] == "FAIL")
    counts = {k: 0 for k in SEVERITY}
    for i in issues:
        counts[i["sev"]] += 1

    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"STAGES_OK: {','.join(_done)}")
    if dest:
        print(f"REPORT_FILE: {dest}")
    print(f"ISSUE_COUNT: {len(issues)}")
    print("SEVERITY: " + " ".join(f"{SEVERITY[k][0]}={counts[k]}"
                                  for k in sorted(SEVERITY, key=lambda x: SEVERITY[x][1])))
    print(f"RULES_MAPPED: {len(issue_map)}")
    print(f"CHECKS_PASSED: {passed}")
    print(f"CHECKS_FAILED: {failed}")
    if not highlights:
        print("NOTE: no `## @summary` block in findings.md; the Summary tab shows the "
              "generated table only")


if __name__ == "__main__":
    main()
