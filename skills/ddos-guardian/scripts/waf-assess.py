#!/usr/bin/env python3
"""WAF Assess (phase A of 2): normalize a Web ACL export, run mechanical
pre-checks, and write the scripted findings.

Usage: python3 waf-assess.py <input_path> <output_dir> [--context <context.json>]
  input_path: WAF JSON file, or a directory containing one
  output_dir: created if needed
  --context:  application context (see references/context-schema.md)

Stages (all in-process, artifacts written as each completes):
  1. normalize   → waf-summary.json          (format detection, snake_case, statement summaries)
  2. pre-checks  → pre-checks.json           (6 named checks + 3 flag extractions)
  3. findings    → scripted-findings.md      (finished Issue sections)
                   findings-metadata.json    (llm_sections, next_issue_number,
                       llm_context, context_questions)

Phase B (waf-report.py) renders the HTML report after the agent appends its own
findings. Supports: AWS CLI (PascalCase), Console export, snake_case custom formats.

The context file is what separates "the config does not show this" from "this is not
configured". Four generators are gated on it, and every field is echoed into
waf-summary.json so the report can show the reader which findings rest on an answer
somebody gave rather than on the configuration itself. Absent context is never guessed
at: the generator either stays silent or emits the question that would settle it.
"""
import base64
import binascii
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

from waf_finding_templates import TEMPLATES as T

# ── Context ────────────────────────────────────
# Questions whose answers change a verdict rather than only colouring the prose. Each
# names the generator it gates, so an unanswered one is reported as reduced coverage
# instead of silently defaulting. Fields used only for display (markets, environment,
# the architecture block) are deliberately absent -- they belong in the report's
# Application Context section, and no scripted finding turns on them.
CONTEXT_QUESTIONS = [
    ("logging", "Where do WAF logs go -- CloudWatch Logs, S3, Kinesis Firehose, a "
                + "central SIEM, or nowhere? The Web ACL export cannot show this; "
                + "get-logging-configuration can.",
     "Decides whether the logging finding is 'unverified' or a real gap"),
    ("client_types", "How do clients reach this application -- browser, mobile app, "
                     + "server-to-server API, or a mix?",
     "A non-browser client cannot complete a Challenge, so this decides whether an "
     + "always-on Challenge is protection or an outage"),
    ("landing_page_uris", "Which paths does a browser hit first (for example /, /login, "
                          + "/signup)?",
     "Names the paths an always-on Challenge would cover"),
    ("api_paths", "Which path prefixes are API or non-browser endpoints?",
     "Decides which Challenge rules are effectively Block, and which exempt-URI "
     + "branches are legitimate"),
    ("traffic_profile", "What is the peak request rate from a single client IP, and the "
                        + "average? AWS's method is peak-per-source plus a 50-100% buffer, so "
                        + "an aggregate figure gives a threshold far too high -- state which "
                        + "it is.",
     "Lets the blanket rate-limit threshold be checked arithmetically instead of against a "
     + "flat heuristic"),
    ("waf_only_for_ddos", "Is this Web ACL deliberately scoped to DDoS protection only, "
                          + "with application-layer attacks handled elsewhere?",
     "Decides whether missing CRS and KnownBadInputs is a gap or a design choice"),
]


def ctx_declared(ctx, key) -> bool:
    """True when the key is present, even if its value is null.

    `"logging": null` and omitting `logging` are different statements. The first asserts
    that logging is not configured -- a fact, and a finding. The second says nobody
    looked, which is a question. Both read as None from `.get`, so presence has to be
    tested on its own.
    """
    return isinstance(ctx, dict) and key in ctx


def ctx_list(ctx, key):
    """A context value as a list of lower-cased strings, however it was written."""
    v = (ctx or {}).get(key)
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    return [str(i).strip().lower() for i in v if str(i).strip()]


def has_browser_client(ctx) -> bool:
    """Whether any declared client type can execute a Challenge interstitial."""
    return any(k in c for c in ctx_list(ctx, "client_types")
               for k in ("browser", "web", "site", "desktop"))

STAGES = ("normalize", "pre-checks", "findings")
_done = []


def fatal(msg: str):
    """Print FATAL result block and exit with code 2."""
    print(msg, file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: FATAL")
    print("ACTION: FIX")
    if _done:
        print(f"STAGES_OK: {','.join(_done)}")
    print(f"FAILED_STAGE: {STAGES[len(_done)]}")
    print(f"CONTEXT: {msg}")
    sys.exit(2)

# ════════════════════════════════════
# STAGE 1 — NORMALIZE
# ════════════════════════════════════

# Keys to skip during processing (internal/display-only fields)
SKIP_KEYS = frozenset({
    "visible_scope_down_statement", "VisibleScopeDownStatement",
    "shadow_ip_set_reference_statement", "ShadowIpSetReferenceStatement",
    "payer_token", "PayerToken",
    "isolation_status", "IsolationStatus",
    "retrofitted_by_fms", "RetrofittedByFirewallManager",
    "simplified_web_acl", "alb_web_acl_attributes",
    "oversize_fields_handling_compliant",
})

SAMPLE_THRESHOLD = 3  # OR branches with more same-type leaves get sampled

# ── Key normalization ────────────────────────────────────

_PASCAL_RE = re.compile(r'(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])')

# Known acronyms that _PASCAL_RE mishandles (consecutive uppercase)
_ACRONYM_FIXES = {
    "d_do_s": "ddos",
    "ur_is": "uris",
    "a_w_s": "aws",
    "i_p": "ip",
    "a_c_l": "acl",
    "a_r_n": "arn",
    "x_s_s": "xss",
    "sq_li": "sqli",
    "s_q_l": "sql",
}

def _to_snake(name: str) -> str:
    """PascalCase -> snake_case, with the acronym repairs applied at token boundaries only.

    The repairs exist because _PASCAL_RE splits consecutive capitals badly: `IPSet` and
    `AntiDDoSRuleSet` come out as `i_p_set` and `anti_d_do_s_rule_set`. Applying them as bare
    substring replacements is what makes `uri_path` become `uripath` -- the `i_p` -> `ip`
    repair matches across the boundary between `uri` and `path`. That single character
    difference silenced several checks: `_field_to_match_str` tests for `uri_path`, and
    `_check_default_action_redundancy`, `_has_uri_constraint` and the report's path extraction
    all grep the summary for it, so on any PascalCase (AWS CLI) export they matched nothing.
    Padding with underscores makes each repair apply only to whole tokens.
    """
    result = _PASCAL_RE.sub('_', name).lower()
    padded = f"_{result}_"
    for wrong, right in _ACRONYM_FIXES.items():
        padded = padded.replace(f"_{wrong}_", f"_{right}_")
    return padded.strip("_")

def _normalize_keys(obj):
    """Recursively convert all dict keys to snake_case, skipping SKIP_KEYS.

    Null values are dropped as they go. Some exports of this format are fully expanded:
    every rule carries all seventeen statement keys and every union carries all its arms,
    with null for the ones not in use. Left in place, a plain `"rate_based_statement" in
    stmt` test matches the null arm rather than the populated one -- so a geo rule reads
    as a rate-based rule and the `.get()` on it raises. Null means absent in this format.
    An empty dict does not: `{"allow": {}}` is a real Allow with default configuration, so
    only None is stripped.
    """
    if isinstance(obj, dict):
        return {_to_snake(k): _normalize_keys(v) for k, v in obj.items()
                if v is not None
                and k not in SKIP_KEYS and _to_snake(k) not in SKIP_KEYS}
    if isinstance(obj, list):
        return [_normalize_keys(i) for i in obj]
    return obj

# ── Input discovery & normalization ────────────────────────────────────

def _find_input_file(input_path: str) -> str:
    p = Path(input_path)
    if p.is_file():
        return str(p.resolve())
    if p.is_dir():
        candidates = []
        for f in p.rglob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                if _detect_format(data) is not None:
                    candidates.append(f)
            except (json.JSONDecodeError, OSError):
                continue
        if len(candidates) == 0:
            fatal(f"No WAF JSON found in {p}")
        if len(candidates) > 1:
            names = ", ".join(c.name for c in candidates)
            fatal(f"Multiple WAF JSON files found: {names}. Please specify the exact file path.")
        return str(candidates[0].resolve())
    fatal(f"Path not found: {input_path}")

def _is_wafv2_rule(rule) -> bool:
    """Does this rule look like a WAFv2 rule, rather than some other service's?

    A bare `Rules` array is not enough to identify WAFv2. AWS Network Firewall
    exports `{"Rules": [...]}` too, and a suricata rule there carries `Header` and
    `RuleOptions`. Accepting it produced five confident findings about a config with
    no WAF in it, including a Critical about rate-limiting tiers -- worse than a
    refusal, because it looks like an answer. Every real WAFv2 rule has a Statement;
    Priority plus Action is accepted as a weaker signal for hand-trimmed exports.
    """
    if not isinstance(rule, dict):
        return False
    keys = {k.lower() for k in rule}
    if "statement" in keys:
        return True
    return "priority" in keys and "action" in keys


def _detect_format(data: dict) -> str | None:
    if "WebACL" in data and isinstance(data["WebACL"], dict):
        return "aws_cli"
    if "web_acl" in data and isinstance(data["web_acl"], dict):
        return "snake_case_custom"
    for key in ("Rules", "rules"):
        rules = data.get(key)
        if isinstance(rules, list):
            # An empty array is a legitimate web ACL with no rules; a populated one
            # must actually contain WAFv2 rules.
            if not rules or any(_is_wafv2_rule(r) for r in rules):
                return "console_export"
            return None
    return None

def _unrecognized_reason(data: dict, where: str) -> str:
    """Explain a rejected input, distinguishing the two ways it can fail.

    "Not a rules file" and "a rules file from the wrong service" need different
    answers from the caller, so they get different messages.
    """
    for key in ("Rules", "rules"):
        if isinstance(data.get(key), list) and data[key]:
            return (f"{where} has a '{key}' array, but none of its entries look like "
                    f"WAFv2 rules (no Statement, and no Priority + Action). This is "
                    f"most likely an export from a different service -- AWS Network "
                    f"Firewall also uses a top-level 'Rules' key. This skill assesses "
                    f"WAFv2 web ACLs only.")
    return (f"Unrecognized WAF JSON format in {where}. Expected a top-level 'WebACL' "
            f"(AWS CLI), 'web_acl' (internal export), or a 'Rules'/'rules' array.")


def _extract_web_acl(data: dict) -> tuple[dict, str]:
    fmt = _detect_format(data)
    if fmt == "aws_cli":
        return data["WebACL"], fmt
    if fmt == "snake_case_custom":
        return data["web_acl"], fmt
    if fmt == "console_export":
        return data, fmt
    fatal(_unrecognized_reason(data, "input"))

# ── Line number tracking ────────────────────────────────────

def _build_line_index(text: str, rules_key: str) -> dict[int, tuple[int, int]]:
    """Map rule index → (start_line, end_line) by scanning JSON text."""
    lines = text.split('\n')
    # Find each rule by looking for "name" or "Name" keys at the rule level
    # Strategy: find the rules array, then track brace depth for each element
    result = {}
    in_rules = False
    depth = 0
    rule_idx = -1
    rule_start = -1
    brace_depth_at_rules = 0

    # Simple state machine: find "rules": [ or "Rules": [
    rules_pattern = re.compile(r'"(?:rules|Rules)"\s*:\s*\[')
    rules_line = -1
    for i, line in enumerate(lines):
        if rules_pattern.search(line):
            rules_line = i
            break

    if rules_line < 0:
        return result

    # Now track braces from rules_line onwards
    depth = 0
    started = False
    in_string = False
    escaped = False
    for i in range(rules_line, len(lines)):
        line = lines[i]
        for ch in line:
            if escaped:
                escaped = False
                continue
            if ch == '\\':
                if in_string:
                    escaped = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '[' and not started:
                started = True
                depth = 0
                continue
            if not started:
                continue
            if ch == '{':
                if depth == 0:
                    rule_idx += 1
                    rule_start = i + 1  # 1-indexed
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0 and rule_start > 0:
                    result[rule_idx] = (rule_start, i + 1)  # 1-indexed inclusive
            elif ch == ']' and depth == 0:
                return result
    return result

# ── Statement summarization ────────────────────────────────────

def _decode_search_string(v) -> str:
    """Decode a ByteMatchStatement SearchString, which WAFv2 carries as a blob.

    Both the AWS CLI and this export base64-encode blob fields, so a rule matching
    `/auth/` arrives as `L2F1dGgv`. Leaving it encoded is not merely ugly: five checks in
    this file decide by looking for literal values in the statement summary -- `/api/`,
    `method EXACTLY 'POST'`, `STARTS_WITH '/'`, and the landing-page path list -- and every
    one of them is dead against a real export unless the value is decoded first. It also
    makes the opaque-secret heuristic fire on ordinary paths, because base64 looks
    high-entropy.

    Conservative in the one direction that matters. The decode is accepted only when it
    round-trips to the identical input and yields printable ASCII, so a plain literal like
    `googlebot` (not valid base64) or `test` (decodes to bytes) is passed through
    untouched. A literal that is itself valid base64 for printable text would be shown
    decoded, which is the correct reading for an export that encodes this field.
    """
    s = str(v if v is not None else "")
    if len(s) < 4 or len(s) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return s
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return s
    if base64.b64encode(raw) != s.encode():
        return s
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return s
    if not text or not text.isprintable():
        return s
    return text


def _field_to_match_str(ftm: dict) -> str:
    if not ftm or not isinstance(ftm, dict):
        return "unknown_field"
    for key, val in ftm.items():
        if key == "single_header":
            name = val.get("name", "?") if isinstance(val, dict) else "?"
            return f"single_header:{name}"
        if key == "uri_path" or key == "uri":
            return "uri_path"
        if key == "query_string":
            return "query_string"
        if key == "body":
            return "body"
        if key == "json_body":
            return "json_body"
        if key == "method":
            return "method"
        if key == "single_query_argument":
            name = val.get("name", "?") if isinstance(val, dict) else "?"
            return f"single_query_argument:{name}"
        if key in ("ja3_fingerprint", "ja4_fingerprint"):
            return key
        if key == "cookie" or key == "cookies":
            return "cookie"
        if key == "headers":
            return "headers"
        if key == "header_order":
            return "header_order"
        return key
    return "unknown_field"

def _summarize_statement(stmt: dict) -> dict:
    """Return {summary: str, leaf_count: int, leaf_types: set, samples: dict|None}."""
    if not stmt or not isinstance(stmt, dict):
        return {"summary": "EMPTY", "leaf_count": 0, "leaf_types": set(), "samples": None}

    # Leaf: byte_match_statement
    if "byte_match_statement" in stmt:
        bm = stmt["byte_match_statement"]
        ftm = _field_to_match_str(bm.get("field_to_match", {}))
        ss = _decode_search_string(bm.get("search_string", "?"))
        pc = bm.get("positional_constraint", "?")
        return {"summary": f"{ftm} {pc} '{ss}'", "leaf_count": 1,
                "leaf_types": {"byte_match"}, "samples": None}

    # Leaf: sqli_match_statement
    if "sqli_match_statement" in stmt:
        sm = stmt["sqli_match_statement"]
        ftm = _field_to_match_str(sm.get("field_to_match", {}))
        return {"summary": f"sqli_match({ftm})", "leaf_count": 1,
                "leaf_types": {"sqli_match"}, "samples": None}

    # Leaf: xss_match_statement
    if "xss_match_statement" in stmt:
        xm = stmt["xss_match_statement"]
        ftm = _field_to_match_str(xm.get("field_to_match", {}))
        return {"summary": f"xss_match({ftm})", "leaf_count": 1,
                "leaf_types": {"xss_match"}, "samples": None}

    # Leaf: size_constraint_statement
    if "size_constraint_statement" in stmt:
        sc = stmt["size_constraint_statement"]
        ftm = _field_to_match_str(sc.get("field_to_match", {}))
        op = sc.get("comparison_operator", "?")
        sz = sc.get("size", "?")
        return {"summary": f"size({ftm}) {op} {sz}", "leaf_count": 1,
                "leaf_types": {"size_constraint"}, "samples": None}

    # Leaf: geo_match_statement
    if "geo_match_statement" in stmt:
        gm = stmt["geo_match_statement"]
        codes = gm.get("country_codes", [])
        return {"summary": f"geo_match {codes}", "leaf_count": 1,
                "leaf_types": {"geo_match"}, "samples": None}

    # Leaf: ip_set_reference_statement
    if "ip_set_reference_statement" in stmt:
        ips = stmt["ip_set_reference_statement"]
        arn = ips.get("ip_set_arn", ips.get("arn", "?"))
        return {"summary": f"ip_set '{arn}'", "leaf_count": 1,
                "leaf_types": {"ip_set"}, "samples": None}

    # Leaf: regex_match_statement
    if "regex_match_statement" in stmt:
        rm = stmt["regex_match_statement"]
        ftm = _field_to_match_str(rm.get("field_to_match", {}))
        regex = rm.get("regex_string", "?")
        return {"summary": f"regex_match({ftm}, '{regex}')", "leaf_count": 1,
                "leaf_types": {"regex_match"}, "samples": None}

    # Leaf: regex_pattern_set_reference_statement
    if "regex_pattern_set_reference_statement" in stmt:
        rp = stmt["regex_pattern_set_reference_statement"]
        ftm = _field_to_match_str(rp.get("field_to_match", {}))
        arn = rp.get("regex_pattern_set_arn", rp.get("arn", "?"))
        return {"summary": f"regex_set({ftm}, '{arn}')", "leaf_count": 1,
                "leaf_types": {"regex_pattern_set"}, "samples": None}

    # Leaf: label_match_statement
    if "label_match_statement" in stmt:
        lm = stmt["label_match_statement"]
        key = lm.get("key", "?")
        scope = lm.get("scope", "LABEL")
        return {"summary": f"label_match '{key}' (scope={scope})", "leaf_count": 1,
                "leaf_types": {"label_match"}, "samples": None}

    # Leaf: asn_match_statement
    if "asn_match_statement" in stmt:
        am = stmt["asn_match_statement"]
        asns = am.get("asn_list", [])
        return {"summary": f"asn_match {asns}", "leaf_count": 1,
                "leaf_types": {"asn_match"}, "samples": None}

    # Logic: and_statement
    if "and_statement" in stmt:
        children = stmt["and_statement"].get("statements", [])
        return _summarize_logic("AND", children)

    # Logic: or_statement
    if "or_statement" in stmt:
        children = stmt["or_statement"].get("statements", [])
        return _summarize_logic("OR", children)

    # Logic: not_statement
    if "not_statement" in stmt:
        inner = stmt["not_statement"].get("statement", {})
        child = _summarize_statement(inner)
        return {"summary": f"NOT({child['summary']})",
                "leaf_count": child["leaf_count"],
                "leaf_types": child["leaf_types"],
                "samples": child["samples"]}

    # Rate-based (top-level only, scope_down handled separately)
    if "rate_based_statement" in stmt:
        rb = stmt["rate_based_statement"]
        return {"summary": f"rate_based(limit={rb.get('limit', '?')}, window={rb.get('time_window', rb.get('evaluation_window_sec', '?'))}s)",
                "leaf_count": 0, "leaf_types": set(), "samples": None}

    # Managed rule group
    for mkey in ("managed_rule_group_statement", "managed_rule_set_statement"):
        if mkey in stmt:
            mg = stmt[mkey]
            vendor = mg.get("vendor_name", "AWS")
            name = mg.get("name", "")
            if not name:
                arn = mg.get("managed_rule_set_arn", mg.get("managed_rule_group_arn", ""))
                if "/" in arn and not arn.startswith("<"):
                    parts = arn.split("/")
                    name = parts[-2] if len(parts) >= 3 else parts[-1]
            version = mg.get("managed_rule_set_version", mg.get("version", ""))
            # name may still be empty; caller will fill via _extract_managed_group_name
            return {"summary": f"managed: {vendor}/{name} {version}".strip(),
                    "leaf_count": 0, "leaf_types": set(), "samples": None}

    # Rule group reference
    if "rule_group_reference_statement" in stmt:
        rg = stmt["rule_group_reference_statement"]
        arn = rg.get("rule_group_arn", rg.get("arn", "?"))
        return {"summary": f"rule_group '{arn}'", "leaf_count": 0,
                "leaf_types": set(), "samples": None}

    # Unknown
    keys = list(stmt.keys())
    return {"summary": f"UNKNOWN: {keys}", "leaf_count": 0,
            "leaf_types": set(), "samples": None}

def _summarize_logic(op: str, children: list) -> dict:
    child_results = [_summarize_statement(c) for c in children]
    total_leaves = sum(r["leaf_count"] for r in child_results)
    all_types = set()
    for r in child_results:
        all_types.update(r["leaf_types"])

    # Check for sampling: if all children are same leaf type and count > threshold
    samples = None
    if len(child_results) > SAMPLE_THRESHOLD and len(all_types) == 1 and all(r["leaf_count"] == 1 for r in child_results):
        leaf_type = next(iter(all_types))
        summaries = [r["summary"] for r in child_results]
        # Extract search_string values from summaries for sampling
        values = []
        for s in summaries:
            m = re.search(r"'([^']*)'", s)
            if m:
                values.append(m.group(1))
        if values:
            sample_vals = values[:2] + values[-1:]
            samples = {"type": leaf_type, "total": len(child_results), "values": sample_vals}
        # Name the values, not just the count. Everything downstream reads this string --
        # the report's description column, and the checks that look for '/api/' or a
        # landing-page path -- so collapsing to "4 byte_match matches" discards the only
        # part that carries meaning. Long lists are still elided in the middle.
        if values and len(values) == len(child_results):
            shown = (", ".join(f"'{v}'" for v in values) if len(values) <= 6
                     else ", ".join(f"'{v}'" for v in values[:5])
                     + f", ... ({len(values) - 5} more)")
            # Keep the field and constraint when every branch shares them, so the value
            # list stays attributable: "OR(uri_path STARTS_WITH '/auth/', '/price/')"
            # rather than a bare list whose subject has been thrown away. Consumers
            # extract paths by anchoring on the field name, so dropping it here is what
            # made the report say "Request-content match" for a URI prefix rule.
            prefixes = {re.match(r"^(.*?)\s+'", c["summary"]).group(1)
                        for c in child_results
                        if re.match(r"^(.*?)\s+'", c["summary"])}
            if len(prefixes) == 1 and len(child_results) == len(values):
                summary = f"{op}({prefixes.pop()} {shown})"
            else:
                summary = f"{op}({leaf_type}: {shown})"
        else:
            summary = f"{op}({len(child_results)} {leaf_type} matches)"
    else:
        parts = [r["summary"] for r in child_results]
        summary = f"{op}({', '.join(parts)})"

    # Propagate first child's samples if only one child has them
    if samples is None:
        for r in child_results:
            if r["samples"] is not None:
                samples = r["samples"]
                break

    return {"summary": summary, "leaf_count": total_leaves,
            "leaf_types": all_types, "samples": samples}

# ── Rule extraction ────────────────────────────────────

def _extract_action(rule: dict) -> str:
    # Custom rules: rule_action / action
    for key in ("rule_action", "action"):
        ra = rule.get(key, {})
        if ra and isinstance(ra, dict):
            for act in ("allow", "block", "count", "challenge", "captcha"):
                if act in ra:
                    return act

    # Managed rule groups: rule_group_action / override_action
    for key in ("rule_group_action", "override_action"):
        rga = rule.get(key, {})
        if rga and isinstance(rga, dict):
            if "none" in rga:
                return "managed_default"
            for act in ("allow", "block", "count", "challenge", "captcha"):
                if act in rga:
                    return act

    return "unknown"

def _extract_overrides(mg: dict) -> list:
    overrides = mg.get("rule_action_overrides", [])
    result = []
    for o in overrides:
        name = o.get("name", "?")
        action_obj = o.get("action_to_use", {})
        action = "excluded"
        for act in ("allow", "block", "count", "challenge", "captcha"):
            if act in action_obj:
                action = act
                break
        result.append({"rule_name": name, "action": action})
    return result

def _extract_excluded_rules(mg: dict) -> list:
    excluded = mg.get("excluded_rules", [])
    return [e.get("name", "?") for e in excluded if isinstance(e, dict) and "name" in e]

def _extract_managed_config(mg: dict) -> dict | None:
    configs = mg.get("managed_rule_set_configs", mg.get("managed_rule_group_configs", []))
    if not configs:
        return None
    result = {}
    for cfg in configs:
        if isinstance(cfg, dict):
            for key, val in cfg.items():
                if isinstance(val, dict):
                    result.update(val)
                else:
                    result[key] = val
    return result or None

def _extract_managed_group_name(mg: dict, rule_name: str) -> tuple[str, str]:
    """Return (vendor, group_name)."""
    vendor = mg.get("vendor_name", "AWS")
    name = mg.get("name", "")
    if name:
        return vendor, name
    # Fallback: extract from ARN (format: arn:aws:wafv2:...:managed-rule-set/vendor/name/id)
    arn = mg.get("managed_rule_set_arn", mg.get("managed_rule_group_arn", ""))
    if "/" in arn and not arn.startswith("<"):
        parts = arn.split("/")
        if len(parts) >= 3:
            return parts[-3], parts[-2]  # vendor, name
        return vendor, parts[-1]
    # Last resort: use rule name — strip common prefixes like "AWS-"
    gn = rule_name
    if gn.startswith("AWS-"):
        gn = gn[4:]
    return vendor, gn

def _extract_scope_down(container: dict) -> dict | None:
    sd = container.get("scope_down_statement")
    if not sd:
        return None
    s = _summarize_statement(sd)
    return {"summary": s["summary"], "source_lines": None}  # source_lines filled later

def _process_rule(rule: dict, idx: int, line_index: dict, jsonpath_prefix: str) -> dict:
    name = rule.get("name", f"rule_{idx}")
    priority = rule.get("priority", idx)
    action = _extract_action(rule)
    stmt = rule.get("statement", {})

    # Determine type
    rule_type = "custom"
    managed_info = None
    rate_info = None
    scope_down = None

    # Check for managed rule group
    mg = None
    for mkey in ("managed_rule_group_statement", "managed_rule_set_statement"):
        if mkey in stmt:
            mg = stmt[mkey]
            rule_type = "managed_rule_group"
            break

    if mg:
        vendor, group_name = _extract_managed_group_name(mg, name)
        version = mg.get("managed_rule_set_version", mg.get("version", ""))
        managed_info = {
            "vendor": vendor,
            "group_name": group_name,
            "version": version,
            "overrides": _extract_overrides(mg),
            "excluded_rules": _extract_excluded_rules(mg),
            "config": _extract_managed_config(mg),
        }
        scope_down = _extract_scope_down(mg)

    # Check for rate-based
    if "rate_based_statement" in stmt:
        rule_type = "rate_based"
        rb = stmt["rate_based_statement"]
        fic = rb.get("forwarded_ip_config") or {}
        rate_info = {
            "limit": rb.get("limit"),
            "evaluation_window_sec": rb.get("time_window", rb.get("evaluation_window_sec")),
            "aggregate_key_type": rb.get("aggregate_key_type", "IP"),
            # Captured because three checks turn on them and none could see them before:
            # aggregating on the wrong address is the most common rate-rule misconfiguration
            # AWS documents, and composite keys are the documented remedy for shared-IP NAT.
            "forwarded_ip_config": ({"header_name": fic.get("header_name"),
                                     "fallback_behavior": fic.get("fallback_behavior")}
                                    if fic else None),
            "custom_keys": [list(k.keys())[0] for k in (rb.get("custom_keys") or [])
                            if isinstance(k, dict) and k],
        }
        scope_down = _extract_scope_down(rb)

    # Statement summary
    stmt_result = _summarize_statement(stmt)

    # Fix managed rule group summary with resolved group_name
    if managed_info and stmt_result["summary"].startswith("managed:"):
        version = managed_info["version"]
        stmt_result["summary"] = f"managed: {managed_info['vendor']}/{managed_info['group_name']} {version}".strip()

    # Rule labels
    labels_raw = rule.get("rule_labels", [])
    labels = [l.get("name", l) if isinstance(l, dict) else l for l in labels_raw]

    # Visibility config
    vc = rule.get("visibility_config", {})
    vis = {
        "metric_name": vc.get("metric_name", ""),
        "sampled_requests_enabled": vc.get("sampled_requests_enabled", False),
        "cloudwatch_metrics_enabled": vc.get(
            "cloud_watch_metrics_enabled",
            vc.get("cloudwatch_metrics_enabled", False)),
    }

    # Challenge/CAPTCHA config at rule level
    challenge_cfg = None
    cc = rule.get("challenge_config", {})
    if cc:
        itp = cc.get("immunity_time_property", {})
        if itp:
            challenge_cfg = {"immunity_time": itp.get("immunity_time")}

    # Source lines
    lines = line_index.get(idx)
    source = {
        "lines": list(lines) if lines else None,
        "jsonpath": f"{jsonpath_prefix}[{idx}]",
    }

    # Fill scope_down source_lines from rule's source lines
    if scope_down and lines:
        scope_down["source_lines"] = list(lines)

    result = {
        "name": name,
        "priority": priority,
        "type": rule_type,
        "action": action,
        "rule_labels": labels,
        "visibility_config": vis,
        "statement": {
            "summary": stmt_result["summary"],
            "leaf_count": stmt_result["leaf_count"],
            "leaf_types": sorted(stmt_result["leaf_types"]),
            "samples": stmt_result["samples"],
            # Top-level boolean branch counts, computed here because this is the only
            # place the raw statement is in scope. Counts rather than the statement
            # itself: carrying the raw tree into waf-summary.json would roughly double
            # the file for one check.
            "branches": _branch_counts(stmt),
        },
        "source": source,
        "scope_down": scope_down,
    }

    if managed_info:
        result["managed"] = managed_info
    if rate_info:
        result["rate_based"] = rate_info
    if challenge_cfg:
        result["challenge_config"] = challenge_cfg

    return result

def _stage_normalize(input_path: str, output_dir: str, context=None) -> tuple[dict, str]:
    """Parse the raw export into waf-summary.json. Returns (summary, input_file)."""
    input_file = _find_input_file(input_path)
    print(f"Input file: {input_file}", file=sys.stderr)

    try:
        raw_text = Path(input_file).read_text(encoding="utf-8", errors="replace")
        raw_data = json.loads(raw_text)
    except (json.JSONDecodeError, OSError) as e:
        fatal(f"Failed to parse {input_file}: {e}")

    fmt = _detect_format(raw_data)
    if fmt is None:
        fatal(_unrecognized_reason(raw_data, input_file))

    web_acl_raw, fmt = _extract_web_acl(raw_data)
    web_acl = _normalize_keys(web_acl_raw)
    line_index = _build_line_index(raw_text, "rules")

    if fmt == "aws_cli":
        jp_prefix = "$.WebACL.Rules"
    elif fmt == "snake_case_custom":
        jp_prefix = "$.web_acl.rules"
    else:
        jp_prefix = "$.Rules"

    rules = [_process_rule(rule, idx, line_index, jp_prefix)
             for idx, rule in enumerate(web_acl.get("rules", []))]

    default_action = "unknown"
    da = web_acl.get("default_action", {})
    if "allow" in da:
        default_action = "allow"
    elif "block" in da:
        default_action = "block"

    # Block carries custom_response (a status code + body key); Allow and Count carry
    # custom_request_handling (inserted headers). They are different keys, so testing
    # only one silently misses the other -- and a Block returning 200 is exactly the
    # case worth catching, because it makes every block invisible downstream.
    da_obj = da.get("allow", da.get("block", {}))
    has_custom_handling = False
    default_action_response_code = None
    if isinstance(da_obj, dict) and da_obj:
        custom_response = da_obj.get("custom_response") or {}
        has_custom_handling = bool(custom_response or
                                   da_obj.get("custom_request_handling"))
        if isinstance(custom_response, dict):
            default_action_response_code = custom_response.get("response_code")

    challenge_config = None
    cc = web_acl.get("challenge_config", {})
    if cc:
        itp = cc.get("immunity_time_property", {})
        if itp:
            challenge_config = {"immunity_time": itp.get("immunity_time")}

    captcha_config = None
    capc = web_acl.get("captcha_config", {})
    if capc:
        itp = capc.get("immunity_time_property", {})
        if itp:
            captcha_config = {"immunity_time": itp.get("immunity_time")}

    # actual_capacity is what the rules really consume and is often higher than the
    # published capacity. Cost and the 5000 ceiling both follow the higher of the two,
    # so both are carried and the report reads the effective figure rather than picking.
    actual = web_acl.get("actual_capacity")
    capacity = web_acl.get("capacity")
    summary = {
        "schema_version": "1.0",
        "input_file": input_file,
        "input_format": fmt,
        "web_acl": {
            "name": web_acl.get("name", "unknown"),
            "id": web_acl.get("id", ""),
            "arn": web_acl.get("arn", web_acl.get("resource_arn", "")),
            "description": web_acl.get("description", ""),
            "default_action": default_action,
            "default_action_custom_handling": has_custom_handling,
            "default_action_response_code": default_action_response_code,
            "capacity": capacity,
            "actual_capacity": actual,
            "effective_capacity": max([c for c in (capacity, actual)
                                       if isinstance(c, int)] or [0]) or None,
            "token_domains": web_acl.get("token_domains", []),
            "challenge_config": challenge_config,
            "captcha_config": captcha_config,
            "managed_by_fms": web_acl.get("managed_by_fms"),
            "shield_advanced": any(
                "ShieldMitigationRuleGroup" in json.dumps(r.get("statement", {}))
                for r in rules) or bool((context or {}).get("shield_advanced")),
            "ddos_protection_config": web_acl.get("ddos_protection_config"),
        },
        "rule_count": len(rules),
        "rules": rules,
        # Echoed rather than only read, for two reasons: the report prints back which
        # facts were supplied so a reader can see what a finding rests on, and a later
        # re-run can tell a real config change from an answer that changed underneath it.
        "context": context or {},
    }

    # A context file records answers about ONE web ACL. Stamp it, and complain loudly if it
    # was gathered against a different one -- reusing another config's context would gate
    # findings on facts that are not about this config.
    acl_arn = summary["web_acl"]["arn"] or summary["web_acl"]["name"]
    if context:
        stamped = context.get("_webacl_arn")
        if stamped and stamped != acl_arn:
            summary["context"]["_arn_mismatch"] = {
                "gathered_against": stamped, "assessed": acl_arn}
            print(f"WARNING: the context file was gathered against {stamped}, but this "
                  f"assessment is of {acl_arn}. Context answers are per-web-ACL facts -- "
                  f"re-gather them for this one rather than reusing another config's.",
                  file=sys.stderr)
        else:
            summary["context"]["_webacl_arn"] = acl_arn

    os.makedirs(output_dir, exist_ok=True)
    out = os.path.join(output_dir, "waf-summary.json")
    try:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
    except OSError as e:
        fatal(f"Failed to write {out}: {e}")

    print(f"Processed {len(rules)} rules", file=sys.stderr)
    return summary, input_file


# ════════════════════════════════════
# STAGE 2 — PRE-CHECKS
# ════════════════════════════════════

# ── Forgeability mapping ────────────────────────────────────
# These lists are the source of truth. references/managed-labels.md documents
# them for reviewers; update this code, then that doc.

FORGEABLE_FIELDS = {
    "single_header", "single_query_argument", "cookie", "cookies",
    "body", "json_body", "uri_path", "query_string", "method",
    "header_order", "headers",
}
UNFORGEABLE_STMT_TYPES = {
    "ip_set", "asn_match", "geo_match", "rate_based",
}
UNFORGEABLE_FIELDS = {
    "ja3_fingerprint", "ja4_fingerprint",
}

ALL_KNOWN_FIELDS = FORGEABLE_FIELDS | UNFORGEABLE_FIELDS | UNFORGEABLE_STMT_TYPES | {"label_match"}

def _classify_condition(summary: str) -> tuple[list, list]:
    """Parse statement summary and classify conditions as forgeable/unforgeable.

    IMPORTANT: This regex is tightly coupled to the summary format produced by
    _summarize_statement() in waf-normalizer.py. If that format changes, update
    the patterns here accordingly.
    """
    forgeable = []
    unforgeable = []

    # Extract known field types from summary (ignore quoted values)
    # Match patterns like: "single_header:user-agent EXACTLY", "ip_set '...'", "asn_match [..."
    for match in re.finditer(r'([\w]+(?::[\w:.-]+)?)\s+(?:EXACTLY|STARTS_WITH|ENDS_WITH|CONTAINS|\'|\[)', summary):
        field = match.group(1)
        base_field = field.split(":")[0]

        if base_field not in ALL_KNOWN_FIELDS:
            continue  # skip non-field tokens (e.g., search_string values)

        if base_field in UNFORGEABLE_FIELDS or base_field in UNFORGEABLE_STMT_TYPES:
            unforgeable.append(field)
        elif base_field == "label_match":
            unforgeable.append(field)
        else:
            forgeable.append(field)

    # Check for statement-level patterns not caught by field regex
    for stmt_type in UNFORGEABLE_STMT_TYPES:
        if stmt_type in summary and stmt_type not in [u.split(":")[0] for u in unforgeable]:
            unforgeable.append(stmt_type)

    return forgeable, unforgeable

def _has_uri_constraint(summary: str) -> bool:
    """Check if statement contains a meaningful URI path constraint.
    uri_path STARTS_WITH '/' matches all traffic — not a real constraint."""
    if not re.search(r'uri_path\s+(?:EXACTLY|STARTS_WITH|ENDS_WITH|CONTAINS)', summary):
        return False
    # STARTS_WITH '/' matches everything — treat as no constraint
    if re.search(r"uri_path\s+STARTS_WITH\s+'/'", summary):
        return False
    return True

# ── Pre-checks ────────────────────────────────────

def _check_token_domain(web_acl: dict) -> dict:
    """Check #11: token_domains redundancy."""
    domains = web_acl.get("token_domains", [])
    if not domains:
        return {"status": "PASS", "finding": None}

    # Find apex domains and their subdomains.
    # Heuristic: the shortest domain for each TLD suffix is the apex.
    # This handles multi-part TLDs like .co.uk, .com.cn, .co.jp.
    issues = []

    # Group domains by their last-2 parts (potential simple TLD)
    # Then identify apex as the shortest domain in each suffix group
    apex_domains = set()
    # Sort by part count ascending — shortest first
    sorted_domains = sorted(domains, key=lambda d: len(d.split(".")))
    for d in sorted_domains:
        # A domain is an apex if no existing apex is a suffix of it
        is_sub = any(d.endswith("." + apex) for apex in apex_domains)
        if not is_sub:
            apex_domains.add(d)

    redundant = []
    for d in domains:
        if d in apex_domains:
            continue  # apex itself
        # Check if any apex covers this subdomain (suffix match)
        covering_apex = next((a for a in apex_domains if d.endswith("." + a)), None)
        if covering_apex:
            redundant.append(d)

    # Check for missing apex: domains whose apex (shortest covering suffix)
    # is not in the token_domains list
    missing_apex = set()
    for d in domains:
        if d in apex_domains:
            continue
        has_covering = any(d.endswith("." + a) for a in apex_domains)
        if not has_covering:
            # This domain has no covering apex in the list — it IS an apex
            # (already handled above), or its apex is missing.
            # Since we already identified all apexes, this shouldn't happen,
            # but guard against it.
            missing_apex.add(d)

    if redundant:
        issues.append(f"Redundant subdomains (covered by apex): {', '.join(redundant)}")
    if missing_apex:
        issues.append(f"Missing apex domains (add to cover subdomains): {', '.join(missing_apex)}")

    if issues:
        return {"status": "FAIL", "finding": "; ".join(issues),
                "domains": domains, "redundant": redundant,
                "missing_apex": list(missing_apex)}
    return {"status": "PASS", "finding": None}

def _check_managed_versions(rules: list) -> dict:
    """Check #12: managed rule group versions."""
    issues = []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        gn = mg.get("group_name", "")
        ver = mg.get("version", "")

        if "SQLiRuleSet" in gn or "sqli" in gn.lower():
            # Check if version < 2.0
            m = re.search(r'(\d+)\.(\d+)', ver)
            if m and int(m.group(1)) < 2:
                issues.append(f"{r['name']}: SQLiRuleSet version {ver} < 2.0 (recommend upgrading)")

        if "BotControlRuleSet" in gn or "bot_control" in gn.lower():
            m = re.search(r'(\d+)\.(\d+)', ver)
            if m and int(m.group(1)) < 5:
                issues.append(f"{r['name']}: BotControlRuleSet version {ver} < 5.0 (recommend upgrading)")

    if issues:
        return {"status": "FAIL", "finding": "; ".join(issues), "details": issues}
    return {"status": "PASS", "finding": None}

def _check_default_action_redundancy(web_acl: dict, rules: list) -> dict:
    """Check #15: redundant trailing Allow-all rule."""
    if web_acl.get("default_action") != "allow":
        return {"status": "PASS", "finding": None}
    if not rules:
        return {"status": "PASS", "finding": None}

    last = rules[-1]
    if last["action"] == "allow":
        summary = last.get("statement", {}).get("summary", "")
        # Check if it matches all traffic (URI STARTS_WITH '/' or similar)
        if ("STARTS_WITH '/'" in summary or summary == "EMPTY"
                or "uri_path STARTS_WITH '/'" in summary):
            return {"status": "FAIL",
                    "finding": f"Rule '{last['name']}' (priority {last['priority']}) matches all traffic with Allow, "
                               f"but default_action is already Allow. This rule is redundant.",
                    "rule": last["name"], "priority": last["priority"]}
    return {"status": "PASS", "finding": None}

def _check_count_without_labels(rules: list) -> dict:
    """Check #17a: custom Count rules without RuleLabels."""
    flagged = []
    for r in rules:
        if (r["action"] == "count" and r["type"] == "custom"
                and not r.get("rule_labels")):
            flagged.append({"name": r["name"], "priority": r["priority"]})

    if flagged:
        names = ", ".join(f["name"] for f in flagged)
        return {"status": "FAIL",
                "finding": f"Custom Count rules without labels (metric-only): {names}",
                "rules": flagged}
    return {"status": "PASS", "finding": None}


def _branch_counts(stmt):
    """{op, total, distinct} for a top-level And/Or, or None when there is no boolean root.

    `a OR a` is `a`, so total > distinct means at least one branch is dead code. Recorded
    as counts so the check needs nothing but waf-summary.json.
    """
    op, branches = _canonical_branches(stmt)
    if not branches:
        return None
    return {"op": op.replace("_statement", "").upper(),
            "total": len(branches), "distinct": len(set(branches))}


def _canonical_branches(stmt):
    """Direct children of a top-level And/Or, as canonical JSON strings.

    Only the top level: a repeated branch nested three deep is a different and much rarer
    mistake, and flattening would make the finding hard to state precisely.
    """
    for op in ("and_statement", "or_statement"):
        body = stmt.get(op)
        if isinstance(body, dict) and isinstance(body.get("statements"), list):
            return op, [json.dumps(c, sort_keys=True) for c in body["statements"]]
    return None, []


def _check_duplicate_branches(rules: list) -> dict:
    """A top-level boolean branch that repeats itself, which is dead code.

    `a OR a` is `a`. The repeat can never change the outcome, and nothing about it looks
    wrong -- both branches are valid and reference real objects. The case that motivated
    this check was an IP allowlist and an IP denylist that each ORed one IPv4 set ARN with
    itself, where the intended second branch was the IPv6 companion set. So the rule
    consulted one address family while appearing to consult two, and IPv6 clients matched
    neither list.
    """
    flagged = []
    for r in rules:
        b = (r.get("statement") or {}).get("branches")
        if not b or b["total"] <= b["distinct"]:
            continue
        flagged.append({"name": r["name"], "priority": r["priority"], "op": b["op"],
                        "branches": b["total"], "distinct": b["distinct"],
                        "duplicates": b["total"] - b["distinct"]})
    if flagged:
        names = ", ".join(f["name"] for f in flagged)
        return {"status": "FAIL", "rules": flagged,
                "finding": f"Rules with a repeated boolean branch: {names}"}
    return {"status": "PASS", "finding": None}


def _check_ip_set_families(rules: list) -> dict:
    """IP-set rules that reference only one address family.

    An AWS IP set holds a single family, so covering both needs two sets. Detected from the
    set name, which is the only signal an export carries -- the ARN does not record the
    family. That makes this a heuristic, so the finding is worded as something to confirm
    rather than as a certainty.
    """
    flagged = []
    for r in rules:
        arns = re.findall(r"ip_set '([^']*)'", r.get("statement", {}).get("summary", ""))
        distinct = list(dict.fromkeys(arns))
        if not distinct:
            continue
        names = [a.rstrip("/").split("/")[-2] if a.count("/") >= 2 else a for a in distinct]
        if any(re.search(r"v6|ipv6", n, re.I) for n in names):
            continue
        if not any(re.search(r"v4|ipv4", n, re.I) for n in names):
            continue          # nothing in the naming says either way; do not guess
        flagged.append({"name": r["name"], "priority": r["priority"],
                        "action": r.get("action"), "sets": names})
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "IPv4-only IP set references: "
                           + ", ".join(f["name"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_orphan_managed_labels(rules: list) -> dict:
    """A managed sub-rule left at its Count default whose label nothing consumes.

    Reads MANAGED_COUNT_ONLY_LABELS, which is the code-side copy of the catalogue in
    references/managed-labels.md. A Count-only sub-rule is not a misconfiguration -- the
    default is deliberate -- but it protects nothing on its own, and that is invisible.
    """
    consumed = set()
    for r in rules:
        for k in re.findall(r"label_match '([^']+)'", r.get("statement", {}).get("summary", "")):
            consumed.add(k)
    flagged = []
    for r in rules:
        mg = r.get("managed") or {}
        table = MANAGED_COUNT_ONLY_LABELS.get(mg.get("group_name", ""))
        if not table:
            continue
        overridden = {o.get("rule_name") for o in mg.get("overrides", [])}
        for sub, (label, why, subsumed_by) in table.items():
            if sub in overridden:
                continue          # the operator has made an explicit choice
            if label in consumed:
                continue
            flagged.append({"name": r["name"], "priority": r["priority"], "sub_rule": sub,
                            "label": label, "why": why, "subsumed_by": subsumed_by})
    if flagged:
        return {"status": "FAIL", "rules": flagged,
                "finding": "Count-only managed labels with no consumer: "
                           + ", ".join(f["sub_rule"] for f in flagged)}
    return {"status": "PASS", "finding": None}


def _check_challenge_on_post_api(rules: list, api_paths=None) -> dict:
    """Check #4: Challenge/CAPTCHA on POST or API paths (effectively Block).

    `/api` is a convention, not a rule. Where the operator has named their actual
    non-browser path prefixes, those are matched too -- an API served from `/v2/graphql`
    is just as unable to complete a Challenge, and nothing in the path says so.
    """
    flagged = []
    for r in rules:
        if r["action"] not in ("challenge", "captcha"):
            continue
        summary = r.get("statement", {}).get("summary", "")
        reasons = []
        if "method EXACTLY 'POST'" in summary or "method EXACTLY 'PUT'" in summary:
            reasons.append("targets POST/PUT requests")
        if "/api/" in summary or "/api'" in summary:
            reasons.append("targets API path")
        for path in api_paths or []:
            if path and path in summary.lower():
                reasons.append(f"targets declared API path '{path}'")
                break
        if reasons:
            flagged.append({"name": r["name"], "priority": r["priority"],
                            "reasons": reasons})
    if flagged:
        details = "; ".join(f"{f['name']} (P{f['priority']}): {', '.join(f['reasons'])}" for f in flagged)
        return {"status": "FAIL",
                "finding": f"Challenge/CAPTCHA on non-browser paths (effectively Block): {details}",
                "rules": flagged}
    return {"status": "PASS", "finding": None}

def _check_hosting_provider_allow(rules: list) -> dict:
    """Check #7: HostingProviderIPList overridden to Allow (dangerous)."""
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        for override in mg.get("overrides", []):
            if override.get("rule_name") == "HostingProviderIPList" and override.get("action") == "allow":
                return {"status": "FAIL",
                        "finding": f"HostingProviderIPList overridden to Allow in {r['name']} (priority {r['priority']}). "
                                   f"Cloud-hosted attack traffic bypasses all subsequent rules. Override to Count instead.",
                        "rule": r["name"], "priority": r["priority"]}
    return {"status": "PASS", "finding": None}

# ── Flags ────────────────────────────────────

def _flag_allow_rules(rules: list) -> list:
    """Flag all Allow rules with forgeability analysis."""
    flags = []
    for r in rules:
        if r["action"] != "allow":
            continue
        summary = r.get("statement", {}).get("summary", "")
        forgeable, unforgeable = _classify_condition(summary)
        all_forgeable = len(unforgeable) == 0 and len(forgeable) > 0
        blast_radius = "path_scoped" if _has_uri_constraint(summary) else "global"

        flags.append({
            "name": r["name"],
            "priority": r["priority"],
            "statement_summary": summary,
            "forgeable_conditions": forgeable,
            "unforgeable_conditions": unforgeable,
            "all_forgeable": all_forgeable,
            "blast_radius": blast_radius,
        })
    return flags

def _flag_scope_downs(rules: list) -> list:
    """Flag all scope-down statements for LLM review."""
    flags = []
    for r in rules:
        sd = r.get("scope_down")
        if not sd:
            continue
        flags.append({
            "rule": r["name"],
            "priority": r["priority"],
            "rule_type": r["type"],
            "scope_down_summary": sd["summary"],
            "source_lines": sd.get("source_lines"),
        })
    return flags

def _split_regex_branches(regex: str) -> list[str]:
    """Split regex on | only at top level (outside parentheses)."""
    branches = []
    depth = 0
    current = []
    escaped = False
    for ch in regex:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == '\\':
            current.append(ch)
            escaped = True
            continue
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == '|' and depth == 0:
            branches.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        branches.append(''.join(current))
    return branches

def _flag_exempt_regex(rules: list) -> list:
    """Flag AntiDDoS AMR exempt URI regex branches with anchoring analysis."""
    flags = []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        cfg = mg.get("config") or {}
        exempt = cfg.get("uris_exempt_from_challenge", [])
        if not exempt:
            continue

        regex_str = exempt[0] if isinstance(exempt, list) and exempt else str(exempt)
        branches = _split_regex_branches(regex_str)
        branch_analysis = []
        for b in branches:
            b = b.strip()
            branch_analysis.append({
                "pattern": b,
                "anchored_start": b.startswith("^"),
                "anchored_end": b.endswith("$"),
            })
        flags.append({
            "rule": r["name"],
            "priority": r["priority"],
            "full_regex": regex_str,
            "branches": branch_analysis,
        })
    return flags

def _stage_pre_checks(summary: dict, output_dir: str) -> dict:
    """Run the 6 mechanical checks and 3 flag extractions. Returns pre-checks data."""
    web_acl = summary.get("web_acl", {})
    rules = summary.get("rules", [])
    ctx = summary.get("context") or {}

    pre_checks = {
        "token_domain": _check_token_domain(web_acl),
        "managed_versions": _check_managed_versions(rules),
        "default_action_redundancy": _check_default_action_redundancy(web_acl, rules),
        "count_without_labels": _check_count_without_labels(rules),
        "challenge_on_post_api": _check_challenge_on_post_api(
            rules, ctx_list(ctx, "api_paths")),
        "hosting_provider_allow": _check_hosting_provider_allow(rules),
        "duplicate_branches": _check_duplicate_branches(rules),
        "ip_set_families": _check_ip_set_families(rules),
        "orphan_managed_labels": _check_orphan_managed_labels(rules),
    }
    flags = {
        "allow_rules": _flag_allow_rules(rules),
        "scope_downs": _flag_scope_downs(rules),
        "exempt_regex_branches": _flag_exempt_regex(rules),
    }
    result = {"pre_checks": pre_checks, "flags": flags}

    out = os.path.join(output_dir, "pre-checks.json")
    try:
        Path(out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        fatal(f"Failed to write {out}: {e}")

    failed = sum(1 for v in pre_checks.values() if v["status"] == "FAIL")
    print(f"Ran {len(pre_checks)} checks, {failed} failed", file=sys.stderr)
    return result


# ════════════════════════════════════
# STAGE 3 — SCRIPTED FINDINGS
# ════════════════════════════════════

# ── Constants ────────────────────────────────────

ALWAYS_LLM_SECTIONS = {5, 8, 17}
APPENDIX_ONLY_SECTIONS = {10}

SEVERITY_ORDER = {"Critical": 0, "Medium": 1, "Low": 2, "Awareness": 3}

RECOMMENDED_ORDER = [
    # The baseline rule order, reconciled from three sources and reviewed 2026-08-29.
    #
    # AWS's own wording on the Anti-DDoS AMR settles what may precede it: it "should have
    # either the highest priority inside your web ACL ... or be placed right below any custom
    # rules with Allow action, such as IP match conditions rule lists". Note the specificity --
    # **Allow** only. A Block rule above it is not sanctioned, and the reasoning holds: during
    # an attack the denylisted traffic *is* the attack, so blocking it earlier means the rule
    # group observes less of the event and may not trigger at all.
    ("allow_rule", "Custom rules with Allow action (IP allowlists)"),
    # Position 2 is a reconciliation, not AWS's words. The statement's letter permits only
    # Allow rules above the AMR, but references/crawler-seo.md requires the ASN+UA labelling
    # rule to precede it so the AMR can exempt crawlers via scope-down. Both hold because a
    # Count rule is non-terminating: it reduces what the AMR inspects by nothing, which is the
    # statement's own stated rationale. Reviewed and accepted.
    ("label_producer", "Count + label rules (crawler labelling, client-type tagging)"),
    ("antiddos_amr", "Anti-DDoS AMR"),
    ("operator_block", "Operator explicit Block (IP denylist, geo block)"),
    # Rate tiers run most-specific first: a rate rule that Blocks is terminating, so the
    # stricter threshold must get the chance to apply before a broader, looser one.
    ("rate_reputation", "Rate-based - country / bad-source scoped"),
    ("rate_uri", "Rate-based - specific URI"),
    ("rate_blanket", "Rate-based - blanket"),
    # Operator decisions before vendor decisions: your own bad-source rate rules precede AWS's
    # reputation lists. This is the second reviewed divergence -- the reverse (reputation
    # first, so known-bad traffic never reaches the rate counters) is also defensible, and
    # neither carries a per-request fee, so cost does not decide it.
    ("ip_reputation_amazon", "Amazon IP reputation list"),
    ("ip_reputation_anonymous", "Anonymous IP list"),
    ("always_on_challenge", "Always-on Challenge"),
    ("crs", "Core Rule Set"),
    ("usecase_amr", "Use-case AMRs (SQLi, Linux, Windows, PHP, WordPress)"),
    # A false-positive exception consumes a label its target group emits, so it can only work
    # *after* that group. Placing it earlier is the failure the label-ordering rule exists to
    # prevent, and it looks like working configuration.
    ("fp_exception", "False-positive exception rules"),
    ("custom_app", "Application-specific custom rules"),
    ("bot_control", "Bot Control"),
    ("fraud_control", "Fraud Control (ATP, ACFP)"),
]

#: Tiers excluded from the ordering check entirely. A Shield mitigation group is placed by
#: Shield and is always last; an opaque customer rule group cannot be positioned because its
#: contents are not in the export, and asserting a black box is misplaced is a verdict the
#: evidence does not support.
UNORDERED_TIERS = {"shield_mitigation", "opaque_rule_group"}

MANAGED_BASELINE_GROUPS = {
    "AWSManagedRulesCommonRuleSet": "CRS",
    "AWSManagedRulesKnownBadInputsRuleSet": "KnownBadInputs",
}

IP_REPUTATION_GROUPS = {
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
}

#: Managed sub-rules that default to **Count** and therefore only apply a label. Each
#: protects nothing unless a later rule consumes the label, which is a real gap that looks
#: like working configuration. Sourced from references/managed-labels.md; that file
#: documents the full label catalogue for reviewers, this is the copy the code reads.
#:
#: group -> sub_rule -> (label, why AWS defaults it to Count, what subsumes it)
MANAGED_COUNT_ONLY_LABELS = {
    "AWSManagedRulesAmazonIpReputationList": {
        "AWSManagedIPDDoSList": (
            "awswaf:managed:aws:amazon-ip-list:AWSManagedIPDDoSList",
            "the addresses on it -- open proxies, and residential addresses temporarily "
            "conscripted into a botnet -- may belong to real users, so AWS declines to "
            "block them on your behalf",
            "AWSManagedRulesAntiDDoSRuleSet"),
    },
}

#: Rule groups whose whole-group Count override is a Critical loss rather than a Medium one:
#: each is a core protection with no substitute elsewhere in a typical Web ACL.
CORE_GROUPS = {
    "AWSManagedRulesAntiDDoSRuleSet": "the strongest application-layer DDoS control AWS offers",
    "AWSManagedRulesCommonRuleSet": "the broadest single control in a Web ACL -- OWASP-class "
                                    "injection, traversal and malformed-request coverage",
}

#: Name tokens that assert an action, for the name/action contradiction check. A rule whose
#: name promises one outcome and whose action delivers another misleads every future reader.
NAME_INTENT = {
    "block": ("block",), "deny": ("block",), "reject": ("block",), "drop": ("block",),
    "ban": ("block",), "blacklist": ("block",), "blocklist": ("block",),
    "allow": ("allow",), "permit": ("allow",), "whitelist": ("allow",),
    "allowlist": ("allow",), "bypass": ("allow",), "exempt": ("allow",),
}

#: Requests per second above which a per-IP rate limit will not be reached by a real client.
#: Deliberately generous: the point is to catch a threshold that cannot fire, not to tune one.
RATE_RPS_IMPLAUSIBLE = 50

#: Label namespace per managed rule group, from references/managed-labels.md. A managed
#: group applies labels the export does not list, so the namespace is the only way to name
#: the label a Count-overridden sub-rule produces.
LABEL_NS = {
    "AWSManagedRulesAntiDDoSRuleSet": "anti-ddos",
    "AWSManagedRulesAmazonIpReputationList": "amazon-ip-list",
    "AWSManagedRulesAnonymousIpList": "anonymous-ip-list",
    "AWSManagedRulesBotControlRuleSet": "bot-control",
    "AWSManagedRulesATPRuleSet": "atp",
    "AWSManagedRulesACFPRuleSet": "acfp",
    "AWSManagedRulesCommonRuleSet": "core-rule-set",
    "AWSManagedRulesKnownBadInputsRuleSet": "known-bad-inputs",
}

#: Documented default action per sub-rule, for the groups where a deviation is meaningful.
#: `AWSManagedIPDDoSList` defaults to Count deliberately -- the addresses on it may belong to
#: real users -- so an override to Block is as much a finding as the other two being relaxed.
#: group -> sub_rule -> (default, why the default is what it is)
SUBRULE_DEFAULTS = {
    "AWSManagedRulesAmazonIpReputationList": {
        "AWSManagedIPReputationList": (
            "Block", "It blocks addresses Amazon threat intelligence has identified as "
            "actively malicious, drawn from sources including MadPot. It is safe to leave "
            "at Block for almost every workload"),
        "AWSManagedReconnaissanceList": (
            "Block", "It blocks addresses performing reconnaissance against AWS resources, "
            "which is activity with no legitimate counterpart on a production endpoint"),
        "AWSManagedIPDDoSList": (
            "Count", "AWS defaults it to Count on purpose: the addresses on it include open "
            "proxies and residential addresses temporarily conscripted into a botnet, which "
            "may belong to real users. Blocking them outright causes false positives"),
    },
}

#: Groups whose absence is a baseline gap in its own right, with what each contributes.
IP_REPUTATION_BASELINE = {
    "AWSManagedRulesAmazonIpReputationList": (
        "Amazon IP reputation list",
        "known malicious and reconnaissance source addresses go uninspected. This group "
        "carries Amazon's own threat intelligence and is the cheapest broad filter available",
        25),
    "AWSManagedRulesAnonymousIpList": (
        "Anonymous IP list",
        "traffic from VPNs, Tor exit nodes, public proxies and hosting providers is not "
        "distinguished from ordinary client traffic",
        50),
}

CRAWLER_LABEL_PATTERNS = ("crawler:", "custom:crawler")

NOT_APPLICABLE = "NOT_APPLICABLE"
AMBIGUOUS = "AMBIGUOUS"


# ── Helpers ────────────────────────────────────



def _classify_rule_type(rule: dict) -> str:
    """Classify a rule into a baseline-order tier.

    Managed groups are named explicitly rather than bucketed, because the baseline
    distinguishes Amazon IP reputation from Anonymous IP, CRS from the use-case groups, and
    Bot Control from Fraud Control -- collapsing any of those pairs makes a real mis-ordering
    undetectable. Custom rules are classified by statement *shape*, with the action used only
    to name the role: gating on the action alone sent every IP denylist into the generic
    bucket and produced false violations against correctly placed rules.
    """
    mg = rule.get("managed")
    sm = (rule.get("statement") or {}).get("summary", "")
    lt = (rule.get("statement") or {}).get("leaf_types") or []
    action = rule.get("action")

    if "ShieldMitigationRuleGroup" in sm:
        return "shield_mitigation"
    if sm.startswith("rule_group "):
        return "opaque_rule_group"

    if mg:
        gn = mg.get("group_name", "")
        if "AntiDDoS" in gn:
            return "antiddos_amr"
        if gn == "AWSManagedRulesAmazonIpReputationList":
            return "ip_reputation_amazon"
        if gn == "AWSManagedRulesAnonymousIpList":
            return "ip_reputation_anonymous"
        if gn == "AWSManagedRulesCommonRuleSet":
            return "crs"
        if "BotControl" in gn:
            return "bot_control"
        if "ATPRuleSet" in gn or "ACFPRuleSet" in gn:
            return "fraud_control"
        # KnownBadInputs is not named in the baseline; it is a broad baseline group like CRS
        # rather than a stack-specific one, so it sits with CRS.
        if gn == "AWSManagedRulesKnownBadInputsRuleSet":
            return "crs"
        return "usecase_amr"

    if rule.get("type") == "rate_based":
        return {"reputation": "rate_reputation", "uri": "rate_uri",
                "blanket": "rate_blanket"}.get(_rate_tier(rule), "rate_blanket")

    # A label match on a managed namespace is a false-positive exception: it consumes a label
    # the group emits, so it can only work after that group.
    consumed = re.findall(r"label_match '([^']+)'", sm)
    if any(c.startswith("awswaf:managed:") for c in consumed):
        return "fp_exception"

    if action in ("challenge", "captcha"):
        return "always_on_challenge" if consumed else "custom_app"

    # A Count rule that applies a label is a producer, and every downstream scope-down
    # depends on it. Non-terminating, so it may precede the Anti-DDoS AMR.
    if action == "count" and rule.get("rule_labels"):
        return "label_producer"

    if action == "allow":
        return "allow_rule"
    if action == "block" and ("ip_set" in lt or "geo_match" in lt):
        return "operator_block"
    return "custom_app"


def _plural(n, word):
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _has_opaque_value(value: str) -> str:
    """Check if a string looks like a hash/secret. Returns 'yes', 'maybe', or 'no'."""
    if len(value) < 16:
        return "no"
    # Exclude common non-secret patterns
    if value.startswith("/"):  # URI paths
        return "no"
    if re.match(r'^[\w.-]+\.\w{2,}$', value):  # hostnames like example.com
        return "no"
    if value in ("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"):
        return "no"
    classes = 0
    if re.search(r'[a-z]', value):
        classes += 1
    if re.search(r'[A-Z]', value):
        classes += 1
    if re.search(r'[0-9]', value):
        classes += 1
    if re.search(r'[^a-zA-Z0-9]', value):
        classes += 1
    if classes >= 3:
        return "yes"
    if classes >= 2 and len(value) >= 24:
        return "maybe"
    return "no"


def _extract_exactly_values(summary: str) -> list[tuple[str, str]]:
    """Extract (field, value) pairs from EXACTLY matches in statement summary."""
    results = []
    for m in re.finditer(r"([\w:.-]+)\s+EXACTLY\s+'([^']*)'", summary):
        results.append((m.group(1), m.group(2)))
    return results

# ── Generators ────────────────────────────────────
# Each returns (issue_md, metadata_dict) | NOT_APPLICABLE | AMBIGUOUS

def _gen_forgeable_allow(summary, pre_checks, flags):
    allow_flags = flags.get("allow_rules", [])
    # Exclude rules handled by default_action_redundancy
    redundant_rule = None
    dar = pre_checks.get("default_action_redundancy", {})
    if dar.get("status") == "FAIL":
        redundant_rule = dar.get("rule")
    # Only handle all_forgeable + global blast radius
    candidates = [a for a in allow_flags
                  if a.get("all_forgeable") and a.get("blast_radius") == "global"
                  and a["name"] != redundant_rule]
    if not candidates:
        # If all Allow rules have unforgeable conditions, section is safe
        remaining = [a for a in allow_flags if a["name"] != redundant_rule]
        if not remaining:
            return NOT_APPLICABLE
        if all(not a.get("all_forgeable") for a in remaining):
            return NOT_APPLICABLE
        # Mixed forgeability within a group — needs LLM judgment
        return AMBIGUOUS

    # Group by forgeable_conditions content
    groups = defaultdict(list)
    for a in candidates:
        key = tuple(sorted(a.get("forgeable_conditions", [])))
        groups[key].append(a)

    results = []
    for key, group in groups.items():
        names = [a["name"] for a in group]
        rule_names = " / ".join(names)
        if len(group) == 1:
            rule_line = f"{names[0]} (priority {group[0]['priority']})"
            dup_note = ""
            dup_rec = ""
        else:
            rule_line = ", ".join(f"{a['name']} (priority {a['priority']})" for a in group)
            dup_note = f"- {len(group)} rules have identical logic, only one is needed\n"
            dup_rec = "- Remove duplicate rules, keep one\n"

        fc = group[0]["forgeable_conditions"]
        forgeable_fields = ", ".join(fc)
        is_are = "is" if len(fc) == 1 else "are"
        # Build example
        if any("user-agent" in c for c in fc):
            forgeable_example = "the matching User-Agent header"
        elif any("header" in c for c in fc):
            forgeable_example = "the matching custom header"
        else:
            forgeable_example = "the matching condition"

        # Check for opaque/secret values in the statement (fix #1)
        opaque_note = ""
        opaque_rec = ""
        for a in group:
            for field, value in _extract_exactly_values(a.get("statement_summary", "")):
                if _has_opaque_value(value) == "yes":
                    truncated = value[:30] + "..." if len(value) > 30 else value
                    opaque_note = f"- The match value `{truncated}` is stored in the WAF configuration — anyone with read access to the Web ACL can obtain it, and a leaked value means full WAF bypass\n"
                    opaque_rec = "- Periodically rotate the secret value and audit IAM access to WAF configuration\n"
                    break
            if opaque_note:
                break

        md = T["forgeable_allow"].format(
            n="{n}", rule_names=rule_names, rule_line=rule_line,
            stmt_summary=group[0]["statement_summary"],
            forgeable_fields=forgeable_fields, is_are=is_are,
            forgeable_example=forgeable_example,
            dup_note=dup_note, dup_rec=dup_rec,
            opaque_note=opaque_note, opaque_rec=opaque_rec)
        results.append((md, {"severity": "Critical", "title_key": "forgeable_allow",
                             "rules": names, "sections": [1]}))
    return results if results else NOT_APPLICABLE


def _gen_hosting_provider_allow(summary, pre_checks, flags):
    check = pre_checks.get("hosting_provider_allow", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    md = T["hosting_provider_allow"].format(
        n="{n}", rule_name=check["rule"], priority=check["priority"])
    return [(md, {"severity": "Critical", "title_key": "hosting_provider_allow",
                  "rules": [check["rule"]], "sections": [7]})]


def _gen_scope_down_too_narrow(summary, pre_checks, flags):
    scope_downs = flags.get("scope_downs", [])
    narrow = [s for s in scope_downs
              if s.get("scope_down_summary") == "uri_path EXACTLY '/'"
              and any(g in s.get("rule", "") for g in ("IpReputation", "AnonymousIp"))]
    if not narrow:
        # Check if IP reputation groups exist but have no scope-down
        return NOT_APPLICABLE
    rule_line = " and ".join(f"{s['rule']} (priority {s['priority']})" for s in narrow)
    md = T["scope_down_too_narrow"].format(n="{n}", rule_line=rule_line)
    return [(md, {"severity": "Medium", "title_key": "scope_down_too_narrow",
                  "rules": [s["rule"] for s in narrow], "sections": [2]})]


def _gen_challenge_on_post_api(summary, pre_checks, flags):
    check = pre_checks.get("challenge_on_post_api", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = check.get("rules", [])
    rule_line = ", ".join(f"{r['name']} (priority {r['priority']})" for r in rules)
    # Check for duplicates
    dup_rec = ""
    names = [r["name"] for r in rules]
    md = T["challenge_on_post_api"].format(n="{n}", rule_line=rule_line, dup_rec=dup_rec)
    return [(md, {"severity": "Medium", "title_key": "challenge_on_post_api",
                  "rules": names, "sections": [4]})]


def _gen_missing_baseline(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    present = set()
    for r in rules:
        mg = r.get("managed")
        if mg:
            gn = mg.get("group_name", "")
            if gn in MANAGED_BASELINE_GROUPS:
                present.add(MANAGED_BASELINE_GROUPS[gn])
    missing = {"CRS", "KnownBadInputs"} - present
    if not missing:
        return NOT_APPLICABLE
    # A Web ACL deliberately scoped to DDoS, with application-layer attacks handled by
    # another Web ACL or another layer, is a design rather than an omission. Only an
    # operator can say which this is, so the finding is suppressed on their word and
    # never on an inference from the rule set.
    if (summary.get("context") or {}).get("waf_only_for_ddos") is True:
        return NOT_APPLICABLE
    missing_names = " and ".join(sorted(missing))
    details = []
    recs = []
    if "CRS" in missing:
        details.append("CRS provides OWASP Top 10 protection (SQLi, XSS, etc.) — the baseline protection layer for most web applications")
        recs.append("- Evaluate whether to add CRS; if adding, override `SizeRestrictions_Body` to Count to avoid false positives on large-payload API endpoints (see Appendix F)")
    if "KnownBadInputs" in missing:
        details.append("KnownBadInputsRuleSet protects against Log4Shell (CVE-2021-44228), Java deserialization exploits, and other known malicious input patterns — low WCU cost, low false positive rate")
        recs.append("- Add AWSManagedRulesKnownBadInputsRuleSet (low WCU cost, recommended as priority)")
    cap = summary.get("web_acl", {}).get("capacity")
    if cap is not None:
        recs.append(f"- Verify remaining WCU capacity in AWS Console before adding (current: {cap} / 5000)")
    md = T["missing_baseline"].format(
        n="{n}", missing_names=missing_names,
        missing_detail="\n- ".join(details), missing_rec="\n".join(recs))
    return [(md, {"severity": "Medium", "title_key": "missing_baseline",
                  "rules": [], "sections": [9]})]


def _gen_token_domain(summary, pre_checks, flags):
    check = pre_checks.get("token_domain", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    domains = check.get("domains", [])
    redundant = check.get("redundant", [])
    if not redundant:
        return NOT_APPLICABLE
    # Find apex
    apex = [d for d in domains if len(d.split(".")) == 2]
    apex_str = apex[0] if apex else domains[0]
    domain_list = ", ".join(f"`{d}`" for d in domains)
    md = T["token_domain"].format(n="{n}", domain_list=domain_list, apex=apex_str)
    return [(md, {"severity": "Low", "title_key": "token_domain",
                  "rules": [], "sections": [11]})]


def _gen_no_logging(summary, pre_checks, flags):
    """Logging, which the Web ACL export cannot show either way.

    Three outcomes, and keeping them apart is the whole point of the context file. With
    no answer this is "unverified" -- worth saying, worth nothing more, because reporting
    a critical failure for something nobody was shown is the fastest way to have the
    whole assessment dismissed. With an answer it becomes either a real Critical gap or
    no finding at all.
    """
    ctx = summary.get("context") or {}
    if not ctx_declared(ctx, "logging"):
        md = T["no_logging"].format(n="{n}")
        return [(md, {"severity": "Awareness", "title_key": "no_logging",
                      "rules": [], "sections": [13]})]

    log = ctx.get("logging")
    off = ("none", "no", "off", "disabled", "false")
    if log is None or log is False or str(log).strip().lower() in off:
        md = T["logging_disabled"].format(n="{n}")
        return [(md, {"severity": "Critical", "title_key": "logging_disabled",
                      "rules": [], "sections": [13]})]

    if not isinstance(log, dict):
        log = {"destination": str(log)}
    dest = log.get("destination") or "an unnamed destination"
    retention = log.get("retention_days")
    redacted = log.get("redacted_fields") or []
    filtered = log.get("filtered")

    gaps = []
    recs = []
    if retention is None:
        gaps.append("retention is not stated, so it is whatever the destination "
                    "defaults to")
        recs.append("- Set an explicit retention period on the log destination. 90 days "
                    "is the usual floor for incident investigation; an unset CloudWatch "
                    "log group retains forever and bills for it")
    elif isinstance(retention, int) and retention < 90:
        gaps.append(f"retention is {retention} days, short of the 90 days an "
                    "investigation usually reaches back for")
        recs.append(f"- Extend retention from {retention} to at least 90 days")
    if not redacted:
        gaps.append("no fields are redacted, so authorization headers, cookies and query "
                    "arguments are written to the logs verbatim")
        recs.append("- Redact the authorization header, session cookies and any query "
                    "argument carrying a token. Redaction is configured on the logging "
                    "configuration, not on the rules")
    if filtered is None:
        recs.append("- Consider a logging filter if volume is a cost concern: keeping "
                    "Block, Count and challenge outcomes and dropping plain Allows cuts "
                    "the bulk of the volume without losing the records anyone reads")

    if not gaps:
        return NOT_APPLICABLE

    md = T["logging_gaps"].format(
        n="{n}", destination=dest, gap_detail="\n- ".join(gaps),
        gap_rec="\n".join(recs))
    return [(md, {"severity": "Medium", "title_key": "logging_gaps",
                  "rules": [], "sections": [13]})]


def _gen_default_action_redundancy(summary, pre_checks, flags):
    check = pre_checks.get("default_action_redundancy", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rule_name = check["rule"]
    priority = check["priority"]
    # Find statement summary
    stmt = ""
    for r in summary.get("rules", []):
        if r["name"] == rule_name:
            stmt = r.get("statement", {}).get("summary", "")
            break
    md = T["default_action_redundancy"].format(
        n="{n}", rule_name=rule_name, priority=priority, stmt_summary=stmt)
    return [(md, {"severity": "Low", "title_key": "default_action_redundancy",
                  "rules": [rule_name], "sections": [15]})]


def _gen_count_without_labels(summary, pre_checks, flags):
    check = pre_checks.get("count_without_labels", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = check.get("rules", [])
    names = [r["name"] for r in rules]
    rule_names = " / ".join(names)
    rule_line = ", ".join(f"{r['name']} (priority {r['priority']})" for r in rules)
    # Check for duplicates within the group
    dup_note = ""
    dup_rec = ""
    if len(rules) > 1:
        dup_note = f"- {len(rules)} rules may have identical logic — check if duplicates exist\n"
        dup_rec = "- Remove duplicate rules if logic is identical\n"
    md = T["count_without_labels"].format(
        n="{n}", rule_names=rule_names, rule_line=rule_line,
        dup_note=dup_note, dup_rec=dup_rec)
    return [(md, {"severity": "Awareness", "title_key": "count_without_labels",
                  "rules": names, "sections": [17]})]


def _gen_challenge_all_during_event(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    amr = None
    for r in rules:
        mg = r.get("managed")
        if mg and "AntiDDoS" in mg.get("group_name", ""):
            amr = r
            break
    if not amr:
        return NOT_APPLICABLE
    overrides = amr.get("managed", {}).get("overrides", [])
    disabled = any(o.get("rule_name") == "ChallengeAllDuringEvent" and o.get("action") == "count"
                   for o in overrides)
    if not disabled:
        return NOT_APPLICABLE
    cfg = amr.get("managed", {}).get("config", {})
    block_sens = cfg.get("sensitivity_to_block", "unknown")
    sens_map = {"LOW": ("high-suspicion", "medium and low-suspicion"),
                "MEDIUM": ("medium and high-suspicion", "low-suspicion"),
                "HIGH": ("all suspicion levels of", "no")}
    block_desc, remaining_desc = sens_map.get(block_sens, ("some", "remaining"))
    md = T["challenge_all_during_event"].format(
        n="{n}", rule_name=amr["name"], priority=amr["priority"],
        block_sens=block_sens, block_desc=block_desc, remaining_desc=remaining_desc)
    return [(md, {"severity": "Medium", "title_key": "challenge_all_during_event",
                  "rules": [amr["name"]], "sections": [3]})]


def _gen_unanchored_exempt_regex(summary, pre_checks, flags):
    regex_flags = flags.get("exempt_regex_branches", [])
    if not regex_flags:
        return NOT_APPLICABLE
    results = []
    for rf in regex_flags:
        unanchored = [b for b in rf.get("branches", [])
                      if not b.get("anchored_start") and not b.get("anchored_end")]
        if not unanchored:
            continue
        unanchored_list = ", ".join(f"`{b['pattern']}`" for b in unanchored)
        examples = ", ".join(f"`/admin{b['pattern'].replace(chr(92), '')}/export`"
                             for b in unanchored[:2])
        anchored = "`" + "|".join(
            f"^{b['pattern']}" if not b.get("anchored_start") else b["pattern"]
            for b in rf["branches"]) + "`"
        md = T["unanchored_exempt_regex"].format(
            n="{n}", rule_name=rf["rule"], priority=rf["priority"],
            regex=rf["full_regex"], unanchored_list=unanchored_list,
            examples=examples, anchored_suggestion=anchored)
        results.append((md, {"severity": "Medium", "title_key": "unanchored_exempt_regex",
                             "rules": [rf["rule"]], "sections": [3]}))
    return results if results else NOT_APPLICABLE


def _gen_missing_crawler_labeling(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    has_amr = any("AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules)
    if not has_amr:
        return NOT_APPLICABLE
    # Check for crawler labeling rule
    for r in rules:
        labels = r.get("rule_labels", [])
        for lbl in labels:
            if any(lbl.startswith(p) for p in CRAWLER_LABEL_PATTERNS):
                return NOT_APPLICABLE
        # Structural: Count + asn_match + produces any label
        if (r.get("action") == "count" and
                "asn_match" in r.get("statement", {}).get("leaf_types", []) and
                labels):
            return NOT_APPLICABLE
    md = T["missing_crawler_labeling"].format(n="{n}")
    return [(md, {"severity": "Medium", "title_key": "missing_crawler_labeling",
                  "rules": [], "sections": [3]})]


def _gen_bot_control_search_allow(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    for r in rules:
        mg = r.get("managed")
        if not mg or "BotControl" not in mg.get("group_name", ""):
            continue
        search_allows = [o for o in mg.get("overrides", [])
                         if o.get("action") == "allow" and
                         o.get("rule_name", "") in ("CategorySearchEngine", "CategorySeo")]
        if search_allows:
            override_names = " / ".join(o["rule_name"] for o in search_allows)
            md = T["bot_control_search_allow"].format(
                n="{n}", rule_name=r["name"], priority=r["priority"],
                override_names=override_names)
            return [(md, {"severity": "Low", "title_key": "bot_control_search_allow",
                          "rules": [r["name"]], "sections": [5]})]
    return NOT_APPLICABLE


def _gen_duplicate_rules(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    # Group rate-based rules
    rate_groups = defaultdict(list)
    for r in rules:
        if r.get("type") != "rate_based":
            continue
        rb = r.get("rate_based", {})
        sd = r.get("scope_down", {})
        sd_summary = sd.get("summary", "") if sd else ""
        key = (r["action"], rb.get("limit"), rb.get("evaluation_window_sec"), sd_summary)
        rate_groups[key].append(r)

    results = []
    all_dup_names = []
    all_pair_lines = []
    for key, group in rate_groups.items():
        if len(group) < 2:
            continue
        sorted_g = sorted(group, key=lambda x: x["priority"])
        for i in range(0, len(sorted_g) - 1, 2):
            all_pair_lines.append(f"{sorted_g[i]['name']} (P{sorted_g[i]['priority']}) / {sorted_g[i+1]['name']} (P{sorted_g[i+1]['priority']})")
        all_dup_names.extend(r["name"] for r in group)

    if not all_pair_lines:
        return NOT_APPLICABLE

    rule_line = "; ".join(all_pair_lines)
    pair_count = len(all_pair_lines)
    dup_problem = "For rate-based rules with overlapping scope-downs, only the lowest-threshold rule triggers for overlapping traffic — higher-threshold duplicates have no additional effect"
    match_desc = "scope-down, limit, and window"
    rule_type = "rate-limit"
    md = T["duplicate_rules"].format(
        n="{n}", rule_type=rule_type, rule_line=rule_line,
        pair_count=pair_count, match_desc=match_desc,
        dup_problem=dup_problem)
    results.append((md, {"severity": "Awareness", "title_key": "duplicate_rules",
                         "rules": all_dup_names, "sections": [6]}))
    return results


def _gen_managed_versions(summary, pre_checks, flags):
    check = pre_checks.get("managed_versions", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    results = []
    for detail_str in check.get("details", []):
        # Parse "rule_name: GroupName version X < Y (recommend upgrading)"
        parts = detail_str.split(":", 1)
        rule_name = parts[0].strip() if parts else "unknown"
        # Find rule
        priority = 0
        current_version = "unknown"
        for r in summary.get("rules", []):
            if r["name"] == rule_name:
                priority = r["priority"]
                current_version = r.get("managed", {}).get("version", "unknown")
                break
        if "BotControl" in detail_str:
            version_problem = "BotControlRuleSet Version_5.0 Common level can identify close to 700 bot types (based on UA and IP), far more than earlier versions"
            version_rec = "Upgrade BotControlRuleSet to Version_5.0"
            detail = f"Bot Control version outdated ({current_version}), recommend upgrading to 5.0"
        elif "SQLi" in detail_str:
            version_problem = "SQLiRuleSet version 2.0 has significantly higher SQLi detection coverage than 1.0"
            version_rec = "Upgrade SQLiRuleSet to version 2.0"
            detail = f"SQLiRuleSet version outdated ({current_version}), recommend upgrading to 2.0"
        else:
            continue
        md = T["managed_versions"].format(
            n="{n}", detail=detail, rule_name=rule_name, priority=priority,
            current_version=current_version, version_problem=version_problem,
            version_rec=version_rec)
        results.append((md, {"severity": "Low", "title_key": "managed_versions",
                             "rules": [rule_name], "sections": [12]}))
    return results if results else NOT_APPLICABLE


def _gen_missing_always_on_challenge(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    ctx = summary.get("context") or {}
    # A Challenge can only be completed by a browser. Where the declared clients are all
    # native apps or server-to-server callers, recommending an always-on Challenge is
    # recommending an outage, so the finding is withheld rather than softened.
    if ctx_list(ctx, "client_types") and not has_browser_client(ctx):
        return NOT_APPLICABLE
    has_amr = any("AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules)
    if not has_amr:
        return NOT_APPLICABLE
    # Check for always-on challenge pattern
    # Pattern 1: Challenge rule consuming a label
    label_producers = {}
    for r in rules:
        for lbl in r.get("rule_labels", []):
            label_producers[lbl] = r["name"]
    for r in rules:
        if r.get("action") != "challenge" or r.get("type") != "custom":
            continue
        stmt = r.get("statement", {}).get("summary", "")
        # Check if it references a label
        label_refs = re.findall(r"label_match '([^']+)'", stmt)
        for lref in label_refs:
            if lref in label_producers:
                return NOT_APPLICABLE
    # Pattern 2: Challenge on landing page URIs directly
    landing_patterns = ("/", "/login", "/signup", "/register", "/index", "/home")
    for r in rules:
        if r.get("action") != "challenge" or r.get("type") != "custom":
            continue
        stmt = r.get("statement", {}).get("summary", "")
        if any(f"'{p}'" in stmt for p in landing_patterns):
            return NOT_APPLICABLE
    # Declared landing pages are rendered verbatim, because a placeholder path invented
    # here would appear in the customer's report as though it were theirs.
    declared = ctx_list(ctx, "landing_page_uris")
    uri_list = (", ".join(f"`{u}`" for u in declared) if declared
                else "`/`, `/login`, `/signup`, etc. — confirm the real list")
    md = T["missing_always_on_challenge"].format(n="{n}", uri_list=uri_list)
    return [(md, {"severity": "Medium", "title_key": "missing_always_on_challenge",
                  "rules": [], "sections": [16]})]


def _gen_priority_order(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    if len(rules) < 2:
        return NOT_APPLICABLE
    # Classify each rule
    classified = [(r, _classify_rule_type(r)) for r in rules
                  if _classify_rule_type(r) not in UNORDERED_TIERS]
    order_index = {cat: i for i, (cat, _) in enumerate(RECOMMENDED_ORDER)}

    violations = []
    seen_cat_pairs = {}  # (cat1, cat2) -> (r1_name, r2_name) representative
    for i, (r1, cat1) in enumerate(classified):
        if cat1 not in order_index:
            continue
        for j in range(i + 1, len(classified)):
            r2, cat2 = classified[j]
            if cat2 not in order_index:
                continue
            if order_index[cat1] > order_index[cat2]:
                # Guard, narrowed after the baseline review. An Allow rule at the very top is
                # now the sanctioned shape, so reporting a rule that precedes it is correct.
                # What must never be suggested is moving a *forgeable* Allow earlier -- that
                # widens a bypass rather than fixing an ordering problem, and this generator
                # proposed exactly that on the first real config it ran against.
                if r2.get("action") == "allow" and not (
                        {"ip_set", "asn_match", "geo_match", "label_match"}
                        & set((r2.get("statement") or {}).get("leaf_types") or [])):
                    continue
                pair = (cat1, cat2)
                if pair not in seen_cat_pairs:
                    seen_cat_pairs[pair] = (r1, r2)

    for (cat1, cat2), (r1, r2) in seen_cat_pairs.items():
        desc1 = dict(RECOMMENDED_ORDER).get(cat1, cat1)
        desc2 = dict(RECOMMENDED_ORDER).get(cat2, cat2)
        violations.append(
            f"- {r1['name']} (P{r1['priority']}, {desc1}) is before "
            f"{r2['name']} (P{r2['priority']}, {desc2}), but recommended order is reversed")

    if not violations:
        return NOT_APPLICABLE
    if len(violations) > 8:
        violations = violations[:8]
        violations.append("- ... and more ordering issues")

    problems = "\n".join(violations)
    summary_text = _plural(len(violations), "ordering violation") + " found"
    current_state = ", ".join(f"{r['name']} (P{r['priority']})" for r in rules[:5])
    if len(rules) > 5:
        current_state += f" ... ({len(rules)} rules total)"
    md = T["priority_order"].format(
        n="{n}", summary=summary_text, current_state=current_state, problems=problems)
    all_rules = [r["name"] for r in rules]
    return [(md, {"severity": "Medium", "title_key": "priority_order",
                  "rules": all_rules[:10], "sections": [18]})]


def _gen_opaque_search_string(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    # Skip rules already flagged as forgeable Allow (they get their own Critical finding)
    forgeable_allow_names = set()
    for a in flags.get("allow_rules", []):
        if a.get("all_forgeable") and a.get("blast_radius") == "global":
            forgeable_allow_names.add(a["name"])
    results = []
    seen_values = set()
    for r in rules:
        if r.get("type") != "custom":
            continue
        if r["name"] in forgeable_allow_names:
            continue
        stmt_summary = r.get("statement", {}).get("summary", "")
        for field, value in _extract_exactly_values(stmt_summary):
            if value in seen_values:
                continue
            opacity = _has_opaque_value(value)
            if opacity == "no":
                continue
            if opacity == "maybe":
                return AMBIGUOUS
            seen_values.add(value)
            is_allow = r.get("action") == "allow"
            if is_allow:
                risk_note = "Since this rule's action is Allow, a leaked value means full WAF bypass for anyone who knows it"
                rec_note = "If this is a shared secret for probe/monitoring access, switch to an unforgeable condition (IP Set or WAF Token)"
            else:
                risk_note = "This value may be a shared secret or redacted content"
                rec_note = "Verify whether this value is a secret that should be protected from exposure"
            md = T["opaque_search_string"].format(
                n="{n}", rule_name=r["name"], priority=r["priority"],
                stmt_summary=stmt_summary[:100], value=value[:30] + "..." if len(value) > 30 else value,
                risk_note=risk_note, rec_note=rec_note)
            results.append((md, {"severity": "Awareness", "title_key": "opaque_search_string",
                                 "rules": [r["name"]], "sections": [14]}))
    return results if results else NOT_APPLICABLE


def _gen_managed_allow_override(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    handled_rules = {"HostingProviderIPList", "CategorySearchEngine", "CategorySeo"}
    results = []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        for o in mg.get("overrides", []):
            if o.get("action") == "allow" and o.get("rule_name", "") not in handled_rules:
                override_detail = f"`{o['rule_name']}` overridden to Allow"
                md = T["managed_allow_override"].format(
                    n="{n}", rule_name=r["name"], priority=r["priority"],
                    override_detail=override_detail)
                results.append((md, {"severity": "Awareness",
                                     "title_key": "managed_allow_override",
                                     "rules": [r["name"]], "sections": [1]}))
    return results if results else NOT_APPLICABLE

def _gen_duplicate_branches(summary, pre_checks, flags):
    check = pre_checks.get("duplicate_branches", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    # One finding for all of them: the defect and the fix are identical, so separate cards
    # would say the same thing twice and split the reader's attention across two priorities.
    flagged = check.get("rules", [])
    if not flagged:
        return NOT_APPLICABLE
    details, ip_names = [], []
    for f in flagged:
        rule = next((r for r in summary.get("rules", []) if r["name"] == f["name"]), {})
        arns = re.findall(r"ip_set '([^']*)'",
                          (rule.get("statement") or {}).get("summary", ""))
        line = (f"`{f['name']}` (priority {f['priority']}): `{f['op']}` of "
                f"{f['branches']} branches referencing only {f['distinct']} distinct "
                "condition")
        if arns:
            names = [a.rstrip("/").split("/")[-2] if a.count("/") >= 2 else a
                     for a in dict.fromkeys(arns)]
            line += f" — IP set `{names[0]}` referenced {f['branches']} times"
            ip_names.extend(names)
        details.append(line)
    if ip_names:
        family_note = ("- Each duplicated branch is an IP set reference, and the set names "
                       "carry an address-family suffix. That is the signature of an IPv6 "
                       "companion set having been copy-pasted over with the IPv4 one\n")
        fix = ("Point each duplicate branch at its IPv6 companion set. Check whether they "
               "exist first: `aws wafv2 list-ip-sets --scope REGIONAL`")
    else:
        family_note = ""
        fix = "Remove each duplicate branch, or point it at the condition intended"
    md = T["duplicate_branch"].format(
        n="{n}", rule_names=" / ".join(f["name"] for f in flagged),
        rule_line=", ".join(f"{f['name']} (priority {f['priority']})" for f in flagged),
        detail="; ".join(details), family_note=family_note, fix=fix)
    return [(md, {"severity": "Medium", "title_key": "duplicate_branch",
                  "rules": [f["name"] for f in flagged], "sections": [1]})]


def _gen_single_address_family(summary, pre_checks, flags):
    check = pre_checks.get("ip_set_families", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = check.get("rules", [])
    md = T["single_address_family"].format(
        n="{n}", rule_names=" / ".join(r["name"] for r in rules),
        rule_line=", ".join(f"{r['name']} (priority {r['priority']})" for r in rules),
        n_sets=sum(len(r["sets"]) for r in rules),
        set_names=", ".join(f"`{n}`" for r in rules for n in r["sets"]))
    return [(md, {"severity": "Medium", "title_key": "single_address_family",
                  "rules": [r["name"] for r in rules], "sections": [1]})]


def _gen_orphan_managed_label(summary, pre_checks, flags):
    check = pre_checks.get("orphan_managed_labels", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = summary.get("rules", [])
    results = []
    for f in check.get("rules", []):
        subsumer = f.get("subsumed_by") or ""
        holder = next((r for r in rules
                       if (r.get("managed") or {}).get("group_name") == subsumer), None)
        if holder is None:
            note = (f"- Normally `{subsumer}` subsumes this list, but it is not present in "
                    "this Web ACL, so nothing is acting on these addresses\n")
            fix = f"Add `{subsumer}`, which handles this list natively once it is enforcing"
        elif holder.get("action") == "count":
            note = (f"- Normally `{subsumer}` subsumes this list. **That does not apply "
                    "here**: it is overridden to Count, so neither control is acting on "
                    "these addresses\n")
            fix = (f"Restore `{subsumer}` to enforcing. Once it is, it handles this list "
                   "and this finding closes itself")
        else:
            note = (f"- `{subsumer}` is present and enforcing, and handles this list "
                    "natively — so no action is needed\n")
            fix = f"No action required: `{subsumer}` covers these addresses"
        md = T["orphan_managed_label"].format(
            n="{n}", rule_name=f["name"], priority=f["priority"],
            sub_rule=f["sub_rule"], label=f["label"], why_count=f["why"],
            subsume_note=note, fix=fix)
        results.append((md, {"severity": "Awareness", "title_key": "orphan_managed_label",
                             "rules": [f["name"]], "sections": [17]}))
    return results or NOT_APPLICABLE


def _gen_challenge_readiness(summary, pre_checks, flags):
    """Token scope and immunity, but only worth raising when nothing challenges yet.

    Once a Challenge rule exists these settings are live configuration and belong to
    whichever finding covers that rule. Silent when they are already set.
    """
    acl = summary.get("web_acl", {})
    rules = summary.get("rules", [])
    challenges = [r for r in rules if r.get("action") in ("challenge", "captcha")]
    amr = next((r for r in rules
                if "AntiDDoS" in (r.get("managed") or {}).get("group_name", "")), None)
    amr_challenging = bool(amr) and amr.get("action") != "count"
    if challenges or amr_challenging:
        return NOT_APPLICABLE           # a live setting, not a readiness note
    if amr is None:
        return NOT_APPLICABLE           # nothing here could issue a Challenge at all
    td = acl.get("token_domains") or []
    immunity = (acl.get("challenge_config") or {}).get("immunity_time")
    if td and immunity:
        return NOT_APPLICABLE
    md = T["challenge_not_ready"].format(
        n="{n}",
        td_state="empty" if not td else f"set to {', '.join(td)}",
        immunity_state=("No Web ACL `ChallengeConfig`, so the 300-second service default "
                        "applies." if not immunity
                        else f"Challenge immunity is {immunity}s."))
    return [(md, {"severity": "Awareness", "title_key": "challenge_not_ready",
                  "rules": [], "sections": [11]})]


def _gen_terminating_allow_strands(summary, pre_checks, flags):
    """A terminating Allow with rules below it, which is a bypass of everything below.

    Not the same question as forgeability. `_gen_forgeable_allow` asks whether the *condition*
    can be asserted by the caller and only fires on a globally-scoped Allow; this asks what
    the Allow *skips*, which matters just as much when the match is a path prefix. The
    combination that motivated it -- an Allow on four path prefixes, 19 rules below it
    including the Shield mitigation group -- was invisible to every other check.
    """
    rules = sorted(summary.get("rules", []), key=lambda r: r.get("priority") or 0)
    ctx = summary.get("context") or {}
    results = []
    for r in rules:
        if r.get("action") != "allow":
            continue
        below = [x for x in rules if (x.get("priority") or 0) > (r.get("priority") or 0)]
        if not below:
            continue
        stmt = (r.get("statement") or {}).get("summary", "")
        shield = [x for x in below
                  if "ShieldMitigationRuleGroup" in (x.get("statement") or {}).get("summary", "")]
        paths = re.findall(r"uri_path\s+(?:EXACTLY|STARTS_WITH|CONTAINS|ENDS_WITH)\s+'([^']*)'",
                           stmt)
        if paths:
            scope_desc = "for " + ", ".join(f"`{v}`" for v in paths[:5])
            scope_problem = (f"The exempted paths are {', '.join(chr(96)+v+chr(96) for v in paths[:5])}"
                             ", and a request only has to match one of them to skip everything "
                             "below")
        else:
            scope_desc = "for any request it matches"
            scope_problem = ("The rule carries no URI restriction, so the exemption applies to "
                             "every path in the application")
        # An Allow keyed on something the caller cannot set is a deliberate allowlist, and a
        # terminating Allow is its function -- reporting that as a bypass is how this kind of
        # review embarrasses itself. It still deserves a note, because it is a standing
        # exemption from everything below, so it gets its own Awareness finding instead.
        leaves = (r.get("statement") or {}).get("leaf_types") or []
        unforgeable = bool({"ip_set", "asn_match", "geo_match", "label_match"} & set(leaves))
        if unforgeable:
            md = T["deliberate_allowlist"].format(
                n="{n}", rule_name=r["name"], priority=r["priority"], count=len(below),
                stmt_summary=stmt[:180])
            results.append((md, {"severity": "Awareness", "title_key": "deliberate_allowlist",
                                 "rules": [r["name"]], "sections": [1]}))
            continue
        forge_note = ("**The condition is attacker-controlled.** No forgery or secret is "
                      "needed: a request to a matching path is exempt, and anyone probing "
                      "the service finds it by accident")
        # Severity by blast radius. Stranding most of the Web ACL is Critical. Stranding
        # only a trailing Shield mitigation group is not: everything else has already
        # evaluated, so the loss is Shield's automatic mitigations rather than inspection.
        severity = "Critical" if len(below) >= 5 else "Medium"
        labels = r.get("rule_labels") or []
        label_note = (f". Applies label `{labels[0]}`" if labels else "")
        shield_note = ("" if not shield else
                       ", **including the Shield Advanced mitigation rule group**, which Shield "
                       "places last by design and which this Allow therefore puts out of reach")
        stranded = "\n".join(
            f"- Stranded: `{x['name']}` (priority {x['priority']})" for x in below[:6])
        if len(below) > 6:
            stranded += f"\n- ... and {len(below) - 6} more"
        stranded += "\n"
        md = T["terminating_allow_strands"].format(
            n="{n}", severity=severity, rule_name=r["name"], priority=r["priority"],
            count=f"{len(below)} rule" + ("s" if len(below) != 1 else ""),
            scope_desc=scope_desc, scope_problem=scope_problem, forge_note=forge_note,
            stmt_summary=stmt[:180], label_note=label_note, shield_note=shield_note,
            stranded_list=stranded)
        results.append((md, {"severity": severity,
                             "title_key": "terminating_allow_strands",
                             "rules": [r["name"]], "sections": [1]}))
    return results or NOT_APPLICABLE


def _gen_group_level_count(summary, pre_checks, flags):
    """A managed rule group overridden to Count as a whole, so nothing inside it acts.

    v2's check looks for a sub-rule override on ChallengeAllDuringEvent and finds nothing when
    the *whole group* is overridden instead -- which is broader and worse. That gap hid the
    single largest finding on the first real config this ran against.
    """
    rules = summary.get("rules", [])
    shield = summary.get("web_acl", {}).get("shield_advanced")
    results = []
    for r in rules:
        if r.get("type") != "managed_rule_group" or r.get("action") != "count":
            continue
        mg = r.get("managed") or {}
        gn = mg.get("group_name", "")
        core = CORE_GROUPS.get(gn)
        cfg = mg.get("config") or {}
        config_note = ""
        intent_note = ""
        if cfg:
            shown = ", ".join(f"`{k}: {v}`" for k, v in list(cfg.items())[:3]
                              if not isinstance(v, (dict, list)))
            if shown:
                config_note = f". Group configuration is otherwise deliberate: {shown}"
                intent_note = ("- The configuration around it shows real intent, which the Count "
                               "override contradicts. That is more consistent with a staged "
                               "rollout nobody completed than with a decision\n")
        if "AntiDDoS" in gn:
            impact = ("During a detected DDoS event this rule group would label traffic, move its "
                      "metrics, and mitigate nothing -- no Block and no Challenge")
            if shield:
                shield_note = ("- **Shield Advanced is subscribed and already includes this rule "
                               "group** and its request fees for up to 50 billion requests a month "
                               "across the organisation, so it is paid for and producing metrics "
                               "only\n- Count is also the more expensive resting state: AWS waives "
                               "the request charge for DDoS traffic the group is *actively "
                               "mitigating*, and that means Block or Challenge, not Count\n")
            else:
                shield_note = ""
            fix = ("Do not simply lift the override. If the group's Challenge action is enabled and "
                   "any client cannot execute a JavaScript interstitial, enabling it as configured "
                   "turns a mitigation into an outage. Disable the Challenge action and raise Block "
                   "sensitivity first, then lift the override. `references/antiddos-amr.md` has "
                   "both the separate-Web-ACL and dual-instance patterns")
        else:
            impact = (f"{core}, and in Count none of it blocks" if core
                      else "Everything this group would have caught now reaches the origin")
            shield_note = ""
            fix = ("Lift the group-level override and promote sub-rules individually, starting with "
                   "the ones least likely to false-positive")
        md = T["group_level_count"].format(
            n="{n}", severity="Critical" if core else "Medium", group_name=gn,
            rule_name=r["name"], priority=r["priority"], config_note=config_note,
            impact=impact, shield_note=shield_note, intent_note=intent_note, fix=fix)
        results.append((md, {"severity": "Critical" if core else "Medium",
                             "title_key": "group_level_count",
                             "rules": [r["name"]], "sections": [3]}))
    return results or NOT_APPLICABLE


def _gen_name_action_mismatch(summary, pre_checks, flags):
    flagged = []
    for r in summary.get("rules", []):
        action = r.get("action")
        if action not in ("allow", "block", "count"):
            continue
        name = (r.get("name") or "").lower()
        for token, expected in NAME_INTENT.items():
            if not re.search(rf"(?:^|[^a-z]){token}(?:[^a-z]|$)", name):
                continue
            if action in expected:
                continue
            if action == "count" and "block" in expected:
                continue          # Count is a normal staging step towards Block
            flagged.append({"name": r["name"], "priority": r["priority"], "action": action,
                            "token": token, "expected": expected[0]})
            break
    if not flagged:
        return NOT_APPLICABLE
    detail = "; ".join(f"`{f['name']}` says *{f['token']}* but its action is **{f['action']}**"
                       for f in flagged)
    consequence = ("An `Allow` is terminating, so a rule named for blocking that allows also skips "
                   "every rule below it"
                   if any(f["action"] == "allow" for f in flagged)
                   else "The rule does not do what its name claims")
    md = T["name_action_mismatch"].format(
        n="{n}", rule_names=" / ".join(f["name"] for f in flagged),
        rule_line=", ".join(f"{f['name']} (priority {f['priority']})" for f in flagged),
        detail=detail, consequence=consequence)
    return [(md, {"severity": "Medium", "title_key": "name_action_mismatch",
                  "rules": [f["name"] for f in flagged], "sections": [1]})]


def _gen_rate_rule_ineffective(summary, pre_checks, flags):
    flagged, problems = [], []
    for r in summary.get("rules", []):
        if r.get("type") != "rate_based":
            continue
        rb = r.get("rate_based") or {}
        limit, win = rb.get("limit"), rb.get("evaluation_window_sec")
        why = []
        if r.get("action") == "count":
            why.append("action is Count, so it never enforces anything")
        if isinstance(limit, int) and win and limit / win > RATE_RPS_IMPLAUSIBLE:
            why.append(f"threshold is {limit:,} per {win}s, i.e. **{limit / win:,.0f} requests "
                       f"per second sustained from one {rb.get('aggregate_key_type', 'IP')}**, "
                       "which no legitimate client approaches")
        if why:
            flagged.append((r, limit, win, rb.get("aggregate_key_type", "IP"), why))
    if not flagged:
        return NOT_APPLICABLE
    for r, limit, win, key, why in flagged:
        for w in why:
            problems.append(f"- `{r['name']}`: {w}")
    problems.append("- A metric whose threshold nothing reaches produces a flat line that reads "
                    "as healthy, so neither mitigation nor signal is being obtained")
    detail = "; ".join(
        f"`{r['name']}` limit {limit:,} per {win}s per {key}, action {r.get('action')}"
        for r, limit, win, key, _ in flagged)
    md = T["rate_rule_ineffective"].format(
        n="{n}", rule_names=" / ".join(r["name"] for r, *_ in flagged),
        rule_line=", ".join(f"{r['name']} (priority {r['priority']})" for r, *_ in flagged),
        detail=detail, problems="\n".join(problems))
    return [(md, {"severity": "Medium", "title_key": "rate_rule_ineffective",
                  "rules": [r["name"] for r, *_ in flagged], "sections": [6]})]


#: Sub-rule overrides to Count that are widely recommended and need no justification.
_JUSTIFIED_COUNT = {"SizeRestrictions_BODY", "SizeRestrictions_Body", "NoUserAgent_HEADER",
                    "SignalNonBrowserUserAgent", "CategoryHttpLibrary", "HostingProviderIPList"}


def _gen_managed_count_overrides(summary, pre_checks, flags):
    rows, unjustified, body = [], [], []
    for r in summary.get("rules", []):
        mg = r.get("managed") or {}
        counts = [o["rule_name"] for o in mg.get("overrides", [])
                  if o.get("action") == "count"]
        if not counts:
            continue
        rows.append((r, counts))
        for c in counts:
            if c not in _JUSTIFIED_COUNT:
                unjustified.append(c)
                if c.upper().endswith("_BODY"):
                    body.append(c)
    if not unjustified:
        return NOT_APPLICABLE
    body_title = (" — request-body inspection is not blocking" if body else "")
    body_problem = ""
    if body:
        body_problem = (f"- {len(body)} of them are body-inspection rules "
                        f"({', '.join(chr(96)+b+chr(96) for b in body)}), so **the request body "
                        "is inspected for nothing that blocks** — local file inclusion, "
                        "cross-site scripting and SQL injection in the body are recorded and "
                        "passed through. For an API workload that is the wrong half to relax, "
                        "because payloads travel in the body\n")
    # A sub-rule at Count applies a label and takes no action, so it only protects anything
    # if a later rule consumes that label. The doc is explicit: "Count without a follow-up
    # enforcement rule provides visibility but no protection." Nothing checked it before.
    consumed = set()
    for r in summary.get("rules", []):
        consumed.update(re.findall(r"label_match '([^']+)'",
                                   (r.get("statement") or {}).get("summary", "")))
    unpaired = []
    for r, counts in rows:
        ns = LABEL_NS.get((r.get("managed") or {}).get("group_name", ""))
        if not ns:
            continue
        for c in counts:
            if c in _JUSTIFIED_COUNT:
                continue
            label = f"awswaf:managed:aws:{ns}:{c}"
            if label not in consumed:
                unpaired.append((c, label))
    if unpaired:
        pairing_problem = (
            f"- **{len(unpaired)} of these Count overrides "
            f"{'has' if len(unpaired) == 1 else 'have'} no enforcement rule behind "
            "them.** A Count override adds a label and lets the request through, so "
            "it protects nothing unless a later rule matches that label and acts. No rule in "
            "this Web ACL matches any of them: "
            + ", ".join(f"`{lbl}`" for _c, lbl in unpaired[:4])
            + (f" and {len(unpaired) - 4} more" if len(unpaired) > 4 else "") + "\n")
        pairing_rec = (
            "- For any Count override meant to be acted on rather than merely observed, add a "
            "rule matching its label at a higher priority number than the group, and give it "
            "the action intended. Without that the override is visibility only, which is a "
            "legitimate choice but should be a deliberate one")
    else:
        pairing_problem = ""
        pairing_rec = ""

    detail = "; ".join(f"`{r['name']}` (priority {r['priority']}): "
                       + ", ".join(f"`{c}`" for c in counts) for r, counts in rows)
    # Count only the overrides that need justifying. Counting all of them, including the
    # recommended ones, overstates the finding in its own title.
    md = T["managed_count_overrides"].format(
        n="{n}", count=_plural(len(unjustified), "managed sub-rule"), body_title=body_title,
        rule_line=", ".join(f"{r['name']} (priority {r['priority']})" for r, _ in rows),
        detail=detail, body_problem=body_problem,
        pairing_problem=pairing_problem, pairing_rec=pairing_rec)
    return [(md, {"severity": "Medium", "title_key": "managed_count_overrides",
                  "rules": [r["name"] for r, _ in rows], "sections": [2]})]


def _gen_geo_vs_markets(summary, pre_checks, flags):
    """A geo denylist where the declared footprint makes an allowlist the better shape.

    Gated on `markets`: without it, recommending an allowlist could cut off real customers,
    and inferring a footprint from a hostname or an account region is exactly the guess the
    context file exists to prevent.
    """
    ctx = summary.get("context") or {}
    markets = [m.upper() for m in ctx_list(ctx, "markets")]
    if not markets or len(markets) > 12:
        return NOT_APPLICABLE
    for r in summary.get("rules", []):
        stmt = (r.get("statement") or {}).get("summary", "")
        if "geo_match" not in (r.get("statement") or {}).get("leaf_types", []):
            continue
        if r.get("action") != "block" or stmt.startswith("NOT("):
            continue                # already an allowlist, or not enforcing
        codes = re.findall(r"'([A-Z]{2})'", stmt)
        if not codes or len(codes) > 40:
            return NOT_APPLICABLE   # a large denylist is a different conversation
        md = T["geo_vs_markets"].format(
            n="{n}", rule_name=r["name"], priority=r["priority"],
            codes_count=len(codes), codes_list=", ".join(codes),
            markets_desc=", ".join(markets),
            markets_codes=", ".join(f'"{m}"' for m in markets))
        return [(md, {"severity": "Medium", "title_key": "geo_vs_markets",
                      "rules": [r["name"]], "sections": [7]})]
    return NOT_APPLICABLE


def _gen_opaque_rule_groups(summary, pre_checks, flags):
    rules = sorted(summary.get("rules", []), key=lambda r: r.get("priority") or 0)
    opaque = [r for r in rules
              if (r.get("statement") or {}).get("summary", "").startswith("rule_group ")
              and "ShieldMitigationRuleGroup" not in (r.get("statement") or {}).get("summary", "")]
    if not opaque:
        return NOT_APPLICABLE
    acl = summary.get("web_acl", {})
    eff = acl.get("effective_capacity")
    wcu_title = wcu_state = wcu_problem = wcu_rec = ""
    if eff:
        over = eff - 1500
        wcu_state = f"Effective capacity is {eff:,} WCU of the 5,000 ceiling."
        if over > 0:
            steps = -(-over // 500)
            wcu_title = ", and capacity is above the included allocation"
            wcu_problem = (f"- **Capacity is a real cost here.** {eff:,} WCU is {over:,} above the "
                           f"1,500 included allocation, which is {steps} surcharge increment(s) "
                           f"applied across every request. Shield Advanced does not cover that "
                           f"surcharge. These groups are the most likely large contributor, and "
                           f"there is {5000 - eff:,} WCU of headroom before the ceiling\n")
            wcu_rec = ("- Confirm the capacity breakdown in the console before adding anything. "
                       "The published figure can understate real consumption, and the higher "
                       "number is the one that bills\n")
        else:
            wcu_problem = ""
    # A terminating Allow above them makes their contents moot for the matching traffic.
    allows = [r for r in rules if r.get("action") == "allow"
              and (r.get("priority") or 0) < min(x.get("priority") or 0 for x in opaque)]
    stranded_note = ""
    if allows:
        stranded_note = (f"- **All of them sit below the terminating Allow in `{allows[0]['name']}` "
                         f"(priority {allows[0]['priority']}).** For traffic that Allow matches, "
                         "none of these groups evaluates — so whatever protection they contain is "
                         "not running for those paths\n")
    md = T["opaque_rule_groups"].format(
        n="{n}", count=len(opaque), wcu_title=wcu_title,
        rule_line=(f"{opaque[0]['name']} (priority {opaque[0]['priority']})"
                   + (f", {opaque[-1]['name']} (priority {opaque[-1]['priority']})"
                      if len(opaque) > 1 else "")),
        wcu_state=wcu_state, stranded_note=stranded_note,
        wcu_problem=wcu_problem, wcu_rec=wcu_rec)
    return [(md, {"severity": "Awareness", "title_key": "opaque_rule_groups",
                  "rules": [opaque[0]["name"]] + ([opaque[-1]["name"]] if len(opaque) > 1 else []),
                  "sections": [10]})]


def _gen_no_bot_management(summary, pre_checks, flags):
    rules = summary.get("rules", [])
    have = [g for r in rules for g in [(r.get("managed") or {}).get("group_name", "")]
            if any(k in g for k in ("BotControl", "ATPRuleSet", "ACFPRuleSet"))]
    if have:
        return NOT_APPLICABLE
    ctx = summary.get("context") or {}
    clients = ctx_list(ctx, "client_types")
    nonbrowser = clients and not has_browser_client(ctx)
    if nonbrowser:
        client_title = " — and Bot Control would block this application's own clients"
        client_problem = (f"- **Bot Control Common level would block these clients.** The declared "
                          f"client types are {', '.join(clients)}, and Common level classifies by "
                          "User-Agent with `SignalNonBrowserUserAgent` defaulting to Block. A "
                          "native app using okhttp, Alamofire or a platform HTTP library is "
                          "non-browser by definition and would be blocked on its first request\n")
        caveat = ("Recommending Bot Control here without the caveats would be recommending an "
                  "outage, so the honest position is that it needs a plan rather than an "
                  "enablement.")
        rec = ("- Do not add Bot Control as a quick win. The sequence is: override "
               "`SignalNonBrowserUserAgent` and `CategoryHttpLibrary` to Count before enabling "
               "anything, then integrate the AWS WAF Mobile SDK so app requests carry a valid "
               "token, then reassess\n"
               "- **Never override `TGT_TokenAbsent` to Count** if Targeted level is used — it is "
               "the foundation of the whole session-tracking mechanism\n"
               "- Consider `AWSManagedRulesATPRuleSet` on the login endpoint as the higher-value "
               "starting point instead: it tracks login success and failure rates per IP and per "
               "session rather than classifying by User-Agent, so it does not have the "
               "non-browser problem. Note its response-inspection component works only on "
               "CloudFront\n")
    else:
        client_title = ""
        client_problem = ""
        caveat = ("Whether it is worth adding depends on whether these threats apply to this "
                  "application.")
        rec = ("- If bot traffic is a concern, add `AWSManagedRulesBotControlRuleSet` at Common "
               "level **last** in the Web ACL, so cheaper rules filter traffic before the "
               "per-request charge applies\n"
               "- Override `SignalNonBrowserUserAgent` and `CategoryHttpLibrary` to Count first; "
               "both default to Block and both catch legitimate non-browser clients such as "
               "monitoring, partner integrations and payment webhooks\n"
               "- For credential stuffing specifically, `AWSManagedRulesATPRuleSet` on the login "
               "endpoint is more targeted than Bot Control\n")
    md = T["no_bot_management"].format(
        n="{n}", client_title=client_title, client_problem=client_problem,
        caveat=caveat, recommendation=rec)
    return [(md, {"severity": "Awareness", "title_key": "no_bot_management",
                  "rules": [], "sections": [5]})]


def _gen_ip_reputation_actions(summary, pre_checks, flags):
    """Sub-rule actions inside the Amazon IP reputation group against their documented defaults.

    Checklist section 7 was previously claimed fully-covered by a check that only looks at
    HostingProviderIPList, so the three sub-rules here were reviewed by neither the scripts nor
    the analysis step. Two must be Block and one must be Count, and a deviation in either
    direction is a finding.
    """
    results = []
    for r in summary.get("rules", []):
        mg = r.get("managed") or {}
        table = SUBRULE_DEFAULTS.get(mg.get("group_name", ""))
        if not table:
            continue
        actions = {o.get("rule_name"): o.get("action") for o in mg.get("overrides", [])}
        for sub, (default, why) in table.items():
            act = actions.get(sub)
            if act is None or act.lower() == default.lower():
                continue
            act_t = act.capitalize()
            if default == "Block":
                severity = "Critical" if act_t == "Allow" else "Medium"
                consequence = (
                    "Overriding it to Allow does not merely stop it blocking -- Allow is "
                    "terminating, so a matching request skips every remaining rule in the Web "
                    "ACL as well" if act_t == "Allow" else
                    "In Count it records the match and lets the request through, so the "
                    "addresses this list exists to stop reach the origin")
                fix = (f"Restore `{sub}` to its default of Block"
                       + (". There is no case for Allow on a threat-intelligence list"
                          if act_t == "Allow" else ""))
            else:
                severity = "Medium"
                consequence = ("Overriding it to Block discards a judgement AWS made "
                               "deliberately, and the false positives it causes fall on real "
                               "users whose devices were compromised rather than on attackers")
                fix = (f"Restore `{sub}` to its default of Count. If action on these addresses "
                       "is wanted, add a rate-based rule scoped down to the label "
                       f"`awswaf:managed:aws:{LABEL_NS.get(mg['group_name'], '')}:{sub}` so a "
                       "flagged address is limited rather than refused")
            md = T["ip_reputation_action"].format(
                n="{n}", severity=severity, sub_rule=sub, action=act_t, default=default,
                rule_name=r["name"], priority=r["priority"], why_default=why,
                consequence=consequence, fix=fix)
            results.append((md, {"severity": severity, "title_key": "ip_reputation_action",
                                 "rules": [r["name"]], "sections": [7]}))
    return results or NOT_APPLICABLE


def _gen_missing_ip_reputation(summary, pre_checks, flags):
    """Absence of the two address-reputation groups, which MANAGED_BASELINE_GROUPS omits.

    `_gen_missing_baseline` covers CRS and KnownBadInputs only, so a Web ACL with neither
    reputation group was never told so.
    """
    present = {(r.get("managed") or {}).get("group_name") for r in summary.get("rules", [])}
    missing = [g for g in IP_REPUTATION_BASELINE if g not in present]
    if not missing:
        return NOT_APPLICABLE
    names, details, recs = [], [], []
    for g in missing:
        label, gap, wcu = IP_REPUTATION_BASELINE[g]
        names.append(f"`{g}`")
        details.append(f"- Without the {label}, {gap}")
        recs.append(f"- Add `{g}` ({wcu} WCU) at its default actions")
    md = T["missing_ip_reputation"].format(
        n="{n}", missing_names=" and ".join(names),
        gap=("address-based filtering is absent from this Web ACL"
             if len(missing) == 2 else "part of the recommended address filtering is absent"),
        details="\n".join(details), recs="\n".join(recs))
    return [(md, {"severity": "Medium", "title_key": "missing_ip_reputation",
                  "rules": [], "sections": [7]})]


#: Evaluation windows AWS WAF actually supports for a rate-based statement.
RATE_WINDOWS = (60, 120, 300, 600)

#: Context values for `cdn` that mean a proxy rewrites the source address. Global
#: Accelerator is deliberately absent: it preserves the client IP by default on
#: internet-facing ALB endpoints, so forwarding there replaces a correct address with an
#: attacker-settable header and makes things worse.
_PROXY_FRONTS = ("cloudfront", "cdn", "akamai", "cloudflare", "fastly", "proxy",
                 "alb behind", "reverse proxy")


def _front_door(ctx):
    """(name, is_address_rewriting_proxy) for whatever the context says sits in front."""
    raw = str((ctx or {}).get("cdn") or "").lower()
    if not raw or "none" in raw and "accelerator" not in raw:
        if "accelerator" in raw:
            return "Global Accelerator", False
        return None, False
    if "accelerator" in raw:
        return "Global Accelerator", False
    for token in _PROXY_FRONTS:
        if token in raw:
            return ("CloudFront" if "cloudfront" in raw else raw.split(",")[0].strip()), True
    return raw.split(",")[0].strip(), False


def _gen_rate_forwarded_ip(summary, pre_checks, flags):
    """Rate rules aggregating on the connecting address while a proxy rewrites it.

    Gated on context: whether the source address is the client's is a fact about the
    architecture, not about the rule. Without an answer this stays silent rather than
    recommending a change that, behind Global Accelerator, would actively make things worse.
    """
    ctx = summary.get("context") or {}
    front, rewrites = _front_door(ctx)
    rate_rules = [r for r in summary.get("rules", []) if r.get("type") == "rate_based"]
    if not rate_rules:
        return NOT_APPLICABLE

    # Missing fallback behaviour is a finding whether or not a proxy is declared.
    missing_fallback = [r for r in rate_rules
                       if (r.get("rate_based") or {}).get("forwarded_ip_config")
                       and not (r["rate_based"]["forwarded_ip_config"] or {}).get(
                           "fallback_behavior")]
    if missing_fallback:
        rl = ", ".join(f"{r['name']} (priority {r['priority']})" for r in missing_fallback)
        md = T["rate_fallback_unset"].format(
            n="{n}", rule_names=" / ".join(r["name"] for r in missing_fallback),
            rule_line=rl,
            detail="; ".join(
                f"`{r['name']}` forwards on "
                + f"`{(r['rate_based']['forwarded_ip_config'] or {}).get('header_name', '?')}` "
                + "with no FallbackBehavior" for r in missing_fallback))
        return [(md, {"severity": "Medium", "title_key": "rate_fallback_unset",
                      "rules": [r["name"] for r in missing_fallback], "sections": [6]})]

    if not front or not rewrites:
        return NOT_APPLICABLE
    wrong = [r for r in rate_rules
             if (r.get("rate_based") or {}).get("aggregate_key_type", "IP") == "IP"
             and not (r.get("rate_based") or {}).get("forwarded_ip_config")]
    if not wrong:
        return NOT_APPLICABLE
    detail = "; ".join(
        f"`{r['name']}` aggregates on IP, limit {(r['rate_based'].get('limit') or '?')} "
        + f"per {(r['rate_based'].get('evaluation_window_sec') or '?')}s"
        for r in wrong)
    md = T["rate_forwarded_ip"].format(
        n="{n}", severity="Critical" if len(wrong) > 1 else "Medium",
        rule_names=" / ".join(r["name"] for r in wrong),
        rule_line=", ".join(f"{r['name']} (priority {r['priority']})" for r in wrong),
        front=front, detail=detail, fallback_note="",
        ga_note="")
    return [(md, {"severity": "Critical" if len(wrong) > 1 else "Medium",
                  "title_key": "rate_forwarded_ip",
                  "rules": [r["name"] for r in wrong], "sections": [6]})]


def _gen_rate_window(summary, pre_checks, flags):
    bad = [r for r in summary.get("rules", []) if r.get("type") == "rate_based"
           and isinstance((r.get("rate_based") or {}).get("evaluation_window_sec"), int)
           and r["rate_based"]["evaluation_window_sec"] not in RATE_WINDOWS]
    if not bad:
        return NOT_APPLICABLE
    md = T["rate_window_out_of_range"].format(
        n="{n}", rule_names=" / ".join(r["name"] for r in bad),
        rule_line=", ".join(f"{r['name']} (priority {r['priority']})" for r in bad),
        detail="; ".join(f"`{r['name']}` window is "
                         + f"{r['rate_based']['evaluation_window_sec']}s" for r in bad))
    return [(md, {"severity": "Medium", "title_key": "rate_window_out_of_range",
                  "rules": [r["name"] for r in bad], "sections": [6]})]


def _gen_rate_shared_ip_keys(summary, pre_checks, flags):
    """IP-only aggregation where the declared clients are known to share addresses.

    Context-gated on `client_types`, because whether addresses are shared is a fact about
    the client population. A mobile app population sits behind carrier NAT; a
    server-to-server caller does not, and neither conclusion is visible in the config.
    """
    ctx = summary.get("context") or {}
    clients = ctx_list(ctx, "client_types")
    shared = [c for c in clients if any(k in c for k in ("mobile", "native", "app"))]
    if not shared:
        return NOT_APPLICABLE
    plain = [r for r in summary.get("rules", []) if r.get("type") == "rate_based"
             and (r.get("rate_based") or {}).get("aggregate_key_type", "IP") == "IP"
             and not (r.get("rate_based") or {}).get("custom_keys")]
    if not plain:
        return NOT_APPLICABLE
    md = T["rate_shared_ip_keys"].format(
        n="{n}", rule_names=" / ".join(r["name"] for r in plain),
        rule_line=", ".join(f"{r['name']} (priority {r['priority']})" for r in plain),
        key="IP", client_note=f". Declared client types: {', '.join(clients)}",
        why_shared=("The declared clients are mobile apps, which reach the service through "
                    "carrier NAT — thousands of subscribers can share one address, and one "
                    "subscriber can move between addresses mid-session"))
    return [(md, {"severity": "Awareness", "title_key": "rate_shared_ip_keys",
                  "rules": [r["name"] for r in plain], "sections": [6]})]


#: Labels a reputation-scoped rate rule would key on, to recognise the third tier.
_REPUTATION_LABEL_HINTS = ("amazon-ip-list", "anonymous-ip-list", "ip-reputation",
                           "reconnaissance", "ddos-list", "hostingprovider")


def _rate_tier(rule):
    """Which of the three recommended tiers a rate-based rule belongs to.

    Read from the scope-down shape, because that is what actually decides which traffic the
    rule counts: no scope-down is a blanket rule, a URI condition makes it endpoint-specific,
    and a reputation label or IP set makes it threat-intelligence-scoped.
    """
    sd = rule.get("scope_down") or {}
    summary = (sd.get("summary") or "").lower()
    if not summary:
        return "blanket"
    if any(h in summary for h in _REPUTATION_LABEL_HINTS):
        return "reputation"
    if "ip_set" in summary or "geo_match" in summary:
        return "reputation"
    if "uri_path" in summary or "single_header" in summary or "query_string" in summary:
        return "uri"
    return "other"


_TIER_LABEL = {
    "blanket": ("a blanket rule across all endpoints",
                "Add a blanket rate-based rule with no scope-down, aggregating on the source "
                "the architecture makes correct, at a threshold derived from the traffic "
                "baseline. This is the floor against volumetric abuse"),
    "uri": ("a URI-specific rule on sensitive endpoints",
            "Add a rate-based rule scoped down to the sensitive endpoints — login, search, "
            "password reset, token issuance — with a threshold an order of magnitude lower "
            "than the blanket rule. Ten to fifty requests per five minutes per source is a "
            "defensible starting point for a login endpoint"),
    "reputation": ("a reputation-scoped rule on known-malicious sources",
                   "Add a rate-based rule scoped down to the label from "
                   "`AWSManagedRulesAmazonIpReputationList` (or an IP set of known offenders) "
                   "with the lowest threshold of the three. Some operators block these "
                   "outright; rate-limiting is the conservative equivalent"),
}


def _gen_rate_layers(summary, pre_checks, flags):
    """Which of the three recommended rate-limiting tiers are absent.

    Reports absence, which nothing did before -- every existing rate check evaluates rules
    that are present. Caveated where opaque customer rule groups could contain the missing
    tiers, because asserting a gap that might be filled inside a black box would be wrong.
    """
    rules = summary.get("rules", [])
    rate_rules = [r for r in rules if r.get("type") == "rate_based"]
    tiers = {_rate_tier(r) for r in rate_rules}
    missing = [t for t in ("blanket", "uri", "reputation") if t not in tiers]
    if not missing:
        return NOT_APPLICABLE

    opaque = [r for r in rules
              if (r.get("statement") or {}).get("summary", "").startswith("rule_group ")
              and "ShieldMitigation" not in (r.get("statement") or {}).get("summary", "")]
    opaque_note = ""
    severity = "Medium" if len(missing) < 3 else "Critical"
    if opaque:
        opaque_note = (f"- **{len(opaque)} customer rule groups are referenced by ARN only**, and "
                       "any of the missing tiers could be inside them. Retrieve them with "
                       "`get-rule-group` before treating this as a confirmed gap -- their names "
                       "suggest rate limiting, which is exactly what would fill it\n")
        severity = "Awareness"        # cannot assert a gap that a black box may already fill

    have = sorted(t for t in tiers if t in _TIER_LABEL)
    have_desc = (", ".join(_TIER_LABEL[t][0] for t in have) + " present"
                 if have else "no tier is clearly present")
    detail = ("; ".join(f"`{r['name']}` (priority {r['priority']}) is "
                        + f"{_TIER_LABEL.get(_rate_tier(r), ('unclassified',))[0]}"
                        for r in rate_rules)
              or "No rate-based rules in this Web ACL")
    md = T["rate_layers_missing"].format(
        n="{n}", severity=severity, have_desc=have_desc,
        rule_line=(", ".join(f"{r['name']} (priority {r['priority']})" for r in rate_rules)
                   or "N/A (missing rule)"),
        detail=detail,
        missing_detail="".join(f"- **Missing: {_TIER_LABEL[t][0]}.**\n" for t in missing),
        opaque_note=opaque_note,
        recs="\n".join(f"- {_TIER_LABEL[t][1]}" for t in missing))
    return [(md, {"severity": severity, "title_key": "rate_layers_missing",
                  "rules": [r["name"] for r in rate_rules], "sections": [6]})]


def _gen_rate_threshold_vs_baseline(summary, pre_checks, flags):
    """The blanket threshold against the declared traffic baseline, AWS's actual method.

    Replaces guesswork with arithmetic where the operator has supplied a peak. Gated on
    `traffic_profile`: without it the only alternative is the flat heuristic in
    `_gen_rate_rule_ineffective`, which cannot tell a busy application from a misconfigured one.
    """
    ctx = summary.get("context") or {}
    tp = ctx.get("traffic_profile") or {}
    if not isinstance(tp, dict):
        return NOT_APPLICABLE
    peak_rps = tp.get("peak_rps_per_ip") or tp.get("peak_rps")
    per_ip = "peak_rps_per_ip" in tp
    if not isinstance(peak_rps, (int, float)) or peak_rps <= 0:
        return NOT_APPLICABLE

    blanket = [r for r in summary.get("rules", [])
               if r.get("type") == "rate_based" and _rate_tier(r) == "blanket"
               and isinstance((r.get("rate_based") or {}).get("limit"), int)]
    if not blanket:
        return NOT_APPLICABLE
    r = blanket[0]
    win = (r["rate_based"].get("evaluation_window_sec") or 300)
    limit = r["rate_based"]["limit"]
    peak_per_window = peak_rps * win
    lo, hi = int(peak_per_window * 1.5), int(peak_per_window * 2.0)
    if lo <= limit <= hi:
        return NOT_APPLICABLE

    if limit > hi:
        verdict, severity = "far above", "Medium"
        problem = (f"- The configured threshold is **{limit:,} per {win}s**, "
                   f"{limit / peak_per_window:.1f}x the declared peak rather than the 1.5–2x the "
                   "method calls for. A threshold that high is not reached by an attacker who "
                   "stays below it, which is what an attacker who has read the config will do\n")
        fix = (f"Lower the threshold into the {lo:,}–{hi:,} range. Deploy in Count first and "
               "confirm the metric stays at zero under normal traffic before switching to Block")
    else:
        verdict, severity = "below", "Critical"
        problem = (f"- The configured threshold is **{limit:,} per {win}s**, which is *below* the "
                   f"declared peak of {peak_per_window:,.0f} per {win}s. Legitimate traffic at "
                   "its normal high-water mark will breach this rule and be blocked\n")
        fix = (f"Raise the threshold to at least {lo:,} per {win}s. Until then this rule is an "
               "availability risk rather than a protection, and it should be switched to Count "
               "immediately if it is currently enforcing")
    if not per_ip:
        problem += ("- The declared figure is `peak_rps`, which does not state whether it is per "
                    "source or aggregate. If aggregate, the per-source peak is far lower and the "
                    "recommended range narrows accordingly — confirm before applying\n")
    md = T["rate_threshold_vs_baseline"].format(
        n="{n}", severity=severity, rule_names=r["name"], verdict=verdict,
        rule_line=f"{r['name']} (priority {r['priority']})",
        detail=f"Limit {limit:,} per {win}s, aggregating on "
               f"{r['rate_based'].get('aggregate_key_type', 'IP')}",
        peak_desc=(f"{peak_rps:g} requests/second per source" if per_ip
                   else f"{peak_rps:g} requests/second (per-source status unstated)"),
        lo=lo, hi=hi, window=win, problem=problem, fix=fix)
    return [(md, {"severity": severity, "title_key": "rate_threshold_vs_baseline",
                  "rules": [r["name"]], "sections": [6]})]


#: Managed groups whose documented matching condition is "All requests", so a scope-down on
#: them is a narrowing of baseline protection rather than a tuning decision.
ALL_REQUESTS_GROUPS = {
    "AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesAnonymousIpList",
    "AWSManagedRulesSQLiRuleSet",
}


def _gen_managed_scope_down(summary, pre_checks, flags):
    """A scope-down on a managed group whose recommended match scope is All requests.

    `_gen_scope_down_too_narrow` only fires on the single shape `uri_path EXACTLY '/'` and only
    for two group names, so a scope-down on the Core rule set passed silently. Anti-DDoS is
    excluded: a scope-down there is wrong at any width because it degrades the traffic baseline
    the detection depends on, which is a different finding.
    """
    scoped = []
    for r in summary.get("rules", []):
        gn = (r.get("managed") or {}).get("group_name", "")
        if gn not in ALL_REQUESTS_GROUPS:
            continue
        sd = r.get("scope_down") or {}
        if not sd.get("summary"):
            continue
        scoped.append((r, gn, sd["summary"]))
    if not scoped:
        return NOT_APPLICABLE
    core = [x for x in scoped if x[1] in CORE_GROUPS]
    core_note = ""
    if core:
        core_note = ("- " + ", ".join(f"`{gn}`" for _r, gn, _sd in core)
                     + " is a baseline group: it is the broadest protection in the Web ACL and "
                       "the one where a narrowed scope costs the most coverage\n")
    md = T["managed_scope_down"].format(
        n="{n}", severity="Medium" if core else "Low",
        rule_names=" / ".join(r["name"] for r, _g, _s in scoped),
        rule_line=", ".join(f"{r['name']} (priority {r['priority']})" for r, _g, _s in scoped),
        detail="; ".join(f"`{r['name']}` scope-down: {sd[:120]}" for r, _g, sd in scoped),
        core_note=core_note)
    return [(md, {"severity": "Medium" if core else "Low",
                  "title_key": "managed_scope_down",
                  "rules": [r["name"] for r, _g, _s in scoped], "sections": [2]})]


def _gen_antiddos_position(summary, pre_checks, flags):
    """What precedes the Anti-DDoS AMR, against AWS's explicit guidance on its placement.

    A dedicated finding rather than one bullet inside the general ordering list, because it is
    the only tier whose *effectiveness* depends on what runs before it -- every other position
    is a cost or efficiency question -- and because the permitted exception is narrow enough to
    state exactly: Allow rules, and nothing else terminating.
    """
    rules = sorted(summary.get("rules", []), key=lambda r: r.get("priority") or 0)
    amr = next((r for r in rules
                if "AntiDDoS" in (r.get("managed") or {}).get("group_name", "")), None)
    if amr is None:
        return NOT_APPLICABLE           # CHECK on absence is _gen_missing_baseline's job

    above = [r for r in rules if (r.get("priority") or 0) < (amr.get("priority") or 0)]
    offenders = []
    for r in above:
        tier = _classify_rule_type(r)
        if tier in ("allow_rule", "label_producer"):
            continue                    # sanctioned, or non-terminating and therefore harmless
        if tier in UNORDERED_TIERS:
            continue
        offenders.append((r, tier))
    if not offenders:
        return NOT_APPLICABLE

    terminating = [(r, t) for r, t in offenders if r.get("action") in ("allow", "block")]
    severity = "Medium" if terminating else "Low"
    allows_above = [r for r in above if _classify_rule_type(r) == "allow_rule"]
    if allows_above:
        target = min(r.get("priority") or 0 for r in allows_above)
        target_desc = (f"directly below the Allow rule(s) at priority {target} — "
                       "that is the placement AWS sanctions")
        allow_note = (f"The Allow rule(s) at priority {target} may stay above it: those are the "
                      "explicit exception in AWS's guidance, and moving them below would defeat "
                      "the allowlist")
    else:
        target_desc = ("**1** — the highest priority in the web ACL, since there are no `Allow` "
                       "rules to sit below")
        allow_note = ("There are no `Allow` rules in this web ACL, so the AMR belongs at the very "
                      "top with nothing above it")
    tier_names = dict(RECOMMENDED_ORDER)
    md = T["antiddos_position"].format(
        n="{n}", severity=severity, rule_name=amr["name"], priority=amr["priority"],
        count=_plural(len(offenders), "rule"),
        detail=(f"The rule group is at priority {amr['priority']} of "
                f"{summary.get('rule_count')} rules, with {len(above)} rule(s) above it, "
                f"{len(offenders)} of which are not `Allow` rules"),
        offenders="".join(
            f"  - `{r['name']}` (priority {r['priority']}, action **{r.get('action')}**) — "
            + f"{tier_names.get(t, t)}\n" for r, t in offenders[:6]),
        target_desc=target_desc, allow_note=allow_note)
    return [(md, {"severity": severity, "title_key": "antiddos_position",
                  "rules": [amr["name"]] + [r["name"] for r, _t in offenders[:4]],
                  "sections": [18]})]


ALL_GENERATORS = [
    # (function, covered_sections, fully_covers_sections)
    (_gen_forgeable_allow, [1], True),
    (_gen_managed_allow_override, [1], True),
    (_gen_duplicate_branches, [1], False),      # a dead branch is not only an Allow issue
    (_gen_single_address_family, [1], False),
    (_gen_terminating_allow_strands, [1], False),
    (_gen_name_action_mismatch, [1], False),
    (_gen_group_level_count, [3], True),
    (_gen_managed_count_overrides, [2], True),
    (_gen_managed_scope_down, [2], False),
    (_gen_rate_rule_ineffective, [6], True),
    (_gen_rate_forwarded_ip, [6], False),
    (_gen_rate_window, [6], False),
    (_gen_rate_shared_ip_keys, [6], False),
    (_gen_rate_layers, [6], False),
    (_gen_rate_threshold_vs_baseline, [6], False),
    (_gen_geo_vs_markets, [7], False),   # geo is not section 7's subject
    (_gen_opaque_rule_groups, [10], True),
    (_gen_no_bot_management, [5], False),
    (_gen_scope_down_too_narrow, [2], True),
    (_gen_challenge_all_during_event, [3], True),
    (_gen_unanchored_exempt_regex, [3], True),
    (_gen_missing_crawler_labeling, [3], True),
    (_gen_challenge_on_post_api, [4], True),
    (_gen_bot_control_search_allow, [5], False),  # Section 5 is always-LLM
    (_gen_duplicate_rules, [6], True),
    (_gen_hosting_provider_allow, [7], False),
    (_gen_ip_reputation_actions, [7], False),
    (_gen_missing_ip_reputation, [7], False),
    (_gen_missing_baseline, [9], True),
    (_gen_token_domain, [11], True),
    (_gen_managed_versions, [12], True),
    (_gen_no_logging, [13], True),
    (_gen_opaque_search_string, [14], True),
    (_gen_default_action_redundancy, [15], True),
    (_gen_missing_always_on_challenge, [16], True),
    (_gen_count_without_labels, [17], True),  # Covers 17a only; 17 is always-LLM
    (_gen_orphan_managed_label, [17], False),
    (_gen_challenge_readiness, [11], False),
    (_gen_antiddos_position, [18], False),
    (_gen_priority_order, [18], True),
]

def _stage_findings(summary: dict, pre_checks_data: dict, output_dir: str) -> dict:
    """Run all generators, write scripted-findings.md + findings-metadata.json."""
    pre_checks = pre_checks_data.get("pre_checks", {})
    flags = pre_checks_data.get("flags", {})

    all_findings = []                       # (md_template, metadata)
    section_outcomes = defaultdict(list)    # section -> [(outcome_type, fully_covers)]

    for gen_func, sections, fully_covers in ALL_GENERATORS:
        result = gen_func(summary, pre_checks, flags)
        if result == NOT_APPLICABLE:
            for s in sections:
                section_outcomes[s].append(("not_applicable", fully_covers))
        elif result == AMBIGUOUS:
            for s in sections:
                section_outcomes[s].append(("ambiguous", fully_covers))
        else:
            for md, meta in result:
                all_findings.append((md, meta))
            for s in sections:
                section_outcomes[s].append(("finding", fully_covers))

    # Sort by severity then by first rule priority
    def sort_key(item):
        _md, meta = item
        sev = SEVERITY_ORDER.get(meta["severity"], 99)
        min_pri = 999
        for r in summary.get("rules", []):
            if r["name"] in meta.get("rules", []):
                min_pri = min(min_pri, r["priority"])
        return (sev, min_pri)

    all_findings.sort(key=sort_key)

    # Assign issue numbers
    findings_md = []
    scripted_issues = []
    issue_rule_mapping = {}

    for i, (md_template, meta) in enumerate(all_findings, 1):
        md = md_template.replace("{n}", str(i))
        findings_md.append(md)
        first_line = md.strip().split("\n")[0]
        title = first_line.split("): ", 1)[1] if "): " in first_line else first_line
        scripted_issues.append({
            "number": i,
            "severity": meta["severity"],
            "title": title.strip(),
            "rules": meta.get("rules", []),
            "checklist_sections": meta.get("sections", []),
        })
        for rule_name in meta.get("rules", []):
            if rule_name in issue_rule_mapping:
                issue_rule_mapping[rule_name] += f", #{i}"
            else:
                issue_rule_mapping[rule_name] = f"\u26a0\ufe0f Issue #{i}"

    # Compute llm_sections
    llm_sections = sorted(ALWAYS_LLM_SECTIONS)
    for s in range(1, 19):
        if s in ALWAYS_LLM_SECTIONS or s in APPENDIX_ONLY_SECTIONS:
            continue
        outcomes = section_outcomes.get(s, [])
        if not outcomes:
            llm_sections.append(s)          # no generator covers this section
            continue
        if any(otype == "ambiguous" and fc for otype, fc in outcomes):
            llm_sections.append(s)          # a fully-covering generator gave up
            continue
        if not [(otype, fc) for otype, fc in outcomes if fc]:
            llm_sections.append(s)          # only partial generators registered
    llm_sections = sorted(set(llm_sections))

    rules = summary.get("rules", [])
    llm_context = {
        "ua_allow_found": any(
            "user-agent" in " ".join(a.get("forgeable_conditions", []))
            for a in flags.get("allow_rules", [])),
        "has_antiddos_amr": any(
            "AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules),
        "has_bot_control": any(
            "BotControl" in r.get("managed", {}).get("group_name", "") for r in rules),
        "has_always_on_challenge": any(
            r.get("action") == "challenge" and r.get("type") == "custom" and
            "label_match" in r.get("statement", {}).get("summary", "")
            for r in rules),
        "has_crawler_labeling_rule": any(
            any(lbl.startswith(p) for p in CRAWLER_LABEL_PATTERNS)
            for r in rules for lbl in r.get("rule_labels", [])),
    }

    findings_path = os.path.join(output_dir, "scripted-findings.md")
    Path(findings_path).write_text("".join(findings_md), encoding="utf-8")

    # Every gating question nobody has answered yet, with what it would settle. This is
    # the list the agent turns into a picker before re-running; an unanswered question is
    # reduced coverage rather than a default, so it has to be visible.
    ctx = summary.get("context") or {}
    context_questions = [
        {"field": field, "question": question, "unblocks": unblocks}
        for field, question, unblocks in CONTEXT_QUESTIONS
        if not ctx_declared(ctx, field)
    ]

    metadata = {
        "scripted_count": len(all_findings),
        "scripted_issues": scripted_issues,
        "issue_rule_mapping": issue_rule_mapping,
        "llm_sections": llm_sections,
        "llm_context": llm_context,
        "context_supplied": sorted(k for k in ctx
                                  if not k.startswith("_") and ctx[k] is not None),
        "context_questions": context_questions,
        "next_issue_number": len(all_findings) + 1,
    }
    Path(os.path.join(output_dir, "findings-metadata.json")).write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Generated {len(all_findings)} scripted findings, "
          f"LLM sections: {llm_sections}", file=sys.stderr)
    return metadata


# ════════════════════════════════════
# MAIN
# ════════════════════════════════════

def main():
    args = [a for a in sys.argv[1:]]
    context = None
    if "--context" in args:
        i = args.index("--context")
        if i + 1 >= len(args):
            fatal("--context requires a file path")
        path = args[i + 1]
        try:
            context = json.loads(Path(path).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            fatal(f"Failed to read context file {path}: {e}")
        if not isinstance(context, dict):
            fatal(f"Context file {path} must contain a JSON object")
        del args[i:i + 2]

    if len(args) < 2:
        fatal("Usage: waf-assess.py <input_path> <output_dir> [--context <context.json>]")

    input_path, output_dir = args[0], args[1]

    summary, input_file = _stage_normalize(input_path, output_dir, context)
    _done.append("normalize")

    pre_checks_data = _stage_pre_checks(summary, output_dir)
    _done.append("pre-checks")

    metadata = _stage_findings(summary, pre_checks_data, output_dir)
    _done.append("findings")

    failed = sum(1 for v in pre_checks_data["pre_checks"].values()
                 if v["status"] == "FAIL")
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"STAGES_OK: {','.join(_done)}")
    print(f"INPUT_FILE: {input_file}")
    print(f"OUTPUT_DIR: {output_dir}")
    print(f"RULE_COUNT: {summary['rule_count']}")
    print(f"CHECKS_FAILED: {failed}")
    print(f"SCRIPTED_COUNT: {metadata['scripted_count']}")
    print(f"LLM_SECTIONS: {','.join(str(s) for s in metadata['llm_sections'])}")
    print(f"NEXT_ISSUE_NUMBER: {metadata['next_issue_number']}")
    print(f"CONTEXT_SUPPLIED: {','.join(metadata['context_supplied']) or 'none'}")
    print(f"CONTEXT_QUESTIONS: {len(metadata['context_questions'])}")
    mism = (summary.get("context") or {}).get("_arn_mismatch")
    if mism:
        print("CONTEXT_ARN_MISMATCH: yes — context was gathered against "
              f"{mism['gathered_against']}, assessed {mism['assessed']}")
    for q in metadata["context_questions"]:
        print(f"  [{q['field']}] {q['question']}", file=sys.stderr)


if __name__ == "__main__":
    main()
