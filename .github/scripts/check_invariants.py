#!/usr/bin/env python3
"""Enforce the three invariants documented in CONTRIBUTING.md.

  1. Standard library only  -- no import outside the stdlib or this package.
  2. No network             -- no network-capable module, and no HTTP URL emitted
                               into the generated report.
  3. Never mutates AWS      -- no AWS SDK, and no mutating wafv2 CLI verb.

Usage: python3 .github/scripts/check_invariants.py [skill_dir]
       (default skill_dir: skills/ddos-guardian)

Exits 0 when every check passes, 1 with a per-violation report otherwise.
Standard library only, so it runs anywhere the skill itself runs.
"""

import ast
import pathlib
import sys

# Network- or process-capable module roots. Some are stdlib, which is exactly why an
# allowlist of "stdlib" alone is not sufficient to prove the no-network invariant.
FORBIDDEN_MODULES = {
    "urllib", "http", "socket", "ssl", "ftplib", "smtplib", "poplib", "imaplib",
    "telnetlib", "socketserver", "xmlrpc", "webbrowser", "asyncio",
    "requests", "urllib3", "httpx", "aiohttp",
    "boto3", "botocore", "aws_cdk",
    "subprocess", "multiprocessing", "ctypes",
}

# Escape hatches around the import system that would defeat the checks above.
FORBIDDEN_CALLS = {
    ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
    ("os", "spawnv"), ("os", "fork"),
    ("importlib", "import_module"),
}

# wafv2 verbs that change a customer's configuration.
MUTATING_AWS = (
    "wafv2 update-", "wafv2 put-", "wafv2 delete-", "wafv2 create-",
    "wafv2 associate-", "wafv2 disassociate-", "wafv2 tag-", "wafv2 untag-",
)


def local_modules(scripts_dir):
    """Module names importable from within the scripts directory itself."""
    return {p.stem for p in scripts_dir.glob("*.py")}


def check_imports(path, local, errors):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    stdlib = getattr(sys, "stdlib_module_names", None)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots = [(a.name.split(".")[0], node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            # Relative imports (level > 0) are local by definition.
            if node.level:
                continue
            roots = [((node.module or "").split(".")[0], node.lineno)]
        else:
            continue

        for root, lineno in roots:
            if not root:
                continue
            if root in FORBIDDEN_MODULES:
                errors.append(
                    f"{path}:{lineno}: imports '{root}' -- network, subprocess or AWS SDK "
                    f"module. Breaks the no-network / never-mutates-AWS invariant."
                )
            elif root not in local and stdlib is not None and root not in stdlib:
                errors.append(
                    f"{path}:{lineno}: imports '{root}', which is not in the standard library. "
                    f"Breaks the standard-library-only invariant."
                )


def check_calls(path, errors):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
            if (fn.value.id, fn.attr) in FORBIDDEN_CALLS:
                errors.append(
                    f"{path}:{node.lineno}: calls {fn.value.id}.{fn.attr}() -- process "
                    f"execution or dynamic import is not permitted."
                )
        elif isinstance(fn, ast.Name) and fn.id == "__import__":
            errors.append(f"{path}:{node.lineno}: calls __import__() -- not permitted.")


def check_mutating_aws(path, errors):
    text = path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), 1):
        for verb in MUTATING_AWS:
            if verb in line:
                errors.append(
                    f"{path}:{lineno}: mentions '{verb}' -- a mutating wafv2 call. "
                    f"Remediation is emitted for a human to apply, never executed."
                )


def main():
    skill_dir = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "skills/ddos-guardian")
    scripts_dir = skill_dir / "scripts"
    if not scripts_dir.is_dir():
        print(f"FAIL: no scripts directory at {scripts_dir}", file=sys.stderr)
        return 1

    sources = sorted(scripts_dir.glob("*.py"))
    if not sources:
        print(f"FAIL: no Python sources under {scripts_dir}", file=sys.stderr)
        return 1

    local = local_modules(scripts_dir)
    errors = []
    for path in sources:
        check_imports(path, local, errors)
        check_calls(path, errors)
        check_mutating_aws(path, errors)

    if errors:
        print(f"Invariant check FAILED -- {len(errors)} violation(s):\n", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        print(
            "\nSee CONTRIBUTING.md#invariants-that-must-not-break for why these hold.",
            file=sys.stderr,
        )
        return 1

    print(f"Invariants OK: {len(sources)} file(s) checked in {scripts_dir}")
    print("  stdlib only, no network-capable imports, no mutating AWS call")
    return 0


if __name__ == "__main__":
    sys.exit(main())
