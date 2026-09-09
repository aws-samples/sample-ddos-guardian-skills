"""Copy real get-web-acl exports into tests/fixtures with the account ID redacted.

Run once after `aws wafv2 get-web-acl ... > exports/<name>.json`:
    python3 tests/make_real_fixtures.py /path/to/exports
"""
import json
import pathlib
import sys

REDACT = {"638769857148": "111122223333"}
MAP = [
    ("real-amr-noconfigs", "amr-count-no-configs.json"),
    ("real-amr-exempt", "amr-exempt-regex-unanchored.json"),
    ("real-fms", "fms-real-preprocess-crs.json"),
]


def main(src_dir: str) -> None:
    src = pathlib.Path(src_dir)
    dst = pathlib.Path(__file__).resolve().parent / "fixtures"
    for name, out in MAP:
        text = src.joinpath(name + ".json").read_text(encoding="utf-8")
        for real, fake in REDACT.items():
            text = text.replace(real, fake)
        data = json.loads(text)
        data.pop("LockToken", None)
        data.pop("ApplicationIntegrationURL", None)
        data["_source"] = ("real `aws wafv2 get-web-acl` export, REGIONAL us-east-1, 2026-09-09; "
                           "account ID redacted, LockToken removed")
        dst.joinpath(out).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        acl = data["WebACL"]
        print(out, "rules", len(acl.get("Rules", [])),
              "pre", len(acl.get("PreProcessFirewallManagerRuleGroups", [])))


if __name__ == "__main__":
    main(sys.argv[1])
