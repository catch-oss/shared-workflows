#!/usr/bin/env python3
"""Render the central exception register into scanner-specific policy files.

Exceptions live in `exceptions.yml` in this directory — never in the target
repository — so suppressing a finding always takes a reviewed pull request
against catch-oss/shared-workflows by someone other than the author of
the change that introduced it.

Two files come out of this:

* a Grype configuration. Passing it explicitly also disables Grype's
  auto-discovery of a target-repository `.grype.yaml`, so a pull request
  cannot weaken the vulnerability gate from inside the repository it gates.
* an end-of-life ignore list consumed by `eol_scan.py`.

Both are written unconditionally. An empty policy is what locks the target
repository out of supplying its own.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - runners ship PyYAML, mirrors do not
    print("::error::PyYAML is required to render the exception register")
    raise

# Grype ignore-rule keys. Anything else in a rule is documentation for humans
# and is stripped before the config reaches the scanner.
GRYPE_RULE_KEYS = {
    "vulnerability", "reason", "namespace", "fix-state", "package", "vex-status",
}
# Six months, matching the policy this repository has always documented.
MAX_EXCEPTION_HORIZON_DAYS = 183


class PolicyError(Exception):
    """A malformed or lapsed exception register."""


def parse_expiry(value: object, where: str, today: date) -> date:
    if not isinstance(value, str):
        raise PolicyError(f"{where}: `expires` is required (YYYY-MM-DD)")
    try:
        expires = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        raise PolicyError(f"{where}: `expires` is not YYYY-MM-DD: {value}") from None
    if (expires - today).days > MAX_EXCEPTION_HORIZON_DAYS:
        raise PolicyError(
            f"{where}: `expires` is {value}, more than six months out. "
            "Exceptions are meant to be re-reviewed, not parked."
        )
    return expires


def validate_rules(rules: object, where: str, required: tuple[str, ...]) -> list[dict]:
    if not isinstance(rules, list) or not rules:
        raise PolicyError(f"{where}: `ignore` must be a non-empty list")
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PolicyError(f"{where}: ignore[{index}] must be a mapping")
        if not str(rule.get("reason") or "").strip():
            raise PolicyError(
                f"{where}: ignore[{index}] has no `reason`. Record why the finding "
                "is not actionable — \"no fixed version exists\", \"not reachable "
                "because X\" — not that it is noisy."
            )
        if not any(rule.get(key) for key in required):
            raise PolicyError(
                f"{where}: ignore[{index}] must set one of {', '.join(required)}"
            )
    return rules


def load_register(path: Path) -> dict:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise PolicyError(f"{path.name}: top level must be a mapping")
    return data


def section_for(register: dict, repository: str, kind: str) -> dict:
    repositories = register.get("repositories") or {}
    entry = repositories.get(repository) or {}
    section = entry.get(kind) or {}
    if not isinstance(section, dict):
        raise PolicyError(f"{repository}.{kind}: must be a mapping")
    return section


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--register", required=True)
    parser.add_argument("--grype-out", required=True)
    parser.add_argument("--eol-out", required=True)
    parser.add_argument("--summary-out", default="")
    parser.add_argument("--on-expired", choices=("fail", "warn"), default="fail")
    args = parser.parse_args()

    today = datetime.now(timezone.utc).date()
    register = load_register(Path(args.register))

    grype_policy: dict = {}
    eol_policy: dict = {}
    active: list[str] = []
    expired: list[str] = []

    for kind, out_path, required in (
        ("vulnerabilities", args.grype_out, ("vulnerability", "package")),
        ("end-of-life", args.eol_out, ("product",)),
    ):
        section = section_for(register, args.repository, kind)
        policy: dict = {}
        if section:
            where = f"{args.repository}.{kind}"
            expires = parse_expiry(section.get("expires"), where, today)
            rules = validate_rules(section.get("ignore"), where, required)
            if expires < today:
                expired.append(f"{kind} (expired {expires.isoformat()})")
            else:
                active.append(f"{kind} (expires {expires.isoformat()})")
                if kind == "vulnerabilities":
                    policy = {"ignore": [
                        {k: v for k, v in rule.items() if k in GRYPE_RULE_KEYS}
                        for rule in rules
                    ]}
                else:
                    policy = {"ignore": rules}
        if kind == "vulnerabilities":
            Path(out_path).write_text(yaml.safe_dump(policy, sort_keys=False, width=100)
                                      if policy else "{}\n", encoding="utf-8")
            grype_policy = policy
        else:
            Path(out_path).write_text(json.dumps(policy or {}, indent=2) + "\n",
                                      encoding="utf-8")
            eol_policy = policy

    if expired:
        message = (
            f"Exceptions for {args.repository} have lapsed: {'; '.join(expired)}. "
            "Re-review them in catch-oss/shared-workflows and either remove "
            "or renew them."
        )
        if args.on_expired == "fail":
            print(f"::error::{message}")
            return 1
        print(f"::warning::{message}")

    if active:
        print(f"::warning::{args.repository} has active security exceptions: "
              f"{'; '.join(active)}. See the job summary.")

    if args.summary_out and (active or expired):
        lines = ["### Active security exceptions", "",
                 f"Repository `{args.repository}` is suppressing findings below the gates.",
                 ""]
        for note in expired:
            lines.append(f"- **Lapsed:** {note} — the gate fails until this is re-reviewed.")
        for note in active:
            lines.append(f"- Active: {note}.")
        for title, policy in (("Vulnerabilities", grype_policy), ("End of life", eol_policy)):
            if policy:
                lines += ["", f"**{title}**", "", "```yaml",
                          yaml.safe_dump(policy, sort_keys=False, width=100).rstrip(), "```"]
        with open(args.summary_out, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    print(f"exceptions-active={'true' if active else 'false'}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PolicyError as error:
        print(f"::error::exceptions.yml is invalid — {error}")
        sys.exit(2)
