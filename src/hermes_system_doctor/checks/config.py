from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..models import CheckResult, Finding
from .discovery import profile_dirs

SECRET_KEY_PARTS = ("key", "token", "secret", "password", "passwd", "auth")


def _safe_keys(data: Any) -> Any:
    if isinstance(data, dict):
        safe: dict[str, Any] = {}
        for key, value in data.items():
            key_s = str(key)
            if any(part in key_s.lower() for part in SECRET_KEY_PARTS):
                safe[key_s] = "[REDACTED]"
            elif isinstance(value, dict):
                safe[key_s] = _safe_keys(value)
            else:
                safe[key_s] = type(value).__name__
        return safe
    return type(data).__name__


def config_check(hermes_home: Path) -> CheckResult:
    findings: list[Finding] = []
    facts: dict[str, Any] = {"profiles": {}}
    profiles = profile_dirs(hermes_home)
    if not hermes_home.exists():
        return CheckResult("config", "FAIL", "Hermes home missing", [], facts)

    for name, path in profiles:
        config_path = path / "config.yaml"
        profile_fact: dict[str, Any] = {"config_exists": config_path.exists()}
        if not config_path.exists():
            findings.append(
                Finding(
                    id="config.missing",
                    severity="WARN",
                    component="config",
                    profile=name,
                    summary="Profile config.yaml is missing",
                    evidence=[name],
                    risk="The profile may be incomplete or stale.",
                    next_action=f"Run hermes --profile {name} config path to verify the profile.",
                )
            )
            facts["profiles"][name] = profile_fact
            continue
        try:
            parsed = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            profile_fact["parse_ok"] = True
            profile_fact["top_level_keys"] = sorted(str(k) for k in parsed) if isinstance(parsed, dict) else []
            profile_fact["value_shapes"] = _safe_keys(parsed)
        except (OSError, ValueError, yaml.YAMLError, RecursionError) as exc:
            profile_fact["parse_ok"] = False
            findings.append(
                Finding(
                    id="config.parse_error",
                    severity="FAIL",
                    component="config",
                    profile=name,
                    summary="Profile config.yaml cannot be parsed",
                    evidence=[exc.__class__.__name__],
                    risk="Hermes may fail to load this profile or silently ignore config sections.",
                    next_action=f"Validate YAML syntax for profile {name} before restarting anything.",
                )
            )
        facts["profiles"][name] = profile_fact

    severity = "FAIL" if any(f.severity == "FAIL" for f in findings) else "WARN" if findings else "OK"
    return CheckResult("config", severity, f"profiles={len(profiles)} findings={len(findings)}", findings, facts)
