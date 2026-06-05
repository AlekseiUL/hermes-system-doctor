from __future__ import annotations

from pathlib import Path
from typing import Any, cast
import os
import re
import shutil
from urllib.parse import urlparse

import yaml

from ..models import CheckResult, Finding, Severity
from ..path_utils import safe_relpath
from .discovery import profile_dirs

SECRET_KEY_PARTS = ("key", "token", "secret", "password", "passwd", "auth", "cookie")
PLACEHOLDER_PREFIXES = ("${", "$env:", "env:")
ENV_REF_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
MAX_ENV_BYTES = 256 * 1024


def _is_placeholder_value(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith(PLACEHOLDER_PREFIXES) or bool(ENV_REF_PATTERN.search(stripped))


def _load_config(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return {}, None
    if path.is_symlink():
        return None, "config_symlink"
    try:
        parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return None, exc.__class__.__name__
    if not isinstance(parsed, dict):
        return None, "config_not_mapping"
    return parsed, None


def _safe_command_label(command: str, profile_path: Path, hermes_home: Path) -> str:
    command_path = Path(command).expanduser()
    if command_path.is_absolute() or any(sep in command for sep in ("/", "\\")):
        if not command_path.is_absolute():
            command_path = profile_path / command_path
        return safe_relpath(command_path, hermes_home)
    return command


def _command_available(command: str, profile_path: Path) -> bool:
    command_path = Path(command).expanduser()
    if command_path.is_absolute() or any(sep in command for sep in ("/", "\\")):
        if not command_path.is_absolute():
            command_path = profile_path / command_path
        try:
            resolved = command_path.resolve()
            profile_root = profile_path.resolve()
            if not resolved.is_relative_to(profile_root):
                return False
        except Exception:
            return False
        return command_path.exists() and not command_path.is_dir()
    return shutil.which(command) is not None


def _has_inline_sensitive_value(mapping: Any) -> list[str]:
    if not isinstance(mapping, dict):
        return []
    risky: list[str] = []
    for key, value in mapping.items():
        key_s = str(key)
        value_s = value if isinstance(value, str) else ""
        key_looks_secret = any(part in key_s.lower() for part in SECRET_KEY_PARTS)
        value_looks_inline = bool(value_s) and not _is_placeholder_value(value_s)
        if key_looks_secret and value_looks_inline:
            risky.append(key_s)
    return sorted(set(risky))


def _profile_env_names(profile_path: Path) -> set[str]:
    env_path = profile_path / ".env"
    if not env_path.exists() or env_path.is_symlink():
        return set()
    try:
        stat = env_path.stat()
    except OSError:
        return set()
    names: set[str] = set()
    try:
        with env_path.open("rb") as handle:
            raw = handle.read(min(stat.st_size, MAX_ENV_BYTES))
    except OSError:
        return set()
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key.startswith("export "):
            key = key.removeprefix("export ").strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            names.add(key)
    return names


def _missing_env_refs(mapping: Any, available_env: set[str]) -> list[str]:
    if not isinstance(mapping, dict):
        return []
    missing: set[str] = set()
    for value in mapping.values():
        if not isinstance(value, str):
            continue
        for env_name in ENV_REF_PATTERN.findall(value):
            if env_name not in available_env:
                missing.add(env_name)
    return sorted(missing)


def _severity(findings: list[Finding]) -> Severity:
    if any(f.severity == "FAIL" for f in findings):
        return "FAIL"
    if any(f.severity == "UNKNOWN" for f in findings):
        return "UNKNOWN"
    if any(f.severity == "WARN" for f in findings):
        return "WARN"
    return "OK"


def mcp_check(hermes_home: Path) -> CheckResult:
    findings: list[Finding] = []
    facts: dict[str, Any] = {
        "profiles_scanned": 0,
        "servers_configured": 0,
        "stdio_servers": 0,
        "http_servers": 0,
        "env_keys": {},
        "header_keys": {},
        "network_probes": "not_run",
        "tools_executed": "not_run",
    }
    for profile_name, profile_path in profile_dirs(hermes_home):
        facts["profiles_scanned"] += 1
        config, error = _load_config(profile_path / "config.yaml")
        if error:
            findings.append(
                Finding(
                    id="mcp.config_unreadable",
                    severity="WARN",
                    component="mcp",
                    profile=profile_name,
                    summary="MCP config could not be inspected because config.yaml is unreadable",
                    evidence=[f"profile={profile_name}", f"error={error}"],
                    risk="Configured MCP servers may be hidden by a malformed or unsafe config file.",
                    next_action="Validate config.yaml syntax before trusting MCP status.",
                )
            )
            continue
        assert config is not None
        available_env = set(os.environ) | _profile_env_names(profile_path)
        servers = config.get("mcp_servers", {})
        if servers in (None, {}):
            continue
        if not isinstance(servers, dict):
            findings.append(
                Finding(
                    id="mcp.config_shape_invalid",
                    severity="FAIL",
                    component="mcp",
                    profile=profile_name,
                    summary="mcp_servers config is not a mapping",
                    evidence=[f"profile={profile_name}", f"type={type(servers).__name__}"],
                    risk="Hermes will not be able to load MCP servers from this config shape.",
                    next_action="Use mcp_servers: <server_name>: {command|url: ...} format.",
                )
            )
            continue
        for server_name, server_cfg in sorted(servers.items(), key=lambda item: str(item[0])):
            server_label = str(server_name)
            facts["servers_configured"] += 1
            if not isinstance(server_cfg, dict):
                findings.append(
                    Finding(
                        id="mcp.server_config_invalid",
                        severity="FAIL",
                        component="mcp",
                        profile=profile_name,
                        summary="MCP server config is not a mapping",
                        evidence=[f"server={server_label}", f"type={type(server_cfg).__name__}"],
                        risk="Hermes cannot interpret this MCP server config.",
                        next_action="Replace this server entry with a mapping containing command or url.",
                    )
                )
                continue
            command = server_cfg.get("command")
            url = server_cfg.get("url")
            has_command = isinstance(command, str) and bool(command.strip())
            has_url = isinstance(url, str) and bool(url.strip())
            if has_command and has_url:
                findings.append(
                    Finding(
                        id="mcp.transport_ambiguous",
                        severity="FAIL",
                        component="mcp",
                        profile=profile_name,
                        summary="MCP server has both command and url transports configured",
                        evidence=[f"server={server_label}"],
                        risk="Hermes expects one transport per MCP server; ambiguous transport may fail startup.",
                        next_action="Keep either command for stdio or url for HTTP, not both.",
                    )
                )
            if not has_command and not has_url:
                findings.append(
                    Finding(
                        id="mcp.transport_missing",
                        severity="FAIL",
                        component="mcp",
                        profile=profile_name,
                        summary="MCP server has neither command nor url configured",
                        evidence=[f"server={server_label}"],
                        risk="Hermes cannot connect to this MCP server.",
                        next_action="Add a stdio command or HTTP url.",
                    )
                )
                continue
            if has_command:
                facts["stdio_servers"] += 1
                command_s = cast(str, command).strip()
                if not _command_available(command_s, profile_path):
                    findings.append(
                        Finding(
                            id="mcp.command_missing",
                            severity="WARN",
                            component="mcp",
                            profile=profile_name,
                            summary="MCP stdio command is not available without executing it",
                            evidence=[f"server={server_label}", f"command={_safe_command_label(command_s, profile_path, hermes_home)}"],
                            risk="Hermes may fail to start or discover tools for this MCP server.",
                            next_action="Install the command or fix the configured executable path; do not run untrusted MCP servers blindly.",
                        )
                    )
                args = server_cfg.get("args", [])
                if args is not None and not isinstance(args, list):
                    findings.append(
                        Finding(
                            id="mcp.args_shape_invalid",
                            severity="WARN",
                            component="mcp",
                            profile=profile_name,
                            summary="MCP stdio args are not a list",
                            evidence=[f"server={server_label}", f"type={type(args).__name__}"],
                            risk="Hermes may pass invalid process arguments to the MCP server.",
                            next_action="Represent args as a YAML list.",
                        )
                    )
                env = server_cfg.get("env", {})
                if env is not None and not isinstance(env, dict):
                    findings.append(
                        Finding(
                            id="mcp.env_shape_invalid",
                            severity="WARN",
                            component="mcp",
                            profile=profile_name,
                            summary="MCP env config is not a mapping",
                            evidence=[f"server={server_label}", f"type={type(env).__name__}"],
                            risk="Hermes may ignore or fail env injection for this server.",
                            next_action="Use env: KEY: ${ENV_VAR} style values.",
                        )
                    )
                else:
                    env_keys = sorted(str(key) for key in (env or {}).keys())
                    if env_keys:
                        facts["env_keys"][f"{profile_name}:{server_label}"] = env_keys
                    risky_env = _has_inline_sensitive_value(env)
                    if risky_env:
                        findings.append(
                            Finding(
                                id="mcp.inline_secret_env",
                                severity="WARN",
                                component="mcp",
                                profile=profile_name,
                                summary="MCP env appears to contain inline sensitive values",
                                evidence=[f"server={server_label}", "keys=" + ",".join(risky_env)],
                                risk="Inline secrets in config.yaml can leak through backups, reports, or accidental commits.",
                                next_action="Move secrets to environment variables and reference them with ${VAR_NAME}.",
                            )
                        )
                    missing_env = _missing_env_refs(env, available_env)
                    if missing_env:
                        findings.append(
                            Finding(
                                id="mcp.env_ref_missing",
                                severity="WARN",
                                component="mcp",
                                profile=profile_name,
                                summary="MCP env references variables not visible in process env or profile .env",
                                evidence=[f"server={server_label}", "vars=" + ",".join(missing_env)],
                                risk="Hermes may start the MCP server without required credentials or settings.",
                                next_action="Define the referenced variables in the profile .env or runtime environment; do not paste secret values into reports.",
                            )
                        )
            if has_url:
                facts["http_servers"] += 1
                parsed = urlparse(cast(str, url).strip())
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    findings.append(
                        Finding(
                            id="mcp.url_invalid",
                            severity="FAIL",
                            component="mcp",
                            profile=profile_name,
                            summary="MCP HTTP URL has invalid shape",
                            evidence=[f"server={server_label}", f"scheme={parsed.scheme or 'missing'}"],
                            risk="Hermes cannot connect to an invalid MCP URL.",
                            next_action="Use a valid http:// or https:// MCP endpoint.",
                        )
                    )
                if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                    findings.append(
                        Finding(
                            id="mcp.http_without_tls",
                            severity="WARN",
                            component="mcp",
                            profile=profile_name,
                            summary="Remote MCP URL uses plain HTTP",
                            evidence=[f"server={server_label}", f"host={parsed.hostname or 'unknown'}"],
                            risk="Remote MCP traffic may expose prompts, tool metadata, or auth headers.",
                            next_action="Prefer HTTPS for remote MCP endpoints; localhost HTTP can be acceptable for local-only servers.",
                        )
                    )
                headers = server_cfg.get("headers", {})
                if headers is not None and not isinstance(headers, dict):
                    findings.append(
                        Finding(
                            id="mcp.headers_shape_invalid",
                            severity="WARN",
                            component="mcp",
                            profile=profile_name,
                            summary="MCP headers config is not a mapping",
                            evidence=[f"server={server_label}", f"type={type(headers).__name__}"],
                            risk="Hermes may ignore or fail HTTP header injection for this server.",
                            next_action="Use headers: Header-Name: ${ENV_VAR} style values.",
                        )
                    )
                else:
                    header_keys = sorted(str(key) for key in (headers or {}).keys())
                    if header_keys:
                        facts["header_keys"][f"{profile_name}:{server_label}"] = header_keys
                    risky_headers = _has_inline_sensitive_value(headers)
                    if risky_headers:
                        findings.append(
                            Finding(
                                id="mcp.inline_secret_header",
                                severity="WARN",
                                component="mcp",
                                profile=profile_name,
                                summary="MCP headers appear to contain inline sensitive values",
                                evidence=[f"server={server_label}", "headers=" + ",".join(risky_headers)],
                                risk="Inline auth headers in config.yaml can leak through backups or accidental commits.",
                                next_action="Move header secrets to environment variables and reference them with ${VAR_NAME}.",
                            )
                        )
                    missing_headers = _missing_env_refs(headers, available_env)
                    if missing_headers:
                        findings.append(
                            Finding(
                                id="mcp.header_env_ref_missing",
                                severity="WARN",
                                component="mcp",
                                profile=profile_name,
                                summary="MCP headers reference variables not visible in process env or profile .env",
                                evidence=[f"server={server_label}", "vars=" + ",".join(missing_headers)],
                                risk="Hermes may connect to the MCP server without required HTTP auth headers.",
                                next_action="Define the referenced variables in the profile .env or runtime environment; do not paste secret values into reports.",
                            )
                        )
    severity = _severity(findings)
    return CheckResult(
        "mcp",
        severity,
        f"servers={facts['servers_configured']} stdio={facts['stdio_servers']} http={facts['http_servers']}",
        findings,
        facts,
    )
