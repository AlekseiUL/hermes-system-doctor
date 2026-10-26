from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from ..models import CheckResult, Finding, Severity
from ..path_utils import safe_relpath
from .discovery import profile_dirs

PID_CANDIDATES = ("gateway.pid", ".gateway.pid", "run/gateway.pid", "gateway/gateway.pid")
LOG_PATTERNS = {
    "gateway.sigterm_seen": re.compile(r"(?i)received sigterm|signal=SIGTERM|exiting with code 1"),
    "gateway.startup_seen": re.compile(r"(?i)starting hermes gateway|gateway running with|connected to"),
    "gateway.send_error_seen": re.compile(r"(?i)failed to send|send error|message to edit not found"),
    "gateway.media_block_seen": re.compile(r"(?i)skipping unsafe MEDIA directive|failed to send media"),
}
MAX_GATEWAY_LOG_BYTES = 64 * 1024


def _load_config(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return {}, None
    if path.is_symlink():
        return None, "config_symlink"
    try:
        parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError, yaml.YAMLError, RecursionError) as exc:
        return None, exc.__class__.__name__
    if not isinstance(parsed, dict):
        return None, "config_not_mapping"
    return parsed, None


def _configured_platform_names(config: dict[str, Any]) -> tuple[list[str], list[str]]:
    platforms: set[str] = set()
    shape_errors: list[str] = []
    gateway_section = config.get("gateway")
    value = config.get("platforms")
    if value in (None, {}) and isinstance(gateway_section, dict):
        value = gateway_section.get("platforms")
    if isinstance(value, dict):
        for key, platform_cfg in value.items():
            name = str(key).strip()
            if not name:
                continue
            if isinstance(platform_cfg, dict):
                enabled = platform_cfg.get("enabled")
                if enabled is False:
                    continue
            platforms.add(name)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.strip():
                platforms.add(item.strip())
            elif isinstance(item, dict):
                name = item.get("name") or item.get("platform")
                if isinstance(name, str) and name.strip() and item.get("enabled") is not False:
                    platforms.add(name.strip())
                else:
                    shape_errors.append(f"platforms[]:{type(item).__name__}")
    elif value not in (None, {}):
        shape_errors.append(f"platforms:{type(value).__name__}")
    for key in ("telegram", "discord", "slack", "matrix", "signal", "whatsapp", "email", "sms", "api_server", "webhooks"):
        section = config.get(key)
        if isinstance(section, dict) and section.get("enabled") is True:
            platforms.add(key)
    return sorted(platforms), shape_errors


def _pid_status(pid_file: Path) -> tuple[str | None, str | None]:
    if pid_file.is_symlink():
        return None, "symlink"
    try:
        raw = pid_file.read_text(encoding="utf-8", errors="ignore").strip().splitlines()[0]
    except (OSError, IndexError):
        return None, "read_failed"
    if not raw.isdigit():
        return None, "invalid"
    pid = int(raw)
    if pid <= 0:
        return raw, "invalid"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return raw, "not_running"
    except PermissionError:
        return raw, "exists_permission_unknown"
    except OSError:
        return raw, "unknown"
    return raw, "running"


def _scan_gateway_log(path: Path, hermes_home: Path) -> tuple[dict[str, int], list[Finding], bool]:
    counts = {key: 0 for key in LOG_PATTERNS}
    findings: list[Finding] = []
    if not path.exists():
        return counts, findings, False
    if path.is_symlink() or not path.is_file():
        findings.append(
            Finding(
                id="gateway.log_skipped",
                severity="WARN",
                component="gateway",
                summary="Gateway log path is not a regular file and was skipped",
                evidence=[safe_relpath(path, hermes_home)],
                risk="Gateway evidence may be incomplete or point outside the inspected profile.",
                next_action="Inspect this log path manually before trusting gateway health.",
            )
        )
        return counts, findings, False
    try:
        stat = path.stat()
        with path.open("rb") as handle:
            if stat.st_size > MAX_GATEWAY_LOG_BYTES:
                handle.seek(max(0, stat.st_size - MAX_GATEWAY_LOG_BYTES))
            data = handle.read(MAX_GATEWAY_LOG_BYTES)
    except OSError:
        return counts, findings, False
    if b"\0" in data:
        return counts, findings, False
    text = data.decode("utf-8", errors="replace")
    first_evidence: dict[str, list[str]] = {}
    for line_no, line in enumerate(text.splitlines(), 1):
        for finding_id, regex in LOG_PATTERNS.items():
            if regex.search(line):
                counts[finding_id] += 1
                first_evidence.setdefault(finding_id, [safe_relpath(path, hermes_home), f"line={line_no}"])
    for finding_id, count in sorted(counts.items()):
        if count == 0 or finding_id == "gateway.startup_seen":
            continue
        findings.append(
            Finding(
                id=finding_id,
                severity="WARN",
                component="gateway",
                summary=f"Gateway log signal matched {count} time(s)",
                evidence=[*first_evidence.get(finding_id, []), f"count={count}"],
                risk="Gateway logs contain a lifecycle or delivery-risk signal. Raw log text is not included by default.",
                next_action="Inspect the local gateway log around the reported line before restarting anything.",
            )
        )
    return counts, findings, True


def _severity(findings: list[Finding]) -> Severity:
    if any(f.severity == "FAIL" for f in findings):
        return "FAIL"
    if any(f.severity == "UNKNOWN" for f in findings):
        return "UNKNOWN"
    if any(f.severity == "WARN" for f in findings):
        return "WARN"
    return "OK"


def gateway_check(hermes_home: Path) -> CheckResult:
    findings: list[Finding] = []
    facts: dict[str, Any] = {
        "profiles_scanned": 0,
        "configured_platforms": {},
        "pid_files": {},
        "gateway_logs_scanned": 0,
        "signals": {},
        "platform_probes": "not_run",
        "service_restarts": "not_run",
        "messages_sent": "not_run",
    }
    for profile_name, profile_path in profile_dirs(hermes_home):
        facts["profiles_scanned"] += 1
        config, error = _load_config(profile_path / "config.yaml")
        if error:
            findings.append(
                Finding(
                    id="gateway.config_unreadable",
                    severity="WARN",
                    component="gateway",
                    profile=profile_name,
                    summary="Gateway config could not be inspected because config.yaml is unreadable",
                    evidence=[f"profile={profile_name}", f"error={error}"],
                    risk="Gateway/platform settings may be hidden by malformed config.",
                    next_action="Validate config.yaml before changing gateway state.",
                )
            )
        else:
            assert config is not None
            platforms, shape_errors = _configured_platform_names(config)
            if platforms:
                facts["configured_platforms"][profile_name] = platforms
            for shape_error in shape_errors:
                findings.append(
                    Finding(
                        id="gateway.platform_shape_invalid",
                        severity="WARN",
                        component="gateway",
                        profile=profile_name,
                        summary="Gateway platform config has an unsupported shape",
                        evidence=[shape_error],
                        risk="Hermes may ignore this platform configuration.",
                        next_action="Use a mapping or list of platform names/config objects.",
                    )
                )
        for relative in PID_CANDIDATES:
            pid_file = profile_path / relative
            if not pid_file.exists() and not pid_file.is_symlink():
                continue
            pid, status = _pid_status(pid_file)
            facts["pid_files"][f"{profile_name}:{relative}"] = status
            if status in {"not_running", "invalid", "read_failed", "symlink"}:
                findings.append(
                    Finding(
                        id="gateway.pid_stale_or_unreadable",
                        severity="WARN",
                        component="gateway",
                        profile=profile_name,
                        summary="Gateway PID file is stale or could not be verified",
                        evidence=[safe_relpath(pid_file, hermes_home), f"status={status}", f"pid={pid or 'unknown'}"],
                        risk="A stale PID file can mislead gateway status checks or restart scripts.",
                        next_action="Verify with hermes gateway status or OS process tools; do not delete PID files blindly.",
                    )
                )
        log_path = profile_path / "logs" / "gateway.log"
        counts, log_findings, scanned = _scan_gateway_log(log_path, hermes_home)
        if scanned:
            facts["gateway_logs_scanned"] += 1
        for key, value in counts.items():
            facts["signals"][f"{profile_name}:{key}"] = value
        for finding in log_findings:
            finding.profile = profile_name
        findings.extend(log_findings)
    severity = _severity(findings)
    summary = f"profiles={facts['profiles_scanned']} logs={facts['gateway_logs_scanned']}"
    return CheckResult("gateway", severity, summary, findings, facts)
