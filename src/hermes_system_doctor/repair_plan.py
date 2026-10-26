from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redaction import redact

NO_ACTION_FINDINGS = {
    "gateway.startup_seen",
}
DIAGNOSTIC_ONLY_COMPONENTS = {"logs", "gateway", "post_update", "post_update_drift"}
SAFE_IDENTIFIER = re.compile(r"[^A-Za-z0-9_.:-]+")


def _safe_identifier(value: Any, fallback: str) -> str:
    text = str(value or fallback).strip() or fallback
    safe = SAFE_IDENTIFIER.sub("_", text)[:120].strip("_")
    return safe or fallback


@dataclass
class RepairAction:
    action_id: str
    finding_id: str
    component: str
    severity: str
    profile: str | None
    title: str
    mode: str
    approval_required: bool
    backup_required: bool
    destructive: bool
    files_that_would_change: list[str] = field(default_factory=list)
    manual_command: str | None = None
    proposed_change: str | None = None
    rollback_hint: str | None = None
    risk: str | None = None
    source_evidence: list[str] = field(default_factory=list)


@dataclass
class RepairPlan:
    schema_version: str
    generated_at: str
    source_report_mode: str | None
    source_report_status: str | None
    dry_run_only: bool
    actions: list[RepairAction]
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _iter_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for check in report.get("checks", []):
        component = str(check.get("name") or "unknown")
        for finding in check.get("findings", []) or []:
            item = dict(finding)
            item.setdefault("component", finding.get("component") or component)
            findings.append(item)
    return findings


def _mode_for(component: str, severity: str) -> str:
    if severity == "UNKNOWN" or component in DIAGNOSTIC_ONLY_COMPONENTS:
        return "manual_diagnostic"
    return "approval_gated_repair_candidate"


def _backup_required(component: str, mode: str) -> bool:
    return mode == "approval_gated_repair_candidate"


def _manual_command(finding: dict[str, Any]) -> str | None:
    component = _safe_identifier(finding.get("component"), "unknown")
    if component == "config":
        return "hermes config path"
    if component == "gateway":
        return "hermes gateway status"
    if component == "cron":
        return "hermes cron list --all"
    if component == "mcp":
        return "hermes mcp list"
    if component == "plugins":
        return "hermes plugins list"
    if component == "memory":
        return "hermes memory status"
    if component == "auth_surface":
        return "Inspect auth surface file ownership and presence locally; do not print token contents."
    return "Inspect this finding manually using the redacted report evidence."


def build_repair_plan(report: dict[str, Any]) -> RepairPlan:
    actions: list[RepairAction] = []
    for index, finding in enumerate(_iter_findings(report), start=1):
        finding_id = _safe_identifier(finding.get("id"), "finding.unknown")
        severity = str(finding.get("severity") or "UNKNOWN")
        if severity == "OK" or finding_id in NO_ACTION_FINDINGS:
            continue
        component = _safe_identifier(finding.get("component"), "unknown")
        mode = _mode_for(component, severity)
        backup_required = _backup_required(component, mode)
        approval_required = True
        profile = finding.get("profile") if isinstance(finding.get("profile"), str) else None
        evidence_count = len(finding.get("evidence", [])) if isinstance(finding.get("evidence"), list) else 0
        manual_command = _manual_command(finding)
        proposed_change = (
            "No automatic change is included. This plan only records the safest next diagnostic or repair candidate."
            if mode == "manual_diagnostic"
            else "Prepare a backup, inspect the target file locally, then make the smallest manual/config change that resolves this finding."
        )
        rollback_hint = (
            "No rollback needed for diagnostic-only action; do not mutate system state while verifying."
            if mode == "manual_diagnostic"
            else "Restore the pre-change backup for any edited file and re-run hermes-system-doctor before restarting services."
        )
        actions.append(
            RepairAction(
                action_id=f"rp-{index:04d}",
                finding_id=finding_id,
                component=component,
                severity=severity,
                profile=profile,
                title=finding_id,
                mode=mode,
                approval_required=approval_required,
                backup_required=backup_required,
                destructive=False,
                files_that_would_change=[],
                manual_command=manual_command,
                proposed_change=proposed_change,
                rollback_hint=rollback_hint,
                risk=finding.get("risk") if isinstance(finding.get("risk"), str) else None,
                source_evidence=[f"evidence_items={evidence_count}"],
            )
        )
    return RepairPlan(
        schema_version="1.0",
        generated_at=datetime.now(timezone.utc).isoformat(),
        source_report_mode=report.get("mode") if isinstance(report.get("mode"), str) else None,
        source_report_status=report.get("status") if isinstance(report.get("status"), str) else None,
        dry_run_only=True,
        actions=actions,
        notes=[
            "This is a repair plan, not an autofix. It performs no writes, service restarts, network probes, cron runs, plugin execution, or MCP tool calls.",
            "Every action requires explicit human approval before any side effect.",
            "Back up target files before applying any repair candidate; diagnostics should run first when severity is UNKNOWN.",
        ],
    )


def load_report(path: Path) -> dict[str, Any]:
    payload = path.read_text(encoding="utf-8")
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("report JSON must be an object")  # noqa: TRY004 - invalid serialized value, public ValueError contract
    return data


def repair_plan_to_json(plan: RepairPlan) -> str:
    return redact(json.dumps(plan.to_dict(), ensure_ascii=False, indent=2)) + "\n"


def repair_plan_to_markdown(plan: RepairPlan) -> str:
    lines = [
        "# Hermes Agent System Doctor Repair Plan",
        "",
        f"Schema: `{plan.schema_version}`",
        f"Source report mode: `{plan.source_report_mode or 'unknown'}`",
        f"Source report status: `{plan.source_report_status or 'unknown'}`",
        f"Dry-run only: `{str(plan.dry_run_only).lower()}`",
        "",
        "## Safety notes",
    ]
    for note in plan.notes:
        lines.append(f"- {redact(note)}")
    lines += ["", "## Actions"]
    if not plan.actions:
        lines.append("- No repair actions generated from this report.")
    for action in plan.actions:
        lines += [
            "",
            f"### {action.action_id} — {redact(action.finding_id)}",
            f"- Component: `{redact(action.component)}`",
            f"- Severity: `{redact(action.severity)}`",
            f"- Mode: `{redact(action.mode)}`",
            f"- Approval required: `{str(action.approval_required).lower()}`",
            f"- Backup required: `{str(action.backup_required).lower()}`",
            f"- Destructive: `{str(action.destructive).lower()}`",
            f"- Title: {redact(action.title)}",
        ]
        if action.profile:
            lines.append(f"- Profile: `{redact(action.profile)}`")
        if action.manual_command:
            lines.append(f"- Manual command / next diagnostic: `{redact(action.manual_command)}`")
        if action.risk:
            lines.append(f"- Risk: {redact(action.risk)}")
        if action.rollback_hint:
            lines.append(f"- Rollback hint: {redact(action.rollback_hint)}")
    return "\n".join(lines) + "\n"
