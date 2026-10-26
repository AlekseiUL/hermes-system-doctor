from __future__ import annotations

import json
import re
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .path_utils import safe_relpath
from .redaction import redact

SAFE_ACTION_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
SAFE_PROFILE = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
CONFIG_STUB = "# Created by hermes-system-doctor. Review before adding secrets or provider settings.\n{}\n"


@dataclass
class BackupPreview:
    required: bool
    performed: bool
    reason: str
    files: list[str] = field(default_factory=list)


@dataclass
class DiffPreview:
    available: bool
    reason: str
    entries: list[str] = field(default_factory=list)


@dataclass
class FixPreview:
    schema_version: str
    generated_at: str
    dry_run: bool
    execute_requested: bool
    status: str
    approved_action_id: str
    side_effects_performed: list[str]
    action: dict[str, Any] | None
    backup: BackupPreview
    diff: DiffPreview
    rollback_hint: str | None
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_repair_plan(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("repair plan JSON must be an object")  # noqa: TRY004 - invalid serialized value, public ValueError contract
    return data


def _safe_action_id(action_id: str) -> str:
    candidate = str(action_id or "").strip()
    if not SAFE_ACTION_ID.fullmatch(candidate):
        raise ValueError("approved action id must contain only letters, numbers, dot, colon, underscore, or dash")
    return candidate


def _actions(plan: dict[str, Any]) -> list[dict[str, Any]]:
    raw = plan.get("actions", [])
    if not isinstance(raw, list):
        raise ValueError("repair plan actions must be a list")  # noqa: TRY004 - invalid serialized value, public ValueError contract
    actions: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            actions.append(item)
    return actions


def _find_action(plan: dict[str, Any], action_id: str) -> dict[str, Any] | None:
    matches = [action for action in _actions(plan) if action.get("action_id") == action_id]
    if len(matches) > 1:
        raise ValueError("repair plan contains duplicate action ids")
    return matches[0] if matches else None


def build_fix_preview(
    plan: dict[str, Any],
    approve_action_id: str,
    *,
    hermes_home: Path | None = None,
    execute: bool = False,
) -> FixPreview:
    action_id = _safe_action_id(approve_action_id)
    if plan.get("dry_run_only") is not True:
        raise ValueError("input must be a dry-run repair plan produced by repair-plan mode")

    action = _find_action(plan, action_id)
    notes = [
        "This is the gated fix executor. It validates one approved action id and renders backup/diff/rollback intent.",
        "Only registered narrow executors may write. Current registered executor: config.missing creates a minimal parseable config.yaml stub; it does not configure model providers or secrets.",
        "No service restarts, cron runs, plugin execution, MCP tool calls, platform messages, or network calls are performed.",
    ]
    if action is None:
        return _preview(
            action_id=action_id,
            execute=execute,
            status="BLOCKED_ACTION_NOT_FOUND",
            action=None,
            backup=BackupPreview(False, False, "No matching action was found."),
            diff=DiffPreview(False, "No matching action was found."),
            rollback_hint=None,
            notes=notes,
        )

    approval_required = action.get("approval_required") is True
    mode = str(action.get("mode") or "unknown")
    if not approval_required:
        return _preview(
            action_id=action_id,
            execute=execute,
            status="BLOCKED_UNTRUSTED_PLAN_ACTION",
            action=action,
            backup=BackupPreview(False, False, "Plan action did not require approval; refusing to treat it as safe input."),
            diff=DiffPreview(False, "Plan action did not require approval; refusing to treat it as safe input."),
            rollback_hint=None,
            notes=notes,
        )
    if mode == "manual_diagnostic":
        return _preview(
            action_id=action_id,
            execute=execute,
            status="BLOCKED_DIAGNOSTIC_ONLY",
            action=action,
            backup=BackupPreview(False, False, "Diagnostic-only action; no backup should be made because no mutation is allowed."),
            diff=DiffPreview(False, "Diagnostic-only action; inspect manually and re-run the doctor instead of applying a fix."),
            rollback_hint=_rollback_hint(action),
            notes=notes,
        )

    executor = _executor_for(action)
    if executor is None:
        return _preview(
            action_id=action_id,
            execute=execute,
            status="BLOCKED_NO_EXECUTOR",
            action=action,
            backup=BackupPreview(action.get("backup_required") is True, False, "No safe executor is registered for this action. Backup not created because no write will occur."),
            diff=DiffPreview(False, "No file diff is available because no registered mutation exists for the action."),
            rollback_hint=_rollback_hint(action),
            notes=notes,
        )
    if hermes_home is None:
        return _preview(
            action_id=action_id,
            execute=execute,
            status="BLOCKED_HERMES_HOME_REQUIRED",
            action=action,
            backup=BackupPreview(action.get("backup_required") is True, False, "Pass --hermes-home so the executor can resolve the target inside an explicit Hermes home."),
            diff=DiffPreview(False, "Target home is not available."),
            rollback_hint=_rollback_hint(action),
            notes=notes,
        )
    return executor(action_id, action, hermes_home.expanduser(), execute, notes)


def _preview(
    *,
    action_id: str,
    execute: bool,
    status: str,
    action: dict[str, Any] | None,
    backup: BackupPreview,
    diff: DiffPreview,
    rollback_hint: str | None,
    notes: list[str],
    side_effects: list[str] | None = None,
) -> FixPreview:
    return FixPreview(
        schema_version="1.0",
        generated_at=datetime.now(timezone.utc).isoformat(),
        dry_run=not execute,
        execute_requested=execute,
        status=status,
        approved_action_id=action_id,
        side_effects_performed=side_effects or [],
        action=_safe_action_summary(action) if action is not None else None,
        backup=backup,
        diff=diff,
        rollback_hint=rollback_hint,
        notes=notes,
    )


def _executor_for(action: dict[str, Any]):
    if action.get("component") == "config" and action.get("finding_id") == "config.missing":
        return _config_missing_executor
    return None


def _config_missing_executor(
    action_id: str,
    action: dict[str, Any],
    hermes_home: Path,
    execute: bool,
    notes: list[str],
) -> FixPreview:
    target = _config_target(hermes_home, action)
    if target is None:
        return _preview(
            action_id=action_id,
            execute=execute,
            status="BLOCKED_UNSAFE_TARGET",
            action=action,
            backup=BackupPreview(True, False, "Profile name or target path could not be resolved safely inside Hermes home."),
            diff=DiffPreview(False, "Unsafe target path."),
            rollback_hint=None,
            notes=notes,
        )

    target_label = _config_target_label(action)
    if target_label is None:
        return _preview(
            action_id=action_id,
            execute=execute,
            status="BLOCKED_UNSAFE_TARGET",
            action=action,
            backup=BackupPreview(True, False, "Profile name or target label could not be resolved safely."),
            diff=DiffPreview(False, "Unsafe target label."),
            rollback_hint=None,
            notes=notes,
        )
    unsafe_reason = _unsafe_target_reason(target, hermes_home)
    if unsafe_reason:
        return _preview(
            action_id=action_id,
            execute=execute,
            status="BLOCKED_UNSAFE_TARGET",
            action=action,
            backup=BackupPreview(True, False, unsafe_reason),
            diff=DiffPreview(False, unsafe_reason),
            rollback_hint=None,
            notes=notes,
        )
    if target.exists():
        return _preview(
            action_id=action_id,
            execute=execute,
            status="BLOCKED_TARGET_EXISTS",
            action=action,
            backup=BackupPreview(True, False, "Target already exists; refusing to overwrite an existing config file."),
            diff=DiffPreview(False, "No diff produced because existing files are never overwritten by this executor."),
            rollback_hint=None,
            notes=notes,
        )

    diff = DiffPreview(
        available=True,
        reason="Would create a minimal parseable config.yaml stub. It does not add providers, API keys, or secrets.",
        entries=[
            f"create {target_label}",
            "+ # Created by hermes-system-doctor. Review before adding secrets or provider settings.",
            "+ {}",
        ],
    )
    rollback = "Remove the created config.yaml stub and re-run hermes-system-doctor; keep the backup manifest with incident notes."
    if not execute:
        return _preview(
            action_id=action_id,
            execute=execute,
            status="DRY_RUN_READY",
            action=action,
            backup=BackupPreview(True, False, "Backup manifest would be created before writing the config stub."),
            diff=diff,
            rollback_hint=rollback,
            notes=notes,
        )

    backup_dir = _backup_dir(hermes_home, action_id)
    backup_root = backup_dir.parent
    backup_root_preexisting = backup_root.exists()
    backup_dir.mkdir(parents=True, exist_ok=False)
    manifest = {
        "schema_version": "1.0",
        "action_id": action_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target_label,
        "target_existed_before": False,
        "backup_files": [],
        "rollback_hint": rollback,
    }
    manifest_path = backup_dir / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        with target.open("x", encoding="utf-8") as handle:
            handle.write(CONFIG_STUB)
    except Exception:
        manifest_path.unlink(missing_ok=True)
        with suppress(OSError):
            backup_dir.rmdir()
        if not backup_root_preexisting:
            with suppress(OSError):
                backup_root.rmdir()
        raise
    side_effects = ["backup_manifest_written", "config_stub_written"]
    return _preview(
        action_id=action_id,
        execute=execute,
        status="APPLIED",
        action=action,
        backup=BackupPreview(True, True, "Backup manifest created before writing the config stub.", [safe_relpath(manifest_path, hermes_home)]),
        diff=diff,
        rollback_hint=rollback,
        notes=notes,
        side_effects=side_effects,
    )


def _config_target(hermes_home: Path, action: dict[str, Any]) -> Path | None:
    profile = action.get("profile")
    if not isinstance(profile, str) or not SAFE_PROFILE.fullmatch(profile):
        return None
    if profile == "default":
        target = hermes_home / "config.yaml"
    else:
        target = hermes_home / "profiles" / profile / "config.yaml"
    try:
        resolved_home = hermes_home.resolve()
        resolved_parent = target.parent.resolve(strict=False)
        if resolved_home != resolved_parent and resolved_home not in resolved_parent.parents:
            return None
    except OSError:
        return None
    return target


def _config_target_label(action: dict[str, Any]) -> str | None:
    profile = action.get("profile")
    if not isinstance(profile, str) or not SAFE_PROFILE.fullmatch(profile):
        return None
    return "config.yaml" if profile == "default" else "selected-profile/config.yaml"


def _unsafe_target_reason(target: Path, hermes_home: Path) -> str | None:
    if not hermes_home.exists() or not hermes_home.is_dir() or hermes_home.is_symlink():
        return "Hermes home must be an existing non-symlink directory."
    if target.is_symlink():
        return "Target config path is a symlink; refusing to follow or overwrite symlinks."
    if not target.parent.exists() or not target.parent.is_dir() or target.parent.is_symlink():
        return "Target parent must be an existing non-symlink directory; refusing to create profile directories during fix."
    try:
        resolved_home = hermes_home.resolve()
        resolved_parent = target.parent.resolve(strict=True)
        if resolved_home != resolved_parent and resolved_home not in resolved_parent.parents:
            return "Target parent resolves outside Hermes home."
    except OSError:
        return "Target parent could not be resolved safely."
    return None


def _backup_dir(hermes_home: Path, action_id: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_id = _safe_action_id(action_id).replace(":", "-")
    return hermes_home / ".hermes-system-doctor-backups" / f"{stamp}-{safe_id}"


def _rollback_hint(action: dict[str, Any]) -> str:
    mode = str(action.get("mode") or "unknown")
    if mode == "manual_diagnostic":
        return "No rollback is needed for diagnostic-only actions because no mutation is allowed."
    return "Restore the pre-change backup for any edited file and re-run hermes-system-doctor before restarting services."


def _safe_action_summary(action: dict[str, Any]) -> dict[str, Any]:
    safe_action_id = (
        _safe_action_id(str(action.get("action_id") or "unknown"))
        if SAFE_ACTION_ID.fullmatch(str(action.get("action_id") or ""))
        else "unknown"
    )
    components = {
        "auth_surface",
        "config",
        "cron",
        "gateway",
        "logs",
        "mcp",
        "memory",
        "plugins",
        "post_update",
        "post_update_drift",
        "profiles",
        "skills",
        "discovery",
    }
    severities = {"OK", "WARN", "FAIL", "UNKNOWN", "NEEDS_APPROVAL"}
    modes = {"manual_diagnostic", "approval_gated_repair_candidate"}
    files = action.get("files_that_would_change")
    return {
        "action_id": safe_action_id,
        "component": _safe_enum(action.get("component"), components, "unknown"),
        "severity": _safe_enum(action.get("severity"), severities, "UNKNOWN"),
        "mode": _safe_enum(action.get("mode"), modes, "unknown"),
        "profile_present": isinstance(action.get("profile"), str) and bool(action.get("profile")),
        "approval_required": action.get("approval_required") is True,
        "backup_required": action.get("backup_required") is True,
        "destructive": action.get("destructive") is True,
        "files_that_would_change_count": len(files) if isinstance(files, list) else 0,
        "registered_executor": _executor_for(action) is not None,
    }


def _safe_enum(value: Any, allowed: set[str], fallback: str) -> str:
    candidate = str(value or "").strip()
    return candidate if candidate in allowed else fallback


def fix_preview_to_json(preview: FixPreview) -> str:
    return redact(json.dumps(preview.to_dict(), ensure_ascii=False, indent=2)) + "\n"


def fix_preview_to_markdown(preview: FixPreview) -> str:
    lines = [
        "# Hermes Agent System Doctor Fix Preview",
        "",
        f"Schema: `{preview.schema_version}`",
        f"Approved action: `{redact(preview.approved_action_id)}`",
        f"Status: `{redact(preview.status)}`",
        f"Dry run: `{str(preview.dry_run).lower()}`",
        f"Execute requested: `{str(preview.execute_requested).lower()}`",
        "",
        "## Safety",
    ]
    for note in preview.notes:
        lines.append(f"- {redact(note)}")
    lines += [
        f"- Side effects performed: `{len(preview.side_effects_performed)}`",
        f"- Backup required: `{str(preview.backup.required).lower()}`",
        f"- Backup performed: `{str(preview.backup.performed).lower()}`",
        f"- Backup note: {redact(preview.backup.reason)}",
        f"- Diff available: `{str(preview.diff.available).lower()}`",
        f"- Diff note: {redact(preview.diff.reason)}",
    ]
    for entry in preview.diff.entries:
        lines.append(f"- Diff: `{redact(entry)}`")
    if preview.rollback_hint:
        lines.append(f"- Rollback hint: {redact(preview.rollback_hint)}")
    if preview.action:
        lines += ["", "## Action"]
        for key in ("action_id", "component", "severity", "mode", "registered_executor"):
            if key in preview.action:
                lines.append(f"- {key}: `{redact(str(preview.action[key]))}`")
    return "\n".join(lines) + "\n"
