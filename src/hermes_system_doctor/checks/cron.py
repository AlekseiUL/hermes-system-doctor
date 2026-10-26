from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import CheckResult, Finding
from ..path_utils import safe_relpath
from .discovery import profile_dirs


def _candidate_job_files(profile_path: Path) -> list[Path]:
    cron_dir = profile_path / "cron"
    if not cron_dir.exists():
        return []
    candidates = []
    for pattern in ("*.json", "jobs/*.json"):
        candidates.extend(sorted(cron_dir.glob(pattern)))
    return [p for p in candidates if p.is_file()]


def _job_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("jobs"), list):
            return [x for x in data["jobs"] if isinstance(x, dict)]
        return [data]
    return []


def _safe_job_id(job: dict[str, Any], fallback: str) -> str:
    for key in ("job_id", "id", "name"):
        value = job.get(key)
        if isinstance(value, str) and value:
            return value[:64]
    return fallback


def _path_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def _resolve_script_candidates(script: str, profile_path: Path) -> list[Path]:
    script_path = Path(script).expanduser()
    if script_path.is_absolute():
        return [script_path]
    candidates = [profile_path / script_path]
    if not str(script_path).startswith("scripts/"):
        candidates.insert(0, profile_path / "scripts" / script_path)
    return candidates


def cron_check(hermes_home: Path) -> CheckResult:
    findings: list[Finding] = []
    facts: dict[str, Any] = {"profiles": {}, "jobs_total": 0}
    for profile_name, profile_path in profile_dirs(hermes_home):
        job_files = _candidate_job_files(profile_path)
        profile_fact: dict[str, Any] = {"job_files": len(job_files), "jobs": 0}
        for job_file in job_files:
            try:
                data = json.loads(job_file.read_text(encoding="utf-8"))
            except (OSError, ValueError, RecursionError) as exc:
                findings.append(
                    Finding(
                        id="cron.metadata_parse_error",
                        severity="FAIL",
                        component="cron",
                        profile=profile_name,
                        summary="Cron metadata JSON cannot be parsed",
                        evidence=[safe_relpath(job_file, hermes_home), exc.__class__.__name__],
                        risk="Hermes cron may skip or fail this job metadata.",
                        next_action="Validate the cron metadata JSON before running or editing jobs.",
                    )
                )
                continue
            for index, job in enumerate(_job_items(data)):
                profile_fact["jobs"] += 1
                facts["jobs_total"] += 1
                job_id = _safe_job_id(job, f"job-{index}")
                script = job.get("script")
                if isinstance(script, str) and script:
                    script_candidates = _resolve_script_candidates(script, profile_path)
                    if not all(_path_inside(path, profile_path) for path in script_candidates):
                        findings.append(
                            Finding(
                                id="cron.script_outside_profile",
                                severity="WARN",
                                component="cron",
                                profile=profile_name,
                                summary="Cron job script path resolves outside the profile directory",
                                evidence=[job_id, "[REDACTED_PATH]"],
                                risk="The job depends on code outside the inspected profile, so portability and safety are unclear.",
                                next_action="Move the script under the profile scripts directory or use an explicit reviewed path.",
                            )
                        )
                    elif not any(path.exists() for path in script_candidates):
                        findings.append(
                            Finding(
                                id="cron.script_missing",
                                severity="FAIL",
                                component="cron",
                                profile=profile_name,
                                summary="Cron job references a missing script",
                                evidence=[job_id, safe_relpath(script_candidates[0], hermes_home)],
                                risk="The job will fail before the agent receives context.",
                                next_action="Create the script, correct the path, or pause the job before relying on it.",
                            )
                        )
                workdir = job.get("workdir")
                if isinstance(workdir, str) and workdir:
                    workdir_path = Path(workdir).expanduser()
                    if not workdir_path.is_absolute():
                        workdir_path = profile_path / workdir_path
                    if not workdir_path.exists():
                        findings.append(
                            Finding(
                                id="cron.workdir_missing",
                                severity="WARN",
                                component="cron",
                                profile=profile_name,
                                summary="Cron job references a missing workdir",
                                evidence=[job_id, safe_relpath(workdir_path, hermes_home)],
                                risk="The job may run in an unexpected directory or fail at startup.",
                                next_action="Create the workdir or update the job configuration.",
                            )
                        )
        facts["profiles"][profile_name] = profile_fact
    severity = "FAIL" if any(f.severity == "FAIL" for f in findings) else "WARN" if findings else "OK"
    return CheckResult("cron", severity, f"jobs={facts['jobs_total']} findings={len(findings)}", findings, facts)
