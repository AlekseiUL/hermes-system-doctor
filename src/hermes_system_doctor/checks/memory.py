from __future__ import annotations

import json
from pathlib import Path

from ..models import CheckResult, Finding
from ..path_utils import safe_relpath
from .discovery import profile_dirs

MEMORY_NAMES = {"memories", "memory", "memory.json", "memory.db", "user.md", "USER.md", "MEMORY.md"}
FILE_WARN_BYTES = 256 * 1024
DIR_WARN_FILES = 200
PROFILE_WARN_BYTES = 2 * 1024 * 1024


def _surface_candidates(profile_path: Path) -> list[Path]:
    candidates = [profile_path / name for name in sorted(MEMORY_NAMES)]
    seen: set[tuple[int, int]] = set()
    unique: list[Path] = []
    for candidate in candidates:
        try:
            stat = candidate.lstat()
        except OSError:
            unique.append(candidate)
            continue
        key = (stat.st_dev, stat.st_ino)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return False


def _dir_inventory(path: Path) -> tuple[int, int, int]:
    count = 0
    total = 0
    skipped = 0
    try:
        for item in path.iterdir():
            if item.is_symlink():
                skipped += 1
                continue
            try:
                stat = item.stat()
            except OSError:
                skipped += 1
                continue
            count += 1
            if item.is_file():
                total += stat.st_size
    except OSError:
        skipped += 1
    return count, total, skipped


def memory_check(hermes_home: Path) -> CheckResult:
    findings: list[Finding] = []
    facts = {
        "profiles_scanned": 0,
        "surfaces_found": 0,
        "files": 0,
        "directories": 0,
        "bytes": 0,
        "symlinks_skipped": 0,
    }
    profiles = profile_dirs(hermes_home)
    for profile_name, profile_path in profiles:
        facts["profiles_scanned"] += 1
        profile_bytes = 0
        profile_files = 0
        for candidate in _surface_candidates(profile_path):
            if _is_symlink(candidate):
                facts["symlinks_skipped"] += 1
                findings.append(
                    Finding(
                        id="memory.symlink_skipped",
                        severity="WARN",
                        component="memory",
                        profile=profile_name,
                        summary="Memory surface is a symlink and was not followed",
                        evidence=[safe_relpath(candidate, hermes_home)],
                        risk="A memory path points outside the normal profile layout or cannot be safely inspected.",
                        next_action="Inspect the symlink manually before trusting or cleaning this memory surface.",
                    )
                )
                continue
            if not candidate.exists():
                continue
            facts["surfaces_found"] += 1
            try:
                stat = candidate.stat()
            except OSError:
                findings.append(
                    Finding(
                        id="memory.stat_failed",
                        severity="WARN",
                        component="memory",
                        profile=profile_name,
                        summary="Memory surface metadata could not be read",
                        evidence=[safe_relpath(candidate, hermes_home)],
                        risk="The doctor cannot inventory this memory surface safely.",
                        next_action="Check file permissions and path health manually.",
                    )
                )
                continue
            if candidate.is_file():
                facts["files"] += 1
                facts["bytes"] += stat.st_size
                profile_bytes += stat.st_size
                profile_files += 1
                if candidate.name == "memory.json":
                    try:
                        with candidate.open("rb") as handle:
                            payload = handle.read(min(stat.st_size, FILE_WARN_BYTES + 1))
                        if len(payload) <= FILE_WARN_BYTES:
                            json.loads(payload.decode("utf-8", errors="strict"))
                    except (OSError, ValueError, RecursionError):
                        findings.append(
                            Finding(
                                id="memory.json_invalid",
                                severity="WARN",
                                component="memory",
                                profile=profile_name,
                                summary="memory.json could not be parsed as JSON metadata",
                                evidence=[safe_relpath(candidate, hermes_home)],
                                risk="Structured local memory metadata may be corrupted or not JSON.",
                                next_action="Back up the file, then inspect or regenerate it with Hermes tooling.",
                            )
                        )
                if stat.st_size > FILE_WARN_BYTES:
                    findings.append(
                        Finding(
                            id="memory.file_large",
                            severity="WARN",
                            component="memory",
                            profile=profile_name,
                            summary="Memory file is large",
                            evidence=[f"{safe_relpath(candidate, hermes_home)} size={stat.st_size}"],
                            risk="Large memory files can slow diagnostics or indicate stale accumulated context.",
                            next_action="Review memory hygiene with a backup-first workflow; do not delete blindly.",
                        )
                    )
            elif candidate.is_dir():
                facts["directories"] += 1
                count, total, skipped = _dir_inventory(candidate)
                profile_files += count
                profile_bytes += total
                facts["files"] += count
                facts["bytes"] += total
                facts["symlinks_skipped"] += skipped
                if skipped:
                    findings.append(
                        Finding(
                            id="memory.symlink_skipped",
                            severity="WARN",
                            component="memory",
                            profile=profile_name,
                            summary="Symlinked memory entries were skipped",
                            evidence=[safe_relpath(candidate, hermes_home), f"skipped={skipped}"],
                            risk="Some memory entries point outside the inspected profile or are not safe to follow.",
                            next_action="Inspect skipped symlinks manually before cleanup.",
                        )
                    )
                if count > DIR_WARN_FILES:
                    findings.append(
                        Finding(
                            id="memory.dir_many_files",
                            severity="WARN",
                            component="memory",
                            profile=profile_name,
                            summary="Memory directory contains many files",
                            evidence=[f"{safe_relpath(candidate, hermes_home)} files={count}"],
                            risk="Large memory directories can indicate stale or fragmented memory state.",
                            next_action="Run a backup-first memory hygiene review.",
                        )
                    )
        if profile_bytes > PROFILE_WARN_BYTES:
            findings.append(
                Finding(
                    id="memory.profile_large",
                    severity="WARN",
                    component="memory",
                    profile=profile_name,
                    summary="Profile memory footprint is large",
                    evidence=[f"profile={profile_name} bytes={profile_bytes} files={profile_files}"],
                    risk="Large memory footprint can reduce reliability and make future context noisy.",
                    next_action="Back up the profile and perform memory hygiene review; do not prune automatically.",
                )
            )
    severity = "WARN" if findings else "OK"
    return CheckResult("memory", severity, f"surfaces={facts['surfaces_found']} bytes={facts['bytes']}", findings, facts)
