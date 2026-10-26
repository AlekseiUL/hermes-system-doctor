from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from ..models import CheckResult, Finding, Severity
from ..path_utils import safe_relpath
from .discovery import profile_dirs

MAX_MANIFEST_BYTES = 64 * 1024
TOO_MANY_PLUGINS = 50
PLUGIN_CONFIG_KEYS = ("plugins", "plugin", "enabled_plugins")
MANIFEST_NAMES = (
    "plugin.yaml",
    "plugin.yml",
    "manifest.yaml",
    "manifest.yml",
    "plugin.json",
    "manifest.json",
    "pyproject.toml",
    "package.json",
)
SECRET_KEY_PARTS = ("key", "token", "secret", "password", "passwd", "auth", "cookie")
PLACEHOLDER_PREFIXES = ("${", "$env:", "env:")


def _is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return False


def _load_config(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return {}, None
    if _is_symlink(path):
        return None, "config_symlink"
    try:
        parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError, yaml.YAMLError, RecursionError) as exc:
        return None, exc.__class__.__name__
    if not isinstance(parsed, dict):
        return None, "config_not_mapping"
    return parsed, None


def _configured_plugin_names(config: dict[str, Any]) -> tuple[set[str], list[str]]:
    names: set[str] = set()
    shape_errors: list[str] = []
    for key in PLUGIN_CONFIG_KEYS:
        if key not in config:
            continue
        value = config[key]
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    names.add(item.strip())
                elif isinstance(item, dict):
                    item_name = item.get("name") or item.get("id")
                    if isinstance(item_name, str) and item_name.strip():
                        names.add(item_name.strip())
        elif isinstance(value, dict):
            for plugin_name, plugin_cfg in value.items():
                if isinstance(plugin_name, str) and plugin_name.strip():
                    names.add(plugin_name.strip())
                if isinstance(plugin_cfg, dict):
                    item_name = plugin_cfg.get("name") or plugin_cfg.get("id")
                    if isinstance(item_name, str) and item_name.strip():
                        names.add(item_name.strip())
        elif isinstance(value, str) and value.strip():
            names.add(value.strip())
        else:
            shape_errors.append(f"{key}:{type(value).__name__}")
    return names, shape_errors


def _plugin_dirs(plugins_root: Path) -> tuple[list[Path], int]:
    if not plugins_root.exists():
        return [], 0
    if _is_symlink(plugins_root):
        return [], 1
    if not plugins_root.is_dir():
        return [], 0
    dirs: list[Path] = []
    skipped = 0
    try:
        entries = sorted(plugins_root.iterdir())
    except OSError:
        return [], 1
    for entry in entries:
        if _is_symlink(entry):
            skipped += 1
            continue
        if entry.is_dir():
            dirs.append(entry)
    return dirs, skipped


def _read_manifest(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if _is_symlink(path):
        return None, "symlink"
    try:
        stat = path.stat()
    except OSError:
        return None, "stat_failed"
    if stat.st_size > MAX_MANIFEST_BYTES:
        return None, "manifest_too_large"
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None, "read_failed"
    if path.suffix.lower() == ".json":
        try:
            parsed = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return None, "json_invalid"
    elif path.suffix.lower() in {".yaml", ".yml"}:
        try:
            parsed = yaml.safe_load(raw) or {}
        except yaml.YAMLError:
            return None, "yaml_invalid"
    else:
        return {"manifest_type": path.name}, None
    if not isinstance(parsed, dict):
        return None, "manifest_not_mapping"
    return parsed, None


def _manifest_files(plugin_dir: Path) -> list[Path]:
    return [plugin_dir / name for name in MANIFEST_NAMES if (plugin_dir / name).exists()]


def _manifest_name(metadata: dict[str, Any], fallback: str) -> str:
    for key in ("name", "id", "plugin", "title"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    project = metadata.get("project")
    if isinstance(project, dict):
        value = project.get("name")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def _inline_sensitive_keys(metadata: Any) -> list[str]:
    risky: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_s = str(key)
                item_s = item if isinstance(item, str) else ""
                if (any(part in key_s.lower() for part in SECRET_KEY_PARTS)
                        and item_s and not item_s.strip().startswith(PLACEHOLDER_PREFIXES)):
                    risky.append(key_s)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(metadata)
    return sorted(set(risky))


def _severity(findings: list[Finding]) -> Severity:
    if any(f.severity == "FAIL" for f in findings):
        return "FAIL"
    if any(f.severity == "UNKNOWN" for f in findings):
        return "UNKNOWN"
    if any(f.severity == "WARN" for f in findings):
        return "WARN"
    return "OK"


def plugins_check(hermes_home: Path) -> CheckResult:
    findings: list[Finding] = []
    facts: dict[str, Any] = {
        "profiles_scanned": 0,
        "configured_plugins": 0,
        "plugin_dirs": 0,
        "manifest_files": 0,
        "manifests_ok": 0,
        "symlinks_skipped": 0,
        "payloads_executed": "not_run",
    }
    for profile_name, profile_path in profile_dirs(hermes_home):
        facts["profiles_scanned"] += 1
        config, error = _load_config(profile_path / "config.yaml")
        configured: set[str] = set()
        if error:
            findings.append(
                Finding(
                    id="plugins.config_unreadable",
                    severity="WARN",
                    component="plugins",
                    profile=profile_name,
                    summary="Plugin config could not be inspected because config.yaml is unreadable",
                    evidence=[f"profile={profile_name}", f"error={error}"],
                    risk="Configured plugins may be hidden by malformed or unsafe config.",
                    next_action="Validate config.yaml syntax before trusting plugin status.",
                )
            )
        else:
            assert config is not None
            configured, shape_errors = _configured_plugin_names(config)
            facts["configured_plugins"] += len(configured)
            for shape_error in shape_errors:
                findings.append(
                    Finding(
                        id="plugins.config_shape_invalid",
                        severity="WARN",
                        component="plugins",
                        profile=profile_name,
                        summary="Plugin config has an unsupported shape",
                        evidence=[shape_error],
                        risk="Hermes may ignore this plugin config entry.",
                        next_action="Use a list or mapping of plugin names/config objects.",
                    )
                )
        plugins_root = profile_path / "plugins"
        plugin_dirs, skipped = _plugin_dirs(plugins_root)
        facts["symlinks_skipped"] += skipped
        if skipped:
            findings.append(
                Finding(
                    id="plugins.symlink_skipped",
                    severity="WARN",
                    component="plugins",
                    profile=profile_name,
                    summary="Symlinked plugin paths were skipped",
                    evidence=[safe_relpath(plugins_root, hermes_home), f"skipped={skipped}"],
                    risk="A plugin path may point outside the inspected Hermes profile.",
                    next_action="Inspect symlinked plugin paths manually before loading or cleaning them.",
                )
            )
        facts["plugin_dirs"] += len(plugin_dirs)
        if len(plugin_dirs) > TOO_MANY_PLUGINS:
            findings.append(
                Finding(
                    id="plugins.too_many",
                    severity="WARN",
                    component="plugins",
                    profile=profile_name,
                    summary="Profile has many plugin directories",
                    evidence=[f"profile={profile_name} plugin_dirs={len(plugin_dirs)}"],
                    risk="Large plugin surfaces increase startup and security review complexity.",
                    next_action="Review plugin inventory; do not remove automatically.",
                )
            )
        discovered_names: set[str] = set()
        for plugin_dir in plugin_dirs:
            manifests = _manifest_files(plugin_dir)
            if not manifests:
                findings.append(
                    Finding(
                        id="plugins.manifest_missing",
                        severity="WARN",
                        component="plugins",
                        profile=profile_name,
                        summary="Plugin directory has no recognized manifest",
                        evidence=[safe_relpath(plugin_dir, hermes_home)],
                        risk="The doctor cannot identify this plugin's metadata safely.",
                        next_action="Add a plugin.yaml/manifest.yaml/plugin.json/manifest.json/pyproject.toml/package.json or verify the directory manually.",
                    )
                )
                discovered_names.add(plugin_dir.name)
                continue
            for manifest in manifests:
                facts["manifest_files"] += 1
                label = safe_relpath(manifest, hermes_home)
                metadata, manifest_error = _read_manifest(manifest)
                if manifest_error == "symlink":
                    facts["symlinks_skipped"] += 1
                    findings.append(
                        Finding(
                            id="plugins.symlink_skipped",
                            severity="WARN",
                            component="plugins",
                            profile=profile_name,
                            summary="Symlinked plugin manifest was skipped",
                            evidence=[label],
                            risk="A plugin manifest may point outside the inspected profile.",
                            next_action="Inspect this symlink manually before loading the plugin.",
                        )
                    )
                    continue
                if manifest_error:
                    findings.append(
                        Finding(
                            id="plugins.manifest_invalid",
                            severity="WARN",
                            component="plugins",
                            profile=profile_name,
                            summary="Plugin manifest is invalid or too large to parse safely",
                            evidence=[label, f"error={manifest_error}"],
                            risk="Hermes may fail to load this plugin or metadata may be stale.",
                            next_action="Fix or replace the manifest after backing up the plugin directory.",
                        )
                    )
                    continue
                facts["manifests_ok"] += 1
                assert metadata is not None
                discovered_names.add(_manifest_name(metadata, plugin_dir.name))
                risky_keys = _inline_sensitive_keys(metadata)
                if risky_keys:
                    findings.append(
                        Finding(
                            id="plugins.inline_secret_metadata",
                            severity="WARN",
                            component="plugins",
                            profile=profile_name,
                            summary="Plugin manifest appears to contain inline sensitive values",
                            evidence=[label, "keys=" + ",".join(risky_keys)],
                            risk="Plugin manifests can be committed or shared accidentally; keep secrets in env/config outside manifests.",
                            next_action="Move sensitive values to environment variables or a local .env file.",
                        )
                    )
        for plugin_name in sorted(configured):
            if plugin_name not in discovered_names and not (plugins_root / plugin_name).exists():
                findings.append(
                    Finding(
                        id="plugins.configured_missing",
                        severity="WARN",
                        component="plugins",
                        profile=profile_name,
                        summary="Plugin is configured but no matching plugin directory was found",
                        evidence=[f"plugin={plugin_name}"],
                        risk="Hermes may fail to load or silently skip this configured plugin.",
                        next_action="Run hermes plugins list and verify installation; do not install/remove automatically.",
                    )
                )
    severity = _severity(findings)
    return CheckResult(
        "plugins",
        severity,
        f"configured={facts['configured_plugins']} dirs={facts['plugin_dirs']} manifests={facts['manifest_files']}",
        findings,
        facts,
    )
