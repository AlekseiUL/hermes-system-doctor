from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .checks import (
    auth_surface_check,
    config_check,
    cron_check,
    discover_home,
    gateway_check,
    logs_check,
    mcp_check,
    memory_check,
    plugins_check,
    post_update_drift_check,
    profile_inventory_check,
    skills_check,
)
from .fix_executor import (
    build_fix_preview,
    fix_preview_to_json,
    fix_preview_to_markdown,
    load_repair_plan,
)
from .models import DoctorReport
from .path_utils import safe_home_label
from .repair_plan import (
    build_repair_plan,
    load_report,
    repair_plan_to_json,
    repair_plan_to_markdown,
)
from .reporting import to_json, to_markdown


def build_report(mode: str, hermes_home: Path) -> DoctorReport:
    checks = [discover_home(hermes_home)]
    if mode in {"quick", "full", "post-update"}:
        checks.extend(
            [
                profile_inventory_check(hermes_home),
                config_check(hermes_home),
                gateway_check(hermes_home),
                cron_check(hermes_home),
                logs_check(hermes_home),
                auth_surface_check(hermes_home),
                memory_check(hermes_home),
                skills_check(hermes_home),
                plugins_check(hermes_home),
                mcp_check(hermes_home),
            ]
        )
    if mode in {"full", "post-update"}:
        checks.append(post_update_drift_check(hermes_home))
    return DoctorReport.build(mode=mode, hermes_home=safe_home_label(hermes_home), checks=checks)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hermes-system-doctor")
    p.add_argument("command", choices=["discover", "quick", "full", "post-update", "repair-plan", "fix", "version"])
    p.add_argument("--hermes-home", default=None, help="Hermes home to inspect; required for registered fix executors")
    p.add_argument(
        "--all-profiles",
        action="store_true",
        help="Scan all profiles under the selected Hermes home; currently the default when profiles/ exists.",
    )
    p.add_argument("--json", action="store_true")
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--output")
    p.add_argument("--input", help="Input JSON report for repair-plan mode")
    p.add_argument("--plan", help="Input repair-plan JSON for fix preview mode")
    p.add_argument("--approve", help="Approved repair-plan action id for fix preview mode")
    p.add_argument("--execute", action="store_true", help="Apply a registered approved fix executor; blocked for unregistered actions")
    p.add_argument("--fail-on", choices=["unknown", "warn", "fail", "needs-approval"], default=None)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "repair-plan":
        if not args.input:
            parser().error("repair-plan requires --input report.json")
        plan = build_repair_plan(load_report(Path(args.input)))
        rendered = repair_plan_to_markdown(plan) if args.markdown else repair_plan_to_json(plan)
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    if args.command == "fix":
        if not args.plan:
            parser().error("fix requires --plan repair-plan.json")
        if not args.approve:
            parser().error("fix requires --approve action-id")
        try:
            preview = build_fix_preview(
                load_repair_plan(Path(args.plan)),
                args.approve,
                hermes_home=Path(args.hermes_home).expanduser() if args.hermes_home else None,
                execute=args.execute,
            )
        except (OSError, ValueError) as exc:
            parser().error(f"fix failed: {exc}")
        rendered = fix_preview_to_markdown(preview) if args.markdown else fix_preview_to_json(preview)
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        if preview.status.startswith("BLOCKED"):
            return 2 if args.execute else 1
        return 0
    report = build_report(args.command, Path(args.hermes_home or "~/.hermes").expanduser())
    rendered = to_json(report) if args.json else to_markdown(report)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if args.fail_on == "unknown" and report.status in {"UNKNOWN", "WARN", "FAIL", "NEEDS_APPROVAL"}:
        return 1
    if args.fail_on == "warn" and report.status in {"WARN", "FAIL", "NEEDS_APPROVAL"}:
        return 1
    if args.fail_on == "fail" and report.status in {"FAIL", "NEEDS_APPROVAL"}:
        return 2
    if args.fail_on == "needs-approval" and report.status == "NEEDS_APPROVAL":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
