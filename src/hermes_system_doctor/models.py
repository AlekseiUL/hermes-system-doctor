from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Severity = Literal["OK", "WARN", "FAIL", "UNKNOWN", "NEEDS_APPROVAL"]


@dataclass
class Finding:
    id: str
    severity: Severity
    component: str
    summary: str
    profile: str | None = None
    evidence: list[str] = field(default_factory=list)
    risk: str | None = None
    next_action: str | None = None
    requires_approval: bool = False
    confidence: str = "medium"


@dataclass
class CheckResult:
    name: str
    severity: Severity
    summary: str
    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)


@dataclass
class DoctorReport:
    mode: str
    status: Severity
    generated_at: str
    hermes_home: str
    checks: list[CheckResult]

    @classmethod
    def build(cls, mode: str, hermes_home: str, checks: list[CheckResult]) -> DoctorReport:
        order = ["OK", "UNKNOWN", "WARN", "FAIL", "NEEDS_APPROVAL"]
        status: Severity = "OK"
        for check in checks:
            if order.index(check.severity) > order.index(status):
                status = check.severity
        return cls(
            mode=mode,
            status=status,
            generated_at=datetime.now(timezone.utc).isoformat(),
            hermes_home=hermes_home,
            checks=checks,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
