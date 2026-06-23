from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    severity: str        # "high" | "medium" | "low" | "info"
    label: str           # short headline, e.g. "Trailing data after PNG IEND"
    detail: str          # human-readable explanation
    artifact: str | None = None  # path to extracted file, if any


@dataclass
class ModuleResult:
    name: str
    status: str          # "ok" | "skipped" | "error"
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""
    duration_s: float = 0.0
