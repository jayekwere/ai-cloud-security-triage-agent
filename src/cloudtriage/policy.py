"""Versioned and explainable decision policy. Models cannot override these decisions."""

from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from .intel import Intel
from .models import CLASSES, Finding, digest


@dataclass(frozen=True)
class Decision:
    finding_id: str
    score: int
    priority: str
    due_at: str
    reasons: tuple[str, ...]
    uncertainties: tuple[str, ...]
    policy_version: str
    policy_digest: str
    policy_config_digest: str
    policy_code_digest: str

    def as_dict(self) -> dict:
        return asdict(self)


class Policy:
    def __init__(self, path: Path):
        self.config = tomllib.loads(path.read_text())
        self.config_digest = digest(self.config)
        self.code_digest = digest(Path(__file__).read_text())
        self.digest = digest(
            {"configuration": self.config_digest, "implementation": self.code_digest}
        )
        c = self.config
        if not (0 <= c["p3_threshold"] < c["p2_threshold"] < c["p1_threshold"] <= 100):
            raise ValueError("policy thresholds must be strictly increasing")
        if type(c["max_intel_age_days"]) is not int or not 0 <= c["max_intel_age_days"] <= 30:
            raise ValueError("invalid intel freshness policy")
        for priority in ("P1", "P2", "P3", "P4"):
            hours = c["sla_hours"][priority]
            if type(hours) is not int or not 1 <= hours <= 8760:
                raise ValueError("invalid SLA")

    def evaluate(self, finding: Finding, intel: Intel | None, as_of: date) -> Decision:
        parts: list[tuple[int, str]] = [(round(finding.cvss * 3), "CVSS severity × 3")]
        unknown = []
        if finding.kind != "vulnerability":
            parts.append((25, "cloud configuration baseline"))
        if finding.cve:
            if intel is None or intel.uncertain(as_of, self.config["max_intel_age_days"]):
                unknown.append(
                    "missing, stale, or future-dated CVE intelligence; manual verification"
                )
            if intel and intel.epss is not None:
                parts.append((round(intel.epss * 20), "EPSS exploitation likelihood × 20"))
            if intel and intel.kev is True:
                parts.append((35, "CISA KEV membership (observed or simulated per provenance)"))
        if finding.internet_exposed:
            parts.append((15, "internet exposure"))
        parts.append((finding.criticality * 2, "asset criticality × 2"))
        if CLASSES[finding.data_class] >= 2:
            parts.append((10, "confidential/restricted data classification"))
        if finding.privileged:
            parts.append((10, "privileged workload or entitlement"))
        score = min(100, sum(points for points, _ in parts))
        priority = next(
            (p for p in ("P1", "P2", "P3") if score >= self.config[f"{p.lower()}_threshold"]), "P4"
        )
        reasons = [f"+{points}: {why}" for points, why in parts if points]
        if finding.internet_exposed and (
            (intel is not None and intel.kev is True)
            or (finding.kind == "storage_public" and CLASSES[finding.data_class] >= 2)
        ):
            priority = "P1"
            reasons.append("P1 override: exposed KEV asset or exposed sensitive storage")
        if unknown and priority not in {"P1", "P2"}:
            priority = "P2"
            reasons.append("P2 floor: incomplete intelligence cannot imply low risk")
        if finding.kind == "iam_wildcard" and finding.privileged and priority not in {"P1", "P2"}:
            priority = "P2"
            reasons.append("P2 floor: privileged wildcard entitlement requires expedited review")
        due = datetime.combine(as_of, datetime.min.time(), tzinfo=UTC) + timedelta(
            hours=self.config["sla_hours"][priority]
        )
        return Decision(
            finding.id,
            score,
            priority,
            due.isoformat(),
            tuple(reasons),
            tuple(unknown),
            self.config["version"],
            self.digest,
            self.config_digest,
            self.code_digest,
        )
