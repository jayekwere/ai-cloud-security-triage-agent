"""Typed, fail-closed normalization boundary for vendor-inspired synthetic exports."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 1_000_000
KINDS = {"vulnerability", "storage_public", "iam_wildcard", "network_open"}
CLASSES = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def load_json(path: Path) -> Any:
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds 1 MB limit")
    return json.loads(raw)


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", value):
        raise ValueError("expected an opaque identifier, not a path, URL or free text")
    return value


def number(value: Any, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError("expected numeric value")
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError("numeric value outside allowed bounds")
    return float(value)


def boolean(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError("expected boolean; string booleans are forbidden")
    return value


@dataclass(frozen=True)
class Finding:
    id: str
    asset: str
    cloud: str
    kind: str
    cve: str | None
    cvss: float
    internet_exposed: bool
    privileged: bool
    criticality: int
    data_class: str
    sources: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def ai_view(self) -> dict[str, Any]:
        """Only schema-controlled fields cross the model boundary; omit asset identity."""
        return {k: v for k, v in self.as_dict().items() if k not in {"asset", "sources"}}


def normalize(document: Any) -> tuple[list[Finding], int]:
    if not isinstance(document, dict) or set(document) != {"synthetic", "wiz", "qualys"}:
        raise ValueError("expected synthetic Wiz/Qualys-inspired export envelope")
    if document["synthetic"] is not True:
        raise ValueError("this portfolio build accepts explicitly synthetic data only")
    merged: dict[str, Finding] = {}
    count = 0
    for vendor in ("wiz", "qualys"):
        if not isinstance(document[vendor], list) or len(document[vendor]) > 500:
            raise ValueError("each vendor must contain at most 500 records")
        for row in document[vendor]:
            count += 1
            if not isinstance(row, dict):
                raise ValueError("finding must be an object")
            # These are intentionally small, documented adapter contracts, not vendor APIs.
            if vendor == "wiz":
                asset, kind, cvss = row["resource"], row["control"], row["severity_score"]
            else:
                asset, kind, cvss = row["asset_id"], row["category"], row["cvss_base"]
            asset = identifier(asset)
            cloud = row["cloud"]
            cve = row.get("cve")
            if cloud not in {"aws", "azure"} or kind not in KINDS:
                raise ValueError("unsupported cloud or control")
            if cve is not None and (
                not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve)
            ):
                raise ValueError("invalid CVE")
            if (kind == "vulnerability") != (cve is not None):
                raise ValueError("only vulnerability findings require a CVE")
            criticality = row["criticality"]
            number(criticality, 1, 5)
            if type(criticality) is not int:
                raise ValueError("criticality must be an integer")
            data_class = row["data_class"]
            if data_class not in CLASSES:
                raise ValueError("unsupported classification")
            key = digest([cloud, asset, kind, cve])[:16]
            finding = Finding(
                key,
                asset,
                cloud,
                kind,
                cve,
                number(cvss, 0, 10),
                boolean(row["internet_exposed"]),
                boolean(row["privileged"]),
                criticality,
                data_class,
                (vendor,),
            )
            if previous := merged.get(key):
                finding = replace(
                    finding,
                    cvss=max(previous.cvss, finding.cvss),
                    internet_exposed=previous.internet_exposed or finding.internet_exposed,
                    privileged=previous.privileged or finding.privileged,
                    criticality=max(previous.criticality, finding.criticality),
                    data_class=max((previous.data_class, finding.data_class), key=CLASSES.get),
                    sources=tuple(sorted(set(previous.sources + finding.sources))),
                )
            merged[key] = finding
    return sorted(merged.values(), key=lambda f: f.id), count
