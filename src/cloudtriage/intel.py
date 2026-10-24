"""CVE enrichment: explicit simulated fixtures or bounded public-feed reads."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import date
from typing import Any

from .http import request_json
from .models import number


@dataclass(frozen=True)
class Intel:
    cve: str
    epss: float | None
    kev: bool | None
    epss_date: str | None
    kev_date: str | None
    provenance: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def uncertain(self, as_of: date, max_age_days: int) -> bool:
        if self.epss is None or self.kev is None:
            return True
        for observed in (self.epss_date, self.kev_date):
            if observed is None:
                return True
            age = (as_of - date.fromisoformat(observed)).days
            if age < 0 or age > max_age_days:
                return True
        return False


def fixture_intel(document: dict, cves: set[str]) -> dict[str, Intel]:
    if document.get("simulated") is not True:
        raise ValueError("offline intel must declare simulated=true")
    observed = document["as_of"]
    date.fromisoformat(observed)
    result = {}
    for cve in sorted(cves):
        row = document["data"].get(cve, {})
        epss = row.get("epss")
        kev = row.get("kev")
        if epss is not None:
            epss = number(epss, 0, 1)
        if kev is not None and not isinstance(kev, bool):
            raise ValueError("KEV must be boolean or unknown")
        result[cve] = Intel(
            cve,
            epss,
            kev,
            observed if epss is not None else None,
            observed if kev is not None else None,
            "simulated-fixture",
        )
    return result


async def live_intel(cves: set[str]) -> dict[str, Intel]:
    """Fail the run on feed failure; never disguise fixtures as current intelligence."""
    if not cves:
        return {}
    kev_document = await asyncio.to_thread(
        request_json,
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        allowed_host="www.cisa.gov",
        retries=2,
    )
    kev_date = kev_document["dateReleased"][:10]
    date.fromisoformat(kev_date)
    kev_ids = {row["cveID"] for row in kev_document["vulnerabilities"]}
    semaphore = asyncio.Semaphore(4)

    async def enrich(cve: str) -> Intel:
        async with semaphore:
            response = await asyncio.to_thread(
                request_json,
                f"https://api.first.org/data/v1/epss?cve={cve}",
                allowed_host="api.first.org",
                retries=2,
            )
            rows = response["data"]
            row = rows[0] if rows else None
            if row and row["cve"] != cve:
                raise ValueError("EPSS response CVE mismatch")
            observed = row["date"] if row else None
            if observed:
                date.fromisoformat(observed)
            return Intel(
                cve,
                number(float(row["epss"]), 0, 1) if row else None,
                cve in kev_ids,
                observed,
                kev_date,
                "FIRST-EPSS+CISA-KEV",
            )

    values = await asyncio.gather(*(enrich(cve) for cve in sorted(cves)))
    return {item.cve: item for item in values}
