"""Hash-chained local events. Detects editing, not a malicious host rewriting the whole log."""

from __future__ import annotations

import json
from pathlib import Path

from .models import canonical, digest


class Audit:
    def __init__(self):
        self.events: list[dict] = []

    def record(self, event: str, **fields) -> None:
        allowed = {"finding_id", "tool", "outcome", "detail_digest", "mode", "count"}
        if set(fields) - allowed:
            raise ValueError("audit field is not allowlisted")
        row = {
            "seq": len(self.events) + 1,
            "event": event,
            **fields,
            "previous": self.events[-1]["hash"] if self.events else "0" * 64,
        }
        row["hash"] = digest(row)
        self.events.append(row)

    def write(self, path: Path) -> None:
        with path.open("x") as stream:
            for event in self.events:
                stream.write(canonical(event) + "\n")


def verify(path: Path) -> int:
    previous = "0" * 64
    count = 0
    with path.open() as stream:
        for count, line in enumerate(stream, 1):
            row = json.loads(line)
            claimed = row.pop("hash")
            if row["seq"] != count or row["previous"] != previous or digest(row) != claimed:
                raise ValueError("audit chain mismatch")
            previous = claimed
    if not count:
        raise ValueError("empty audit log")
    return count
