"""Single-host approval ledger with expiry, digest binding and atomic replay protection."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import digest, identifier


def utcnow() -> datetime:
    return datetime.now(UTC)


class Approvals:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path, timeout=5)
        self.db.execute("""CREATE TABLE IF NOT EXISTS approvals (
            digest TEXT PRIMARY KEY, reviewer TEXT NOT NULL, expires TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('approved','submitting','sent','unknown'))
        )""")
        self.db.commit()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    def approve(
        self, envelope: dict, reviewer: str, confirmation: str, now: datetime | None = None
    ) -> str:
        key = digest(envelope)
        identifier(reviewer)
        if confirmation != f"APPROVE {key}":
            raise PermissionError("explicit human confirmation of full action digest required")
        now = now or utcnow()
        expires = (now + timedelta(hours=1)).isoformat()
        # Re-approving a consumed intent is forbidden; reconcile remotely and create a new intent.
        with self.db:
            self.db.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, 'approved')", (key, reviewer, expires)
            )
        return key

    def reserve(self, envelope: dict, now: datetime | None = None) -> str:
        key = digest(envelope)
        now = now or utcnow()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT expires,status FROM approvals WHERE digest=?", (key,)
            ).fetchone()
            if not row or row[1] != "approved" or datetime.fromisoformat(row[0]) <= now:
                raise PermissionError("approval missing, expired, changed or already consumed")
            self.db.execute("UPDATE approvals SET status='submitting' WHERE digest=?", (key,))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return key

    def finish(self, key: str, status: str) -> None:
        if status not in {"sent", "unknown"}:
            raise ValueError("invalid receipt status")
        with self.db:
            self.db.execute(
                "UPDATE approvals SET status=? WHERE digest=? AND status='submitting'",
                (status, key),
            )
