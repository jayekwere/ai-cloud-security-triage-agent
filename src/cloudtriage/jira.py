"""Jira Cloud v3 preview by default. Live writes require a separate human-approved intent."""

from __future__ import annotations

import base64
import re
from collections.abc import Callable
from datetime import UTC, datetime

from .approval import Approvals
from .audit import Audit
from .http import request_json
from .models import digest


def validate_intent(envelope: dict) -> None:
    if set(envelope) != {"action", "host", "project", "payload", "intent_id"}:
        raise ValueError("unexpected intent fields")
    if envelope["action"] != "jira.create_issue":
        raise ValueError("unsupported action")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}\.atlassian\.net", envelope["host"]):
        raise ValueError("only a specific Jira Cloud tenant hostname is supported")
    if not re.fullmatch(r"[A-Z][A-Z0-9]{1,19}", envelope["project"]):
        raise ValueError("invalid Jira project key")
    if envelope["payload"]["fields"]["project"]["key"] != envelope["project"]:
        raise ValueError("project/payload mismatch")
    datetime.fromisoformat(envelope["intent_id"])


def preview(result: dict, host: str, project: str, intent_id: str | None = None) -> dict:
    decision = result["decision"]
    proposal = result["agent"]["proposal"]
    text = (
        f"Synthetic portfolio finding {result['finding']['id']}. "
        f"Priority {decision['priority']}; due {decision['due_at']}. "
        f"Policy {decision['policy_version']}; digest {decision['policy_digest']}. "
        f"Proposal {proposal['proposal_digest']}. "
        "Confirm applicability and owner before action.\n" + "\n".join(proposal["steps"])
    )
    envelope = {
        "action": "jira.create_issue",
        "host": host,
        "project": project,
        "intent_id": intent_id or datetime.now(UTC).isoformat(),
        "payload": {
            "fields": {
                "project": {"key": project},
                "issuetype": {"name": "Task"},
                "summary": (
                    f"[Synthetic][{decision['priority']}] Review {result['finding']['kind']}"
                ),
                "labels": ["synthetic-portfolio", "cloudtriage"],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}],
                },
            }
        },
    }
    validate_intent(envelope)
    return envelope


def submit(
    envelope: dict,
    approvals: Approvals,
    email: str,
    token: str,
    audit: Audit,
    transport: Callable = request_json,
) -> dict:
    validate_intent(envelope)
    if not email or not token:
        raise ValueError("Jira credentials required for explicit submit only")
    try:
        key = approvals.reserve(envelope)
    except PermissionError:
        audit.record(
            "jira_submit_denied", outcome="approval_required", detail_digest=digest(envelope)
        )
        raise
    audit.record("jira_submit_started", outcome="reserved", detail_digest=key)
    credential = base64.b64encode(f"{email}:{token}".encode()).decode()
    try:
        response = transport(
            f"https://{envelope['host']}/rest/api/3/issue",
            allowed_host=envelope["host"],
            payload=envelope["payload"],
            headers={"Authorization": f"Basic {credential}"},
        )
        ticket = response["key"]
        if not re.fullmatch(re.escape(envelope["project"]) + r"-\d+", ticket):
            raise ValueError("unexpected Jira response key")
    except Exception:
        approvals.finish(key, "unknown")
        audit.record("jira_submit_finished", outcome="unknown_do_not_retry", detail_digest=key)
        raise RuntimeError(
            "Jira outcome unknown; reconcile tenant before creating another intent"
        ) from None
    approvals.finish(key, "sent")
    audit.record("jira_submit_finished", outcome="sent", detail_digest=digest(ticket))
    return {"key": ticket, "url": f"https://{envelope['host']}/browse/{ticket}", "status": "sent"}
