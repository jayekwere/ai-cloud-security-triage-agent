import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from cloudtriage.approval import Approvals
from cloudtriage.audit import Audit
from cloudtriage.jira import preview, submit
from cloudtriage.models import digest
from cloudtriage.pipeline import run


@pytest.fixture
def intent(tmp_path):
    result = run(tmp_path / "run")["results"][0]
    return preview(result, "example.atlassian.net", "SEC", "2026-10-23T00:00:00+00:00")


def approve(store, intent, **kwargs):
    store.approve(intent, "human-reviewer", f"APPROVE {digest(intent)}", **kwargs)


def test_no_approval_no_network(intent, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("remote write without approval")

    with Approvals(tmp_path / "approval.sqlite") as store, pytest.raises(PermissionError):
        submit(intent, store, "test@example.com", "test-only-token", Audit(), forbidden)


def test_requires_full_confirmation(intent, tmp_path):
    with Approvals(tmp_path / "approval.sqlite") as store, pytest.raises(PermissionError):
        store.approve(intent, "reviewer", "yes")


@pytest.mark.parametrize("mutation", ["host", "project", "payload"])
def test_approval_bound_to_destination_and_payload(intent, tmp_path, mutation):
    with Approvals(tmp_path / "approval.sqlite") as store:
        approve(store, intent)
        changed = copy.deepcopy(intent)
        if mutation == "payload":
            changed["payload"]["fields"]["summary"] = "different content"
        else:
            changed[mutation] = "OTHER" if mutation == "project" else "other.atlassian.net"
        with pytest.raises(PermissionError):
            store.reserve(changed)


def test_expiry_and_replay(intent, tmp_path):
    now = datetime.now(UTC)
    with Approvals(tmp_path / "approval.sqlite") as store:
        approve(store, intent, now=now)
        with pytest.raises(PermissionError):
            store.reserve(intent, now=now + timedelta(hours=1))
        store.reserve(intent, now=now)
        with pytest.raises(PermissionError):
            store.reserve(intent, now=now)


def test_atomic_concurrent_reservation(intent, tmp_path):
    path = tmp_path / "approval.sqlite"
    with Approvals(path) as store:
        approve(store, intent)

    def reserve(_):
        with Approvals(path) as store:
            try:
                store.reserve(intent)
                return True
            except PermissionError:
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(reserve, range(2))) == [False, True]


def test_one_approved_jira_submission(intent, tmp_path):
    observed = []

    def transport(url, **kwargs):
        observed.append((url, kwargs["payload"]))
        return {"key": "SEC-123"}

    audit = Audit()
    with Approvals(tmp_path / "approval.sqlite") as store:
        approve(store, intent)
        receipt = submit(intent, store, "test@example.com", "test-only-token", audit, transport)
        assert receipt["url"] == "https://example.atlassian.net/browse/SEC-123"
        with pytest.raises(PermissionError):
            submit(intent, store, "test@example.com", "test-only-token", audit, transport)
    assert observed == [("https://example.atlassian.net/rest/api/3/issue", intent["payload"])]
    assert "test-only-token" not in str(audit.events)


def test_ambiguous_remote_failure_is_consumed(intent, tmp_path):
    def transport(*args, **kwargs):
        raise TimeoutError("ambiguous timeout")

    with Approvals(tmp_path / "approval.sqlite") as store:
        approve(store, intent)
        with pytest.raises(RuntimeError, match="unknown"):
            submit(intent, store, "test@example.com", "test-only-token", Audit(), transport)
        with pytest.raises(PermissionError):
            store.reserve(intent)


@pytest.mark.parametrize(
    "host",
    [
        "http://example.atlassian.net",
        "example.atlassian.net.evil.org",
        "127.0.0.1",
        "example.atlassian.net@evil.org",
    ],
)
def test_jira_destination_allowlist(intent, host):
    from cloudtriage.jira import validate_intent

    intent["host"] = host
    with pytest.raises(ValueError):
        validate_intent(intent)
