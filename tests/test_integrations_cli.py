import asyncio
import io
import json
from unittest.mock import patch

import pytest

from cloudtriage.cli import execute, parser
from cloudtriage.http import NoRedirect, request_json
from cloudtriage.intel import live_intel
from cloudtriage.pipeline import run


@pytest.mark.parametrize(
    "url",
    [
        "http://api.first.org/data",
        "https://evil.example/data",
        "https://api.first.org:444/data",
        "file:///etc/passwd",
        "https://user:password@api.first.org/data",
    ],
)
def test_transport_rejects_unsafe_destinations(url):
    with pytest.raises(ValueError, match="destination"):
        request_json(url, allowed_host="api.first.org")


def test_redirect_rejected():
    with pytest.raises(ValueError, match="redirect"):
        NoRedirect().redirect_request(None, None, None, None, None, "https://evil.example")


def test_http_payload_and_limit():
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    with patch("urllib.request.OpenerDirector.open", return_value=Response(b'{"ok":true}')):
        assert request_json("https://api.first.org/data", allowed_host="api.first.org") == {
            "ok": True
        }
    with (
        patch("urllib.request.OpenerDirector.open", return_value=Response(b"x" * 8_000_001)),
        pytest.raises(ValueError, match="8 MB"),
    ):
        request_json("https://api.first.org/data", allowed_host="api.first.org")


def test_live_feed_contract_and_missing_epss(monkeypatch):
    def transport(url, **kwargs):
        if "cisa.gov" in url:
            return {
                "dateReleased": "2026-10-23T12:00:00Z",
                "vulnerabilities": [{"cveID": "CVE-2021-44228"}],
            }
        if "CVE-2021-44228" in url:
            return {"data": [{"cve": "CVE-2021-44228", "epss": "0.8", "date": "2026-10-23"}]}
        return {"data": []}

    monkeypatch.setattr("cloudtriage.intel.request_json", transport)
    result = asyncio.run(live_intel({"CVE-2021-44228", "CVE-2099-9999999"}))
    assert result["CVE-2021-44228"].kev is True
    assert result["CVE-2021-44228"].epss == 0.8
    assert result["CVE-2099-9999999"].kev is False  # absent from a successfully read catalog
    assert result["CVE-2099-9999999"].epss is None


def test_model_egress_requires_opt_in(tmp_path):
    args = parser().parse_args(["triage", "--out", str(tmp_path / "run"), "--provider", "openai"])
    with pytest.raises(PermissionError, match="egress"):
        execute(args)


def test_approval_cli_requires_interactive_terminal(tmp_path, monkeypatch):
    run(tmp_path / "run")
    intent = json.loads((tmp_path / "run/jira-dry-run.json").read_text())[0]
    path = tmp_path / "intent.json"
    path.write_text(json.dumps(intent))
    args = parser().parse_args(
        [
            "approve",
            "--intent",
            str(path),
            "--ledger",
            str(tmp_path / "ledger.sqlite"),
            "--reviewer",
            "reviewer",
        ]
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(PermissionError, match="interactive"):
        execute(args)


def test_report_does_not_execute_untrusted_html(tmp_path):
    from cloudtriage.pipeline import render_html

    report = run(tmp_path / "run")
    report["results"][0]["finding"]["asset"] = '<img src=x onerror="alert(1)">'
    text = render_html(report)
    assert "<img src=x" not in text and "&lt;img src=x" in text


def test_live_mode_report_wording_and_provenance(tmp_path, monkeypatch):
    from cloudtriage.intel import fixture_intel
    from cloudtriage.models import load_json
    from cloudtriage.pipeline import data_path

    async def simulated_live(cves):
        return fixture_intel(load_json(data_path("intel.json")), cves)

    monkeypatch.setattr("cloudtriage.pipeline.live_intel", simulated_live)
    report = run(tmp_path / "live", intel_mode="live")
    assert report["intel_mode"] == "live"
    text = (tmp_path / "live/report.html").read_text()
    assert "Live public intelligence" in text
    assert "Offline EPSS/KEV" not in text
