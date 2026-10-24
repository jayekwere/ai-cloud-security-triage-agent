import json
from dataclasses import replace
from datetime import date

import pytest

from cloudtriage.intel import Intel, fixture_intel
from cloudtriage.models import load_json, normalize, number
from cloudtriage.pipeline import data_path, run

DAY = date(2026, 10, 23)


def test_conservative_dedup_and_raw_text_exclusion():
    normalized, count = normalize(load_json(data_path("findings.json")))
    assert count == 9 and len(normalized) == 8
    duplicate = next(f for f in normalized if len(f.sources) == 2)
    assert duplicate.cvss == 10 and duplicate.privileged
    assert duplicate.criticality == 5 and duplicate.data_class == "restricted"
    assert "Ignore previous" not in json.dumps([f.as_dict() for f in normalized])
    assert "asset" not in duplicate.ai_view()


@pytest.mark.parametrize(
    "field,value",
    [
        ("resource", "../../etc/passwd"),
        ("resource", "https://evil.example"),
        ("cloud", "gcp"),
        ("criticality", True),
        ("criticality", 2.5),
        ("internet_exposed", "false"),
        ("privileged", 1),
        ("cve", "$(env)"),
        ("data_class", "patient-name"),
        ("severity_score", float("nan")),
    ],
)
def test_invalid_vendor_data_rejected(field, value):
    document = load_json(data_path("findings.json"))
    document["wiz"][0][field] = value
    with pytest.raises(ValueError):
        normalize(document)


@pytest.mark.parametrize("value", [float("inf"), float("nan"), -1, 11, True, "9.8"])
def test_numeric_contract(value):
    with pytest.raises(ValueError):
        number(value, 0, 10)


def test_non_synthetic_and_large_input_rejected(tmp_path):
    document = load_json(data_path("findings.json"))
    document["synthetic"] = False
    with pytest.raises(ValueError, match="synthetic"):
        normalize(document)
    path = tmp_path / "oversized.json"
    path.write_text("x" * 1_000_001)
    with pytest.raises(ValueError, match="1 MB"):
        load_json(path)


def test_kev_public_overrides_cvss(policy, findings):
    f = replace(next(f for f in findings if f.cve), cvss=1, internet_exposed=True)
    evidence = Intel(f.cve, 0.01, True, DAY.isoformat(), DAY.isoformat(), "test")
    result = policy.evaluate(f, evidence, DAY)
    assert result.priority == "P1"
    assert result.score < 80
    assert result.due_at == "2026-10-24T00:00:00+00:00"


@pytest.mark.parametrize("observed", [None, "2026-10-01", "2027-01-01"])
def test_uncertainty_cannot_silently_downgrade(policy, findings, observed):
    f = replace(
        next(f for f in findings if f.cve),
        cvss=0,
        internet_exposed=False,
        privileged=False,
        criticality=1,
        data_class="public",
    )
    evidence = Intel(f.cve, 0.0, False, observed, observed, "test")
    result = policy.evaluate(f, evidence, DAY)
    assert result.priority == "P2" and result.uncertainties


def test_missing_is_not_known_negative():
    intel = fixture_intel(load_json(data_path("intel.json")), {"CVE-2099-9999999"})
    assert intel["CVE-2099-9999999"].kev is None
    assert intel["CVE-2099-9999999"].epss is None


def test_exposed_sensitive_storage_override(policy, findings):
    f = next(f for f in findings if f.kind == "storage_public")
    assert policy.evaluate(f, None, DAY).priority == "P1"


def test_high_severity_internal_is_not_automatically_p1(policy, findings):
    f = next(f for f in findings if f.cve == "CVE-2024-3094")
    evidence = Intel(f.cve, 0.04, False, DAY.isoformat(), DAY.isoformat(), "test")
    assert policy.evaluate(f, evidence, DAY).priority == "P3"


def test_privileged_wildcard_and_public_network_require_expedited_review(policy, findings):
    for kind in ("iam_wildcard", "network_open"):
        finding = next(f for f in findings if f.kind == kind)
        assert policy.evaluate(finding, None, DAY).priority == "P2"


def test_known_low_risk_can_be_p4(policy, findings):
    finding = replace(
        next(f for f in findings if f.cve),
        cvss=1,
        criticality=1,
        privileged=False,
        internet_exposed=False,
        data_class="public",
    )
    evidence = Intel(finding.cve, 0.0, False, DAY.isoformat(), DAY.isoformat(), "test")
    result = policy.evaluate(finding, evidence, DAY)
    assert result.priority == "P4" and not result.uncertainties


def test_demo_reproducible_and_no_network(tmp_path, monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("offline demo attempted network")

    monkeypatch.setattr("urllib.request.OpenerDirector.open", deny)
    a, b = tmp_path / "a", tmp_path / "b"
    first = run(a)
    second = run(b)
    assert first == second
    assert first["external_changes"] == 0
    for path in a.iterdir():
        assert path.read_bytes() == (b / path.name).read_bytes()
    with pytest.raises(FileExistsError):
        run(a)


def test_invalid_policy_thresholds(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text(
        data_path("policy.toml").read_text().replace("p1_threshold = 80", "p1_threshold = 20")
    )
    from cloudtriage.policy import Policy

    with pytest.raises(ValueError, match="threshold"):
        Policy(path)


def test_policy_evidence_binds_implementation_as_well_as_config(monkeypatch):
    from pathlib import Path

    from cloudtriage.policy import Policy

    first = Policy(data_path("policy.toml"))
    original = Path.read_text

    def changed_implementation(path, *args, **kwargs):
        text = original(path, *args, **kwargs)
        return text + "\n# implementation revision\n" if path.name == "policy.py" else text

    monkeypatch.setattr(Path, "read_text", changed_implementation)
    second = Policy(data_path("policy.toml"))
    assert first.config_digest == second.config_digest
    assert first.code_digest != second.code_digest
    assert first.digest != second.digest
