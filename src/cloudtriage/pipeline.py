"""Reproducible orchestration and locally rendered evidence artifacts."""

from __future__ import annotations

import asyncio
import html
import json
from collections import Counter
from collections.abc import Callable
from datetime import date
from importlib.resources import files
from pathlib import Path

from .agent import DeterministicPlanner, Planner, run_agent
from .audit import Audit
from .intel import fixture_intel, live_intel
from .jira import preview
from .models import digest, load_json, normalize
from .policy import Policy


def data_path(name: str) -> Path:
    return Path(str(files("cloudtriage").joinpath("data", name)))


def write_json(path: Path, value) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# Cloud Security Triage — Review Brief",
        "",
        f"**Synthetic independent project · {report['as_of']} · {report['provider']} planner**",
        "",
        f"{s['raw_findings']} records → {s['unique_findings']} unique findings; "
        f"{s['duplicates_merged']} duplicates merged. No external changes performed.",
        "",
        "| Finding | Cloud / control | Priority | Score | Review due (UTC) |",
        "|---|---|---|---:|---|",
    ]
    for item in report["results"]:
        f, d = item["finding"], item["decision"]
        lines.append(
            f"| {f['id']} | {f['cloud']} / {f['kind']} | {d['priority']} | "
            f"{d['score']} | {d['due_at']} |"
        )
    lines += [
        "",
        "Scores are triage heuristics, not breach probabilities or compliance attestations.",
        intel_notice(report),
        "Terraform proposals passed local structural controls, not provider validation or a plan.",
    ]
    for item in report["results"]:
        lines += [
            "",
            f"## {item['finding']['id']}",
            "",
            *[f"- {reason}" for reason in item["decision"]["reasons"]],
            *[f"- Uncertainty: {reason}" for reason in item["decision"]["uncertainties"]],
            "",
            "Proposed next steps:",
            "",
            *[f"- {step}" for step in item["agent"]["proposal"]["steps"]],
        ]
    return "\n".join(lines) + "\n"


def intel_notice(report: dict) -> str:
    if report["intel_mode"] == "live":
        return "Live public intelligence; inspect source dates and unknown/stale evidence flags."
    return "Offline EPSS/KEV values are simulated. Unknown intelligence requires manual review."


def render_html(report: dict) -> str:
    escape = html.escape
    cards = "".join(
        f'<div class="metric"><strong>{count}</strong><span>{label}</span></div>'
        for label, count in (
            ("records ingested", report["summary"]["raw_findings"]),
            ("unique findings", report["summary"]["unique_findings"]),
            ("duplicates merged", report["summary"]["duplicates_merged"]),
            ("external changes", 0),
        )
    )
    rows = []
    for item in report["results"]:
        f, d, a = item["finding"], item["decision"], item["agent"]
        reasons = "".join(f"<li>{escape(reason)}</li>" for reason in d["reasons"])
        uncertain = "".join(f'<p class="warning">{escape(u)}</p>' for u in d["uncertainties"])
        trace = " → ".join(t["tool"] for t in a["trace"])
        steps = "".join(f"<li>{escape(step)}</li>" for step in a["proposal"]["steps"])
        rows.append(
            f'<article><div class="row"><span class="pill {d["priority"]}">'
            f"{d['priority']}</span><h2>{escape(f['kind'].replace('_', ' '))}</h2>"
            f'<span class="score">{d["score"]}/100</span></div>'
            f'<p class="meta">{escape(f["cloud"].upper())} · {escape(f["asset"])} · '
            f"{escape(f['cve'] or 'configuration')} · {escape(f['data_class'])} data</p>"
            f"<p>Review due: {escape(d['due_at'])} · Proposal awaiting human review</p>"
            f"{uncertain}<details><summary>Evidence & decision</summary><ul>{reasons}</ul>"
            f"<p>Policy {escape(d['policy_version'])}</p></details>"
            f"<details><summary>Remediation & tool trace</summary><ol>{steps}</ol>"
            f"<pre>{escape(trace)}</pre><pre>"
            f"{escape(json.dumps(a['proposal']['terraform'], indent=2))}</pre>"
            "<p>Static checks passed. Terraform provider validation and plan not run.</p>"
            "</details></article>"
        )
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Cloud Security Triage | Jonathan Ekwere</title><style>
:root{color-scheme:dark;font-family:ui-sans-serif,system-ui,sans-serif;background:#0a1420;color:#e7edf5}
*{box-sizing:border-box}body{max-width:1120px;margin:auto;padding:48px 24px 70px}
.eyebrow{letter-spacing:.16em;text-transform:uppercase;color:#67dec0;font-size:12px;font-weight:700}
h1{font-size:clamp(32px,5vw,58px);line-height:1.05;max-width:800px;margin:18px 0}
.lead{font-size:18px;line-height:1.7;max-width:760px;color:#afc1d5}.metrics{display:grid;
grid-template-columns:repeat(4,1fr);gap:12px;margin:30px 0}.metric{background:#132438;
border:1px solid #28415b;border-radius:12px;padding:22px}
.metric strong{font-size:32px;display:block}
.metric span,.meta{color:#afc1d5;font-size:13px}article{border:1px solid #28415b;background:#0f1e2e;
border-radius:14px;padding:24px;margin:18px 0}.row{display:flex;align-items:center;gap:14px}
h2{font-size:21px;margin:0;text-transform:capitalize}.score{margin-left:auto;font-weight:700}
.pill{padding:6px 10px;border-radius:6px;font-weight:800;font-size:12px;background:#23465a}
.P1{color:#ffc2c0;background:#622c38}.P2{color:#ffda9b;background:#584420}.P3{color:#b3d5ff}
summary{cursor:pointer;padding:14px 0;color:#75d9c2}details{border-top:1px solid #28415b}
li{margin:8px 0;line-height:1.6}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#09131f;
padding:16px;border-radius:8px;font-size:12px}.warning{color:#ffda9b}.notice{border-left:3px solid
#67dec0;padding:12px 20px;color:#afc1d5;font-size:14px;line-height:1.7}footer{color:#afc1d5;
font-size:12px;margin-top:36px}@media(max-width:650px){.metrics{grid-template-columns:repeat(2,1fr)}
.row{flex-wrap:wrap}body{padding:28px 16px}article{padding:18px}}
</style><header><div class="eyebrow">Jonathan Ekwere / Independent Security Engineering</div>
<h1>From cloud findings to a reviewable security decision.</h1>
<p class="lead">Evidence-driven prioritization, constrained agent tools, and remediation proposals
with human judgment at the change boundary.</p></header>""" + (
        f'<section class="metrics" aria-label="Run summary">{cards}</section>'
        f'<div class="notice">Synthetic demo · {escape(report["as_of"])} · '
        f"{escape(report['provider'])} planner. {escape(intel_notice(report))} "
        "Scores are policy heuristics. "
        "No cloud deployment or ticket submission "
        "is represented here. Expand each finding to inspect the evidence and tool trace.</div>"
        + "".join(rows)
        + "<footer>No employer systems, PHI, credentials or proprietary scanner exports were used. "
        "Approval is a separate operator step. "
        "See report.json and audit.jsonl for evidence.</footer></html>"
    )


def run(
    output: Path,
    *,
    findings_path: Path | None = None,
    as_of: date = date(2026, 10, 23),
    intel_mode: str = "fixture",
    provider: str = "deterministic",
    planner_factory: Callable[[], Planner] = DeterministicPlanner,
) -> dict:
    document = load_json(findings_path or data_path("findings.json"))
    findings, raw_count = normalize(document)
    if provider == "openai" and len(findings) > 10:
        raise ValueError("model mode is capped at ten findings per run")
    policy = Policy(data_path("policy.toml"))
    cves = {f.cve for f in findings if f.cve}
    intel = (
        asyncio.run(live_intel(cves))
        if intel_mode == "live"
        else fixture_intel(load_json(data_path("intel.json")), cves)
    )
    output.mkdir(parents=True, exist_ok=False)
    audit = Audit()
    audit.record("run_started", mode=f"{provider}:{intel_mode}", count=raw_count)
    audit.record(
        "normalized", count=len(findings), detail_digest=digest([f.as_dict() for f in findings])
    )
    results = []
    try:
        for finding in findings:
            evidence = intel.get(finding.cve)
            decision = policy.evaluate(finding, evidence, as_of)
            audit.record(
                "risk_decided",
                finding_id=finding.id,
                outcome=decision.priority,
                detail_digest=digest(decision.as_dict()),
            )
            agent = run_agent(finding, evidence, decision, planner_factory(), audit)
            results.append(
                {
                    "finding": finding.as_dict(),
                    "decision": decision.as_dict(),
                    "evidence": evidence.as_dict() if evidence else None,
                    "agent": agent,
                }
            )
        results.sort(
            key=lambda r: (r["decision"]["priority"], -r["decision"]["score"], r["finding"]["id"])
        )
        report = {
            "schema_version": 1,
            "synthetic": True,
            "as_of": as_of.isoformat(),
            "provider": provider,
            "intel_mode": intel_mode,
            "external_changes": 0,
            "input_digest": digest(document),
            "policy_digest": policy.digest,
            "summary": {
                "raw_findings": raw_count,
                "unique_findings": len(findings),
                "duplicates_merged": raw_count - len(findings),
                "by_priority": dict(Counter(r["decision"]["priority"] for r in results)),
            },
            "results": results,
        }
        write_json(output / "report.json", report)
        (output / "report.md").write_text(markdown(report))
        (output / "report.html").write_text(render_html(report))
        write_json(
            output / "jira-dry-run.json",
            [
                preview(r, "example.atlassian.net", "SEC", f"{as_of.isoformat()}T00:00:00+00:00")
                for r in results
            ],
        )
        for item in results:
            if terraform := item["agent"]["proposal"]["terraform"]:
                write_json(output / f"{item['finding']['id']}.tf.json", terraform)
        audit.record("run_completed", count=len(results), detail_digest=digest(report))
        return report
    except Exception:
        audit.record("run_failed", outcome="closed_no_external_changes")
        raise
    finally:
        audit.write(output / "audit.jsonl")
