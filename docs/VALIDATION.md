# Verification record

Verified October 23, 2026 (America/Vancouver). These are observed engineering checks on synthetic scenarios, not production results.

| Check | Observed result |
|---|---|
| Local environment | macOS ARM64, Python 3.14.6; project supports Python 3.11+ |
| Automated suite | **70 passed**, **90.13% statement coverage**; required floor 85% |
| Ruff 0.13.3 | Lint/security rules and formatting passed |
| Bandit 1.9.4 | No reported issues or processing errors; source files processed |
| Offline demo | 9 raw findings → 8 unique; 1 conservative duplicate merge |
| Offline policy | P1=4, P2=3, P3=1, P4=0; proposed review targets only |
| Audit | 51 ordered hash-linked events verified |
| Reproducibility | Entire regenerated demo directory matches committed samples byte for byte |
| Package installation | Final wheel installed in a fresh environment; packaged fixtures and CLI reproduced samples exactly |
| Actual public feeds | FIRST EPSS and CISA KEV read successfully with synthetic context; [recorded observations](LIVE_FEED_SMOKE.json) |
| Browser QA | Self-contained HTML rendered in Chrome; expandable evidence/proposal controls inspected; [captured view](demo-preview.jpg) |
| Architecture | Independent fresh-context read-only review plus author reconciliation; threat model contains checked source anchors |
| GitHub CI | **Passed on Python 3.11, 3.12, 3.13 and 3.14**, including all check steps and evidence upload; [verified run](https://github.com/jayekwere/ai-cloud-security-triage-agent/actions/runs/40056314561) on source commit `4fe7233` |

The suite covers conservative duplicate aggregation, strict booleans/numeric ranges/identifiers, simulated-only input declaration, CVE syntax, size limits, KEV/exposure overrides, missing/stale/future intelligence, configuration baseline and privileged-IAM floor, low-risk priority, implementation/configuration digest binding, and deterministic replay without network access.

Agent tests reject unknown tools, write tools, unexpected arguments, invalid order, repeats and early finish. Contract tests exercise Responses tool calls/results, incomplete provider responses, minimized context, live-feed parsing/missing data, and approved Jira requests. Approval tests cover exact confirmation, changed content/host/project, expiry, concurrent reservations, replay, missing approvals, sanitized logging and ambiguous external outcomes. Transport tests cover unsafe URLs, redirects and response size. HTML escaping and explicit CLI egress/interactive gates are verified.

## Actual execution versus simulations

- The offline demo and local tests ran. The default workflow never called a model or wrote to Jira/cloud infrastructure.
- A separate live public-feed smoke check ran. The recorded scores/flags are observations from that check, not the offline fixture and not a promise that the catalog or scores remain current.
- OpenAI request/response flow is implemented and **mocked contract-tested**. No OPENAI_API_KEY + OPENAI_MODEL configuration was available here; a real model run remains unverified. Model selection quality and stochastic behavior are not measured.
- Jira preview and approval/submit behavior are implemented and **mocked contract-tested**. No real Jira issue was sent; tenant issue types, account permissions, notifications and field readback remain unverified.
- Terraform JSON is statically constrained and validated. No provider initialization, Terraform validate/plan/apply, cloud deployment, live rescan or closure result is claimed.

## Limits of these checks

Coverage measures executed statements, not security correctness. Static scanners and tests cannot establish absence of vulnerabilities. The architecture review did not execute code or claim a full security audit. The ledger trusts the local user and is not independent identity enforcement. The audit chain is not an immutable/complete log. Source data is synthetic and the heuristic policy has not been calibrated on operational outcomes.

The initial Bandit 1.8.6 release could not process Python 3.14 source reliably, despite returning success; it was replaced with 1.9.4. CI explicitly checks the scanner's processing errors and processed-line count to prevent a false green from an empty scan. Direct development dependencies are pinned, but transitive dependencies are not hash-locked. There is no claim of full SCA/DAST/secrets-scan coverage.

## Reproduce

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
bandit -r src -f json -o out-bandit.json
pytest --cov=cloudtriage --cov-report=term-missing --cov-fail-under=85
cloudtriage demo --out out/reproduce
cloudtriage verify-audit out/reproduce/audit.jsonl
diff -r examples/demo out/reproduce
```

Create a new demo output directory for each attempt. The committed sample date is fixed for deterministic verification. Remote validation and artifact links are available from [GitHub Actions](https://github.com/jayekwere/ai-cloud-security-triage-agent/actions/workflows/ci.yml).
