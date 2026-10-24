# Five-minute demo walkthrough

## Overview

This independent cloud security triage workflow connects vulnerability intelligence, cloud exposure and data sensitivity with reviewable remediation. AI can orchestrate analytical tools, while deterministic code owns decisions and change authority. Synthetic scenarios make the workflow inspectable without access to private systems or data.

## Demonstration

**Minute 1 — run it.** Install locally and run `cloudtriage demo --out out/walkthrough`. Open the HTML report. State clearly that this is the deterministic mode, using simulated intelligence, with no cloud/Jira writes. Show nine records becoming eight unique findings.

**Minute 2 — show judgment.** Expand an exposed KEV scenario. Explain why exposure plus known exploitation outranks severity alone. Compare the internal high-CVSS scenario and the fictional CVE with missing evidence. Explain the P2 uncertainty floor and that the additive score is not a calibrated probability. The sample distribution is P1=4, P2=3, P3=1, P4=0; these are scenario results, not business metrics.

**Minute 3 — inspect agent authority.** Open `agent.py`. Show the five analytical tools, fixed empty arguments, prerequisite checks, call budget and output digests. Explain that the OpenAI implementation makes real Responses tool-call requests when explicitly configured, while the demo uses a scripted planner. Mocked provider tests verify request/response flow; they do not prove a live model run. State the live-validation status from VALIDATION.md.

**Minute 4 — review a change.** Show the S3 or Azure Terraform JSON proposal, its static validation result, placeholders and dependency/rollback checks. Explain why you did not invent a fixed version for a CVE or run a cloud change. Show Jira dry-run ADF and the exact intent digest. The separate interactive approval lasts one hour; concurrent/repeated submissions cannot reserve the same intent twice.

**Minute 5 — prove controls and limits.** Run tests and audit verification. Point to prompt-injection exclusion, unsafe-tool denial, changed-payload rejection, expiry, concurrency, timeout ambiguity and HTML escaping tests. Explain local ledger/audit limitations and what central identity, signed approvals, durable logs, real vendor adapters and plan/rescan evidence would add.

## Design questions

| Question | Implementation and limits |
|---|---|
| What is agentic here? | In provider mode, a model iteratively chooses functions, receives evidence and continues. The dispatcher validates every call and fixes the scope. The offline demo replays that same tool boundary without a model. |
| Why not let AI score risk? | Decisions need stable, reviewable policy and provenance; a model may help investigate but cannot silently reduce priority. |
| How do you handle injection? | Raw descriptions/metadata are excluded from the model; only validated fields and fixed tool results cross the boundary. Prompt wording is supplementary, not the enforcement mechanism. |
| Does this protect PHI? | It uses no PHI and is not approved for it. Synthetic declarations/minimization are not DLP, provider-retention or compliance guarantees. |
| Is approval strong enough for production? | It demonstrates exact-intent expiry/replay controls on one trusted host. It lacks independent authenticated approvers and host-tamper resistance. |
| What happens after a Jira timeout? | Reserve is already consumed; outcome is unknown. Reconcile the tenant before choosing another intent to avoid duplicates. |
| How do you know Terraform is safe? | Exact templates and static checks constrain proposals. Only owner-environment validation, policy scans, a reviewed plan and staging tests can establish applicability. |
| What did AI help with? | Code and documentation drafting, implementation iteration and test generation with Codex; final claims are limited to inspected code and actual recorded checks. Do not claim Claude/Cursor built this project unless you use them on it. |
| What did this improve in production? | No production outcome is claimed. The evidence is a working independent demonstration and its reproducible validation. |

## Further reading

See the [project summary](PROJECT_SUMMARY.md), [capabilities and boundaries](CAPABILITIES.md), and [verification record](VALIDATION.md) for implementation details and recorded evidence.
