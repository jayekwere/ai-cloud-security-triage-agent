# Operator runbook

## Review a demo

1. Run `cloudtriage demo --out out/demo` in a new directory.
2. Open `out/demo/report.html`; expand evidence and tool traces.
3. Read `report.json` for provenance, uncertainty and policy/proposal digests.
4. Run `cloudtriage verify-audit out/demo/audit.jsonl`.
5. Inspect `jira-dry-run.json` and `*.tf.json` as proposals. No approval or deployment occurred.

The demo's date is fixed at October 23, 2026 for repeatable results. `triage` defaults to the operator's current local date, so fixtures become stale after seven days; that is intentional. Use `--as-of 2026-10-23` to reproduce the fixture decisions. Never use a historical evaluation date to suggest that stale intelligence is current.

## Optional public feeds

```bash
cloudtriage triage --intel live --out out/live-intel
```

Only CVE IDs go to FIRST; CISA's public catalog is fetched once. Live feed failures stop the run. No automatic fixture fallback exists. Missing EPSS data, stale dates and feed publication dates are separate uncertainty signals. The fictional CVE remains a missing-data example, not a real advisory.

## Optional model

Provision a key through your own API account; set `OPENAI_API_KEY` and an accessible `OPENAI_MODEL` securely in the local environment. Do not commit keys or place them in shell command arguments or screenshots. The model must support Responses function calling.

```bash
cloudtriage triage --provider openai --allow-model-egress \
  --as-of 2026-10-23 --out out/model-review
```

The model gets minimized synthetic context and analytical tools. Each provider response must complete; each tool must be allowed, use `{}`, respect prerequisites, and run once. Incorrect order, unsupported tools, repeated calls, extra arguments or early completion reject the report. A rejected live model run is useful validation evidence; do not lower gates just to get a green run. Billing and service policy depend on the configured account. No live model call is required by CI.

## Optional Jira test tenant

Sending a ticket is a remote write and can notify project participants. Use an authorized sandbox and inspect the exact target and complete content first. The agent never performs this command itself.

```bash
# Copy a finding ID from report.json. Supply the exact Jira Cloud hostname/project.
cloudtriage jira-preview --report out/demo/report.json \
  --finding-id 2b9893a4e562cfe6 --host YOUR-TENANT.atlassian.net \
  --project SEC --out out/intent.json

# Reviewer sees the full payload and must type APPROVE followed by its full digest.
cloudtriage approve --intent out/intent.json \
  --ledger out/approvals.sqlite --reviewer reviewer-alias

# Set JIRA_EMAIL and JIRA_API_TOKEN securely before this explicit write.
cloudtriage jira-submit --intent out/intent.json \
  --ledger out/approvals.sqlite --out out/jira-receipt
```

Replace the uppercase tenant placeholder with a lowercase actual tenant before running. Approval expires after one hour. The digest includes the destination, action, project, intent timestamp and full ADF request. Any change invalidates approval. Success writes a receipt and audit events. Missing approval, expired approval or replay cannot issue a request. On timeout/invalid response, the intent becomes unknown/consumed: check Jira before deciding whether to generate a new intent. Do not automatically retry writes. Jira issue types/project permissions are tenant-specific; this connector expects `Task` and does not discover workflows or close tickets.

Reviewers are local self-asserted aliases; this example does not authenticate a separate approver. Keep the ledger in a private operator-owned directory. It is not an enterprise control for untrusted multi-user environments.

## Terraform review and closure

1. Confirm asset inventory, owner, cloud account/subscription, region and data classification.
2. Reproduce the actual insecure configuration using authorized read-only evidence.
3. Merge the proposed settings into the existing module; replace placeholders and check state/addressing.
4. In the owner's sandbox, pin providers and run formatting, provider validation, policy scanning and a plan. Inspect destructive/availability impacts.
5. Test application/private networking/IAM behavior, encryption and key access; approve the change through the actual change process.
6. Roll out gradually with a recovery plan; rescan the asset/image and attach evidence. Close only after verification.

The portfolio does not perform these deployment steps or claim their outcome.

## Failures and recovery

| Symptom | Inspect / safe response |
|---|---|
| Output directory exists | Choose a new path; preserve prior artifacts |
| Input rejected | Check synthetic envelope, mandatory fields, enums, booleans, CVE format and file size |
| Model denied / failed | Check explicit egress opt-in, key/model availability and provider status; never share tokens in logs |
| Live feed failure | Check fixed source availability, TLS/network conditions and rate limits; rerun a fresh read later |
| Missing/stale evidence | Keep uncertainty and manual review; do not convert unknown to zero risk |
| Audit verification fails | Preserve original files; compare known trusted copies/hashes before relying on the report |
| Approval rejected | Check exact intent, one-hour expiry and consumed status; reconcile any prior attempt |
| Jira outcome unknown | Inspect tenant for the synthetic summary/intent evidence; do not replay the request |

CLI errors deliberately omit arbitrary input, raw remote bodies and secrets. They return nonzero status. A failed run may leave only a failure audit; partial artifacts are not proof of completed triage.
