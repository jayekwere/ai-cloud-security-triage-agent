# Security policy

This is an independent local portfolio demonstration using synthetic data. It is not approved for PHI, employer scanner exports, production credentials, or autonomous cloud remediation.

## Supported scope

The current main branch is the maintained demonstration. Material security properties are: raw scanner text cannot become model instructions or executable code; the agent cannot change the risk policy, run shell/cloud commands or submit Jira; optional external calls have explicit fixed destinations; Jira writes require exact approved intent, unexpired local approval and one reserved attempt; secrets must not appear in logs, reports, fixtures or source.

The trusted operator controls code, policy/configuration, environment, working directory, ledger and selected input files. Local user compromise, altered application source, hostile dependency execution and forged synthetic declarations are outside this application's isolation boundary. The ledger and audit hashes are not a replacement for authenticated central approvals or tamper-resistant logging.

## Reporting

Do not post credentials, real patient data, employer details or exploit-bearing confidential logs in public issues. For a sensitive report, use the maintainer's public profile contact to arrange a private channel. For a non-sensitive reproducible bug, open a GitHub issue with synthetic input, expected/actual behavior, version and minimal reproduction. No response-time SLA or third-party assurance is claimed.

## Production review prerequisites

Read docs/THREAT_MODEL.md and docs/ARCHITECTURE.md. Before any production adaptation, validate integration authentication/authorization, data minimization, model retention/residency, approval identity, remote audit durability, dependency provenance, source freshness and actual Terraform plans with accountable owners. Never treat a proposal or static pass as deployment authorization.
