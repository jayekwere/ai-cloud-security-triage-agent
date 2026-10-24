# Capabilities and boundaries

This table maps the independent project's evidence to cloud security engineering themes. It does not imply company affiliation, endorsement or access to private infrastructure.

| Engineering theme | Reviewable project evidence | What this project does not establish |
|---|---|---|
| Agentic engineering with human judgment | Real optional model/tool loop, deterministic replay, code-enforced gates, adversarial tests, exact-intent Jira approval | Live model quality or an employer's AI operating model |
| AWS/Azure posture and workload security | Synthetic workload/storage/IAM/network findings, exposure/classification signals, S3/Azure Storage templates | Real account posture, federation, runtime protection or deployed controls |
| Controls as code | Versioned risk policy, exact trusted IaC templates, validation gates, CI | Production operation, on-call load or a successful Terraform plan |
| Vulnerability management and response | CVE enrichment, deduplication, KEV/EPSS provenance, uncertainty, review targets, ticket intents and closure runbook | Real scanner ingestion, incident response leadership or remediation SLAs achieved |
| Secure application delivery | Security lint, tests, bounded API clients, pinned Actions, no runtime dependencies, threat model | Full DAST/SCA/secrets scanning coverage or complete supply-chain provenance |
| AI security and privacy | No raw descriptions in model context, no model write tools, minimized synthetic data, explicit egress | Resistance to every AI attack, PHI approval, residency or regulatory compliance |
| Network / identity / key management | IAM/network review steps, least-privilege reasoning, no cloud credentials, HTTPS destination policy | Enterprise zero-trust architecture, KMS implementation, SSO or privileged-access deployment |
| Logging and operational evidence | Structured hash-chain events, intent receipts, policy/proposal digests, tests for denial/replay/uncertainty | SIEM operations, immutable logging, tamper-proof audit or central identity |

The project's strongest contribution is a complete, inspectable path from synthetic findings to a human-reviewable action with meaningful authority boundaries.

## Related public projects

Reviewed the public profile and READMEs for cve-exploit-prediction, agent-anomaly-detection and secure-aws-platform. The CVE project explores EPSS/KEV prediction; the anomaly project explores suspicious agent behavior; the AWS platform README describes planned infrastructure work. This repository adds an executable operational workflow joining threat context, policy, tool orchestration, constrained remediation and approval.

This review does not validate the other repositories' results or operating claims. No existing repository was modified to create this project.
