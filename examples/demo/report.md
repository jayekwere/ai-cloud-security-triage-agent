# Cloud Security Triage — Review Brief

**Synthetic independent project · 2026-10-23 · deterministic planner**

9 records → 8 unique findings; 1 duplicates merged. No external changes performed.

| Finding | Cloud / control | Priority | Score | Review due (UTC) |
|---|---|---|---:|---|
| b2b3ef71648489c4 | aws / vulnerability | P1 | 100 | 2026-10-24T00:00:00+00:00 |
| bd1a8c801163c55c | aws / vulnerability | P1 | 100 | 2026-10-24T00:00:00+00:00 |
| 2b9893a4e562cfe6 | aws / storage_public | P1 | 60 | 2026-10-24T00:00:00+00:00 |
| 54f37d34dcb4ef18 | azure / storage_public | P1 | 58 | 2026-10-24T00:00:00+00:00 |
| f190b91aae1bbc2f | aws / network_open | P2 | 58 | 2026-10-26T00:00:00+00:00 |
| 53555801c7c6f78a | aws / iam_wildcard | P2 | 53 | 2026-10-26T00:00:00+00:00 |
| 77a7be9f6411ec3e | aws / vulnerability | P2 | 16 | 2026-10-26T00:00:00+00:00 |
| 3cd19781c8f388bc | azure / vulnerability | P3 | 35 | 2026-11-06T00:00:00+00:00 |

Scores are triage heuristics, not breach probabilities or compliance attestations.
Offline EPSS/KEV values are simulated. Unknown intelligence requires manual review.
Terraform proposals passed local structural controls, not provider validation or a plan.

## b2b3ef71648489c4

- +29: CVSS severity × 3
- +17: EPSS exploitation likelihood × 20
- +35: CISA KEV membership (observed or simulated per provenance)
- +15: internet exposure
- +8: asset criticality × 2
- +10: confidential/restricted data classification
- P1 override: exposed KEV asset or exposed sensitive storage

Proposed next steps:

- Confirm asset ownership, affected configuration and business dependencies.
- Confirm CVE-2023-34362 applicability against installed versions and vendor guidance.
- Select a vendor-supported fixed version; rebuild, scan and test the workload.
- Use a canary rollout and owner-approved maintenance window.
- Run format, provider validation and a reviewed plan in the owner environment.
- Require human change approval; rescan after rollout and attach closure evidence.

## bd1a8c801163c55c

- +30: CVSS severity × 3
- +19: EPSS exploitation likelihood × 20
- +35: CISA KEV membership (observed or simulated per provenance)
- +15: internet exposure
- +10: asset criticality × 2
- +10: confidential/restricted data classification
- +10: privileged workload or entitlement
- P1 override: exposed KEV asset or exposed sensitive storage

Proposed next steps:

- Confirm asset ownership, affected configuration and business dependencies.
- Confirm CVE-2021-44228 applicability against installed versions and vendor guidance.
- Select a vendor-supported fixed version; rebuild, scan and test the workload.
- Use a canary rollout and owner-approved maintenance window.
- Run format, provider validation and a reviewed plan in the owner environment.
- Require human change approval; rescan after rollout and attach closure evidence.

## 2b9893a4e562cfe6

- +25: cloud configuration baseline
- +15: internet exposure
- +10: asset criticality × 2
- +10: confidential/restricted data classification
- P1 override: exposed KEV asset or exposed sensitive storage

Proposed next steps:

- Confirm asset ownership, affected configuration and business dependencies.
- Map the placeholder to the existing bucket in the owner's Terraform module.
- Inspect access policy, CloudTrail data events and downstream access dependencies.
- Run format, provider validation and a reviewed plan in the owner environment.
- Require human change approval; rescan after rollout and attach closure evidence.

## 54f37d34dcb4ef18

- +25: cloud configuration baseline
- +15: internet exposure
- +8: asset criticality × 2
- +10: confidential/restricted data classification
- P1 override: exposed KEV asset or exposed sensitive storage

Proposed next steps:

- Confirm asset ownership, affected configuration and business dependencies.
- Merge these settings into the existing module; do not create a parallel account.
- Verify private endpoint, DNS and approved residency with the data owner.
- Run format, provider validation and a reviewed plan in the owner environment.
- Require human change approval; rescan after rollout and attach closure evidence.

## f190b91aae1bbc2f

- +25: cloud configuration baseline
- +15: internet exposure
- +8: asset criticality × 2
- +10: privileged workload or entitlement

Proposed next steps:

- Confirm asset ownership, affected configuration and business dependencies.
- Map legitimate callers; propose approved source CIDRs and required ports.
- Remove the existing broad rule in the owner module after connectivity review.
- Test segmentation, firewall/WAF policy and flow-log detections in staging.
- Run format, provider validation and a reviewed plan in the owner environment.
- Require human change approval; rescan after rollout and attach closure evidence.

## 53555801c7c6f78a

- +25: cloud configuration baseline
- +8: asset criticality × 2
- +10: confidential/restricted data classification
- +10: privileged workload or entitlement
- P2 floor: privileged wildcard entitlement requires expedited review

Proposed next steps:

- Confirm asset ownership, affected configuration and business dependencies.
- Review IAM Access Analyzer and CloudTrail usage over an agreed observation window.
- Replace wildcard permissions with reviewed actions, resources and conditions.
- Validate federation/workload identity paths and simulate the proposed policy.
- Run format, provider validation and a reviewed plan in the owner environment.
- Require human change approval; rescan after rollout and attach closure evidence.

## 77a7be9f6411ec3e

- +12: CVSS severity × 3
- +4: asset criticality × 2
- P2 floor: incomplete intelligence cannot imply low risk
- Uncertainty: missing, stale, or future-dated CVE intelligence; manual verification

Proposed next steps:

- Confirm asset ownership, affected configuration and business dependencies.
- Confirm CVE-2099-9999999 applicability against installed versions and vendor guidance.
- Select a vendor-supported fixed version; rebuild, scan and test the workload.
- Use a canary rollout and owner-approved maintenance window.
- Run format, provider validation and a reviewed plan in the owner environment.
- Require human change approval; rescan after rollout and attach closure evidence.

## 3cd19781c8f388bc

- +30: CVSS severity × 3
- +1: EPSS exploitation likelihood × 20
- +4: asset criticality × 2

Proposed next steps:

- Confirm asset ownership, affected configuration and business dependencies.
- Confirm CVE-2024-3094 applicability against installed versions and vendor guidance.
- Select a vendor-supported fixed version; rebuild, scan and test the workload.
- Use a canary rollout and owner-approved maintenance window.
- Run format, provider validation and a reviewed plan in the owner environment.
- Require human change approval; rescan after rollout and attach closure evidence.
