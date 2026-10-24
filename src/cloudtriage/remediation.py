"""Reviewable, constrained remediation. No shell, Terraform process, or cloud mutation."""

from __future__ import annotations

import json
from copy import deepcopy

from .models import Finding, digest


def propose(finding: Finding) -> dict:
    terraform = None
    steps = ["Confirm asset ownership, affected configuration and business dependencies."]
    if finding.kind == "storage_public" and finding.cloud == "aws":
        terraform = {
            "resource": {
                "aws_s3_bucket_public_access_block": {
                    "reviewed": {
                        "bucket": "synthetic-review-bucket",
                        "block_public_acls": True,
                        "block_public_policy": True,
                        "ignore_public_acls": True,
                        "restrict_public_buckets": True,
                    }
                }
            }
        }
        steps += [
            "Map the placeholder to the existing bucket in the owner's Terraform module.",
            "Inspect access policy, CloudTrail data events and downstream access dependencies.",
        ]
    elif finding.kind == "storage_public" and finding.cloud == "azure":
        terraform = {
            "resource": {
                "azurerm_storage_account": {
                    "reviewed": {
                        "name": "syntheticreviewstore",
                        "resource_group_name": "synthetic-review-rg",
                        "location": "canadacentral",
                        "account_tier": "Standard",
                        "account_replication_type": "LRS",
                        "allow_nested_items_to_be_public": False,
                        "public_network_access_enabled": False,
                        "https_traffic_only_enabled": True,
                        "min_tls_version": "TLS1_2",
                    }
                }
            }
        }
        steps += [
            "Merge these settings into the existing module; do not create a parallel account.",
            "Verify private endpoint, DNS and approved residency with the data owner.",
        ]
    elif finding.kind == "iam_wildcard":
        steps += [
            "Review IAM Access Analyzer and CloudTrail usage over an agreed observation window.",
            "Replace wildcard permissions with reviewed actions, resources and conditions.",
            "Validate federation/workload identity paths and simulate the proposed policy.",
        ]
    elif finding.kind == "network_open":
        steps += [
            "Map legitimate callers; propose approved source CIDRs and required ports.",
            "Remove the existing broad rule in the owner module after connectivity review.",
            "Test segmentation, firewall/WAF policy and flow-log detections in staging.",
        ]
    else:
        steps += [
            f"Confirm {finding.cve} applicability against installed versions and vendor guidance.",
            "Select a vendor-supported fixed version; rebuild, scan and test the workload.",
            "Use a canary rollout and owner-approved maintenance window.",
        ]
    steps += [
        "Run format, provider validation and a reviewed plan in the owner environment.",
        "Require human change approval; rescan after rollout and attach closure evidence.",
    ]
    result = {
        "finding_id": finding.id,
        "kind": finding.kind,
        "cloud": finding.cloud,
        "status": "proposal_only",
        "terraform": terraform,
        "steps": steps,
        "rollback": "Revert the reviewed module revision and re-plan; never restore public access "
        "without incident/change-owner approval. Retain last known good workload image.",
        "limitations": [
            "No state, provider credentials, plan or deployment available.",
            "Templates do not replace review of existing resources, encryption or key policy.",
        ],
    }
    return {**result, "proposal_digest": digest(result)}


def validate(proposal: dict, finding: Finding) -> dict:
    """Exact template allowlist plus independent unsafe-construct checks; fail on any change."""
    expected = propose(finding)
    errors = []
    if proposal != expected:
        errors.append("proposal differs from the trusted template/runbook for this finding")
    text = json.dumps(proposal.get("terraform"), sort_keys=True).lower()
    for forbidden in (
        "provisioner",
        "local-exec",
        "remote-exec",
        "external",
        "0.0.0.0/0",
        "::/0",
        "access_key",
        "secret_key",
        "null_resource",
        "http://",
    ):
        if forbidden in text:
            errors.append(f"forbidden IaC construct: {forbidden}")
    return {
        "valid": not errors,
        "errors": errors,
        "checks": [
            "exact trusted proposal",
            "no execution hooks",
            "no broad ingress",
            "no embedded credentials",
        ],
        "terraform_provider_validation": "not_run; requires owner environment",
        "validated_proposal_digest": digest(deepcopy(proposal)),
    }
