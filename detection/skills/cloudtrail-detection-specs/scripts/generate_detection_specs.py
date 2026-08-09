#!/usr/bin/env python3
"""Generate portable CloudTrail detection specs from a business baseline."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_SPECS = [
    {
        "id": "aws_cloudtrail_root_activity",
        "title": "Root Console or API Activity",
        "severity": "critical",
        "business_family": "user_access",
        "description": "Detect any root console login or root API use.",
        "logic": {"any": [{"actor_type": "root"}, {"actor": "root"}]},
        "required_fields": ["eventTime", "eventName", "userIdentity", "sourceIPAddress", "userAgent", "additionalEventData.MFAUsed"],
        "required_evidence": ["raw CloudTrail event", "break-glass ticket", "MFA device type", "post-login root activity"],
        "suppression_conditions": ["Only downgrade after documented break-glass approval and known administrator source context."],
        "response": ["Page security owner", "Validate ticket and approver", "Pull all root events for the following hours"],
    },
    {
        "id": "aws_cloudtrail_create_access_key_non_rotation",
        "title": "CreateAccessKey Outside Designated Rotation",
        "severity": "critical",
        "business_family": "identity_privilege_management",
        "description": "Detect static access-key creation unless performed by an approved rotation role.",
        "logic": {"event_name": "CreateAccessKey", "actor_not_in_exception_class": "approved_rotation_role"},
        "required_fields": ["eventTime", "eventName", "userIdentity", "requestParameters.userName", "sourceIPAddress", "userAgent"],
        "required_evidence": ["raw CloudTrail event", "target IAM user", "caller role/user", "rotation job or change record"],
        "suppression_conditions": ["Approved rotation role", "known scheduled rotation window", "target service user documented"],
        "response": ["Confirm target user owner", "Rotate key if unauthorized", "Move workload to OIDC or role federation"],
    },
    {
        "id": "aws_cloudtrail_iam_writes_unmanaged_egress",
        "title": "IAM Role or Policy Writes From Unmanaged Egress",
        "severity": "critical",
        "business_family": "identity_privilege_management",
        "description": "Detect privilege-bearing IAM writes from named users or non-corporate source IPs.",
        "logic": {"event_name_in": ["CreateRole", "DeleteRole", "AttachRolePolicy", "PutRolePolicy", "AttachUserPolicy", "PutUserPolicy"], "source_ip_not_in": "corporate_or_approved_service_egress"},
        "required_fields": ["eventTime", "eventName", "userIdentity", "sourceIPAddress", "userAgent", "requestParameters"],
        "required_evidence": ["raw CloudTrail event", "source IP ownership", "created/attached policy", "identity owner attestation"],
        "suppression_conditions": ["Approved CI/CD role", "approved service source", "documented emergency change"],
        "response": ["Verify identity owner", "Review created privileges", "Rotate any long-lived keys involved"],
    },
    {
        "id": "aws_cloudtrail_password_policy_outside_pipeline",
        "title": "Account Password Policy Change Outside Pipeline",
        "severity": "high",
        "business_family": "identity_privilege_management",
        "description": "Detect UpdateAccountPasswordPolicy outside approved IaC or management-account change flow.",
        "logic": {"event_name": "UpdateAccountPasswordPolicy", "actor_not_in_exception_class": "approved_identity_policy_pipeline"},
        "required_fields": ["eventTime", "eventName", "userIdentity", "sourceIPAddress", "requestParameters"],
        "required_evidence": ["raw CloudTrail event", "policy parameters", "change ticket", "pipeline run"],
        "suppression_conditions": ["Approved pipeline role", "approved change window and matching ticket"],
        "response": ["Compare parameters to standard", "Confirm change owner", "Move recurring control to IaC"],
    },
    {
        "id": "aws_cloudtrail_s3_delete_bucket_burst_or_audit_bucket",
        "title": "S3 DeleteBucket Burst or Audit Bucket Deletion",
        "severity": "critical",
        "business_family": "data_access_storage",
        "description": "Detect bucket deletion bursts and deletion of buckets whose names/tags indicate CloudTrail, logs, audit, or evidence storage.",
        "logic": {"event_name": "DeleteBucket", "alert_if": ["count_by_actor_account_window_gt_threshold", "bucket_name_matches_audit_log_pattern"]},
        "required_fields": ["eventTime", "eventName", "userIdentity", "sourceIPAddress", "requestParameters.bucketName"],
        "required_evidence": ["raw CloudTrail event", "bucket name", "retention/legal-hold approval", "decommission ticket"],
        "suppression_conditions": ["Approved decommission with retention review", "non-audit sandbox bucket with ticket"],
        "response": ["Check log retention", "Confirm decommission approval", "Preserve remaining evidence"],
    },
    {
        "id": "aws_cloudtrail_logging_tamper",
        "title": "CloudTrail Config or FlowLogs Tamper",
        "severity": "critical",
        "business_family": "governance_security_visibility",
        "description": "Detect actions that reduce security telemetry or forensic visibility.",
        "logic": {"event_name_in": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs", "DeleteConfigRule", "StopConfigurationRecorder", "DeleteConfigurationRecorder"]},
        "required_fields": ["eventTime", "eventName", "userIdentity", "sourceIPAddress", "requestParameters"],
        "required_evidence": ["raw CloudTrail event", "affected trail/config/log resource", "change ticket"],
        "suppression_conditions": ["Approved migration with overlapping telemetry and change record"],
        "response": ["Escalate immediately", "Validate alternate logging", "Restore telemetry if unauthorized"],
    },
    {
        "id": "aws_cloudtrail_network_exposure_named_user",
        "title": "Network Exposure Change by Named or Unusual Actor",
        "severity": "high",
        "business_family": "network_security_changes",
        "description": "Detect security group, route, gateway, NACL, or peering changes from actors outside normal deployment automation.",
        "logic": {"event_name_contains_any": ["SecurityGroup", "NetworkAcl", "Route", "InternetGateway", "VpcPeering"], "actor_not_in_exception_class": "approved_network_automation"},
        "required_fields": ["eventTime", "eventName", "userIdentity", "sourceIPAddress", "requestParameters"],
        "required_evidence": ["raw CloudTrail event", "network diff", "source actor", "change ticket"],
        "suppression_conditions": ["Approved network automation role", "approved emergency change"],
        "response": ["Review exposure delta", "Validate ticket", "Roll back unauthorized public exposure"],
    },
    {
        "id": "aws_cloudtrail_destructive_database_action",
        "title": "Destructive Database Control-Plane Action",
        "severity": "critical",
        "business_family": "database_operations",
        "description": "Detect destructive RDS or database control-plane changes.",
        "logic": {"event_name_in": ["DeleteDBInstance", "DeleteDBCluster"], "always_alert": True},
        "required_fields": ["eventTime", "eventName", "userIdentity", "sourceIPAddress", "requestParameters"],
        "required_evidence": ["raw CloudTrail event", "DB identifier", "snapshot/backup status", "change ticket"],
        "suppression_conditions": ["Approved decommission with backup validation"],
        "response": ["Confirm backups", "Validate decommission ticket", "Escalate if unexpected"],
    },
    {
        "id": "aws_cloudtrail_kms_key_or_grant_unusual_actor",
        "title": "KMS Key or Grant Change by Unusual Actor",
        "severity": "high",
        "business_family": "data_access_storage",
        "description": "Detect KMS key or grant changes from new or non-standard actors.",
        "logic": {"event_name_in": ["CreateGrant", "CreateKey", "DisableKey", "ScheduleKeyDeletion"], "actor_event_source_tuple_not_in_baseline": True},
        "required_fields": ["eventTime", "eventName", "userIdentity", "sourceIPAddress", "requestParameters", "resources"],
        "required_evidence": ["raw CloudTrail event", "key/grant target", "grantee principal", "baseline comparison"],
        "suppression_conditions": ["Known deployment role and expected key lifecycle"],
        "response": ["Validate grantee", "Review key policy", "Revoke unauthorized grants"],
    },
]


def load_baseline(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def add_baseline_drift_spec(baseline: dict[str, Any]) -> dict[str, Any]:
    candidate_count = baseline.get("metadata", {}).get("alert_candidate_count", 0)
    return {
        "id": "aws_cloudtrail_baseline_tuple_drift",
        "title": "CloudTrail Account Actor Event Source-IP Tuple Drift",
        "severity": "medium",
        "business_family": "other_control_plane",
        "description": "Detect account/actor/event/source-IP combinations not present in the approved baseline, with critical events still handled by override rules.",
        "logic": {"tuple": ["account_id", "actor", "event_name", "source_ip"], "not_in": "actor_event_baseline"},
        "required_fields": ["eventTime", "eventName", "userIdentity", "sourceIPAddress", "recipientAccountId", "awsRegion"],
        "required_evidence": ["raw CloudTrail event", "baseline tuple comparison", "first-seen timestamp"],
        "suppression_conditions": ["Explicit approved exception with owner, expiry, and business justification"],
        "response": ["Validate owner", "Determine if new business process or suspicious drift", "Promote to baseline only after approval"],
        "references": [{"baseline_alert_candidate_count": candidate_count}],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    baseline = load_baseline(args.baseline)
    specs = []
    for spec in BASE_SPECS:
        item = dict(spec)
        item["references"] = [{"baseline": str(args.baseline)}]
        specs.append(item)
    specs.append(add_baseline_drift_spec(baseline))
    out = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_baseline": str(args.baseline),
            "spec_count": len(specs),
            "format": "portable_cloudtrail_detection_specs_v1",
        },
        "detections": specs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "spec_count": len(specs)}, indent=2))


if __name__ == "__main__":
    main()
