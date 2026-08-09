# Workload Attribution

Use source attribution carefully. VPC Flow Logs can identify interfaces and addresses, but not every row maps cleanly to an application.

## Stronger Attribution

- ENI maps to an EC2 instance with useful tags.
- Flow log format includes `instance-id`, `vpc-id`, and `subnet-id`.
- ECS task, EKS pod, Batch job, or SageMaker job inventory is joined by ENI or private IP.
- NAT-aware fields such as `pkt-srcaddr` and `pkt-dstaddr` preserve original endpoints.
- Flow timing matches deployment, job, or service telemetry.

## Weaker Attribution

- Source is a NAT gateway ENI.
- Source is a shared proxy, firewall, egress gateway, or service mesh component.
- Source private IP was reused during the analysis window.
- Only public destination IP is available without DNS history.

## Reporting Rule

When attribution is weak, report the source as `egress path` or `network interface` rather than naming a workload. State which inventory join is needed to raise confidence.
