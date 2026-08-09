# GuardDuty finding-type → tactic / primitive mapping

This reference explains how `aws-threat-correlator` interprets GuardDuty findings when it
builds `ActiveThreat` records and lights up chains. It is a guide for analysts and for
extending correlation — the correlator itself matches on **accounts / resources /
crown-jewels**, not on the finding-type string, so a finding lights up any chain that
touches the same asset regardless of type. Use the table below to reason about *which
attack primitive* a live finding corroborates and *which stage* of a chain it confirms.

GuardDuty finding types follow `ThreatPurpose:ResourceTypeAffected/ThreatFamilyName`.
The `ThreatPurpose` prefix aligns closely with MITRE tactics.

## Prefix → tactic

| GuardDuty ThreatPurpose | MITRE tactic | Typical KB primitive family |
|---|---|---|
| `Recon` | reconnaissance | `rc_audit_identity_recon` |
| `UnauthorizedAccess` | initial-access / credential-access | `ia_admin_port_open`, `ca_static_key_theft`, `ca_no_mfa_phish` |
| `Discovery` | discovery / reconnaissance | `co_s3_list_recon`, `rc_audit_identity_recon` |
| `CredentialAccess` | credential-access | `ca_imds_theft`, `ca_secretsmanager_ssm_read` |
| `PrivilegeEscalation` | privilege-escalation | `pe_*` family |
| `Persistence` | persistence | `ps_add_access_key`, `ps_backdoor_role_trust` |
| `DefenseEvasion` | defense-evasion | `de_stop_delete_trail`, `de_cloudtrail_disabled` |
| `Policy` | defense-evasion / initial-access | `pe_root_mfa_manipulation`, `ca_no_mfa_phish` |
| `Impact` | impact | `im_destructive_delete` |
| `Exfiltration` | exfiltration | `co_s3_bulk_get`, `co_backup_pull`, `co_exfil_tor` |
| `Backdoor` / `Trojan` / `CryptoCurrency` | impact / command-and-control | `im_destructive_delete` |

## Representative finding types

| GuardDuty finding type | Confirms primitive(s) | Notes |
|---|---|---|
| `UnauthorizedAccess:EC2/SSHBruteForce` | `ia_admin_port_open` | admin port reachable and attacked |
| `UnauthorizedAccess:EC2/RDPBruteForce` | `ia_admin_port_open` | RDP variant |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*` | `ca_imds_theft`, `pe_instance_role_broad` | instance role creds used off-box |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller.*` | `ca_static_key_theft` | key used from bad IP |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | `ca_no_mfa_phish`, `pe_no_mfa_admin_console` | anomalous console login |
| `CredentialAccess:IAMUser/AnomalousBehavior` | `ca_secretsmanager_ssm_read`, `ca_static_key_theft` | anomalous credential API use |
| `PrivilegeEscalation:IAMUser/AdministrativePermissions*` | `pe_attach_user_policy`, `pe_wildcard_policy` | self-grant of admin |
| `Persistence:IAMUser/*` | `ps_add_access_key`, `ps_add_login_profile` | new key / login profile |
| `Policy:IAMUser/RootCredentialUsage` | `pe_root_mfa_manipulation` | root used |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | `de_stop_delete_trail` | trail tampered |
| `Stealth:S3/ServerAccessLoggingDisabled` | `de_unreadable_access_logs` | log evasion |
| `Discovery:S3/AnomalousBehavior*` | `co_s3_list_recon` | bucket recon |
| `Exfiltration:S3/AnomalousBehavior*` | `co_s3_bulk_get`, `co_backup_pull` | bulk S3 read/exfil |
| `Exfiltration:S3/MaliciousIPCaller` | `co_s3_bulk_get`, `co_exfil_tor` | exfil to bad/Tor IP |
| `Impact:S3/MaliciousIPCaller` / `Impact:EC2/*` | `im_destructive_delete` | destructive/ransom activity |
| `Backdoor:EC2/C&CActivity.*` | `im_destructive_delete` | C2 beacon on host |

## Indicators extracted

The correlator harvests these from any finding shape (raw or simplified) to build the
`indicators` list and the top-level `threat_actor_indicators` rollup:

- **source IPs** — `Service.Action.*.RemoteIpDetails.IpAddressV4` and any `IpAddressV4`
  key found anywhere in the finding (classified as `source_ips`).
- **access keys** — `Resource.AccessKeyDetails.AccessKeyId` / any `AccessKeyId`
  (values starting `AKIA`/`ASIA` classified as `access_keys`).
- **actors** — user names, principal ids, and other non-IP/non-key values
  (classified as `actors`).

## Node-id derivation

To intersect with attack-model node ids (`<type>:<account_id>:<name>`) the correlator
derives candidate `maps_to_nodes` from GuardDuty `Resource`:

| GuardDuty resource detail | Derived node id |
|---|---|
| `InstanceDetails.InstanceId` | `ec2_instance:<acct>:<InstanceId>` |
| `S3BucketDetails[].Name` | `s3_bucket:<acct>:<Name>` |
| `AccessKeyDetails.AccessKeyId` | `access_key:<acct>:<AccessKeyId>` |
| `AccessKeyDetails.UserName` | `iam_user:<acct>:<UserName>` |
| `RdsDbInstanceDetails.DbInstanceIdentifier` | `rds_instance:<acct>:<DbInstanceIdentifier>` |

Simplified findings may instead supply `account_id`, `resource`, `maps_to_nodes`, and
`indicators` directly, in which case those are used verbatim.
