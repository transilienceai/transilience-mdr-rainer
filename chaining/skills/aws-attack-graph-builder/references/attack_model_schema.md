# Shared attack-model contract — `aws_attack_model/v1`

This is the frozen interoperability contract for the AWS red-team attack-chain suite.
Every collector emits records in this shape; the graph builder merges them; the
enumerator traverses them; the report packager renders them. Keep it stable — add
fields, never rename existing ones.

## Envelope (one JSON file per collector, or a merged model)

```json
{
  "schema": "aws_attack_model/v1",
  "customer": "string",
  "collected_at": "ISO-8601 (stamped by the caller/--now, not by the script)",
  "source_skill": "aws-attack-surface-collector | aws-identity-trust-collector | ...",
  "accounts": [ Account ],
  "nodes":    [ Node ],
  "edges":    [ Edge ],
  "findings": [ Finding ],
  "crown_jewels":   [ CrownJewel ],
  "active_threats": [ ActiveThreat ],
  "gaps":     [ Gap ]
}
```

A collector fills the arrays it owns and leaves the others empty. The graph builder
concatenates arrays across all envelopes, de-duplicates nodes/edges by `id`, and
writes a single merged `attack_model.json`.

## Types

### Account
```json
{ "account_id":"12-digit", "label":"string", "env":"prod|non-prod|shared|sandbox|unknown",
  "is_management":false, "org_id":"o-xxxx|null", "notes":"string" }
```

### Node  — `id` MUST be globally unique and stable (recommend `"<type>:<account_id>:<name-or-arn>"`)
```json
{ "id":"string", "type":"NODE_TYPE", "account_id":"12-digit|external|internet",
  "name":"string", "arn":"string|null",
  "exposure": { "internet_facing":false, "ports":[], "cidrs":[] },
  "attributes": { "free-form, type-specific" } }
```
`NODE_TYPE` ∈
`internet`, `external_account`, `account`,
`iam_user`, `iam_role`, `iam_group`, `access_key`, `instance_profile`,
`ec2_instance`, `eks_cluster`, `lambda_function`, `alb`, `api_gateway`,
`s3_bucket`, `rds_instance`, `redshift`, `documentdb`, `elasticache`, `dynamodb`,
`ebs_snapshot`, `ami`, `rds_snapshot`, `ecr_repo`,
`secret`, `ssm_parameter`, `kms_key`,
`bedrock_kb`, `bedrock_agent`, `sagemaker`,
`sso_instance`, `cognito_pool`, `log_bucket`, `ci_system`.

### Edge  — the attack graph. `type` encodes the move.
```json
{ "src":"node id", "dst":"node id", "type":"EDGE_TYPE",
  "attributes": { "primitive_id":"string|null", "via":"service/mechanism", "condition":"string|null" },
  "evidence": { "source":"config|iam|guardduty|inventory|manual", "id":"string" } }
```
`EDGE_TYPE` ∈
`exposes` (internet → resource),
`has_credential` (principal → access_key),
`can_assume` (principal|external_account → iam_role),
`can_passrole` (principal → iam_role, `via` = consuming service),
`can_escalate` (principal → admin/other principal),
`trusts` (iam_role → account|principal|external_account),
`can_reach` (principal|role|instance → data node),
`runs_as` (ec2_instance → instance_profile → iam_role),
`replicates_to` (data → data), `writes_logs_to` (account|resource → log_bucket),
`member_of` (principal → account), `stores_credential_for` (data → principal|resource).

### Finding — an atomic misconfiguration instance
```json
{ "id":"string", "account_id":"12-digit", "control":"e.g. S3_PUBLIC_BUCKET_ACCESS",
  "severity":"critical|high|medium|low", "resource":"identifier",
  "internet_facing":false, "primitive_ids":[], "mitre":[], "raw_source":"path|api" }
```

### CrownJewel
```json
{ "id":"node id", "account_id":"12-digit", "type":"NODE_TYPE", "name":"string",
  "value_score":0-100, "data_class":"pii|financial|source|model|secret|backup|log|other",
  "size":"string", "protections":[], "reachable_by":["node id"] }
```

### ActiveThreat  (from GuardDuty / investigations)
```json
{ "id":"string", "account_id":"12-digit", "finding_type":"e.g. Exfiltration:S3/AnomalousBehavior",
  "severity":"critical|high|medium|low", "resource":"identifier",
  "indicators":["ip/actor/key"], "first_seen":"ISO-8601", "maps_to_nodes":["node id"] }
```

### Gap  — a collection blind spot (drives "find more next time")
```json
{ "area":"string", "reason":"string", "accounts":["12-digit"], "recommended_collection":"CLI/API to run" }
```

## Enumerator output — `aws_attack_chains/v1` (consumed by the report packager)
```json
{ "schema":"aws_attack_chains/v1",
  "metadata":{ "customer":"", "generated_at":"", "account_count":0, "node_count":0,
               "edge_count":0, "technique_count":0, "kill_chain_count":0 },
  "kill_chains":[ { "id":"KC-1", "title":"", "tactic_sequence":[], "steps":["pill labels"],
                    "objective":"", "crown_jewel_id":"", "severity":"critical",
                    "score":0.0, "live":false, "misconfigurations":["strings"],
                    "evidence":"", "node_path":["node id"] } ],
  "techniques":[ { "id":"T-001", "number":1, "category":"A. Initial Access ...", "tactic":"initial-access",
                   "title":"", "chain":"", "misconfigurations":["strings"], "mitre":[],
                   "severity":"high", "live":false,
                   "refs":{ "account_ids":[], "resources":[] } } ],
  "root_causes":[ { "class":"", "scope":"", "count":0, "feeds":[1,2,3] } ],
  "active_threats":[ ActiveThreat ],
  "gaps":[ Gap ] }
```

## Cross-account collection convention
All collectors accept `--accounts accounts.json` (array of `{account_id, role_arn?, profile?, external_id?}`)
and assume `role_arn` per account (default role name `TransilienceComplianceRole`), mirroring a typical
cross-account audit-role model. They must record per-account collection errors/denials as `Gap` records
rather than failing the whole run, and support `--ingest <dir/glob>` to reuse existing CSPM / inventory /
IAM / GuardDuty JSON instead of re-collecting (efficiency).
```
```
Scripts must be deterministic and stdlib+boto3 only. Do NOT call time/date at import; take `--now`
(ISO string) for any timestamp so re-runs are reproducible.
```
