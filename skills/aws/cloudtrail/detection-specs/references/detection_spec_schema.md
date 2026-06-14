# Portable CloudTrail Detection Spec Schema

Required fields:

- `id`: stable snake-case identifier.
- `title`: concise alert title.
- `severity`: `critical`, `high`, `medium`, or `low`.
- `business_family`: baseline family the alert belongs to.
- `description`: what the alert detects and why it matters.
- `logic`: backend-neutral conditions.
- `required_fields`: CloudTrail fields needed to evaluate the alert.
- `required_evidence`: fields/artifacts analysts must collect for triage.
- `suppression_conditions`: explicit conditions that can suppress or downgrade.
- `response`: immediate analyst response steps.
- `references`: paths or baseline sections used to generate the spec.

Do not encode customer-specific exceptions directly in `logic`; put them in `suppression_conditions` or an external exception file.
