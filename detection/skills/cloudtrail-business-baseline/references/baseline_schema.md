# CloudTrail Business Baseline Schema

Top-level fields:

- `metadata`: generation time, customer, source observation file, counts, caveats.
- `overall`: global counts, top events, top actors, top source IPs, business-family mix, risk mix.
- `accounts`: keyed by account ID; each value contains counts, top events, actors, source IPs, regions, and business families.
- `business_families`: keyed by business family; each value contains interpretation, counts, top events/actors/source IPs, and abnormal conditions.
- `actor_event_baseline`: list of tuple records for account/actor/event/source-IP recurrence analysis.
- `alert_candidates`: first-seen, rare, critical, or human-driven high-risk observations that should remain reviewable.

Baseline caveat:

Observed recurrence is business context, not approval. Critical visibility, identity, destructive, exposure, root, and audit-integrity events must remain alertable unless an explicit exception exists.
