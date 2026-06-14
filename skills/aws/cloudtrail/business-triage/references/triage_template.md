# CloudTrail Business Triage Finding Template

Use this structure for every finding:

1. `What happened`: concrete event names, actors, accounts, source IPs, cadence, resources.
2. `Why it likely happened`: business interpretation with confidence.
3. `Evidence`: raw CloudTrail paths, event counts, top fields, reproduction references.
4. `Business-as-usual assessment`: normal, likely sanctioned, suspicious, or unknown.
5. `Residual risk`: what remains risky even if authorized.
6. `Verification`: tickets, owner confirmation, source network, MFA, post-event activity.
7. `Remediation`: control change, not just one-off investigation.
8. `Alerting implication`: what should alert next time and what can be suppressed.
