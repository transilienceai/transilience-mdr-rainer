# Weekly Finding Rules

Shadow AI and OAuth:

- AI-like app in `token` feed: confirmed OAuth evidence, pending business validation.
- AI-like app in `access_evaluation`: contextual evidence; validate whether access was allowed, blocked, or only evaluated.
- Broad OAuth scopes: triage separately even if the app is not AI-like.
- Admin OAuth app-control events: review control change history and current Admin Console state.

Drive exposure:

- `change_user_access` with external email or domain: external grant.
- `download` by external actor: external download.
- `request_access`: access request requiring owner or admin context.
- Visibility containing `people_with_link`, `shared_externally`, or `public`: public-like exposure.
- Ownership transfer involving externally visible files: shared-transfer exposure.

Authentication:

- `login_failure`: aggregate by user and source IP.
- `risky_sensitive_action_allowed` or `risky_sensitive_action_blocked`: high-priority review.
- Password and 2SV events: validate expected user or admin lifecycle activity.

Admin and configuration:

- Role, privilege, SSO, SAML, OAuth, token, CAA, sharing, user lifecycle, group, mobile, and device changes are configuration events.
- High-risk admin events include role assignment, user creation/suspension/deletion, password reset, and sign-in cookie reset.
