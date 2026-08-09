# Google Admin Reports Feed Selection

Default security collection should include:

| Feed | Purpose |
| --- | --- |
| `admin` | Admin policy, role, user lifecycle, OAuth app-control, SSO, security settings. |
| `drive` | External sharing, downloads, ownership changes, public-like visibility, access requests. |
| `login` | Login failures, password and 2SV changes, risky sensitive action events. |
| `token` | OAuth grants, clients, applications, and scopes. |
| `access_evaluation` | Context-aware or app-access evaluation signals, including allowed or blocked access context. |
| `gemini_in_workspace_apps` | Gemini Workspace feature utilization by users and applications. |
| `user_accounts` | Account lifecycle and user state changes. |

Optional feeds for expanded reviews:

- `gmail`, `calendar`, `chat`, `meet`, and `groups_enterprise` for collaboration-specific investigations.
- `saml`, `rules`, `mobile`, and `context_aware_access` for authentication and policy investigations.
- `gcp` when Google Cloud administrative activity is in scope.

Prefer a bounded window first. If OAuth app-control history matters, run a second 180-day `admin` lookback focused on OAuth control events.
