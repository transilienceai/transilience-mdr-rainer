# Admin Console Validation

Before issuing remediation instructions, validate current state:

1. Security > API controls > App access control.
2. Confirm app status: trusted, limited, blocked, configured, or unconfigured.
3. Confirm whether the app has OAuth client IDs, publisher verification, or domain-wide delegation.
4. Check whether the app is approved for all users, an OU, a group, or only individual users.
5. Compare current state with `admin.ndjson` control-change history.
6. Validate business owner and legitimate use case before blocking.

Admin app-control event names to review include:

- `ADD_TO_TRUSTED_OAUTH2_APPS`
- `REMOVE_FROM_TRUSTED_OAUTH2_APPS`
- `ADD_TO_LIMITED_OAUTH2_APPS`
- `REMOVE_FROM_LIMITED_OAUTH2_APPS`
- `ADD_TO_BLOCKED_OAUTH2_APPS`
- `REMOVE_FROM_BLOCKED_OAUTH2_APPS`
- `ADD_TO_TRUSTED_BY_OAUTH_SCOPE_OAUTH2_APPS`
- `REMOVE_FROM_TRUSTED_BY_OAUTH_SCOPE_OAUTH2_APPS`
- `ADD_TO_CAA_EXEMPT_OAUTH2_APPS`
- `REMOVE_FROM_CAA_EXEMPT_OAUTH2_APPS`

Use a 180-day admin lookback when reconstructing app-control history.
