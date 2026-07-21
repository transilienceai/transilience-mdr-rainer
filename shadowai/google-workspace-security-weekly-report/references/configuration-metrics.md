# Configuration Snapshot Metrics

Useful customer usage report metrics include:

- `accounts:num_users`
- `accounts:num_suspended_users`
- `accounts:num_archived_users`
- `accounts:num_disabled_accounts`
- `accounts:num_users_2sv_enrolled`
- `accounts:num_users_2sv_enforced`
- `accounts:num_users_2sv_protected`
- `accounts:num_security_keys`
- `accounts:num_passkeys_enrolled`
- `accounts:num_users_with_passkeys_enrolled`
- `accounts:num_authorized_apps`
- `accounts:num_users_less_secure_apps_access_allowed`
- `drive:num_owned_items_with_visibility_shared_externally_added`
- `drive:num_owned_items_with_visibility_shared_externally_removed`
- `gmail:num_7day_imap_users`
- `gmail:num_7day_pop_users`
- `meet:num_meetings_with_external_users`
- `meet:num_calls_by_external_users`

Missing metrics should be reported as `not_available`, not zero.
