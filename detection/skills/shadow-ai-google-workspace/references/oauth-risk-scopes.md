# OAuth Scope Risk Guide

High-risk scopes include:

- Gmail: `mail.google.com`, `/gmail`, Gmail send/read/modify scopes.
- Drive: `/drive`, Drive file, metadata, appdata, and broad read/write scopes.
- Docs/Sheets/Slides: document, spreadsheet, and presentation read/write scopes.
- Calendar: calendar read/write and event modification scopes.
- Admin SDK: directory, group, user, role, mobile, and reports scopes.
- Apps Script: `script.external_request`, `script.scriptapp`, script project, and execution scopes.
- Broad identity: `openid`, `userinfo.email`, `userinfo.profile` are low risk alone but raise concern when combined with sensitive data scopes.

Severity guidance:

- Critical: AI-like app with Gmail or Admin SDK write-capable scopes, or broad domain-wide delegation.
- High: AI-like app with Drive/Docs/Sheets/Slides read/write across user data.
- Medium: AI-like app with Calendar or many mixed productivity scopes.
- Low: identity-only scopes without content access.

Scope count alone is not a finding. Use scope count as a triage accelerator.
