---
name: shadow-ai-google-workspace
description: Detect and triage employee shadow AI usage from Google Workspace Admin Reports evidence, including OAuth token grants, access evaluation events, Gemini Workspace app utilization, AI-related application names, broad Google scopes, and admin OAuth app-control changes. Use when Codex needs to analyze Google Workspace logs for users enabling AI tools with Google authentication, Microsoft-style auth analogs documented in evidence, or unmanaged AI SaaS exposure.
---

# Google Workspace Shadow AI Detection

Use this skill to identify AI tool usage and OAuth exposure in Google Workspace audit evidence.

## Workflow

1. Start from a Google Workspace evidence directory containing `token.ndjson`, `access_evaluation.ndjson`, `admin.ndjson`, and optionally `gemini_in_workspace_apps.ndjson`.
2. Run `scripts/analyze_shadow_ai.py --input-dir <evidence> --output-dir <analysis> --internal-domain <domain>`.
3. Review confidence levels before making claims:
   - `confirmed_oauth_grant`: token feed evidence for an AI-like app or AI-related scope context.
   - `access_evaluation_context`: access-evaluation evidence that may indicate policy evaluation, attempted access, or contextual allow/block decisions.
   - `workspace_gemini_usage`: Gemini Workspace utilization events.
   - `admin_oauth_control`: Admin app trust, limited, block, exempt, or OAuth-scope control changes.
   - `keyword_only`: weak signal from naming only; validate manually.
4. Check `broad_oauth_events.csv` for non-AI apps with risky Gmail, Drive, Calendar, Admin, Apps Script, or broad identity scope exposure.
5. Validate current state in Admin Console before recommending block, trust, limited, or remediation actions.

## Evidence Interpretation

- Treat OAuth token feed rows as stronger evidence than app-name hits in access evaluation.
- Treat access-evaluation rows as context unless the event parameters clearly show an allowed access decision.
- Treat Gemini Workspace logs as first-party usage, not third-party shadow SaaS.
- Treat broad scopes on productivity apps as data-exposure findings even when the app is not clearly AI.
- Use `references/oauth-risk-scopes.md` for scope severity and `references/ai-app-patterns.yaml` for app matching.
- Use `references/admin-console-validation.md` before finalizing remediation.

## Outputs

The analyzer writes:

- `shadow_ai_summary.json`
- `shadow_ai_oauth_events.csv`
- `broad_oauth_events.csv`
- `gemini_workspace_events.csv`
- `oauth_admin_control_events.csv`

Keep raw evidence separate from analysis outputs.
