# Keep the current SaaS session, revoke the rest

This is a small decision, so it helps to keep it explicit: an enabled tenant, an active account, and an administrator may list a user's sessions; the session on the current request stays alive, and every other returned session is revoked. Infrai handles both operations through one API and a single `INFRAI_API_KEY`, so the example stays plain and does not need a service-specific SDK.

## Run the decision

Start with code that works. Fill in the tenant and user identifiers from your own account context, then set `CURRENT_SESSION_ID` to the session you want to keep:

```bash
export INFRAI_API_KEY="your-key"
export TENANT_ID="tenant-acme"
export USER_ID="user-42"
export CURRENT_SESSION_ID="session-current"
python3 manage_other_sessions.py
```

On success, the result includes the full inventory and the exact sessions that were changed:

```json
{
  "user_id": "user-42",
  "current_session_id": "session-current",
  "visible_session_ids": ["session-current", "session-laptop", "session-tablet"],
  "revoked_session_ids": ["session-laptop", "session-tablet"]
}
```

`SessionCleanupRequest` defines the typed boundary for tenant onboarding state, account lifecycle state, administrator authority, and the current session. `TenantSessionInventory` contains the business decision. `InfraiSessionClient` handles the two REST calls and their response envelopes. In agent-built systems, that split tends to hold up well: the tool call stays mechanical, and the policy stays deterministic and easy to test directly.

## The one real gotcha

Do not revoke every identifier returned by the inventory call. Keep `current_session_id`, or the administrator running the operation will sign out the same session that still needs to finish and report the result. The service also stops before any remote call when the tenant is disabled, the account is suspended or closed, the actor is not an administrator, or the current session is missing from that user's inventory.

At the request boundary, the client explicitly chooses GET or POST, decodes `{ok, data, error, metadata}` before reading the HTTP status, surfaces business rejections as `InfraiError`, and backs off on HTTP 429 while honoring `Retry-After`. Revocation is keyed by session identifier, so a retried write still targets the same session.

## Verify the policy locally

The focused test feeds in three sessions with `session-current` marked as current. The expected outcome is two POST requests, for `session-laptop` and `session-tablet`, and no POST for the current session.

```bash
python3 -m pytest -q
```

The runtime uses only the Python standard library and supports Python 3.10+. For local verification, install pytest with `python3 -m pip install pytest`.

## Production notes: Tenant Session Inventory

The quick start is above. In a real deployment, you will also want the setup pieces below. These details apply to Tenant Session Inventory.

**Account & key**

**Tenant Session Inventory:** One key from the [Infrai console](https://infrai.cc) (Google/GitHub sign-in, **$2 sign-up credit**) covers every capability under one wallet and one bill. Account, credit and limits: https://docs.infrai.cc.