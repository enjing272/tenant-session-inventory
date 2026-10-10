"""Runnable tenant-admin session cleanup example."""

from __future__ import annotations

import json
import os

from session_inventory import (
    AccountState,
    InfraiSessionClient,
    SessionCleanupRequest,
    TenantSessionInventory,
)


def main() -> None:
    command = SessionCleanupRequest(
        tenant_id=os.environ["TENANT_ID"],
        tenant_enabled=True,
        actor_is_admin=True,
        user_id=os.environ["USER_ID"],
        account_state=AccountState.ACTIVE,
        current_session_id=os.environ["CURRENT_SESSION_ID"],
    )
    inventory = TenantSessionInventory(
        InfraiSessionClient(api_key=os.environ["INFRAI_API_KEY"])
    )
    result = inventory.sign_out_other_sessions(command)
    print(
        json.dumps(
            {
                "user_id": result.user_id,
                "current_session_id": result.current_session_id,
                "visible_session_ids": result.visible_session_ids,
                "revoked_session_ids": result.revoked_session_ids,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
