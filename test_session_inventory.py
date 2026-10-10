from __future__ import annotations

import json
import unittest
from typing import Mapping
from urllib.request import Request

from session_inventory import (
    AccountState,
    InfraiSessionClient,
    SessionCleanupRequest,
    TenantSessionInventory,
)


class RecordingTransport:
    def __init__(self) -> None:
        self.requests: list[Request] = []

    def __call__(self, request: Request) -> tuple[int, Mapping[str, str], bytes]:
        self.requests.append(request)
        if request.get_method() == "GET":
            envelope = {
                "ok": True,
                "data": {
                    "items": [
                        {"session_id": "session-current"},
                        {"session_id": "session-laptop"},
                        {"session_id": "session-tablet"},
                    ]
                },
                "error": None,
                "metadata": {},
            }
        else:
            envelope = {"ok": True, "data": {}, "error": None, "metadata": {}}
        return 200, {}, json.dumps(envelope).encode("utf-8")


class TenantSessionInventoryTest(unittest.TestCase):
    def test_admin_keeps_current_session_and_revokes_every_other_session(self) -> None:
        transport = RecordingTransport()
        service = TenantSessionInventory(
            InfraiSessionClient("test-key", transport=transport)
        )
        command = SessionCleanupRequest(
            tenant_id="tenant-acme",
            tenant_enabled=True,
            actor_is_admin=True,
            user_id="user-42",
            account_state=AccountState.ACTIVE,
            current_session_id="session-current",
        )

        result = service.sign_out_other_sessions(command)

        self.assertEqual(
            result.revoked_session_ids,
            ("session-laptop", "session-tablet"),
        )
        self.assertEqual(
            [request.get_method() for request in transport.requests],
            ["GET", "POST", "POST"],
        )
        self.assertTrue(transport.requests[0].full_url.endswith("/user-42"))
        self.assertTrue(transport.requests[1].full_url.endswith("/session-laptop"))
        self.assertTrue(transport.requests[2].full_url.endswith("/session-tablet"))
        self.assertEqual(
            transport.requests[0].get_header("Authorization"),
            "Bearer test-key",
        )


if __name__ == "__main__":
    unittest.main()
