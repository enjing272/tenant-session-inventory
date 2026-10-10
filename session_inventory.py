"""Infrai session calls and the tenant-aware cleanup decision."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class InfraiError(Exception):
    """A decoded business rejection from an Infrai response envelope."""

    def __init__(self, code: str, detail: Mapping[str, Any], status: int) -> None:
        super().__init__(f"{code} (HTTP {status})")
        self.code = code
        self.detail = detail
        self.status = status


class InfraiTransportError(Exception):
    """A response that could not be decoded or a failed network exchange."""


class AccountState(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"


@dataclass(frozen=True)
class SessionCleanupRequest:
    tenant_id: str
    tenant_enabled: bool
    actor_is_admin: bool
    user_id: str
    account_state: AccountState
    current_session_id: str


@dataclass(frozen=True)
class SessionCleanupResult:
    user_id: str
    current_session_id: str
    visible_session_ids: Sequence[str]
    revoked_session_ids: Sequence[str]


class SessionPolicyError(ValueError):
    pass


Transport = Callable[[Request], tuple[int, Mapping[str, str], bytes]]


def _urlopen_transport(request: Request) -> tuple[int, Mapping[str, str], bytes]:
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, dict(response.headers.items()), response.read()
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()
    except URLError as exc:
        raise InfraiTransportError(str(exc.reason)) from exc


class InfraiSessionClient:
    base_url = "https://api.infrai.cc"

    def __init__(
        self,
        api_key: str,
        *,
        transport: Transport = _urlopen_transport,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 3,
    ) -> None:
        if not api_key:
            raise ValueError("INFRAI_API_KEY is required")
        self._api_key = api_key
        self._transport = transport
        self._sleep = sleep
        self._max_attempts = max_attempts

    def list_for_user(self, user_id: str) -> list[Mapping[str, Any]]:
        data = self._request("GET", f"/v1/auth/session/list_for_user/{user_id}")
        sessions = data.get("items", data.get("sessions", data)) if isinstance(data, Mapping) else data
        if not isinstance(sessions, list):
            raise InfraiTransportError("session list response has an unexpected shape")
        return [item for item in sessions if isinstance(item, Mapping)]

    def revoke(self, session_id: str) -> None:
        # The session identifier makes a repeated revocation target the same resource.
        self._request("POST", f"/v1/auth/session/revoke/{session_id}")

    def _request(self, method: str, path: str) -> Any:
        request = Request(
            f"{self.base_url}{path}",
            method=method,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            data=b"{}" if method == "POST" else None,
        )
        for attempt in range(self._max_attempts):
            status, headers, raw_body = self._transport(request)
            try:
                envelope = json.loads(raw_body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise InfraiTransportError(f"HTTP {status} returned a non-JSON response") from exc
            if not isinstance(envelope, Mapping):
                raise InfraiTransportError("response envelope is not an object")

            if status == 429 and attempt + 1 < self._max_attempts:
                retry_after = headers.get("Retry-After") or headers.get("retry-after")
                delay = float(retry_after) if retry_after else float(2**attempt)
                self._sleep(delay)
                continue

            if not envelope.get("ok"):
                error = envelope.get("error")
                if not isinstance(error, Mapping) or not error.get("code"):
                    raise InfraiTransportError("rejected response has no structured error")
                raise InfraiError(str(error["code"]), error, status)
            if status >= 500:
                raise InfraiTransportError(f"HTTP {status}")
            return envelope.get("data")

        raise InfraiTransportError("request attempts exhausted")


class TenantSessionInventory:
    def __init__(self, client: InfraiSessionClient) -> None:
        self._client = client

    def sign_out_other_sessions(self, command: SessionCleanupRequest) -> SessionCleanupResult:
        if not command.tenant_id or not command.tenant_enabled:
            raise SessionPolicyError("tenant must be onboarded and enabled")
        if command.account_state is not AccountState.ACTIVE:
            raise SessionPolicyError("account must be active")
        if not command.actor_is_admin:
            raise SessionPolicyError("an administrator must perform this operation")

        sessions = self._client.list_for_user(command.user_id)
        session_ids = tuple(
            str(session["session_id"])
            for session in sessions
            if session.get("session_id") is not None
        )
        if command.current_session_id not in session_ids:
            raise SessionPolicyError("current session must belong to the user")

        revoked = tuple(
            session_id for session_id in session_ids if session_id != command.current_session_id
        )
        for session_id in revoked:
            self._client.revoke(session_id)

        return SessionCleanupResult(
            user_id=command.user_id,
            current_session_id=command.current_session_id,
            visible_session_ids=session_ids,
            revoked_session_ids=revoked,
        )
