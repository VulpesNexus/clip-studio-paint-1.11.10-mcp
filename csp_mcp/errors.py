from __future__ import annotations

import json
import uuid
from typing import Any, Literal, TypedDict

from mcp.server.fastmcp.exceptions import ToolError


class ToolEnvelope(TypedDict):
    """Stable success contract exposed in every structured MCP output schema."""

    ok: bool
    operationId: str
    stateRevisionBefore: str | None
    stateRevisionAfter: str | None
    stateChange: Literal["none", "possible", "confirmed"]
    result: Any
    verification: dict[str, Any]
    warnings: list[str]


class BridgeError(ToolError):
    """A structured, model-readable MCP tool error."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        stage: str = "operation",
        state_change: str = "none",
        details: dict[str, Any] | None = None,
        recovery: list[str] | None = None,
    ) -> None:
        self.code = code
        self.state_change = state_change
        payload = {
            "ok": False,
            "operationId": str(uuid.uuid4()),
            "error": {
                "code": code,
                "message": message,
                "retryable": retryable,
                "stage": stage,
                "details": details or {},
            },
            "stateChange": state_change,
            "recovery": recovery or [],
        }
        super().__init__(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def ok_result(
    result: dict[str, Any] | list[Any] | str | None = None,
    *,
    state_change: str = "none",
    before: str | None = None,
    after: str | None = None,
    verification: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
) -> ToolEnvelope:
    return {
        "ok": True,
        "operationId": str(uuid.uuid4()),
        "stateRevisionBefore": before,
        "stateRevisionAfter": after,
        "stateChange": state_change,
        "result": result if result is not None else {},
        "verification": verification or {"method": [], "confidence": 1.0},
        "warnings": warnings or [],
    }
