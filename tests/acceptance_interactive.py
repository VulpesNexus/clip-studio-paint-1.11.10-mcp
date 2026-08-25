from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from csp_mcp.config import load_settings


FILE_DIALOG_FIXTURE = load_settings().root("input").path / "mcp-dialog-smoke.svg"


def first_json(result) -> dict:
    text = next(item.text for item in result.content if isinstance(item, TextContent))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # FastMCP prefixes ToolError text (for example, "Error executing
        # tool ...: ") before the server's stable JSON error envelope.
        start = text.find("{")
        if start < 0:
            raise
        return json.loads(text[start:])


async def main() -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-X", "utf8", str(PROJECT_ROOT / "server.py")],
        cwd=PROJECT_ROOT,
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            windows = await session.call_tool("csp_list_windows", {})
            assert not windows.isError, first_json(windows)
            window_items = first_json(windows)["result"]["windows"]
            assert len(window_items) == 1, window_items
            hwnd = int(window_items[0]["hwnd"])

            focus = await session.call_tool("csp_focus", {"hwnd": hwnd})
            assert not focus.isError, first_json(focus)

            dialog_open = False
            try:
                command_parameters = json.dumps(
                    {"command_id": "document.open_dialog"},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                command_preflight = await session.call_tool(
                    "csp_preflight",
                    {
                        "operation": "input",
                        "identifier": "csp_run_command",
                        "parameters_json": command_parameters,
                        "main_hwnd": hwnd,
                    },
                )
                assert not command_preflight.isError, first_json(command_preflight)
                command_token = first_json(command_preflight)["result"]["confirmToken"]
                before = await session.call_tool("csp_capture", {"hwnd": hwnd, "max_width": 1200})
                assert not before.isError, first_json(before)
                before_meta = first_json(before)
                assert before_meta["authorizableForInput"], before_meta

                opened = await session.call_tool(
                    "csp_run_command",
                    {
                        "command_id": "document.open_dialog",
                        "capture_id": before_meta["captureId"],
                        "confirm_token": command_token,
                        "hwnd": hwnd,
                    },
                )
                assert not opened.isError, first_json(opened)
                dialog_open = True
                state = await session.call_tool("csp_get_state", {"hwnd": hwnd})
                assert not state.isError, first_json(state)
                dialogs = first_json(state)["result"]["dialogs"]
                native_dialogs = [item for item in dialogs if item["className"] == "#32770"]
                assert len(native_dialogs) == 1
                dialog_hwnd = int(native_dialogs[0]["hwnd"])

                dialog_parameters = json.dumps(
                    {"path": str(FILE_DIALOG_FIXTURE), "intent": "input", "submit": False},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                dialog_preflight = await session.call_tool(
                    "csp_preflight",
                    {
                        "operation": "input",
                        "identifier": "csp_native_file_dialog",
                        "parameters_json": dialog_parameters,
                        "main_hwnd": hwnd,
                        "dialog_hwnd": dialog_hwnd,
                    },
                )
                assert not dialog_preflight.isError, first_json(dialog_preflight)
                dialog_token = first_json(dialog_preflight)["result"]["confirmToken"]

                filled = await session.call_tool(
                    "csp_native_file_dialog",
                    {
                        "path": str(FILE_DIALOG_FIXTURE),
                        "intent": "input",
                        "submit": False,
                        "dialog_hwnd": dialog_hwnd,
                        "main_hwnd": hwnd,
                        "confirm_token": dialog_token,
                    },
                )
                assert not filled.isError, first_json(filled)
                assert first_json(filled)["result"]["pathSet"] is True
                assert first_json(filled)["result"]["submitted"] is False

                closed = await session.call_tool("csp_cancel", {"hwnd": hwnd})
                assert not closed.isError, first_json(closed)
                dialog_open = False

                after = await session.call_tool("csp_capture", {"hwnd": hwnd, "max_width": 1200})
                assert not after.isError, first_json(after)
                after_meta = first_json(after)

                compare = await session.call_tool(
                    "csp_compare_captures",
                    {
                        "first_capture_id": before_meta["captureId"],
                        "second_capture_id": after_meta["captureId"],
                    },
                )
                assert not compare.isError, first_json(compare)

                narrow = await session.call_tool(
                    "csp_capture",
                    {"hwnd": hwnd, "region": [0.0, 0.0, 0.1, 1.0], "max_width": 1000},
                )
                assert not narrow.isError, first_json(narrow)
                narrow_meta = first_json(narrow)
                unchanged = await session.call_tool(
                    "csp_wait_visual_change",
                    {"capture_id": narrow_meta["captureId"], "threshold": 1.0, "timeout_ms": 100},
                )
                assert not unchanged.isError, first_json(unchanged)
                print(
                    json.dumps(
                        {
                            "ok": True,
                            "windowId": before_meta["windowId"],
                            "beforeCaptureId": before_meta["captureId"],
                            "afterCaptureId": after_meta["captureId"],
                            "comparison": first_json(compare)["result"],
                            "narrowRegionWait": first_json(unchanged)["result"],
                            "stateMutation": "no document mutation; window state left unchanged",
                        },
                        ensure_ascii=False,
                    )
                )
            finally:
                if dialog_open:
                    await session.call_tool("csp_cancel", {"hwnd": hwnd})


if __name__ == "__main__":
    asyncio.run(main())
