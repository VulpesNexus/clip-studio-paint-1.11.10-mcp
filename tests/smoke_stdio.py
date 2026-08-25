from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from csp_mcp.config import load_settings


async def main() -> None:
    settings = load_settings()
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-X", "utf8", str(PROJECT_ROOT / "server.py")],
        cwd=PROJECT_ROOT,
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools = {tool.name: tool for tool in listed.tools}
            expected = {
                "csp_health", "csp_capabilities", "csp_get_activity", "csp_list_windows",
                "csp_get_state", "csp_capture", "csp_compare_captures", "csp_sample_pixel",
                "csp_inspect_ui", "csp_list_commands", "csp_list_auto_actions", "csp_launch",
                "csp_focus", "csp_window_action", "csp_wait_visual_change", "csp_cancel",
                "csp_move_pointer", "csp_click", "csp_drag", "csp_scroll", "csp_type_text",
                "csp_navigation_key", "csp_preflight", "csp_run_command",
                "csp_run_auto_action", "csp_run_command_sequence", "csp_validate_path",
                "csp_list_assets", "csp_file_info", "csp_scan_exports", "csp_wait_for_file",
                "csp_open_document", "csp_native_file_dialog",
            }
            assert tools.keys() == expected, {
                "missing": sorted(expected - tools.keys()),
                "unexpected": sorted(tools.keys() - expected),
            }
            assert tools["csp_health"].annotations.readOnlyHint is True
            assert tools["csp_click"].annotations.destructiveHint is True
            assert tools["csp_cancel"].annotations.idempotentHint is False
            assert tools["csp_preflight"].annotations.idempotentHint is False
            assert "identifier" not in tools["csp_preflight"].inputSchema.get("required", [])
            token_gated = {
                "csp_move_pointer", "csp_click", "csp_drag", "csp_scroll", "csp_type_text",
                "csp_navigation_key", "csp_run_command", "csp_run_auto_action",
                "csp_run_command_sequence", "csp_native_file_dialog",
            }
            for name in token_gated:
                assert "confirm_token" in tools[name].inputSchema.get("required", []), name
            assert tools["csp_capture"].outputSchema is None
            envelope_fields = {
                "ok", "operationId", "stateRevisionBefore", "stateRevisionAfter",
                "stateChange", "result", "verification", "warnings",
            }
            for name, tool in tools.items():
                if name == "csp_capture":
                    continue
                assert tool.outputSchema is not None, name
                assert envelope_fields <= set(tool.outputSchema.get("required", [])), {
                    "tool": name,
                    "schema": tool.outputSchema,
                }

            health = await session.call_tool("csp_health", {})
            assert not health.isError
            text = next(item.text for item in health.content if isinstance(item, TextContent))
            payload = json.loads(text)
            assert payload["ok"] is True
            assert payload["result"]["binary"]["supported"] is True

            denied = await session.call_tool(
                "csp_validate_path",
                {"path": r"C:\Windows\Temp\outside.png", "intent": "output_new"},
            )
            assert denied.isError is True
            denied_text = next(item.text for item in denied.content if isinstance(item, TextContent))
            assert "E_PATH_OUTSIDE_ALLOWLIST" in denied_text

            no_capture = await session.call_tool(
                "csp_click",
                {"x": 0.5, "y": 0.5, "capture_id": "", "confirm_token": "invalid"},
            )
            assert no_capture.isError is True
            no_capture_text = next(item.text for item in no_capture.content if isinstance(item, TextContent))
            assert "E_STALE_CAPTURE" in no_capture_text

            actions = await session.call_tool("csp_list_auto_actions", {})
            assert not actions.isError

            missing_output = settings.root("working").path / f"mcp-concurrency-{uuid.uuid4()}.png"
            wait_task = asyncio.create_task(
                session.call_tool(
                    "csp_wait_for_file",
                    {"path": str(missing_output), "timeout_ms": 2000, "stable_ms": 200},
                )
            )
            await asyncio.sleep(0.1)
            began = time.perf_counter()
            concurrent_activity = await session.call_tool("csp_get_activity", {})
            activity_latency = time.perf_counter() - began
            assert not concurrent_activity.isError
            assert activity_latency < 0.75, activity_latency
            waited = await wait_task
            assert waited.isError is True

            print(json.dumps({"ok": True, "toolCount": len(tools), "tests": 18, "concurrentReadLatencySeconds": round(activity_latency, 3)}, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
