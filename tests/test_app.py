from __future__ import annotations

import asyncio
import re
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp.types import ImageContent, TextContent

from csp_mcp import app


class AppContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_registered_tools_match_the_documented_33_tool_contract(self) -> None:
        registered = {tool.name for tool in await app.mcp.list_tools()}
        catalog = (Path(__file__).resolve().parent.parent / "docs" / "TOOL_CATALOG.md").read_text(
            encoding="utf-8"
        )
        documented = set(re.findall(r"\| `(csp_[^`]+)` \|", catalog))
        self.assertEqual(len(registered), 33)
        self.assertEqual(registered, documented)

        preflight = app.mcp._tool_manager.get_tool("csp_preflight")
        self.assertTrue(preflight.annotations.destructiveHint)
        self.assertTrue(preflight.annotations.openWorldHint)

    async def test_tool_text_shown_in_host_prompts_is_english(self) -> None:
        # Hosts show titles and descriptions in approval prompts; keep them readable
        # without a Chinese UI, as the upstream 5.1.2 profile assumed.
        cjk = re.compile(r"[　-鿿＀-￯]")
        for tool in await app.mcp.list_tools():
            with self.subTest(tool=tool.name):
                self.assertTrue(tool.title)
                self.assertTrue(tool.description)
                self.assertIsNone(cjk.search(tool.title))
                self.assertIsNone(cjk.search(tool.description))
        registry = (Path(__file__).resolve().parent.parent / "config" / "commands.json").read_text(
            encoding="utf-8"
        )
        self.assertIsNone(cjk.search(registry))

    async def test_capture_returns_native_content_without_structured_base64_duplicate(self) -> None:
        with patch.object(
            app.controller,
            "capture",
            return_value=({"captureId": "fixture", "authorizableForInput": False}, b"png-fixture"),
        ):
            result = await app.mcp.call_tool("csp_capture", {})

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], TextContent)
        self.assertIsInstance(result[1], ImageContent)
        self.assertNotIn("cG5nLWZpeHR1cmU=", result[0].text)
        tool = app.mcp._tool_manager.get_tool("csp_capture")
        self.assertIsNone(tool.fn_metadata.output_schema)
        self.assertFalse(tool.fn_metadata.wrap_output)

    async def test_blocking_controller_call_does_not_block_mcp_event_loop(self) -> None:
        started = threading.Event()

        def slow_call():
            started.set()
            time.sleep(0.35)
            return "slow"

        slow_task = asyncio.create_task(app._call(slow_call))
        self.assertTrue(await asyncio.to_thread(started.wait, 1.0))
        began = time.perf_counter()
        self.assertEqual(await app._call(lambda: "fast"), "fast")
        self.assertLess(time.perf_counter() - began, 0.2)
        self.assertEqual(await slow_task, "slow")

    async def test_cancelled_wrapper_waits_for_cooperative_worker_cleanup(self) -> None:
        started = threading.Event()
        stopped = threading.Event()

        def cancellable_call():
            started.set()
            while True:
                event = app.controller._current_cancel_event()
                if event is not None and event.is_set():
                    stopped.set()
                    return "stopped"
                time.sleep(0.01)

        task = asyncio.create_task(app._call(cancellable_call))
        self.assertTrue(await asyncio.to_thread(started.wait, 1.0))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(stopped.is_set())

    async def test_repeated_cancellation_still_joins_cooperative_worker(self) -> None:
        started = threading.Event()
        saw_cancel = threading.Event()
        release = threading.Event()
        stopped = threading.Event()

        def cancellable_call():
            started.set()
            while True:
                event = app.controller._current_cancel_event()
                if event is not None and event.is_set():
                    saw_cancel.set()
                    release.wait(1.0)
                    stopped.set()
                    return "stopped"
                time.sleep(0.005)

        task = asyncio.create_task(app._call(cancellable_call))
        self.assertTrue(await asyncio.to_thread(started.wait, 1.0))
        task.cancel()
        self.assertTrue(await asyncio.to_thread(saw_cancel.wait, 1.0))
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(stopped.is_set())


if __name__ == "__main__":
    unittest.main()
