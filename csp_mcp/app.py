from __future__ import annotations

import base64
import asyncio
import json
import threading
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ImageContent, TextContent, ToolAnnotations

from .controller import CspController
from .errors import ToolEnvelope, ok_result


INSTRUCTIONS = """Control only the signature- and hash-verified CLIP STUDIO PAINT build of the active profile.
Before any atomic input, call csp_preflight with the exact tool name and full parameters.
For ordinary input, capture again after preflight focuses CSP; use that fresh captureId
and the single-use confirmToken. File-dialog tokens bind the exact main/dialog HWNDs.
When a standard #32770 dialog appears, use only csp_native_file_dialog or csp_cancel.
Screenshot changes do not establish layer semantics. Stop on user input, version/DPI
mismatch, or ambiguous windows. Windows culture is unrestricted by default; explicit
locale pins remain supported. Native file-dialog labels are verified independently
in French, English, or Simplified Chinese; unknown dialogs are rejected.
Path-taking tools operate only in allowlisted asset roots. Do not parse or modify
.clip binaries, use private Companion protocols or DLL injection, or operate account,
store, cloud-sync or publishing workflows."""

mcp = FastMCP(
    name="csp-local-mcp",
    instructions=INSTRUCTIONS,
    log_level="WARNING",
)
controller = CspController()

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
RO_NONIDEMPOTENT = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=False)
UI = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)
UI_NONIDEMPOTENT = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
NEW = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
EDIT = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)
EDIT_OPEN = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)


async def _call(operation: Any, *args: Any) -> Any:
    """Keep FastMCP's event loop responsive and stop input cooperatively on cancellation."""
    cancel_event = threading.Event()
    worker = asyncio.create_task(
        asyncio.to_thread(controller.invoke_with_cancellation, operation, cancel_event, *args)
    )
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        cancel_event.set()
        # A caller may cancel the wrapper more than once while the cooperative
        # worker is unwinding.  Keep joining the thread so it cannot continue
        # holding the cross-process control lock after the MCP call returns.
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                cancel_event.set()
                continue
            except Exception:
                break
        if worker.done() and not worker.cancelled():
            try:
                worker.result()
            except Exception:
                pass
        raise


@mcp.tool(name="csp_health", title="CSP MCP health check", description="Checks the MCP, the CSP executable's signature, version, and hash, the process, windows, displays, and current user activity. Does not control the UI.", annotations=RO, structured_output=True)
async def csp_health() -> ToolEnvelope:
    return await _call(controller.health)


@mcp.tool(name="csp_capabilities", title="List CSP capabilities", description="Reports, one capability at a time, whether window, capture, input, file-exchange, and Auto Action features are available in this environment, and why not when they are not.", annotations=RO, structured_output=True)
async def csp_capabilities(hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.capabilities, hwnd)


@mcp.tool(name="csp_get_activity", title="Check user keyboard and mouse activity", description="Conservatively reads recent system input, idle time, pressed keys, and the control-lock state. Never assumes that the last global input came from this MCP.", annotations=RO, structured_output=True)
async def csp_get_activity() -> ToolEnvelope:
    return ok_result(await _call(controller.activity))


@mcp.tool(name="csp_list_windows", title="List CSP main windows", description="Lists only the main windows of the pinned CSP executable, with physical-pixel coordinates, DPI, and state.", annotations=RO, structured_output=True)
async def csp_list_windows() -> ToolEnvelope:
    return await _call(controller.list_windows)


@mcp.tool(name="csp_get_state", title="Read CSP window state", description="Returns the target main window, the foreground state, visible dialogs, and a transient stateRevision. Never invents layer or document state.", annotations=RO, structured_output=True)
async def csp_get_state(hwnd: int = 0, include_dialogs: bool = True) -> ToolEnvelope:
    return await _call(controller.get_state, hwnd, include_dialogs)


@mcp.tool(name="csp_capture", title="Capture the CSP window", description="Captures only the visible CSP window or a normalized region of it, and returns an MCP image and a captureId valid for 30 seconds. Never captures the whole desktop.", annotations=RO, structured_output=False)
async def csp_capture(
    hwnd: int = 0,
    region: list[float] | None = None,
    max_width: int = 1600,
) -> list[TextContent | ImageContent]:
    metadata, png = await _call(controller.capture, hwnd, region, max_width)
    return [
        TextContent(type="text", text=json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))),
        ImageContent(type="image", data=base64.b64encode(png).decode("ascii"), mimeType="image/png"),
    ]


@mcp.tool(name="csp_compare_captures", title="Compare two CSP captures", description="Computes a downsampled pixel difference between two unexpired captures and reports the share of visible change. Infers no meaning.", annotations=RO, structured_output=True)
async def csp_compare_captures(first_capture_id: str, second_capture_id: str) -> ToolEnvelope:
    return await _call(controller.compare_captures, first_capture_id, second_capture_id)


@mcp.tool(name="csp_sample_pixel", title="Sample a capture pixel", description="Reads the RGBA pixel at normalized coordinates of an existing CSP capture.", annotations=RO, structured_output=True)
async def csp_sample_pixel(capture_id: str, x: float, y: float) -> ToolEnvelope:
    return await _call(controller.sample_pixel, capture_id, x, y)


@mcp.tool(name="csp_inspect_ui", title="Inspect the CSP Win32 window tree", description="Enumerates the Win32 child windows and standard dialogs of the CSP main window. CSP's custom-drawn menus and layers do not appear in the result.", annotations=RO, structured_output=True)
async def csp_inspect_ui(hwnd: int = 0, include_dialogs: bool = True, max_items: int = 200) -> ToolEnvelope:
    return await _call(controller.inspect_ui, hwnd, include_dialogs, max_items)


@mcp.tool(name="csp_list_commands", title="List registered CSP commands", description="Lists the versioned shortcut-command catalog without revealing the underlying key combinations.", annotations=RO, structured_output=True)
async def csp_list_commands(category: str = "", available_only: bool = True) -> ToolEnvelope:
    return await _call(controller.list_commands, category, available_only)


@mcp.tool(name="csp_list_auto_actions", title="List registered Auto Actions", description="Lists the Auto Actions that the user bound to shortcuts in CSP and registered locally. Never parses or modifies .laf files.", annotations=RO, structured_output=True)
async def csp_list_auto_actions() -> ToolEnvelope:
    return await _call(controller.list_auto_actions)


@mcp.tool(name="csp_launch", title="Launch CSP", description="Launches only the pinned CSP executable whose signature and hash match. If CSP is already running, returns its window.", annotations=NEW, structured_output=True)
async def csp_launch(wait_ready_ms: int = 15000) -> ToolEnvelope:
    return await _call(controller.launch, wait_ready_ms)


@mcp.tool(name="csp_focus", title="Restore and focus CSP", description="Waits until the user's keyboard and mouse are idle, then restores and focuses the unique CSP main window and verifies the foreground handle.", annotations=UI, structured_output=True)
async def csp_focus(hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.focus, hwnd)


@mcp.tool(name="csp_window_action", title="Change the CSP window state", description="Restores, maximizes, or minimizes the CSP main window. Never moves or resizes any other application.", annotations=UI, structured_output=True)
async def csp_window_action(action: Literal["restore", "maximize", "minimize"], hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.window_action, action, hwnd)


@mcp.tool(name="csp_wait_visual_change", title="Wait for a visible CSP change", description="Waits up to 30 seconds for the target capture to reach the given pixel-change threshold. Observation only; sends no input.", annotations=RO, structured_output=True)
async def csp_wait_visual_change(capture_id: str, threshold: float = 0.002, timeout_ms: int = 10000) -> ToolEnvelope:
    return await _call(controller.wait_visual_change, capture_id, threshold, timeout_ms)


@mcp.tool(name="csp_cancel", title="Cancel the current CSP operation", description="Waits until the user is idle, focuses CSP, sends one Escape, and verifies the result with before and after captures.", annotations=UI_NONIDEMPOTENT, structured_output=True)
async def csp_cancel(hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.cancel, hwnd)


@mcp.tool(name="csp_move_pointer", title="Move the pointer within CSP", description="Consumes a single-use csp_preflight token bound to the exact parameters and moves the pointer to a CSP location bound to the captureId taken afterward.", annotations=UI, structured_output=True)
async def csp_move_pointer(
    x: float,
    y: float,
    capture_id: str,
    confirm_token: str,
    region: Literal["client", "window"] = "client",
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.move_pointer, x, y, region, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_click", title="Click or double-click in CSP", description="Consumes a single-use token bound to the exact parameters and clicks or double-clicks only a CSP point in the capture taken after approval. What a custom-drawn control does cannot be inferred.", annotations=EDIT_OPEN, structured_output=True)
async def csp_click(
    x: float,
    y: float,
    capture_id: str,
    confirm_token: str,
    region: Literal["client", "window"] = "client",
    button: Literal["left", "right", "middle"] = "left",
    count: Literal[1, 2] = 1,
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.click, x, y, region, button, count, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_drag", title="Drag or draw a stroke in CSP", description="Consumes a single-use token bound to the exact parameters and drags along a smoothed path inside the CSP area bound to the capture taken after approval.", annotations=EDIT_OPEN, structured_output=True)
async def csp_drag(
    start_x: float,
    start_y: float,
    end_x: float,
    end_y: float,
    capture_id: str,
    confirm_token: str,
    region: Literal["client", "window"] = "client",
    button: Literal["left", "right", "middle"] = "left",
    duration_seconds: float = 0.5,
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(
        controller.drag,
        start_x,
        start_y,
        end_x,
        end_y,
        region,
        button,
        duration_seconds,
        capture_id,
        confirm_token,
        hwnd,
    )


@mcp.tool(name="csp_scroll", title="Scroll the mouse wheel in CSP", description="Consumes a single-use token bound to the exact parameters and sends a limited number of wheel steps at the position bound to the capture taken after approval.", annotations=EDIT_OPEN, structured_output=True)
async def csp_scroll(
    x: float,
    y: float,
    delta: int,
    capture_id: str,
    confirm_token: str,
    region: Literal["client", "window"] = "client",
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.scroll, x, y, region, delta, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_type_text", title="Type Unicode text into CSP", description="Consumes a single-use token bound to the exact text and types it as Unicode, without the clipboard, into the CSP field that holds focus in the capture taken after approval.", annotations=EDIT_OPEN, structured_output=True)
async def csp_type_text(text: str, capture_id: str, confirm_token: str, hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.type_text, text, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_navigation_key", title="Send a limited navigation key", description="Consumes a single-use token bound to the exact key and repeat count. Disabled while a standard file dialog is open.", annotations=EDIT_OPEN, structured_output=True)
async def csp_navigation_key(
    key: Literal["ESCAPE", "ENTER", "TAB", "LEFT", "RIGHT", "UP", "DOWN", "HOME", "END", "PAGEUP", "PAGEDOWN", "BACKSPACE", "DELETE"],
    capture_id: str,
    confirm_token: str,
    count: int = 1,
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.navigation_key, key, count, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_preflight", title="Approve an exact CSP input", description="Once Codex approves it as a destructive, open-world operation, focuses CSP and issues a single-use token that expires after 45 seconds, bound to the exact tool name and full parameters. The token can authorize closing a document, replacing an output file, or generic visible UI input; ordinary input must capture again afterward.", annotations=EDIT_OPEN, structured_output=True)
async def csp_preflight(
    operation: Literal["input", "command", "auto_action", "output_replace"],
    identifier: str = "",
    parameters_json: str = "",
    capture_id: str = "",
    path: str = "",
    main_hwnd: int = 0,
    dialog_hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(
        controller.preflight,
        operation,
        identifier,
        parameters_json,
        capture_id,
        path,
        main_hwnd,
        dialog_hwnd,
    )


@mcp.tool(name="csp_run_command", title="Run a registered CSP command", description="Runs only commands from config/commands.json. Every run needs an exactly matching single-use csp_preflight token and a capture taken after approval.", annotations=EDIT, structured_output=True)
async def csp_run_command(
    command_id: str,
    capture_id: str,
    confirm_token: str,
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.run_command, command_id, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_run_auto_action", title="Run a registered Auto Action", description="Triggers only registered shortcut actions. Every run needs an exactly matching single-use csp_preflight token and a capture taken after approval.", annotations=EDIT, structured_output=True)
async def csp_run_auto_action(
    action_id: str,
    capture_id: str,
    confirm_token: str,
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.run_auto_action, action_id, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_run_command_sequence", title="Run a safe command sequence", description="Consumes a single-use token bound to the complete, ordered command list and runs up to 12 non-destructive registered commands one after another.", annotations=EDIT, structured_output=True)
async def csp_run_command_sequence(command_ids: list[str], capture_id: str, confirm_token: str, hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.run_command_sequence, command_ids, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_validate_path", title="Validate a CSP exchange path", description="Normalizes a path and validates its root, permissions, format, reparse points, alternate data streams, existence, and overwrite policy.", annotations=RO, structured_output=True)
async def csp_validate_path(path: str, intent: Literal["input", "output_new", "output_replace"]) -> ToolEnvelope:
    return await _call(controller.validate_path, path, intent)


@mcp.tool(name="csp_list_assets", title="List allowlisted CSP assets", description="Lists files of allowed formats in one configured asset root only, at most 500 entries. Never walks a whole drive.", annotations=RO, structured_output=True)
async def csp_list_assets(root_id: Literal["input", "working", "exports"], recursive: bool = False, max_items: int = 200) -> ToolEnvelope:
    return await _call(controller.list_assets, root_id, recursive, max_items)


@mcp.tool(name="csp_file_info", title="Read CSP exchange file info", description="Reads the size, timestamps, and optionally the SHA-256 of an allowlisted input file. Never parses or modifies .clip files.", annotations=RO, structured_output=True)
async def csp_file_info(path: str, include_sha256: bool = True) -> ToolEnvelope:
    return await _call(controller.file_info, path, include_sha256)


@mcp.tool(name="csp_scan_exports", title="Scan recent CSP exports", description="Finds files changed after a UTC time in a writable export root, so that exports can be handed to an asset pipeline.", annotations=RO, structured_output=True)
async def csp_scan_exports(
    root_id: Literal["working", "exports"],
    modified_since_utc: str,
    max_items: int = 200,
) -> ToolEnvelope:
    return await _call(controller.scan_exports, root_id, modified_since_utc, max_items)


@mcp.tool(name="csp_wait_for_file", title="Wait for a CSP output file to settle", description="Waits up to 30 seconds for an allowlisted output file to appear, become non-empty, and keep a stable size and modification time, then returns its SHA-256.", annotations=RO, structured_output=True)
async def csp_wait_for_file(path: str, timeout_ms: int = 10000, stable_ms: int = 500) -> ToolEnvelope:
    return await _call(controller.wait_for_file, path, timeout_ms, stable_ms)


@mcp.tool(name="csp_open_document", title="Open an allowlisted document in CSP", description="Opens a supported allowlisted document with the pinned, signed CSP executable and an argument array. Never uses a shell and accepts no extra arguments.", annotations=NEW, structured_output=True)
async def csp_open_document(path: str, wait_ready_ms: int = 15000) -> ToolEnvelope:
    return await _call(controller.open_document, path, wait_ready_ms)


@mcp.tool(name="csp_native_file_dialog", title="Fill or submit a CSP native file dialog", description="Handles only standard #32770 file dialogs owned by CSP. Every call needs a csp_preflight token bound to the exact path, intent, submit flag, and dialog identity.", annotations=EDIT, structured_output=True)
async def csp_native_file_dialog(
    path: str,
    intent: Literal["input", "output_new", "output_replace"],
    confirm_token: str,
    submit: bool = False,
    dialog_hwnd: int = 0,
    main_hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(
        controller.native_file_dialog,
        path,
        intent,
        submit,
        dialog_hwnd,
        confirm_token,
        main_hwnd,
    )
