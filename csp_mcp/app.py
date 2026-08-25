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


INSTRUCTIONS = """仅控制经签名和哈希验证的 CLIP STUDIO PAINT 5.1.2。任何点击、拖动、滚动、文字、导航键、登记命令、Auto Action、命令序列或原生文件对话框操作，都必须先调用 csp_preflight，批准精确工具名和完整参数。普通界面输入在 preflight 返回并聚焦 CSP 后重新调用 csp_capture，再把新 captureId 与单次 confirmToken 交给原子工具；文件对话框令牌直接绑定 exact main/dialog HWND。标准 #32770 对话框出现时只使用 csp_native_file_dialog 或 csp_cancel。不要把截图变化称为图层级语义确认。发现用户键鼠输入、版本/DPI/语言变化或多窗口歧义时停止。路径参数型工具只在白名单素材目录读写；禁止解析或修改 .clip 二进制，禁止尝试私有 Companion 协议、DLL 注入、账号、商店、云同步和发布操作。"""

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


@mcp.tool(name="csp_health", title="CSP MCP 健康检查", description="检查 MCP、CSP 文件签名/版本/哈希、进程、窗口、显示器和当前用户活动；不控制界面。", annotations=RO, structured_output=True)
async def csp_health() -> ToolEnvelope:
    return await _call(controller.health)


@mcp.tool(name="csp_capabilities", title="列出 CSP 可用能力", description="逐项报告当前环境可用的窗口、截图、输入、文件交换和 Auto Action 能力，并说明不可用原因。", annotations=RO, structured_output=True)
async def csp_capabilities(hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.capabilities, hwnd)


@mcp.tool(name="csp_get_activity", title="检查用户键鼠活动", description="保守读取最近系统输入、静默时长、按下的按键和控制锁状态；不会把全局最后输入猜作本 MCP。", annotations=RO, structured_output=True)
async def csp_get_activity() -> ToolEnvelope:
    return ok_result(await _call(controller.activity))


@mcp.tool(name="csp_list_windows", title="列出 CSP 主窗口", description="只列出来自固定 CSP 可执行文件的主窗口及物理像素坐标、DPI 和状态。", annotations=RO, structured_output=True)
async def csp_list_windows() -> ToolEnvelope:
    return await _call(controller.list_windows)


@mcp.tool(name="csp_get_state", title="读取 CSP 窗口状态", description="返回目标主窗口、前台状态、可见对话框和临时 stateRevision；不会虚构图层或文档对象状态。", annotations=RO, structured_output=True)
async def csp_get_state(hwnd: int = 0, include_dialogs: bool = True) -> ToolEnvelope:
    return await _call(controller.get_state, hwnd, include_dialogs)


@mcp.tool(name="csp_capture", title="截取 CSP 窗口", description="仅截取可见的 CSP 窗口或其归一化区域，返回 MCP 图片和 30 秒有效的 captureId；不会截取整桌面。", annotations=RO, structured_output=False)
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


@mcp.tool(name="csp_compare_captures", title="比较两次 CSP 截图", description="对两次未过期截图做降采样像素差，报告可见变化比例；不推断语义。", annotations=RO, structured_output=True)
async def csp_compare_captures(first_capture_id: str, second_capture_id: str) -> ToolEnvelope:
    return await _call(controller.compare_captures, first_capture_id, second_capture_id)


@mcp.tool(name="csp_sample_pixel", title="采样截图像素", description="在已有 CSP 截图的归一化坐标上读取 RGBA 像素。", annotations=RO, structured_output=True)
async def csp_sample_pixel(capture_id: str, x: float, y: float) -> ToolEnvelope:
    return await _call(controller.sample_pixel, capture_id, x, y)


@mcp.tool(name="csp_inspect_ui", title="检查 CSP Win32 界面树", description="枚举 CSP 主窗口的 Win32 子窗口和标准对话框；CSP 自绘菜单和图层不会出现在结果中。", annotations=RO, structured_output=True)
async def csp_inspect_ui(hwnd: int = 0, include_dialogs: bool = True, max_items: int = 200) -> ToolEnvelope:
    return await _call(controller.inspect_ui, hwnd, include_dialogs, max_items)


@mcp.tool(name="csp_list_commands", title="列出已登记 CSP 命令", description="列出版本化快捷键命令目录，但不泄露底层按键组合。", annotations=RO, structured_output=True)
async def csp_list_commands(category: str = "", available_only: bool = True) -> ToolEnvelope:
    return await _call(controller.list_commands, category, available_only)


@mcp.tool(name="csp_list_auto_actions", title="列出已登记 Auto Actions", description="列出用户在 CSP 内绑定快捷键后登记的 Auto Actions；不会解析或修改 .laf。", annotations=RO, structured_output=True)
async def csp_list_auto_actions() -> ToolEnvelope:
    return await _call(controller.list_auto_actions)


@mcp.tool(name="csp_launch", title="启动 CSP", description="只启动固定、签名和哈希匹配的 production CSP 可执行文件；已经运行时只返回窗口。", annotations=NEW, structured_output=True)
async def csp_launch(wait_ready_ms: int = 15000) -> ToolEnvelope:
    return await _call(controller.launch, wait_ready_ms)


@mcp.tool(name="csp_focus", title="聚焦并恢复 CSP", description="等待用户键鼠静默后恢复、聚焦唯一的 CSP 主窗口并验证前台句柄。", annotations=UI, structured_output=True)
async def csp_focus(hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.focus, hwnd)


@mcp.tool(name="csp_window_action", title="改变 CSP 窗口状态", description="将 CSP 主窗口恢复、最大化或最小化；不移动或调整任意其他应用。", annotations=UI, structured_output=True)
async def csp_window_action(action: Literal["restore", "maximize", "minimize"], hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.window_action, action, hwnd)


@mcp.tool(name="csp_wait_visual_change", title="等待 CSP 可见变化", description="等待目标截图达到指定像素变化阈值，最长 30 秒；纯观察，不发送输入。", annotations=RO, structured_output=True)
async def csp_wait_visual_change(capture_id: str, threshold: float = 0.002, timeout_ms: int = 10000) -> ToolEnvelope:
    return await _call(controller.wait_visual_change, capture_id, threshold, timeout_ms)


@mcp.tool(name="csp_cancel", title="取消 CSP 当前操作", description="等待用户静默、聚焦 CSP 后发送一次 Escape，并用前后截图验证。", annotations=UI_NONIDEMPOTENT, structured_output=True)
async def csp_cancel(hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.cancel, hwnd)


@mcp.tool(name="csp_move_pointer", title="在 CSP 内移动指针", description="消费绑定精确参数的 csp_preflight 单次令牌，把指针移动到随后 captureId 绑定的 CSP 区域。", annotations=UI, structured_output=True)
async def csp_move_pointer(
    x: float,
    y: float,
    capture_id: str,
    confirm_token: str,
    region: Literal["client", "window"] = "client",
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.move_pointer, x, y, region, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_click", title="在 CSP 内单击或双击", description="消费绑定精确参数的单次令牌，仅对批准后截图中的 CSP 点位单击或双击；自绘控件语义不可推断。", annotations=EDIT_OPEN, structured_output=True)
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


@mcp.tool(name="csp_drag", title="在 CSP 内拖动或画笔划", description="消费绑定精确参数的单次令牌，在批准后截图绑定的 CSP 区域内按平滑路径拖动。", annotations=EDIT_OPEN, structured_output=True)
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


@mcp.tool(name="csp_scroll", title="在 CSP 内滚轮滚动", description="消费绑定精确参数的单次令牌，在批准后截图绑定的位置发送受限滚轮步数。", annotations=EDIT_OPEN, structured_output=True)
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


@mcp.tool(name="csp_type_text", title="向 CSP 输入 Unicode 文本", description="消费绑定精确文本的单次令牌，不使用剪贴板，向批准后截图中保持焦点的 CSP 字段输入 Unicode。", annotations=EDIT_OPEN, structured_output=True)
async def csp_type_text(text: str, capture_id: str, confirm_token: str, hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.type_text, text, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_navigation_key", title="发送受限导航键", description="消费绑定精确按键和次数的单次令牌；标准文件对话框中禁用。", annotations=EDIT_OPEN, structured_output=True)
async def csp_navigation_key(
    key: Literal["ESCAPE", "ENTER", "TAB", "LEFT", "RIGHT", "UP", "DOWN", "HOME", "END", "PAGEUP", "PAGEDOWN", "BACKSPACE", "DELETE"],
    capture_id: str,
    confirm_token: str,
    count: int = 1,
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.navigation_key, key, count, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_preflight", title="批准精确 CSP 输入", description="经 Codex 破坏性、开放界面操作批准后聚焦 CSP，并为精确工具名与完整参数生成45秒过期、单次使用令牌；该令牌可授权关闭文档、覆盖输出或通用可见 UI 输入，普通输入随后必须重新截图。", annotations=EDIT_OPEN, structured_output=True)
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


@mcp.tool(name="csp_run_command", title="执行已登记 CSP 命令", description="只执行 config/commands.json 中的命令；每次都需要精确匹配的 csp_preflight 单次令牌和批准后截图。", annotations=EDIT, structured_output=True)
async def csp_run_command(
    command_id: str,
    capture_id: str,
    confirm_token: str,
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.run_command, command_id, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_run_auto_action", title="执行已登记 Auto Action", description="只触发已登记快捷键动作；每次都需要精确匹配的 csp_preflight 单次令牌和批准后截图。", annotations=EDIT, structured_output=True)
async def csp_run_auto_action(
    action_id: str,
    capture_id: str,
    confirm_token: str,
    hwnd: int = 0,
) -> ToolEnvelope:
    return await _call(controller.run_auto_action, action_id, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_run_command_sequence", title="执行安全命令序列", description="消费绑定完整有序命令列表的单次令牌，串行执行最多 12 个非破坏性已登记命令。", annotations=EDIT, structured_output=True)
async def csp_run_command_sequence(command_ids: list[str], capture_id: str, confirm_token: str, hwnd: int = 0) -> ToolEnvelope:
    return await _call(controller.run_command_sequence, command_ids, capture_id, confirm_token, hwnd)


@mcp.tool(name="csp_validate_path", title="验证 CSP 交换路径", description="规范化并验证路径根、权限、格式、重解析点、ADS、是否存在和覆盖策略。", annotations=RO, structured_output=True)
async def csp_validate_path(path: str, intent: Literal["input", "output_new", "output_replace"]) -> ToolEnvelope:
    return await _call(controller.validate_path, path, intent)


@mcp.tool(name="csp_list_assets", title="列出白名单 CSP 素材", description="只列出指定 CSP 素材根中的允许格式，最多 500 项；不会遍历整个 D 盘。", annotations=RO, structured_output=True)
async def csp_list_assets(root_id: Literal["input", "working", "exports"], recursive: bool = False, max_items: int = 200) -> ToolEnvelope:
    return await _call(controller.list_assets, root_id, recursive, max_items)


@mcp.tool(name="csp_file_info", title="读取 CSP 交换文件信息", description="读取白名单输入文件的大小、时间和可选 SHA-256，不解析或修改 .clip。", annotations=RO, structured_output=True)
async def csp_file_info(path: str, include_sha256: bool = True) -> ToolEnvelope:
    return await _call(controller.file_info, path, include_sha256)


@mcp.tool(name="csp_scan_exports", title="扫描最近 CSP 导出", description="在可写导出根内按 UTC 时间查找新改动文件，支持 Godot/素材流水线收件。", annotations=RO, structured_output=True)
async def csp_scan_exports(
    root_id: Literal["working", "exports"],
    modified_since_utc: str,
    max_items: int = 200,
) -> ToolEnvelope:
    return await _call(controller.scan_exports, root_id, modified_since_utc, max_items)


@mcp.tool(name="csp_wait_for_file", title="等待 CSP 输出文件稳定", description="等待白名单输出文件出现、非空且 size/mtime 稳定，然后返回 SHA-256；最长 30 秒。", annotations=RO, structured_output=True)
async def csp_wait_for_file(path: str, timeout_ms: int = 10000, stable_ms: int = 500) -> ToolEnvelope:
    return await _call(controller.wait_for_file, path, timeout_ms, stable_ms)


@mcp.tool(name="csp_open_document", title="在 CSP 打开白名单文档", description="用固定签名 CSP 可执行文件和参数数组打开白名单内受支持文档；不调用 Shell，不接受额外参数。", annotations=NEW, structured_output=True)
async def csp_open_document(path: str, wait_ready_ms: int = 15000) -> ToolEnvelope:
    return await _call(controller.open_document, path, wait_ready_ms)


@mcp.tool(name="csp_native_file_dialog", title="填写或提交 CSP 原生文件对话框", description="仅处理属于 CSP 的标准 #32770 文件对话框；每次都需要绑定精确路径、意图、提交标志和对话框身份的 csp_preflight 令牌。", annotations=EDIT, structured_output=True)
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
