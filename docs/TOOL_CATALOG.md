# 工具目录

当前版本公开 33 个 CSP 专用工具。

## 只读检查

| 工具 | 功能 |
|---|---|
| `csp_health` | 服务、签名、版本、哈希、进程、窗口、显示器与活动状态 |
| `csp_capabilities` | 当前 profile 每项能力的 available/reason/backend |
| `csp_get_activity` | 真人输入、静默时间、按下键与锁 |
| `csp_list_windows` | CSP 主窗口、物理坐标、DPI、窗口指纹 |
| `csp_get_state` | 前台、窗口、对话框、临时 revision |
| `csp_capture` | CSP 窗口/区域 MCP 图片与 captureId |
| `csp_compare_captures` | 两个截图的像素变化比例 |
| `csp_sample_pixel` | 截图归一化坐标 RGBA |
| `csp_inspect_ui` | Win32 子窗口与原生对话框 |
| `csp_list_commands` | 已登记命令目录 |
| `csp_list_auto_actions` | 已登记 Auto Actions |

## 应用和窗口

| 工具 | 功能 |
|---|---|
| `csp_launch` | 启动固定 production CSP |
| `csp_focus` | 恢复并聚焦 CSP |
| `csp_window_action` | 恢复/最大化/最小化 |
| `csp_wait_visual_change` | 等待截图达到阈值 |
| `csp_cancel` | 仅向精确主窗口或唯一一个 CSP 标准对话框发送一次 Escape |

## 可见界面输入

| 工具 | 功能 |
|---|---|
| `csp_move_pointer` | 截图绑定的归一化移动 |
| `csp_click` | 左/右/中键单击或双击 |
| `csp_drag` | 平滑拖动或无笔压笔划 |
| `csp_scroll` | 受限滚轮步数 |
| `csp_type_text` | 不经剪贴板的 Unicode 文本 |
| `csp_navigation_key` | 受限导航键 |
| `csp_run_command` | 已登记快捷键命令 |
| `csp_run_auto_action` | 已登记 Auto Action |
| `csp_run_command_sequence` | 非破坏性登记命令序列 |
| `csp_preflight` | 批准精确工具名/完整参数并聚焦 CSP；普通输入批准后必须重新截图 |

## 文件交换

| 工具 | 功能 |
|---|---|
| `csp_validate_path` | 白名单、格式、重解析点和覆盖校验 |
| `csp_list_assets` | 列出素材根内允许文件 |
| `csp_file_info` | 大小、时间、SHA-256 |
| `csp_scan_exports` | 扫描指定时间后的导出 |
| `csp_wait_for_file` | 等待输出非空且稳定 |
| `csp_open_document` | 向固定 CSP 派发白名单文件请求；只证明派发/窗口证据，需截图确认实际标签页或导入结果 |
| `csp_native_file_dialog` | 以精确路径、意图、提交标志和 dialog HWND 令牌填写/提交原生文件对话框 |

底层原语覆盖可见窗口、截图、受限键鼠、已登记命令/Auto Actions 和白名单文件交换。10 个原子输入工具在 Codex 配置层直通，但服务端全部要求由仍需人工批准的 `csp_preflight` 生成精确、单次令牌。任何可见标准 `#32770` 对话框都会撤销普通截图授权并阻止通用输入，只允许令牌绑定的专用文件对话框工具或精确取消。生产策略拒绝 `Ctrl+S`、被声明为文件 I/O 或未作无文件-I/O声明的 Auto Action、账号、云端与发布流程；服务无法解析 `.laf` 来证明声明真假。登记命令、管理员声明和前后截图只提高可见结果置信度，不构成文档/图层语义验证。CSP 没有公开的通用文档/图层对象 API，因此不存在可诚实实现的 `get_layers`、`set_brush_object` 或 headless render 等工具。

## 本地分支：区域设置

普通控件默认接受任意 Windows 区域设置。原生文件对话框支持法语、英语和简体中文，并要求“打开”或“保存/导出”意图与经验证的控件 ID 一致。未知标签仍不可用。工具签名和确认要求没有变化；配置见 README。
