# Tool catalog

The server exposes 33 tools, all scoped to Clip Studio Paint.

## Read-only inspection

| Tool | What it does |
|---|---|
| `csp_health` | Service, signature, version, hash, process, window, display, and activity status |
| `csp_capabilities` | For each capability of the active profile: available, reason, and backend |
| `csp_get_activity` | Human input, idle time, pressed keys, and the control lock |
| `csp_list_windows` | CSP main windows, physical coordinates, DPI, and window fingerprints |
| `csp_get_state` | Foreground, windows, dialogs, and a transient revision |
| `csp_capture` | An MCP image of the CSP window or a region of it, with a captureId |
| `csp_compare_captures` | Share of changed pixels between two captures |
| `csp_sample_pixel` | RGBA at normalized capture coordinates |
| `csp_inspect_ui` | Win32 child windows and native dialogs |
| `csp_list_commands` | The registered command catalog |
| `csp_list_auto_actions` | Registered Auto Actions |

## Application and window

| Tool | What it does |
|---|---|
| `csp_launch` | Launches the pinned CSP executable |
| `csp_focus` | Restores and focuses CSP |
| `csp_window_action` | Restore, maximize, or minimize |
| `csp_wait_visual_change` | Waits for a capture to reach a change threshold |
| `csp_cancel` | Sends one Escape, only to the exact main window or the single standard CSP dialog |

## Visible UI input

| Tool | What it does |
|---|---|
| `csp_move_pointer` | Normalized pointer move bound to a capture |
| `csp_click` | Left, right, or middle click or double-click |
| `csp_drag` | A smoothed drag, or a stroke without pen pressure |
| `csp_scroll` | A limited number of wheel steps |
| `csp_type_text` | Unicode text, without the clipboard |
| `csp_navigation_key` | Limited navigation keys |
| `csp_run_command` | A registered shortcut command |
| `csp_run_auto_action` | A registered Auto Action |
| `csp_run_command_sequence` | A sequence of non-destructive registered commands |
| `csp_preflight` | Approves an exact tool name with its full parameters and focuses CSP; ordinary input must capture again after approval |

## File exchange

| Tool | What it does |
|---|---|
| `csp_validate_path` | Allowlist, format, reparse-point, and overwrite checks |
| `csp_list_assets` | Lists allowed files inside an asset root |
| `csp_file_info` | Size, timestamps, and SHA-256 |
| `csp_scan_exports` | Finds exports changed after a given time |
| `csp_wait_for_file` | Waits until an output is non-empty and stable |
| `csp_open_document` | Asks the pinned CSP executable to open an allowlisted file; proves dispatch and window evidence only, so confirm the actual tab or import with a capture |
| `csp_native_file_dialog` | Fills or submits a native file dialog with a token bound to the exact path, intent, submit flag, and dialog HWND |

## Boundaries

The primitives cover visible windows, captures, limited keyboard and mouse input, registered commands and Auto Actions, and allowlisted file exchange. The 10 atomic input tools pass through Codex's approval layer, but the server requires each to present an exact, single-use token from `csp_preflight`, which itself still needs human approval.

Any visible standard `#32770` dialog revokes ordinary capture authorization and blocks generic input; only the token-bound file-dialog tool or an exact cancel may act on it. Production policy refuses *Ctrl+S*, Auto Actions declared as file I/O or not attested as free of it, and account, cloud, and publishing workflows. The server cannot parse *.laf* files to prove such an attestation true.

Registered commands, administrator attestations, and before-and-after captures raise confidence in visible results; they do not verify document or layer semantics. CSP has no public document or layer object API, so tools such as `get_layers`, `set_brush_object`, or a headless render cannot be implemented honestly.

Ordinary controls accept any Windows culture. Native file dialogs are recognized in French, English, and Simplified Chinese, and the Open or Save/Export intent must agree with the validated control IDs; unknown labels are refused.
