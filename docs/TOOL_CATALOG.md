# Tool catalog

The server defines 53 tools, all scoped to Clip Studio Paint. A running MCP process must reconnect before it exposes newly added tools.

## Read-only inspection

| Tool | What it does |
|---|---|
| `csp_health` | Service, signature, version, hash, process, window, display, and activity status |
| `csp_capabilities` | For each capability of the active profile: available, reason, and backend |
| `csp_get_activity` | Human input, idle time, pressed keys, and the control lock |
| `csp_list_windows` | CSP main windows, physical coordinates, DPI, and window fingerprints |
| `csp_get_state` | Foreground, windows, dialogs, and a transient revision |
| `csp_capture` | An MCP image of the CSP window or a region of it, with a captureId |
| `csp_capture_new_dialog` | An image of an exact profiled CSP 1.11.10 New layout, with a captureId for one fixed icon or expanded OK action |
| `csp_new_dialog_owner_diagnostic` | Read-only owner PID, visibility, class, and geometry for that exact New dialog |
| `csp_expanded_new_dialog_overlaps` | Read-only z-order and identity of windows overlapping the exact 909×833 New dialog |
| `csp_capture_page_copy_warning` | Captures only the exact 438×109 CSP page-managed Save As copy warning |
| `csp_capture_cst_conversion_warning` | Captures only the exact 300×116 CSP conversion warning for a copied CST, with no input |
| `csp_capture_cst_story_folder_dialog` | Captures only the exact 720×199 Create story folder dialog, with no input |
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
| `csp_cancel_expanded_new_dialog` | Focuses the exact 909×833 New dialog and sends one Escape without generic capture |
| `csp_cancel_cst_conversion_error` | Sends one Escape only to the exact 231×109 CSP conversion-error modal |

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
| `csp_new_dialog_preflight` | Binds one work-icon index to the exact New dialog before a fresh dialog capture |
| `csp_select_new_dialog_work_icon` | Consumes that approval and capture for one of six fixed work-icon clicks |
| `csp_new_comic_confirm_preflight` | Focuses the expanded New dialog and binds its fixed OK button before a fresh capture |
| `csp_confirm_blank_comic` | Consumes the inspected expanded capture to click only OK; does not save the document |
| `csp_new_comic_multiple_pages_preflight` | Binds one fixed Multiple pages checkbox click to the exact 909×833 Comic New dialog before a fresh capture |
| `csp_enable_new_comic_multiple_pages` | Consumes that approval and capture to click only the Multiple pages checkbox |
| `csp_page_copy_warning_preflight` | Binds one fixed OK or Cancel warning choice; OK also binds an allowlisted new output path as intent |
| `csp_choose_page_copy_warning` | Consumes the fresh warning capture for one fixed choice; never enters a file path |
| `csp_cst_conversion_preflight` | Binds one OK choice on the exact conversion warning to a manifest-verified CST copy under the `cst_copy` root; originals are rejected |
| `csp_accept_cst_conversion_warning` | Consumes that approval and capture, rehashes the manifest and copy, and clicks only the warning's OK |
| `csp_cst_story_folder_preflight` | Binds one OK choice on the exact Create story folder dialog to a manifest-verified CST copy and its new management folder |
| `csp_confirm_cst_story_folder` | Consumes that approval and capture, rechecks the copy and the absent target folder, and clicks only the dialog's OK |

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

The primitives cover visible windows, captures, limited keyboard and mouse input, registered commands and Auto Actions, and allowlisted file exchange. Ordinary atomic input tools pass through Codex's approval layer and require an exact, single-use token from `csp_preflight`. The dedicated New-dialog icon route has its own exact preflight and capture; its expanded-dialog Escape route is limited to one recovery key.

Any visible standard `#32770` dialog revokes ordinary capture authorization and blocks generic input; only the token-bound file-dialog tool or an exact cancel may act on it. Production policy refuses *Ctrl+S*, Auto Actions declared as file I/O or not attested as free of it, and account, cloud, and publishing workflows. The server cannot parse *.laf* files to prove such an attestation true.

The dedicated New-dialog work-icon route does not change ordinary main-window or file-dialog guards. It has no text, path, field-editing, or submit action. Its October 14 source and negative tests await execution and live acceptance in a freshly connected MCP process.

Registered commands, administrator attestations, and before-and-after captures raise confidence in visible results; they do not verify document or layer semantics. CSP has no public document or layer object API, so tools such as `get_layers`, `set_brush_object`, or a headless render cannot be implemented honestly.

Ordinary controls accept any Windows culture. Native file dialogs are recognized in French, English, and Simplified Chinese, and the Open or Save/Export intent must agree with the validated control IDs; unknown labels are refused.
