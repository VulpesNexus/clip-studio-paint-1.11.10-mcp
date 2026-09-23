# Usage

How an agent drives CSP through this MCP. The tools themselves are listed in the [tool catalog](TOOL_CATALOG.md), and the reasons behind each limit are in the [security model](SECURITY.md).

## Confirmation-token flow

For ordinary visible UI input:

1. Call `csp_health`, `csp_capabilities`, and `csp_get_state`.
2. Call `csp_capture` for read-only planning.
3. Call `csp_preflight(operation="input", identifier="exact_tool_name", parameters_json="exact JSON parameters")` without an old capture ID.
4. After the user approves preflight, immediately call `csp_capture` again and verify that the target is still visible.
5. Call the exact atomic tool with the fresh `captureId`, the returned `confirmToken`, and byte-for-byte equivalent business parameters.
6. Inspect the post-operation capture; repeat preflight for the next input.

Tokens expire after 45 seconds, are single-use, bind the complete parameters and the exact CSP window or dialog identity, and are invalidated by foreground, pixel, generation, or input-time changes. Parameter mismatches consume the token. Any keyboard or mouse input after the capture also invalidates it, so do not use the computer while an agent works in CSP. `csp_cancel` is a narrow exception: it remains host approval-gated and sends one `Escape` only to the exact CSP main window or its unique verified standard dialog.

## Registered commands

The tracked registry, *config/commands.json*, holds nine commands bound to CSP's default shortcuts:

| Command | Shortcut | Effect |
|---|---|---|
| `ui.cancel` | *Escape* | Closes a menu or cancels an uncommitted operation |
| `document.new_dialog` | *Ctrl+N* | Opens *New*, without confirming it |
| `document.open_dialog` | *Ctrl+O* | Opens *Open* |
| `edit.undo` | *Ctrl+Z* | Undo |
| `edit.redo` | *Ctrl+Y* | Redo |
| `selection.all` | *Ctrl+A* | Select all |
| `selection.deselect` | *Ctrl+D* | Deselect |
| `document.save_as_dialog` | *Ctrl+Shift+S* | Opens *Save As*, without filling in or confirming a path |
| `document.close` | *Ctrl+W* | Closes the document; needs `csp_preflight`, as it can raise an unsaved-changes prompt |

Rebinding a shortcut in CSP changes its settings file, so input stops until you rerun *configure.ps1*; after that the commands still send the default keys. Keep these nine at their defaults.

## Files

Path-taking tools operate only inside the three asset roots of the local configuration. They reject UNC and device paths, alternate data streams, wildcards, reserved device names, reparse points, implicit overwrite, and other unsupported cases. Existing paths are checked through handles, and existing inputs and replacement targets are checked for hard links, but these mitigations cannot eliminate every check-to-use race.

Saving or replacing a file uses this flow:

1. Validate the exact target with `csp_validate_path`.
2. Preflight and run the registered `document.save_as_dialog` command.
3. Obtain the exact main and dialog HWNDs, then preflight `csp_native_file_dialog` with the full path, intent, and submit flag.
4. Submit only through the verified file-dialog control profile. Any later overwrite or format prompt needs manual handling.
5. Accept completion only after `csp_wait_for_file` verifies a stable, non-empty target and returns its SHA-256.

The native file dialog is recognized only in French, English, and Simplified Chinese; in another Windows display language the file-dialog tool refuses to act.

*Ctrl+S* is not registered, because CSP does not expose the current document's path through a public API. Generic coordinate and text tools must not be used for open, save, or export, nor for account, cloud, store, community, or publishing workflows.

`csp_open_document` runs `CLIPStudioPaint.exe <path>` with an argument array. CELSYS does not document this as a stable command-line contract. A successful response proves dispatch and CSP window evidence, not which document tab owns the path; verify the result with a capture.

## Auto Actions

The tracked Auto Action registry starts empty. Create and check each action in CSP by hand, bind only *Ctrl+Alt+[Shift]+F1..F12*, then register it locally as described in [Auto Actions setup](AUTO_ACTIONS.md). Auto Actions need CSP PRO or EX. Every action needs preflight and an exact registered ID, and production configuration refuses any that is declared to touch files or is not attested free of file I/O.

## Click-through overlays

Capture refuses whenever a window from another process overlaps CSP, because a screen capture would include anything that window paints. Some overlays cover the whole desktop permanently yet usually paint nothing; Discord's in-game overlay is one. A local configuration may list such overlays in `capture_ignored_overlays`, each identified by its exact process image name, window class, and title:

```json
"capture_ignored_overlays": [
  {"process": "Discord.exe", "class_name": "Chrome_WidgetWin_1", "title": "Discord Overlay"}
]
```

An entry matches only a layered, mouse-transparent window, so an ordinary window with the same identity still blocks capture. Listing an overlay attests that it is not painting over CSP while you capture. Every capture that skipped one reports the window ID in `ignoredOverlayWindowIds`. Input authorization is unchanged, because Windows hit-testing already passes through such windows. The tracked template lists none.
