# Clip Studio Paint 1.11.10 MCP

A local MCP server that lets an AI agent see and operate CLIP STUDIO PAINT 1.11.10 on Windows: it captures CSP's window, clicks, drags, and types in it, runs registered shortcuts and Auto Actions, and opens and saves files through CSP's own dialogs. Every input needs your approval first.

> [!IMPORTANT]
> Unofficial; not affiliated with or supported by CELSYS. It controls CSP the way a person would, through the visible window, because CSP has no scripting or document API. It cannot read layers, brushes, or other document internals.

This is a fork of [A2pha/clip-studio-paint-5.1.2-production-mcp](https://github.com/A2pha/clip-studio-paint-5.1.2-production-mcp), which targets CSP 5.1.2; use that project for 5.1.2.

## Requirements

- Windows.
- CLIP STUDIO PAINT **1.11.10.0**, with the display at 100% scaling (window DPI 96). Other CSP versions are refused; [compatibility](docs/COMPATIBILITY.md) lists which ones would likely work with a profile of their own.
- Any Windows display language for CSP itself. The native *Open* and *Save As* dialogs are recognized in French, English, and Simplified Chinese only.
- CPython 3.13, and Git.
- Codex, or another stdio MCP host with an equivalent approval policy.
- Auto Actions need CSP PRO or EX.

## Install

```powershell
git clone https://github.com/VulpesNexus/clip-studio-paint-1.11.10-mcp.git
Set-Location .\clip-studio-paint-1.11.10-mcp

& .\scripts\configure.ps1 -CspExecutable "$env:ProgramFiles\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
& .\scripts\install.ps1
& .\scripts\register-codex.ps1
```

*configure.ps1* pins your CSP executable and shortcut settings by hash and creates the asset folders under *Documents\CSP-MCP-Assets*; pass your own path if CSP is installed elsewhere. *install.ps1* builds a hash-locked *.venv*. *register-codex.ps1* adds the server to Codex; *unregister-codex.ps1* removes it. Options, tests, and what each script checks: [setup](docs/SETUP.md).

## Use

Restart Codex, open CSP, and ask the agent to call `csp_health` and then `csp_capabilities`. From there it can capture the window and act in it.

- Every click, drag, keystroke, command, or file-dialog action goes through `csp_preflight`, which the host asks you to approve. The token it issues works once, for 45 seconds, for exactly the approved parameters.
- Don't use the mouse or keyboard while the agent works in CSP: any input cancels its pending action, by design.
- Files are opened and saved only inside *Input* (read-only), *Working*, and *Exports*.
- If CSP rewrites its shortcut settings, input is refused until you rerun *configure.ps1*.
- Discord's overlay, or any other full-screen click-through overlay, blocks captures until you allow it in your local configuration.

The full flow, the registered commands, and the overlay setting: [usage](docs/USAGE.md).

## What it does not do

- It does not read or edit layers, brushes, or document structure, and it does not parse `.clip` files.
- It cannot draw with pen pressure.
- It does not save with *Ctrl+S*; saving goes through *Save As* with a validated path.
- It has no tools for CSP's account, cloud, store, or publishing features, and instructs the agent to stay out of them. It has no shell, registry, or general file access.
- It keeps no network listener, but your MCP host receives the captures and paths it returns and may send them to a remote model.

## Documentation

- [Setup](docs/SETUP.md): configuration, installation, tests, and registration in detail.
- [Usage](docs/USAGE.md): the approval flow, registered commands, files, and overlays.
- [Tool catalog](docs/TOOL_CATALOG.md): all 33 tools.
- [Auto Actions setup](docs/AUTO_ACTIONS.md)
- [Security model](docs/SECURITY.md)
- [Compatibility with other CSP versions](docs/COMPATIBILITY.md)
- [Validation record](docs/VALIDATION.md)
- [Contributing](CONTRIBUTING.md) and the [security policy](.github/SECURITY.md)

## License

[MIT](LICENSE), keeping A2pha's original copyright notice; dependency notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). CLIP STUDIO PAINT and CELSYS are trademarks of their respective owners. This repository contains no CELSYS software or SDK code.
