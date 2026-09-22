# Clip Studio Paint 1.11.10 MCP

> [!IMPORTANT]
> **Unofficial community project.** This repository is not affiliated with, endorsed by, or supported by CELSYS. It is a local stdio MCP bridge for **Windows and CLIP STUDIO PAINT 1.11.10.0**, pinned by signature and SHA-256, at a window DPI of 96. Other CSP versions, DPI values, and operating systems are not supported by the bundled strict profile; see [compatibility](docs/COMPATIBILITY.md) for which versions are likely to work with a profile of their own.

This is a fork of [A2pha/clip-studio-paint-5.1.2-production-mcp](https://github.com/A2pha/clip-studio-paint-5.1.2-production-mcp), which targets CSP 5.1.2 with a Simplified Chinese UI at DPI 120; use that project for 5.1.2. This fork targets CSP 1.11.10 instead, accepts any Windows culture, and uses English for its tools, commands, and documentation.

CELSYS publishes no general-purpose document or layer API, scripting runtime, or supported headless command line for CSP; its public SDK covers EX filter plugins only. CSP's custom-drawn areas do not expose layer, brush, or menu objects through Windows UI Automation. This project therefore offers 33 deliberately constrained tools built from visible-window inspection, captures, allowlisted input, registered shortcuts and Auto Actions, and file exchange. It is **not** a native layer-object API and cannot honestly expose every internal CSP function.

## What is included

- 33 MCP tools; see the complete [tool catalog](docs/TOOL_CATALOG.md).
- CSP executable attestation: fixed path, Authenticode signature, CELSYS company field, exact file version, and SHA-256.
- Per-Monitor DPI Awareness V2 with a DPI pin, and ordinary controls that work under any Windows culture.
- Process, main-window, foreground-window, dialog, display, user-activity, capture, pixel-sampling, and capture-difference inspection.
- Capture-bound pointer movement, clicks, double-clicks, drags, scrolling, navigation keys, and Unicode text input.
- Versioned shortcut commands, constrained command sequences, and user-registered Auto Actions.
- Configured path roots for asset listing, file metadata, import dispatch, export scanning, and stable-output verification.
- Strict native `#32770` file-dialog filling and submission with explicit overwrite intent.
- A preflight confirmation protocol for all 10 atomic input tools.
- Local stdio transport only: no listening port, and no shell, registry, arbitrary-process, or unrestricted-filesystem tool.

### Privacy boundary

Local stdio means this server opens no network listener; it does **not** mean all MCP data stays on the machine. The MCP host receives tool inputs and outputs, including captures, visible UI text, window titles, and configured absolute paths, and may send them to a remote model under that host's data policy. Keep sensitive documents closed, review the host's privacy controls, and treat text or imagery shown inside CSP as untrusted data rather than instructions for the agent.

## Support matrix

| Component | Supported target |
|---|---|
| Operating system | Windows only |
| CLIP STUDIO PAINT | `1.11.10.0`, executable pinned by SHA-256; profile `csp-1.11.10-dpi96-v1` |
| Window DPI | `96`, the effective DPI of CSP's window (100% display scaling) |
| Windows culture | Any; an explicit pin is optional |
| Native file dialogs | French, English, and Simplified Chinese labels |
| Python | CPython `3.13.x` |
| MCP host | Codex registration script included; other stdio hosts need an equivalent approval policy |
| CSP edition | Core visible-window tools are bound to the profile, not the edition; Auto Actions need PRO or EX, and `.cmc` is EX-only |

The profile fails closed when the executable, shortcut files, an optional locale pin, the DPI, or the window identity does not match. Validation evidence is in [docs/VALIDATION.md](docs/VALIDATION.md).

## Quick start: configure → install → test → register

Prerequisites: Git, CPython 3.13, Codex, and CSP 1.11.10. Clone the repository to a trusted local directory:

```powershell
git clone https://github.com/VulpesNexus/clip-studio-paint-1.11.10-mcp.git
Set-Location .\clip-studio-paint-1.11.10-mcp
```

### 1. Configure the local machine

Run the configuration helper before installation. It creates a gitignored local configuration; machine-specific CSP, shortcut, and asset-root paths must not be committed.

```powershell
& .\scripts\configure.ps1 -CspExecutable "$env:ProgramFiles\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
```

Pass your own path if CSP is installed elsewhere. The helper checks the executable's version, CELSYS signature, and publisher, and records its SHA-256 and those of your shortcut settings. It looks for the settings in *Documents\CELSYS* and in *%APPDATA%\CELSYSUserData\CELSYS*, the two places CSP keeps them, and refuses if it finds both or neither; pass `-ShortcutProfileFiles` in that case. It creates three asset roots under *Documents\CSP-MCP-Assets*: a read-only *Input*, and read/write *Working* and *Exports*; `-AssetsRoot` changes the location. It also copies the inert *mcp-dialog-smoke.svg* acceptance fixture into *Input* unless a file of that name is already there.

`-ExpectedLocale fr-FR`, for example, pins a Windows culture; the default `*` accepts any.

At runtime, configuration resolves in this order: the absolute path in `CSP_MCP_CONFIG`, then *config/config.local.json*, then the tracked template *config/config.json*, which is not a ready-to-trust machine profile.

Treat generated hashes as an attestation of a machine you have already inspected, not as proof that an arbitrary executable or shortcut file is trustworthy.

### 2. Install locked dependencies

```powershell
& .\scripts\install.ps1
```

The installer creates *.venv* in the repository and installs `mcp==1.29.0`, `pywin32==312`, and `Pillow==12.3.0` from *requirements.lock.txt* with hashes enforced. If the ACL audit rejects an untrusted ancestor, move the checkout and assets to a trusted directory or have an administrator review the ancestor ACLs. The explicit risk-acceptance switch skips only the initial ancestor gate; it does not repair ACLs or bypass the final requirement that every audited root and file tree be protected.

### 3. Test before registration

```powershell
$Python = Join-Path $PWD '.venv\Scripts\python.exe'

& $Python -X utf8 -m compileall -q csp_mcp server.py tests
& $Python -X utf8 -m unittest discover -s tests -p 'test_*.py' -v
& $Python -X utf8 .\tests\smoke_stdio.py
```

Compilation and unit tests run in GitHub Actions on Windows with Python 3.13. The stdio smoke test also needs a valid local configuration and a running CSP 1.11.10, so hosted CI skips it.

The optional interactive acceptance test restores and focuses CSP, opens its *Open* dialog, validates the configured fixture path without submitting it, cancels that exact dialog, and compares captures:

```powershell
& $Python -X utf8 .\tests\acceptance_interactive.py
```

Run it only while CSP 1.11.10 is open with no document-saving prompt, and while you are not using the mouse or keyboard. It does not replace manual review.

### 4. Register with Codex

```powershell
& .\scripts\register-codex.ps1
```

Restart Codex after registration, then call `csp_health` followed by `csp_capabilities`. To remove the registration, run:

```powershell
& .\scripts\unregister-codex.ps1
```

Registration and unregistration keep a timestamped rollback backup beside Codex's *config.toml*. That backup contains the complete previous Codex configuration and may include sensitive environment values. The scripts reject reparse points or unsafe write ACLs at that location; protect the directory and delete obsolete backups once the new registration works.

The registration keeps `writes` as the default approval mode. It auto-approves only the 10 atomic consumers that cannot operate without a server-issued single-use preflight token: move, click, drag, scroll, text, navigation key, registered command, Auto Action, command sequence, and strict native file dialog. `csp_preflight` itself remains approval-gated.

## Confirmation-token flow

For ordinary visible UI input:

1. Call `csp_health`, `csp_capabilities`, and `csp_get_state`.
2. Call `csp_capture` for read-only planning.
3. Call `csp_preflight(operation="input", identifier="exact_tool_name", parameters_json="exact JSON parameters")` without an old capture ID.
4. After the user approves preflight, immediately call `csp_capture` again and verify that the target is still visible.
5. Call the exact atomic tool with the fresh `captureId`, the returned `confirmToken`, and byte-for-byte equivalent business parameters.
6. Inspect the post-operation capture; repeat preflight for the next input.

Tokens expire after 45 seconds, are single-use, bind the complete parameters and the exact CSP window or dialog identity, and are invalidated by foreground, pixel, generation, or input-time changes. Parameter mismatches consume the token. `csp_cancel` is a narrow exception: it remains host approval-gated and sends one `Escape` only to the exact CSP main window or its unique verified standard dialog.

The MCP protocol gives the server no cryptographic proof that the human approved a host prompt, so the trust boundary includes the configured Codex host. A malicious custom stdio client running as the same user is out of scope; see the [security model](docs/SECURITY.md).

## File operations

Path-taking tools operate only inside the three roots of the local configuration. They reject UNC and device paths, alternate data streams, wildcards, reserved device names, reparse points, implicit overwrite, and other unsupported cases. Existing paths are checked through handles, and existing inputs and replacement targets are checked for hard links, but these mitigations cannot eliminate every check-to-use race.

Saving or replacing a file uses this explicit flow:

1. Validate the exact target with `csp_validate_path`.
2. Preflight and run the registered `document.save_as_dialog` command.
3. Obtain the exact main and dialog HWNDs, then preflight `csp_native_file_dialog` with the full path, intent, and submit flag.
4. Submit only through the verified file-dialog control profile. Any later overwrite or format prompt needs manual handling.
5. Accept completion only after `csp_wait_for_file` verifies a stable, non-empty target and returns its SHA-256.

*Ctrl+S* is not registered, because CSP does not expose the current document's path through a public API. Generic coordinate and text tools must not be used for open, save, or export, nor for account, cloud, store, community, or publishing workflows.

`csp_open_document` runs `CLIPStudioPaint.exe <path>` with an argument array. CELSYS does not document this as a stable command-line contract. A successful response proves dispatch and CSP window evidence, not which document tab owns the path; verify the result with a capture.

## Auto Actions

The tracked Auto Action registry starts empty. Create and check each action in CSP by hand, bind only *Ctrl+Alt+[Shift]+F1..F12*, then register it locally as described in [Auto Actions setup](docs/AUTO_ACTIONS.md).

- Auto Actions are available in CSP PRO and EX, not DEBUT.
- Every action requires preflight and an exact registered ID.
- Production configuration rejects `effect: "filesystem"`.
- Each entry must attest `attested_no_file_io: true`.
- The server cannot parse proprietary *.laf* files, so that attestation is an administrator's promise rather than technical proof.

Use the dedicated validated file workflow for open, save, and export.

## Click-through overlays

Capture refuses whenever a window from another process overlaps CSP, because a screen capture would include anything that window paints. Some overlays cover the whole desktop permanently yet usually paint nothing; Discord's in-game overlay is one. A local configuration may list such overlays in `capture_ignored_overlays`, each identified by its exact process image name, window class, and title:

```json
"capture_ignored_overlays": [
  {"process": "Discord.exe", "class_name": "Chrome_WidgetWin_1", "title": "Discord Overlay"}
]
```

An entry matches only a layered, mouse-transparent window, so an ordinary window with the same identity still blocks capture. Listing an overlay attests that it is not painting over CSP while you capture. Every capture that skipped one reports the window ID in `ignoredOverlayWindowIds`. Input authorization is unchanged, because Windows hit-testing already passes through such windows. The tracked template lists none, and *configure.ps1* does not carry the list over when it rewrites the local configuration.

## Project layout

```text
.
├─ csp_mcp\                 MCP application, policy, controller, Win32 backend
├─ config\                  tracked template and registries
├─ docs\                    tools, security, Auto Actions, compatibility, validation
├─ scripts\                 configure, install, register, unregister, ACL audit
├─ tests\                   unit, stdio smoke, opt-in interactive acceptance
├─ server.py                stdio entry point
├─ pyproject.toml
├─ requirements.txt
└─ requirements.lock.txt
```

## Documentation and sources

- [Tool catalog](docs/TOOL_CATALOG.md)
- [Security model](docs/SECURITY.md)
- [Auto Actions setup](docs/AUTO_ACTIONS.md)
- [Compatibility with other CSP versions](docs/COMPATIBILITY.md)
- [Validation record](docs/VALIDATION.md)
- [OpenAI Codex MCP documentation](https://developers.openai.com/codex/mcp/)
- [CELSYS Auto Actions manual](https://help.clip-studio.com/en-us/manual_en/720_preferences/Auto_Actions.htm)
- [CELSYS public SDK page](https://www.clipstudio.net/ja/sdk/)
- [CELSYS supported open and import formats](https://help.clip-studio.com/en-us/manual_en/210_file/Open_file.htm)

## Development

Pull requests should preserve the fail-closed version, signature, and profile checks, and add tests for behavior changes. Hosted CI performs only compilation and unit tests; the CSP-dependent smoke and interactive tests need a prepared Windows workstation. See [CONTRIBUTING.md](CONTRIBUTING.md) and [the security policy](.github/SECURITY.md).

A different CSP build, DPI, shortcut edit, or license edition needs a fresh signature and hash check, capture calibration, shortcut verification, and non-destructive acceptance testing before a profile for it is published.

## License and trademarks

The project is available under the [MIT License](LICENSE), which keeps A2pha's original copyright notice. Third-party dependency notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

CLIP STUDIO PAINT and CELSYS are trademarks of their respective owners. This repository does not distribute CELSYS software, SDK source, private protocols, or reverse-engineered `.clip` format code.
