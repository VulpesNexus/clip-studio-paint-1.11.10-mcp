# CLIP STUDIO PAINT 5.1.2 Production MCP

> [!IMPORTANT]
> **Unofficial community project.** This repository is not affiliated with, endorsed by, or supported by CELSYS. It is a local stdio MCP bridge for **Windows + a pinned CLIP STUDIO PAINT build**. Two strict profiles are validated: **5.1.2.0 production at DPI 120** and **1.11.10.0 at DPI 96**. Other CSP versions, preview/Early Access builds, DPI values, and operating systems are not supported by the bundled strict profiles.

> [!NOTE]
> **Private fork.** This repository is a private fork of [A2pha/clip-studio-paint-5.1.2-production-mcp](https://github.com/A2pha/clip-studio-paint-5.1.2-production-mcp) (MIT License). It adds a validated CLIP STUDIO PAINT 1.11.10 profile alongside the upstream 5.1.2 profile; see [Validated profiles](#validated-profiles). GitHub does not allow a fork of a public repository to be private, so the upstream is tracked as the `upstream` Git remote instead of through GitHub's fork relationship.

As of 2026-08-25, the CELSYS public documentation reviewed for this project does not document a general-purpose CSP document/layer API, scripting runtime, MCP, or supported headless CLI; its published SDK is scoped to EX filter plug-ins. CSP's custom-drawn areas do not expose meaningful layer, brush, or menu objects through Windows UI Automation. This project therefore offers 33 deliberately constrained capabilities built from visible-window inspection, screenshots, allowlisted input, registered shortcuts/Auto Actions, and file exchange. It is **not** a native layer-object API and cannot honestly expose every internal CSP function.

## What is included

- 33 MCP tools; see the complete [tool catalog](docs/TOOL_CATALOG.md).
- CSP executable attestation: fixed path, Authenticode signature, CELSYS company field, exact file version, and SHA-256.
- Per-Monitor DPI Awareness V2 with a per-profile DPI pin (120 for 5.1.2, 96 for 1.11.10) and locale-independent ordinary controls.
- Process, main-window, foreground-window, dialog, display, user-activity, screenshot, pixel sampling, and screenshot-difference inspection.
- Screenshot-bound pointer movement, clicks, double-clicks, drags, scrolling, navigation keys, and Unicode text input.
- Versioned shortcut commands, constrained command sequences, and user-registered Auto Actions.
- Configured path roots for asset listing, file metadata, import dispatch, export scanning, and stable-output verification.
- Strict native `#32770` file-dialog filling/submission with explicit overwrite intent.
- A preflight confirmation protocol for all 10 atomic input tools.
- Local stdio transport only: no listening port, shell, registry, arbitrary-process, or unrestricted-filesystem tool.

### Privacy boundary

Local stdio means this server opens no network listener; it does **not** mean all
MCP data stays on the machine. The MCP host receives tool inputs and outputs,
including screenshots, visible UI text, window titles, and configured absolute
paths, and may send them to a remote model under that host's data policy. Keep
sensitive documents closed, review the host's privacy controls, and treat text
or imagery shown inside CSP as untrusted data rather than instructions for the
agent.

## Support matrix

| Component | Supported target |
|---|---|
| Operating system | Windows only |
| CLIP STUDIO PAINT | `5.1.2.0` production or `1.11.10.0`, executable pinned by SHA-256 |
| UI profile | Any Windows culture; French, English, and Simplified Chinese native file dialogs; effective CSP window DPI `120` (5.1.2) or `96` (1.11.10) |
| Python | CPython `3.13.x` |
| MCP host | Codex registration script included; other stdio hosts require equivalent approval policy |
| CSP edition | Core visible-window tools are profile-bound; Auto Actions require PRO or EX and `.cmc` is EX-only |

The profile fails closed when the executable, shortcut files, an optional locale pin, DPI, or window identity does not match. Create and validate a separate profile for a different CSP build or DPI.

## Validated profiles

| Profile ID | CSP file version | Window DPI | Shortcut settings folder |
|---|---|---|---|
| `csp-5.1.2-zh-CN-dpi120-v1` | `5.1.2.0` | 120 | `%APPDATA%\CELSYSUserData\CELSYS\CLIPStudioPaintVer1_5_0\Shortcut` |
| `csp-1.11.10-dpi96-v1` | `1.11.10.0` | 96 | `Documents\CELSYS\CLIPStudioPaintVer1_5_0\Shortcut` |

`configure.ps1 -ExpectedVersion` selects the profile and defaults to `5.1.2.0`; any other
version is rejected. CSP 1.x keeps its user settings under Documents rather than
`%APPDATA%\CELSYSUserData`, and the helper looks in the right place for each profile.
`commands.json` and `auto_actions.json` list the profiles they are valid for in
`profile_ids`. A registry that declares no matching profile, or declares both
`profile_id` and `profile_ids`, fails closed.

On 2026-09-10 the nine registered command bindings were checked against the 1.11.10
shortcut database. `default.khc` is SQLite, and `shortcutmenu.modifier` uses the bits
Alt=1, Shift=2, Ctrl=4. All nine bindings match. On Python 3.14.6 the 1.11.10 profile
passed the unit suite. Against a running 1.11.10, `csp_health` reported the binary,
signature, and shortcut pins as supported, and `csp_capabilities` reported a matching
profile. The stdio smoke test passed every functional check, but on a heavily loaded
machine it missed its 0.75-second concurrent-read budget (0.96 seconds). Native
acceptance and capture coverage on 1.11.10 are still pending.

## Local locale support

New configurations use `expected_locale: "*"`, which accepts any Windows culture.
Existing configurations may use that value or an explicit pin such as `fr-FR`.
`configure.ps1 -ExpectedLocale fr-FR` writes that pin. The historical profile ID
remains for registry compatibility; its `zh-CN` substring no longer sets policy.

Native file dialogs still require their existing control structure and matching
Open or Save/Export labels. French, English, and Simplified Chinese labels are
supported, including accelerator markers and ellipses. Unknown labels, conflicting
modes, and ambiguous controls are rejected. Add fixtures and native acceptance
coverage before enabling another dialog language.

Executable, DPI, shortcut, path, and confirmation checks remain in place. The
unit suite passed on Python 3.14.6 on 2026-09-09, including the French and English
dialog fixtures and the DPI and explicit-locale checks. This does not validate the
locked Python 3.13 deployment. Native CSP acceptance on this workstation remains
pending.

## Quick start: configure → install → test → register

Prerequisites: Git, CPython 3.13, Codex, and a CSP build with a validated profile (see above). Clone the repository to a trusted local directory:

```powershell
git clone https://github.com/A2pha/clip-studio-paint-5.1.2-production-mcp.git
Set-Location .\clip-studio-paint-5.1.2-production-mcp
```

### 1. Configure the local machine

Run the configuration helper before installation. It creates a gitignored local configuration; machine-specific CSP, shortcut-profile, and asset-root paths must not be committed.

```powershell
$CspExecutable = Read-Host 'Absolute path to CLIPStudioPaint.exe (5.1.2.0 or 1.11.10.0)'
& .\scripts\configure.ps1 -CspExecutable $CspExecutable                               # 5.1.2.0
& .\scripts\configure.ps1 -CspExecutable $CspExecutable -ExpectedVersion '1.11.10.0'  # 1.11.10.0
```

The configuration must identify:

- the `CLIPStudioPaint.exe` of a validated profile;
- the expected CELSYS signature, that profile's file version, and the executable SHA-256;
- the current user's CSP shortcut-setting files and their SHA-256 values;
- three separate asset roots: read-only `Input`, read/write `Working`, and read/write `Exports`.

Unless explicitly overridden, the helper discovers the supported shortcut files
where the selected profile's CSP keeps them (`%APPDATA%` for 5.1.2, Documents for
1.11.10) and creates the asset root as
`CSP-MCP-Assets` under the current user's Documents folder. Use
`-ShortcutProfileFiles` and `-AssetsRoot` when those locations differ.
It also copies the repository's inert `mcp-dialog-smoke.svg` fixture into the
Input root when that filename is absent; it never overwrites an existing file.

At runtime, configuration resolves in this order: the absolute path in
`CSP_MCP_CONFIG`, then `config/config.local.json`, then the tracked placeholder
`config/config.json`. The tracked file is a template, not a ready-to-trust
machine profile.

Treat generated hashes as an attestation of a machine you have already inspected, not as proof that an arbitrary executable or shortcut file is trustworthy.

### 2. Install locked dependencies

```powershell
& .\scripts\install.ps1
```

The installer creates `.venv` in the repository and installs `mcp==1.29.0`, `pywin32==312`, and `Pillow==12.3.0` from `requirements.lock.txt` with hashes enforced. If the ACL audit rejects an untrusted ancestor, move the checkout/assets to a trusted directory or have an administrator review the ancestor ACLs. The explicit risk-acceptance switch skips only the initial ancestor gate; it does not repair ACLs or bypass the final requirement that every audited root and file tree be protected.

### 3. Test before registration

```powershell
$Python = Join-Path $PWD '.venv\Scripts\python.exe'

& $Python -X utf8 -m compileall -q csp_mcp server.py tests
& $Python -X utf8 -m unittest discover -s tests -p 'test_*.py' -v
& $Python -X utf8 .\tests\smoke_stdio.py
```

Compilation and unit tests run in GitHub Actions on Windows/Python 3.13. The stdio smoke test additionally needs a valid local configuration and the supported CSP environment. It is intentionally excluded from hosted CI.

The optional interactive acceptance test restores and focuses CSP, opens a known Windows file dialog, validates a configured fixture path without submitting it, cancels that exact dialog, and compares screenshots:

```powershell
& $Python -X utf8 .\tests\acceptance_interactive.py
```

Run it only while the supported CSP build is open, no document-saving prompt is present, and you are not simultaneously using the mouse or keyboard. It does not replace manual review.

### 4. Register with Codex

```powershell
& .\scripts\register-codex.ps1
```

Restart Codex after registration, then call `csp_health` followed by `csp_capabilities`. To remove the registration, run:

```powershell
& .\scripts\unregister-codex.ps1
```

Registration and unregistration retain a timestamped rollback backup beside
Codex's `config.toml`. That backup contains the complete previous Codex
configuration and may include sensitive environment values. The scripts reject
reparse points or unsafe write ACLs at that location; protect the directory and
delete obsolete backups after confirming the new registration works.

The registration keeps `writes` as the default approval mode. It auto-approves only the 10 atomic consumers that cannot operate without a server-issued single-use preflight token: move, click, drag, scroll, text, navigation key, registered command, Auto Action, command sequence, and strict native file dialog. `csp_preflight` itself remains approval-gated.

## Confirmation-token flow

For ordinary visible UI input:

1. Call `csp_health`, `csp_capabilities`, and `csp_get_state`.
2. Call `csp_capture` for read-only planning.
3. Call `csp_preflight(operation="input", identifier="exact_tool_name", parameters_json="exact JSON parameters")` without an old capture ID.
4. After the user approves preflight, immediately call `csp_capture` again and verify that the target is still visible.
5. Call the exact atomic tool with the fresh `captureId`, returned `confirmToken`, and byte-for-byte equivalent business parameters.
6. Inspect the post-operation capture; repeat preflight for the next input.

Tokens expire after 45 seconds, are single-use, bind the complete parameters and exact CSP window/dialog identity, and are invalidated by foreground, pixel, generation, or input-time changes. Parameter mismatches consume the token. `csp_cancel` is a narrow exception: it remains host approval-gated and sends one `Escape` only to the exact CSP main window or its unique verified standard dialog.

The MCP protocol does not provide the server with cryptographic proof that the human approved a host prompt. The trust boundary therefore includes the configured Codex host. A malicious custom stdio client running as the same user is out of scope; see the [security model](docs/SECURITY.md).

## File operations

Path-taking tools operate only inside the three roots created by local configuration. They reject UNC/device paths, alternate data streams, wildcards, reserved device names, reparse points, implicit overwrite, and other unsupported cases. Existing paths are checked through handles and existing inputs/replacement targets are checked for hard links, but these mitigations cannot eliminate every check-to-use race.

Saving or replacing a file uses this explicit flow:

1. Validate the exact target with `csp_validate_path`.
2. Preflight and run the registered `document.save_as_dialog` command.
3. Obtain the exact main/dialog HWNDs, then preflight `csp_native_file_dialog` with the full path, intent, and submit flag.
4. Submit only through the verified file-dialog control profile. Any later overwrite/format prompt requires manual handling.
5. Accept completion only after `csp_wait_for_file` verifies a stable, non-empty target and returns its SHA-256.

`Ctrl+S` is not registered because CSP does not expose the current document path through a public API. Generic coordinate/text tools must not be used for open/save/export, account, cloud, store, community, or publishing workflows.

`csp_open_document` dispatches `CLIPStudioPaint.exe <path>` as an argument array because that behavior was observed in the reference deployment. CELSYS does not document it as a stable CLI contract. A successful response proves dispatch and CSP window evidence, not which document tab owns the path; verify the result with a capture.

## Auto Actions

The tracked Auto Action registry starts empty. Create and manually validate each action in CSP, bind only `Ctrl+Alt+[Shift]+F1..F12`, then register it locally as described in [Auto Actions setup](docs/AUTO_ACTIONS.md).

- Auto Actions are available in CSP PRO/EX, not DEBUT.
- Every action requires preflight and an exact registered ID.
- Production configuration rejects `effect: "filesystem"`.
- Each entry must attest `attested_no_file_io: true`.
- The server cannot parse proprietary `.laf` files, so that attestation is an administrator promise rather than technical proof.

Use the dedicated validated file workflow for open/save/export.

## Project layout

```text
.
├─ csp_mcp\                 MCP application, policy, controller, Win32 backend
├─ config\                  tracked examples and registries
├─ docs\                    tools, security, research, Auto Actions
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
- [GitHub project comparison](docs/GITHUB_RESEARCH.md)
- [OpenAI Codex MCP documentation](https://developers.openai.com/codex/mcp/)
- [CELSYS Auto Actions manual](https://help.clip-studio.com/en-us/manual_en/720_preferences/Auto_Actions.htm)
- [CELSYS public SDK page](https://www.clipstudio.net/ja/sdk/)
- [CELSYS supported open/import formats](https://help.clip-studio.com/en-us/manual_en/210_file/Open_file.htm)

## Development and release boundary

Pull requests should preserve fail-closed version/signature/profile checks and add tests for behavior changes. Hosted CI performs only compilation and unit tests; CSP-dependent smoke and interactive validation require an explicitly prepared Windows workstation. See [CONTRIBUTING.md](CONTRIBUTING.md) and [the security policy](.github/SECURITY.md).

The bundled profile is validated only for the exact target listed above. A CSP update, language change, DPI change, shortcut edit, or license-edition change requires fresh signature/hash checks, screenshot calibration, shortcut verification, and non-destructive acceptance testing before a new profile is published.

## License and trademarks

The project is available under the [MIT License](LICENSE). Third-party dependency notices are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

CLIP STUDIO PAINT and CELSYS are trademarks of their respective owners. This repository does not distribute CELSYS software, SDK source, private protocols, or reverse-engineered `.clip` format code.
