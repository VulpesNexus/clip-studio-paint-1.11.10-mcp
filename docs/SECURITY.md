# Security model

## What is allowed

- Stdio, as a local process; no TCP port is opened.
- Only the `CLIPStudioPaint.exe` at the configured path.
- Before every control step, the server verifies the Authenticode signature, the CELSYS company field, the file version pinned by the active profile (1.11.10.0), and the current SHA-256.
- Strict profile: any Windows culture is accepted by default (`expected_locale: "*"`), and a specific culture can be pinned instead. The CSP window DPI must match the profile (96).
- Pointer coordinates are normalized `0..1` values over the CSP window or client area, bound to a capture less than 30 seconds old.
- Before a capture, every top-level window above CSP is enumerated, and any foreign window that intersects the capture rectangle refuses the capture. A 7×7 point check remains as a second line. The only exception is a click-through overlay that the local configuration lists by exact process, class, and title, and that is both layered and mouse-transparent; every capture that skips one reports it.
- Tools that take a path work only inside the three separate roots the local configuration defines: `Input`, `Working`, and `Exports`. Generic input to the custom-drawn UI carries no proof of path meaning. The repository ships no user machine path as a default.
- Every path is checked for reparse points from the configured root down to the target, and an existing target's final path is read back through a Windows file handle. Hard-link counts are checked only for existing inputs and replacement targets. These checks narrow the window between check and use; they cannot close it.
- All input is serialized. Recent human input or a held key blocks execution.
- The 10 atomic input tools (click, move, drag, scroll, text, navigation key, registered command, Auto Action, command sequence, and native file dialog) each need a confirmation token that expires after 45 seconds, is single-use, and is bound to the complete parameters. An ordinary UI token works only with a capture taken after approval. `csp_cancel` is a narrow exception: the host still approves it as a write, and it sends one `Escape` only to the exact CSP main window or the single standard dialog.
- *Ctrl+S* is not registered, because no public interface reveals the current document's path. Saving and exporting go through the native file-dialog flow after path validation.
- Auto Actions registered with a file read or write side effect, or without `attested_no_file_io`, are refused. The server does not parse *.laf* files and cannot prove an administrator's attestation true.
- Auto Action shortcuts are limited to *Ctrl+Alt+[Shift]+F1..F12*. Production command IDs, key combinations, risks, and side effects must match the pinned profile exactly.

## What is refused

- Any shell, PowerShell, process, registry, or whole-disk file tool.
- DLL injection, patching the program, the private Companion protocol, and `.lipcommand`.
- Parsing or modifying `.clip` binaries.
- Semantic tools for accounts, the store, purchases, material uploads, cloud sync, the community, or publishing; the agent is also forbidden from reaching them with generic click and text tools.
- Arbitrary shortcuts passed in over MCP. Only versioned commands or administrator-registered Auto Actions can be called.
- Releasing modifier keys and mouse buttons system-wide is used only for the server's internal cleanup after an error; it is not exposed as an MCP tool.
- UNC paths, device paths, alternate data streams, wildcards, reserved device names, junctions, symbolic links, and implicit overwrites.

## Remaining risks

CSP's main interface is custom-drawn, so Windows UI Automation cannot see its layers, brushes, or menus. Capture checks can confirm only what happened to visible pixels, not the semantic state. A coordinate click can in principle land on the wrong visible button, so every call must start from a valid capture.

The MCP protocol gives the server no cryptographically verifiable proof that the user approved anything in Codex; the server can only require the client to call preflight first. The authorization model therefore trusts Codex and its current configuration, and it cannot stop a malicious stdio client written by the same user. Covering that threat would need the server's own confirmation UI or a signed host assertion, which standard MCP does not provide.

Because the custom-drawn UI has no machine-readable control semantics, the server cannot prove from a coordinate that it is not an account, cloud, or publishing entry point. Four constraints cover that: only PAINT is controlled, not the launcher; the server instructions forbid it explicitly; captures and human input invalidate authorization; and a human approves the exact tool name and full parameters of every `csp_preflight`. So that the approval prompt does not always invalidate the captureId, the registration auto-approves the 10 token-gated atomic tools, which refuse to act without a matching token. For hard isolation, disable every generic coordinate and text tool and enable only registered commands and hand-verified Auto Actions.

An approval prompt closes CSP's transient menus, so opening a menu and then approving a click on one of its items cannot be supported safely. If the capture taken after approval no longer shows the target, the token must be discarded. Use a registered command or an Auto Action for such functions.

For path-taking tools such as `csp_open_document`, path validation, asset listing, export scanning, and the native file dialog, the path allowlist is a validation boundary; reading back the handle's final path and checking hard links narrow, but do not remove, the check-to-use race. For generic coordinate clicks and text input it is only a policy boundary: those tools could still open a menu by hand and type any path, so even with exact parameters approved they must not be used to open, save, or export. The default command table deliberately leaves out *Ctrl+S*, which cannot be bound to a path.

A native file dialog must match `#32770`, a shell file view, the file-name Edit control ID, and the `IDOK` button, and its title and button labels must agree on Open or Save/Export in a supported language: French, English, or Simplified Chinese, compared exactly after normalization. Unknown or ambiguous dialogs are refused. The path is written with a message that has a timeout and is read back exactly. If an overwrite or format dialog follows submission, the MCP does not click it; the response asks for manual handling, and the file must still pass `csp_wait_for_file`.

`GetLastInputInfo` cannot reliably tell human input from synthetic input. The server does not guess where an event came from; any change in the input time invalidates authorization, and every pressed virtual key is checked. A long drag still cannot get the complete isolation that a native input driver would. Do not run automation while a person is using CSP.

The install and registration scripts audit the ACLs of the project tree, the configured asset roots, and their ancestors, and they refuse to change ACLs recursively on their own. Parent folders that grant write access to broad groups occur in practice, so a parent's delete or replace permission is a real local multi-user risk, not a theoretical one. The scripts refuse by default when they find an untrusted ancestor; the explicit risk switch only accepts the remaining risk and does not repair it. Tightening an ancestor's ACL can affect data outside the repository, so it is a separate decision for the machine's administrator. The repository assumes no drive letter or user folder is trustworthy by nature.

Dependencies are installed from *requirements.lock.txt* with SHA-256 hashes and `pip --require-hashes`. Before every control step CSP's signature, version, and pinned hash are verified again; that narrows, but cannot remove, the race in which a malicious process replaces a parent folder on the same volume.
