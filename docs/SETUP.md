# Setup

The README has the four commands; this page explains what each one does and the options it takes.

## 1. Configure

```powershell
& .\scripts\configure.ps1 -CspExecutable "$env:ProgramFiles\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
```

*configure.ps1* writes *config/config.local.json*, which Git ignores; machine-specific CSP, shortcut, and asset-root paths must never be committed. It:

- checks that the executable is file version 1.11.10.0, signed by CELSYS with a valid Authenticode signature, and published by CELSYS, and records its SHA-256;
- finds CSP's shortcut settings, *CLIPStudioPaintVer1_5_0\Shortcut\default.khc* and *DefaultToolModifyKey.tomd*, and records their SHA-256. CSP keeps them in *Documents\CELSYS* until they are moved, and in *%APPDATA%\CELSYSUserData\CELSYS* for installations that started on 1.10.13 or later or used *Move user data folder*. The script refuses if it finds both or neither; pass `-ShortcutProfileFiles` with the two paths in that case;
- creates three asset roots under *Documents\CSP-MCP-Assets*: a read-only *Input*, and read/write *Working* and *Exports*. `-AssetsRoot` puts them elsewhere; it must not be a volume root, and it and the repository must not contain one another;
- copies the inert *mcp-dialog-smoke.svg* acceptance fixture into *Input*, unless a file of that name is already there.

`-ExpectedLocale fr-FR`, for example, pins a Windows culture; the default `*` accepts any.

Treat the recorded hashes as an attestation of a machine you have already inspected, not as proof that an arbitrary executable or shortcut file is trustworthy.

Rerun *configure.ps1* whenever CSP rewrites its shortcut settings, which it can do on its own; the pinned hash then stops matching and input is refused. Check first that the registered bindings in [Registered commands](USAGE.md#registered-commands) still hold. The script rewrites the whole local file, so add back any `capture_ignored_overlays` afterward.

At runtime, configuration resolves in this order: the absolute path in `CSP_MCP_CONFIG`, then *config/config.local.json*, then the tracked template *config/config.json*, which is not a ready-to-trust machine profile.

## 2. Install

```powershell
& .\scripts\install.ps1
```

The installer creates *.venv* in the repository with CPython 3.13 and installs `mcp==1.30.0`, `pywin32==312`, and `Pillow==13.0.0` from *requirements.lock.txt*, with hashes enforced. It finds Python 3.13 through the *py* launcher or the usual install folders; `-Python` names one explicitly.

It also audits the ACLs of the checkout, the asset roots, and their ancestors. If the audit rejects an untrusted ancestor, move the checkout and assets to a trusted directory or have an administrator review the ancestor ACLs. The explicit risk-acceptance switch skips only the initial ancestor gate; it does not repair ACLs or bypass the final requirement that every audited root and file tree be protected.

## 3. Test

```powershell
$Python = Join-Path $PWD '.venv\Scripts\python.exe'

& $Python -X utf8 -m compileall -q csp_mcp server.py tests
& $Python -X utf8 -m unittest discover -s tests -p 'test_*.py' -v
& $Python -X utf8 .\tests\smoke_stdio.py
```

Compilation and unit tests run in GitHub Actions on Windows with Python 3.13. The stdio smoke test also needs a valid local configuration and a running CSP 1.11.10, so hosted CI skips it.

The optional interactive acceptance test restores and focuses CSP, opens its *Open* dialog, fills in the fixture path without submitting it, cancels that exact dialog, and compares captures:

```powershell
& $Python -X utf8 .\tests\acceptance_interactive.py
```

Run it only while CSP 1.11.10 is open with no document-saving prompt, and keep your hands off the mouse and keyboard for about 20 seconds: any input after its capture makes it stop, by design. It does not replace manual review.

## 4. Register with Codex

```powershell
& .\scripts\register-codex.ps1
```

Restart Codex, then call `csp_health` followed by `csp_capabilities`. To remove the registration:

```powershell
& .\scripts\unregister-codex.ps1
```

Registration and unregistration keep a timestamped rollback backup beside Codex's *config.toml*. That backup contains the complete previous Codex configuration and may include sensitive environment values. The scripts reject reparse points or unsafe write ACLs at that location; protect the directory and delete obsolete backups once the new registration works.

The registration keeps `writes` as the default approval mode. It auto-approves only the 10 atomic tools that cannot act without a server-issued single-use preflight token: move, click, drag, scroll, text, navigation key, registered command, Auto Action, command sequence, and native file dialog. `csp_preflight` itself still needs approval. Other stdio hosts need an equivalent approval policy.
