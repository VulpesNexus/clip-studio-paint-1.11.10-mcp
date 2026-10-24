# Validation record

Evidence for the `csp-1.11.10-dpi96-v1` profile: CLIP STUDIO PAINT 1.11.10.0 at window DPI 96, on Windows 11 with a French display language. Newest first.

## 2026-10-25: first full install on the owner machine

- PR #2 merged: the PowerShell audit accepts the CST path roots, the root policy is single-sourced from `csp_mcp/config.py` with a drift test, and a PowerShell policy test runs in CI under 5.1 and 7.
- Machine ACL remediation (owner-run): orphaned foreign-SID grants and `Authenticated Users` Modify removed from the project folder, the `cst_copy` root, and the `cst_ascii_copy` root; explicit owner `FullControl` in place; inheritance isolated per folder.
- *install.ps1* completed end to end for the first time: ACL asserts passed on all audited targets, Python 3.14 venv accepted, hash-verified lockfile, `pip check` clean, production profile passed runtime validation. Unit suite from the installed venv: 92 tests, all pass.
- Fixed during this pass: a second PowerShell 5.1 embedded-quote `-c` argument (the venv version check f-string), and pip logging crashes on the ANSI codepage (`PYTHONIOENCODING=utf-8` for child Python calls).

## 2026-10-25: Python 3.14 support

- The installer accepts CPython 3.13 and 3.14, and CI runs the unit suite on both. The dependency lockfile resolves identically for both minors.
- Fixed the interpreter probe for PowerShell 5.1: the probe embedded double quotes, which PS 5.1 strips when passing `-c` arguments to native executables, so the probe failed on every interpreter and *install.ps1* always reported that Python was not found. The probe is now quote-free; a missing rename of a helper call site was caught and fixed by a unit harness around the resolver.
- On the owner machine (no *py* launcher; Python install-manager layout under *AppData\Local\Python*), the resolver found `pythoncore-3.14-64` through PATH, created *.venv* on Python 3.14, installed the hash-verified lockfile, and passed `pip check`; the unit suite passed there: 90 tests.
- The ACL asserts were not exercised end to end on this machine: the project directory grants Modify to a non-owner SID, so *install.ps1* fail-closed as designed. Pre-existing and unrelated to Python support.

## 2026-09-23: public fork

- CSP had rewritten *default.khc* on 2026-09-18, so its pinned hash no longer matched. The nine registered bindings were checked again and had not changed: `filenew` *Ctrl+N*, `fileopen` *Ctrl+O*, `fileclose` *Ctrl+W*, `filesaveas` *Ctrl+Shift+S*, `undo` *Ctrl+Z*, `redo` *Ctrl+Y*, `selectall` *Ctrl+A*, and `selectdeselect` *Ctrl+D*, with *Escape* handled by CSP itself. The local pins were refreshed.
- *configure.ps1*, run from a clean copy of the repository with the README's command, found the settings under *Documents\CELSYS*, and wrote profile `csp-1.11.10-dpi96-v1` with the same executable hash as the existing local configuration.
- The unit suite passed on Python 3.14.6: 67 tests. CI runs it on Python 3.13.
- The stdio smoke test passed all 18 checks against the running CSP; the concurrent read took 0.008 seconds against its 0.75-second budget.
- The interactive acceptance test passed. Through the registered `document.open_dialog` command it opened CSP's *Open* dialog (French labels), filled in the fixture path without submitting it, canceled that exact dialog, and compared captures before and after (1.5% of pixels changed, from focus). A first attempt stopped before opening anything because someone used the mouse or keyboard a second after the capture: the fail-closed behavior the token flow promises.

## 2026-09-10: profile added

- All nine registered bindings matched the 1.11.10 shortcut database. *default.khc* is SQLite; its `shortcutmenu` table stores a key and a modifier with the bits Alt=1, Shift=2, and Ctrl=4.
- Against a running 1.11.10, `csp_health` reported the binary, signature, and shortcut pins as supported, and `csp_capabilities` reported a matching profile.
- The stdio smoke test passed every functional check, but on a heavily loaded machine it missed its 0.75-second concurrent-read budget (0.96 seconds).
- `csp_capture` was used for reference captures of CSP's canvas at 100% zoom, with Discord's overlay listed in `capture_ignored_overlays`.

## 2026-09-09: any Windows culture

- The locale gate became optional (`expected_locale: "*"`), and native file dialogs are recognized by exact French, English, and Simplified Chinese labels after normalization rather than by Chinese substrings. The unit suite passed on Python 3.14.6, including the French and English dialog fixtures and the DPI and explicit-locale checks.

## Not yet covered

- The locked Python 3.13 deployment has been tested only in CI, not against a running CSP.
- `csp_open_document` (opening a file through CSP's command line) and a submitted save through the native *Save As* dialog have not been exercised on 1.11.10.
- No Auto Action is registered, so `csp_run_auto_action` has only unit coverage.
- Window DPIs other than 96, and dialog languages other than French.
