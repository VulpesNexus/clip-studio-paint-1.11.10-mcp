# Validation record

Evidence for the `csp-1.11.10-dpi96-v1` profile: CLIP STUDIO PAINT 1.11.10.0 at window DPI 96, on Windows 11 with a French display language. Newest first.

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
