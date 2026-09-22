# Compatibility with other CSP versions

Only CLIP STUDIO PAINT **1.11.10.0** at window DPI 96 is validated, and the bundled profile refuses every other build: the executable's version and SHA-256 are pinned. This page infers which other versions would probably work with a profile of their own, from what the MCP depends on and from CELSYS's published release notes. None of it has been tested; a version moves from "likely" to "supported" only through the steps in [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-csp-version).

## What the MCP depends on

| Dependency | How it varies between CSP versions |
|---|---|
| Executable identity | Every build has its own file version and SHA-256, so every build needs its own profile. The CELSYS signature and the *CLIP STUDIO 1.5\CLIP STUDIO PAINT\CLIPStudioPaint.exe* install path are the same in 1.11.10 and in upstream's 5.1.2 template. |
| Window DPI | 1.11.0 made the UI scale to each display's text scaling ([release notes](https://www.clipstudio.net/en/dl/release_note/)). From 1.11.0 on, the window's DPI should follow the display's scaling, so a profile validated at 96 (100%) needs a sibling for 120 (125%), 144 (150%), and so on. How earlier builds report their DPI is unknown. |
| Shortcut settings location | Builds up to 1.10.12 keep user settings in *Documents\CELSYS*. 1.10.13 added *Move user data folder* and uses *%APPDATA%\CELSYSUserData\CELSYS* ([support article](https://support.clip-studio.com/en-us/faq/articles/20190152)), but an installation whose settings were never moved keeps using *Documents*; the 1.11.10 installation validated here does. *configure.ps1* looks in both places. |
| Shortcut settings folder | *CLIPStudioPaintVer1_5_0\Shortcut*, holding *default.khc* (an SQLite database) and *DefaultToolModifyKey.tomd*. The folder name is the same in 1.11.10 and in upstream's 5.1.2 template. |
| Registered commands | Nine CSP default shortcuts: *Escape*, *Ctrl+N*, *Ctrl+O*, *Ctrl+Z*, *Ctrl+Y*, *Ctrl+A*, *Ctrl+D*, *Ctrl+Shift+S*, and *Ctrl+W*. Defaults can change between versions and users can rebind them, so each profile checks them against that build's *default.khc*. |
| Main window | Chosen by executable path as the single unowned top-level window that is not a dialog. Any second such window, for example a sign-in or license window, makes the target ambiguous and stops input. |
| File dialogs | CSP's *Open* and *Save As* use the standard Windows `#32770` file dialog; the MCP checks its control IDs and labels. 1.12.0 changed CSP's folder-browsing dialogs to look like the file-open dialog, which the MCP does not use. |
| Opening from the command line | `CLIPStudioPaint.exe <path>` was observed to open a document in upstream's 5.1.2 deployment; CELSYS does not document it. |
| Auto Actions | PRO and EX only, in every version. |

## Likely compatibility

| CSP versions | Released | Likelihood | What a profile for them would change |
|---|---|---|---|
| 1.11.0–1.11.14 | Sep 2021–Mar 2022 | High | Same minor line as the validated build and the same display scaling. Version and hash; DPI as measured; check the nine bindings. |
| 1.12.0–1.13.2 | May 2022–Jan 2023 | Medium to high | As above. 1.12.11 is the last 1.x build CELSYS still offers for download ([previous versions](https://www.clipstudio.net/en/oldversion/)). |
| 2.0 and later, including 5.1.2 | Mar 2023 on | Medium | The code came from a working 5.1.2 deployment, so the mechanics carry over, as upstream shows. Settings are normally under *%APPDATA%\CELSYSUserData*. Check for sign-in, license, or news windows that could make the main window ambiguous, and for changed default shortcuts. For 5.1.2 itself, [upstream](https://github.com/A2pha/clip-studio-paint-5.1.2-production-mcp) already has a profile. |
| 1.10.13–1.10.14 | Jun–Jul 2021 | Medium | Before per-display scaling, so the window DPI may not follow the display. Settings may be in either location. |
| 1.5.0–1.10.12 | Oct 2015–Jun 2021 | Low | Settings in *Documents* only, no per-display scaling, and older dialogs and shortcut defaults, none of them examined. |
| 1.4 and earlier, Manga Studio 5 | before Oct 2015 | Incompatible | No *CLIPStudioPaintVer1_5_0* folder, and documents are *.lip*, not *.clip*. |
| Early Access and preview builds | — | Unsupported | They change without notice. |

Whatever the version, native file dialogs are recognized only in French, English, and Simplified Chinese, so a Windows display language outside those three blocks the file-dialog tool until its labels are added with fixtures and acceptance coverage.
