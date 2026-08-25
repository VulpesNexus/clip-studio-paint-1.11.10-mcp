# Contributing

Thank you for helping improve this unofficial CLIP STUDIO PAINT MCP bridge.

## Before opening a change

1. Read [README.md](README.md), [docs/SECURITY.md](docs/SECURITY.md), and the
   relevant entries in [docs/TOOL_CATALOG.md](docs/TOOL_CATALOG.md).
2. Search existing issues and pull requests.
3. Keep the change within the public integration boundary: visible Windows UI,
   registered commands/Auto Actions, and validated file exchange.
4. Do not submit CELSYS binaries, SDK source, user shortcut files, proprietary
   `.laf` actions, `.clip` reverse-engineering code, credentials, or personal
   machine paths/hashes.

## Development setup

This project targets Windows, CPython 3.13, and the exact CSP production profile
documented in the README. Run `scripts/configure.ps1` to create local,
gitignored machine configuration, then `scripts/install.ps1` to install the
hash-locked environment.

Before submitting a pull request, run:

```powershell
$Python = Join-Path $PWD '.venv\Scripts\python.exe'
& $Python -X utf8 -m compileall -q csp_mcp server.py tests
& $Python -X utf8 -m unittest discover -s tests -p 'test_*.py' -v
```

When an attested CSP workstation is available, also run the stdio smoke test:

```powershell
& $Python -X utf8 .\tests\smoke_stdio.py
```

Run `tests/acceptance_interactive.py` only with explicit control of the desktop
and after reviewing its non-destructive interaction sequence. Hosted CI does not
run CSP-dependent smoke or interactive acceptance tests.

## Change requirements

- Preserve fail-closed executable signature, version, hash, locale, DPI,
  shortcut-profile, capture, window-identity, and input-time checks.
- Never weaken the preflight/token boundary merely to simplify host approval.
- Do not add arbitrary shell, process, registry, shortcut, or filesystem tools.
- Add focused unit tests for behavioral changes and document new or changed MCP
  tools in `docs/TOOL_CATALOG.md`.
- Keep tracked configuration portable. Examples may use placeholders but must
  not contain a contributor's absolute user or asset paths.
- Update `requirements.lock.txt` with hashes when dependencies change and
  preserve applicable third-party notices.

Security-sensitive reports should follow [the security policy](.github/SECURITY.md)
instead of being filed as public issues.
