# Security policy

## Supported version

Security fixes are applied to the latest release on the default branch. The
bundled automation profile supports only the exact Windows, CSP, locale, DPI,
and executable identity documented in [README.md](../README.md). A different CSP
build is not implicitly supported even if the server starts.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting page:

https://github.com/A2pha/clip-studio-paint-5.1.2-production-mcp/security/advisories/new

Include the affected commit or release, Windows/Python/CSP versions, threat
scenario, reproduction steps, observed result, expected fail-closed behavior,
and the smallest safe proof of concept. Remove usernames, document contents,
credentials, license information, proprietary CELSYS files, and unrelated
screenshots or logs.

Please allow the maintainer time to reproduce and coordinate a fix before public
disclosure. Do not test against machines, accounts, or data you do not own or
have explicit permission to assess.

## In-scope security boundaries

- escaping configured file roots or bypassing overwrite intent;
- bypassing executable/signature/version/profile attestation;
- reusing or changing a preflight confirmation token;
- controlling a non-CSP process/window or an unverified dialog;
- input execution after foreground, pixel, generation, or user-input changes;
- exposure of arbitrary shell, process, registry, shortcut, or filesystem
  behavior through an MCP tool;
- dependency or registration behavior that violates the documented local stdio
  boundary.

General CSP defects, unsupported CSP versions/locales/DPI profiles, social
engineering, and attacks that already have the same user's unrestricted local
code-execution rights are normally outside this project's vulnerability model.
The complete assumptions and residual risks are documented in
[docs/SECURITY.md](../docs/SECURITY.md).
