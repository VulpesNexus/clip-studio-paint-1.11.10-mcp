# Security policy

## Supported version

Security fixes are applied to the latest release on the default branch. The bundled automation profile supports only the Windows, CSP version, DPI, and executable identity documented in [README.md](../README.md), with any Windows culture and the native file-dialog languages listed there. A different CSP build is not implicitly supported even if the server starts.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting page:

https://github.com/VulpesNexus/clip-studio-paint-1.11.10-mcp/security/advisories/new

Include the affected commit or release, the Windows, Python, and CSP versions, the threat scenario, reproduction steps, the observed result, the expected fail-closed behavior, and the smallest safe proof of concept. Remove usernames, document contents, credentials, license information, proprietary CELSYS files, and unrelated screenshots or logs.

Please allow the maintainer time to reproduce and coordinate a fix before public disclosure. Do not test against machines, accounts, or data you do not own or have explicit permission to assess.

## In-scope security boundaries

- escaping configured file roots or bypassing overwrite intent;
- bypassing executable, signature, version, or profile attestation;
- reusing or changing a preflight confirmation token;
- controlling a non-CSP process or window, or an unverified dialog;
- input execution after foreground, pixel, generation, or user-input changes;
- exposure of arbitrary shell, process, registry, shortcut, or filesystem behavior through an MCP tool;
- dependency or registration behavior that violates the documented local stdio boundary.

General CSP defects, unsupported CSP versions and DPI profiles, social engineering, and attacks that already have the same user's unrestricted local code-execution rights are normally outside this project's vulnerability model. The complete assumptions and residual risks are documented in [docs/SECURITY.md](../docs/SECURITY.md).
