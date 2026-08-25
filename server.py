from __future__ import annotations

import warnings

from csp_mcp.win32_backend import enable_per_monitor_dpi_awareness

# This must run before any display coordinate is queried. The validated machine
# uses 125% scaling; without PMv2 awareness every input point would drift.
enable_per_monitor_dpi_awareness()

# mcp 1.29.0 currently triggers this pydantic-settings forward-reference
# warning while constructing FastMCP settings. It does not affect tool schemas
# or runtime behavior and would otherwise add noise to the stdio error stream.
warnings.filterwarnings(
    "ignore",
    message=r"Field 'lifespan' has an incomplete definition:.*",
)

from csp_mcp.app import mcp  # noqa: E402


if __name__ == "__main__":
    mcp.run(transport="stdio")
