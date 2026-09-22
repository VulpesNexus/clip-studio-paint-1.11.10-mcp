# Third-party notices

This project is a fork of [A2pha/clip-studio-paint-5.1.2-production-mcp](https://github.com/A2pha/clip-studio-paint-5.1.2-production-mcp), released under the MIT License; A2pha's copyright notice is kept in [LICENSE](LICENSE).

It depends on the following runtime packages without vendoring their source code:

- [`mcp==1.29.0`](https://github.com/modelcontextprotocol/python-sdk), the Model Context Protocol Python SDK, licensed under the MIT License.
- [`Pillow==12.3.0`](https://github.com/python-pillow/Pillow), licensed under the MIT-CMU License. The complete license text and historical notices are available in Pillow's upstream *LICENSE* file and installed distribution.
- [`pywin32==312`](https://github.com/mhammond/pywin32), primarily distributed under the Python Software Foundation License. The pywin32 distribution also contains bundled components and files carrying their own license notices; those notices remain applicable. Review pywin32's upstream *LICENSE.txt*, repository notices, and the license files included with the installed wheel.

The original design was informed by public patterns in the following projects, but no source code from them is copied into this repository:

- [CursorTouch/Windows-MCP](https://github.com/CursorTouch/Windows-MCP), MIT.
- [microsoft/UFO](https://github.com/microsoft/UFO), MIT.
- [microsoft/AutoGenesis](https://github.com/microsoft/AutoGenesis), MIT.

CLIP STUDIO PAINT and CELSYS are trademarks of their respective owners. This unofficial bridge does not include CELSYS software, SDK source, private protocols, or reverse-engineered `.clip` format code.
